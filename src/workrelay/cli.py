"""Narrow OpenCode v2 adapter. No remote listener, relay, or credential discovery."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import secrets

from .supervision import (SupervisionError, owned_result, enrolled_result,
                          enrollment_row, grant_enrollment, revoke_enrollment, _enrolled)


class BridgeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise BridgeError(message)


def load_config(path):
    p = Path(path).expanduser().resolve()
    require(p.is_file() and p.stat().st_uid == os.getuid() and p.stat().st_mode & 0o077 == 0,
            "private configuration missing, foreign-owned or permissions too broad")
    config = json.loads(p.read_text())
    url = urllib.parse.urlsplit(config["server"])
    require(url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1")
            and not url.username and not url.password and not url.query and not url.fragment
            and url.path in ("", "/"), "server must be an uncredentialed loopback HTTP origin")
    if config.get("transport") == "installed-client":
        module = Path(config["client_service_module"]).expanduser().resolve()
        registration = Path(config["service_registration"]).expanduser().resolve()
        require(module.name == "service.js" and module.parent.name == "promise" and
                module.parent.parent.name == "dist" and module.parent.parent.parent.name == "client" and
                module.is_file() and registration.name == "service.json" and registration.is_file() and
                registration.stat().st_uid == os.getuid() and registration.stat().st_mode & 0o077 == 0,
                "installed service credential reference unavailable")
        require(Path(config["node_executable"]).is_file(), "Node runtime unavailable")
        token = None
    else:
        require(config.get("transport") in (None, "private-token"), "unsupported authenticated transport")
        token = Path(config["token_file"]).expanduser().resolve()
        require(token.is_file() and token.stat().st_uid == os.getuid() and token.stat().st_mode & 0o077 == 0,
                "private token file missing, foreign-owned or permissions too broad")
    directory = Path(config["directory"]).expanduser().resolve(strict=True)
    require(directory.is_dir(), "allowed workspace is not a directory")
    state = Path(config["state_dir"]).expanduser().resolve()
    require(state.is_dir() and state.stat().st_uid == os.getuid() and state.stat().st_mode & 0o077 == 0,
            "private state directory missing, foreign-owned or permissions too broad")
    require(config.get("model", {}).get("providerID") == "openai" and config["model"].get("id"),
            "model must explicitly use OpenAI OAuth; no fallback")
    require(config.get("agent", "quick-builder") in ("quick-builder", "builder"),
            "coding agent must be an enabled scoped builder")
    require(bool(re.fullmatch(r"[A-Za-z0-9_-]{1,80}", config.get("authorized_owner", ""))),
            "private configuration must declare one authorized owner")
    require(Path(config["quota_command"]).is_file(), "quota admission command missing")
    require(config.get("guard_entry") and isinstance(config.get("guard_file_hashes"), dict),
            "pinned installed guard identity missing; execution disabled")
    return config, token, directory, state


class Client:
    def __init__(self, config, token):
        self.url = config["server"].rstrip("/")
        self.auth = "Basic " + base64.b64encode(("opencode:" + token.read_text().strip()).encode()).decode()

    def request(self, method, path, body=None):
        req = urllib.request.Request(self.url + path,
            data=json.dumps(body).encode() if body is not None else None, method=method,
            headers={"Authorization": self.auth, "Content-Type": "application/json"})
        try:
            # urllib's default redirect handler can forward Authorization off-host.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, request, fp, code, msg, headers, newurl):
                    raise BridgeError("OpenCode redirect refused")

            with urllib.request.build_opener(NoRedirect).open(req, timeout=15) as response:
                raw = response.read(2_000_000)
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and method == "GET":
                return None
            # Never emit provider response bodies, which may include prompts or credentials.
            raise BridgeError(f"OpenCode request failed (HTTP {exc.code})") from None
        except (urllib.error.URLError, TimeoutError) as exc:
            raise BridgeError("OpenCode unavailable or request outcome uncertain") from None


class InstalledClient:
    """Use supported Service.discover/headers inside local Node, never export auth."""
    def __init__(self, config):
        self.config = config
        self.script = str(Path(__file__).with_name("transport.mjs"))

    def request(self, method, path, body=None):
        try:
            result = subprocess.run([self.config["node_executable"], self.script, self.config["_private_path"]],
                input=json.dumps({"method": method, "path": path, "body": body,
                                  **self.config.get("_supervision_authority", {})}),
                capture_output=True, text=True, timeout=20)
            require(result.returncode == 0 and len(result.stdout) <= 2_000_000,
                    "guarded local service request unavailable")
            response = json.loads(result.stdout)
            status = response["status"]
            if status == 404 and method == "GET":
                return None
            require(isinstance(status, int) and 200 <= status < 300,
                    "OpenCode request failed (HTTP response)")
            return response["data"]
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError):
            raise BridgeError("guarded local service request unavailable") from None


def admission(config, client):
    try:
        result = subprocess.run([config["quota_command"], "--check"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise BridgeError("quota unavailable; no task started") from None
    if result.returncode == 1:
        raise BridgeError("included OAuth quota admission denied; no paid fallback")
    require(result.returncode == 0, "quota unavailable; no task started")
    from .attestor import AttestationError, verify
    try:
        verify(config, client)
    except AttestationError:
        raise BridgeError("guarded OAuth route unverified; execution disabled") from None


def database(state):
    db = sqlite3.connect(state / "bridge.sqlite", timeout=20, isolation_level=None)
    os.chmod(state / "bridge.sqlite", 0o600)
    db.execute("PRAGMA busy_timeout=20000")
    for attempt in range(10):
        try:
            db.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc) or attempt == 9:
                raise
            time.sleep(0.05 * (attempt + 1))
    db.execute("""CREATE TABLE IF NOT EXISTS tasks (
      task_key TEXT PRIMARY KEY, session_id TEXT NOT NULL UNIQUE,
      prompt_id TEXT NOT NULL, workspace TEXT NOT NULL, request_hash TEXT NOT NULL,
      phase TEXT NOT NULL, owner TEXT NOT NULL, last_error TEXT NOT NULL DEFAULT ''
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS feedback (
      task_key TEXT NOT NULL, feedback_key TEXT NOT NULL, prompt_id TEXT NOT NULL,
      phase TEXT NOT NULL, request_hash TEXT NOT NULL, PRIMARY KEY(task_key, feedback_key)
    )""")
    return db


def validate_key(value):
    require(bool(re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value)), "invalid idempotency key")
    return value


def prompt_exists(client, session_id, prompt_id):
    # Check an exact message ID rather than a paginated transcript.
    result = client.request("GET", f"/api/session/{session_id}/message/{prompt_id}")
    return isinstance(result, dict) and result.get("data", {}).get("id") == prompt_id


def inbox_contains(client, session_id, prompt_id):
    result = client.request("GET", f"/api/session/{session_id}/inbox")
    require(isinstance(result, dict) and isinstance(result.get("data"), list), "inbox state unavailable")
    return any(isinstance(item, dict) and item.get("id") == prompt_id for item in result["data"])


def owned_session(client, sid, key, owner, directory):
    envelope = client.request("GET", f"/api/session/{sid}")
    session = envelope.get("data") if isinstance(envelope, dict) else None
    if session is None:
        return None
    require(session.get("id") == sid and session.get("metadata", {}).get("agentComputerBridge") == key and
            session.get("metadata", {}).get("agentComputerBridgeOwner") == owner and
            session.get("location", {}).get("directory") == str(directory), "session ownership mismatch")
    return session


def task_row(db, key):
    return db.execute("SELECT task_key,session_id,prompt_id,workspace,request_hash,phase,owner,last_error FROM tasks WHERE task_key=?", (key,)).fetchone()


def public(row, session=None):
    phase = row[5]
    if session is not None:
        outcome = session.get("outcome")
        if outcome in ("succeeded", "failed", "interrupted"):
            phase = outcome
        elif phase == "running" and session.get("time", {}).get("idle"):
            phase = "idle"  # idle is not proof of success
    return {"key": row[0], "session": row[1], "phase": phase,
            "owner": row[6], "evidence": "OpenCode session outcome" if session and session.get("outcome") else "local bridge ledger"}


def discover(config, client, directory, state, offset=0, limit=20):
    """Read only the scoped ledger, then revalidate each exact session. No global list."""
    require(type(offset) is int and 0 <= offset <= 1000000 and type(limit) is int and 1 <= limit <= 50,
            "invalid discovery page")
    output = {"projects": [{"id": "configured-workspace", "label": directory.name,
                            "actions": [{"tool": "workrelay_start", "requires": ["key", "text"]}]}],
              "items": [], "next_offset": None,
              "guidance": "These are runs and explicitly enrolled sessions, not agent definitions. "
              "Use returned action arguments. To start new work, choose a new idempotency key and provide the task text. "
              "Other existing sessions require explicit local read-only enrollment; discovery cannot enroll them."}
    path = state / "bridge.sqlite"
    if not path.exists():
        output["empty_reason"] = "No Workrelay ledger yet; start a task or ask the local operator to enroll a selected session."
        return output
    require(not path.is_symlink() and path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0,
            "private ledger unavailable")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        parts, params = [], []
        for table, column, kind, extra in [("tasks", "task_key", "run", ""),
                                          ("supervision_grants", "grant_id", "enrolled_session", " AND revoked=0")]:
            if table in tables:
                parts.append(f"SELECT '{kind}' AS kind,{column} AS id FROM {table} WHERE owner=? AND workspace=?{extra}")
                params.extend([config["authorized_owner"], str(directory)])
        rows = db.execute(" UNION ALL ".join(parts) + " ORDER BY kind,id LIMIT ? OFFSET ?",
                          params + [limit + 1, offset]).fetchall() if parts else []
        if len(rows) > limit:
            output["next_offset"] = offset + limit
        for kind, identity in rows[:limit]:
            try:
                if kind == "run":
                    validate_key(identity)
                    row = task_row(db, identity)
                    require(bool(re.fullmatch(r"ses_bridge_[0-9a-f]{32}", row[1])), "invalid session identity")
                    session = owned_session(client, row[1], identity, config["authorized_owner"], directory)
                    require(session is not None, "session unavailable")
                    item = {"type": kind, "key": identity, "label": f"Task {identity}",
                            "status": public(row, session)["phase"], "actions": [
                                {"tool": f"workrelay_{action}", "arguments": {"key": identity}}
                                for action in ("status", "result", "cancel")]}
                    item["actions"].append({"tool": "workrelay_respond", "arguments": {"key": identity},
                                            "requires": ["feedback_key", "text"]})
                else:
                    config["_supervision_authority"] = {"grant_id": identity}
                    session = _enrolled(db, client, identity, config["authorized_owner"], directory)
                    item = {"type": kind, "grant_id": identity, "label": "Enrolled read-only session",
                            "status": session.get("outcome") if session.get("outcome") in
                            ("succeeded", "failed", "interrupted") else "unknown",
                            "actions": [{"tool": "workrelay_enrolled_result", "arguments": {"grant_id": identity}}]}
                output["items"].append({**item, "project_id": "configured-workspace"})
            except (BridgeError, SupervisionError):
                pass  # Stale or changed authority is not a discoverable item.
            finally:
                config.pop("_supervision_authority", None)
        if not output["items"]:
            output["empty_reason"] = "No accessible items on this page. Follow next_offset if present; otherwise start a task or request local enrollment."
        return output
    finally:
        db.close()


def enrollment_admin_token(config):
    """Local administrator credential via stdin, never argv or MCP arguments."""
    try:
        path = Path(config.get("enrollment_admin_token_file", ""))
        require(path.is_file() and path.stat().st_uid == os.getuid() and
                path.stat().st_mode & 0o077 == 0 and path.stat().st_size <= 4096,
                "private enrollment admin credential unavailable")
        expected = path.read_text().strip()
        supplied = sys.stdin.read(4098).strip()
        require(32 <= len(expected) <= 4096 and len(supplied) <= 4096 and
                secrets.compare_digest(expected.encode(), supplied.encode()),
                "enrollment administrator authentication failed")
        return supplied
    except (OSError, UnicodeError):
        raise BridgeError("private enrollment admin credential unavailable") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scoped local OpenCode task adapter")
    parser.add_argument("--config", default=os.environ.get("AGENT_COMPUTER_BRIDGE_CONFIG", ""))
    commands = parser.add_subparsers(dest="command", required=True)
    discovery = commands.add_parser("discover", help="List permitted work without internal IDs")
    discovery.add_argument("--owner", required=True)
    discovery.add_argument("--offset", type=int, default=0)
    discovery.add_argument("--limit", type=int, default=20)
    start = commands.add_parser("start")
    start.add_argument("--key", required=True)
    start.add_argument("--owner", required=True)
    start.add_argument("--text")  # Legacy trusted local CLI alias; remote entry uses stdin.
    start.add_argument("--stdin-text", action="store_true")
    status = commands.add_parser("status")
    status.add_argument("--key", required=True)
    status.add_argument("--owner", required=True)
    result = commands.add_parser("result", help="Read bounded, redacted output of an owned task")
    result.add_argument("--key", required=True)
    result.add_argument("--owner", required=True)
    enrolled = commands.add_parser("enrolled-result", help="Read an existing session by locally issued grant ID")
    enrolled.add_argument("--grant-id", required=True)
    enrolled.add_argument("--owner", required=True)
    for name in ("grant-enrollment", "revoke-enrollment"):
        admin = commands.add_parser(name, help="Local admin only; requires private credential on stdin")
        admin.add_argument("--session-id", required=True)
        admin.add_argument("--owner", required=True)
        admin.add_argument("--workspace", required=True)
        admin.add_argument("--stdin-admin-token", action="store_true", required=True)
        if name == "revoke-enrollment":
            admin.add_argument("--grant-id", required=True)
    feedback = commands.add_parser("respond")
    feedback.add_argument("--key", required=True)
    feedback.add_argument("--owner", required=True)
    feedback.add_argument("--feedback-key", required=True)
    feedback.add_argument("--text")
    feedback.add_argument("--stdin-text", action="store_true")
    cancel = commands.add_parser("cancel")
    cancel.add_argument("--key", required=True)
    cancel.add_argument("--owner", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ("start", "respond"):
            require(bool(args.stdin_text) != (args.text is not None), "supply exactly one text source")
            if args.stdin_text:
                args.text = sys.stdin.read(16002)
        require(bool(args.config), "set --config to a private config file")
        config, token, directory, state = load_config(args.config)
        config["_private_path"] = str(Path(args.config).expanduser().resolve())
        client = InstalledClient(config) if config.get("transport") == "installed-client" else Client(config, token)
        require(args.owner == config["authorized_owner"], "owner not authorized by private configuration")
        if args.command == "discover":
            print(json.dumps(discover(config, client, directory, state, args.offset, args.limit)))
            return 0
        db = database(state)
        if args.command in ("grant-enrollment", "revoke-enrollment"):
            token = enrollment_admin_token(config)
            require(args.workspace == str(directory), "selected workspace not authorized by private configuration")
            selection = {"session_id": args.session_id, "owner": config["authorized_owner"], "workspace": str(directory)}
            if args.command == "grant-enrollment":
                config["_supervision_authority"] = {"local_admin_selection": selection, "local_admin_token": token}
                print(json.dumps(grant_enrollment(db, client, args.session_id, config["authorized_owner"],
                                                 directory, local_admin_grant=selection)))
            else:
                row = enrollment_row(db, args.grant_id, config["authorized_owner"], directory)
                require(row[0] == args.session_id, "selected session does not match enrollment")
                revoke_enrollment(db, args.grant_id)
                print(json.dumps({"grant_id": args.grant_id, "revoked": True}))
            return 0
        if args.command == "enrolled-result":
            enrollment_row(db, args.grant_id, config["authorized_owner"], directory)
            config["_supervision_authority"] = {"grant_id": args.grant_id}
            print(json.dumps(enrolled_result(db, client, args.grant_id, config["authorized_owner"], directory)))
            return 0
        key = validate_key(args.key)
        if args.command == "start":
            import hashlib
            require(bool(args.text.strip()) and len(args.text) <= 16000, "task text missing or too long")
            require(bool(args.owner.strip()) and len(args.owner) <= 100, "owner missing or too long")
            digest = hashlib.sha256((args.owner + "\0" + args.text).encode()).hexdigest()
            admission(config, client)
            db.execute("BEGIN IMMEDIATE")
            row = task_row(db, key)
            if row:
                db.execute("COMMIT")
                require(row[4] == digest and row[6] == args.owner and row[3] == str(directory), "idempotency key reused for different task")
            else:
                sid, mid = "ses_bridge_" + uuid.uuid4().hex, "msg_" + uuid.uuid4().hex
                db.execute("INSERT INTO tasks(task_key,session_id,prompt_id,workspace,request_hash,phase,owner) VALUES(?,?,?,?,?,?,?)",
                           (key, sid, mid, str(directory), digest, "reserved", args.owner))
                db.execute("COMMIT")
            db.execute("BEGIN IMMEDIATE")  # claim across processes through session creation and exact-message check
            row = task_row(db, key)
            sid, mid = row[1], row[2]
            require(bool(re.fullmatch(r"ses_bridge_[0-9a-f]{32}", sid)) and
                    bool(re.fullmatch(r"msg_[0-9a-f]{32}", mid)), "invalid owned session identity")
            try:
                current = owned_session(client, sid, key, args.owner, directory)
                if current is None:
                    require(row[5] == "reserved", "owned session disappeared; refusing to recreate")
                    response = client.request("POST", "/api/session", {"id": sid, "title": "Workrelay: " + key,
                          "location": {"directory": str(directory)}, "model": config["model"],
                          "agent": config.get("agent", "quick-builder"),
                          "metadata": {"agentComputerBridge": key, "agentComputerBridgeOwner": args.owner}})
                    require(response and response.get("data", {}).get("id") == sid, "session creation not confirmed")
                    current = owned_session(client, sid, key, args.owner, directory)
                    require(current is not None, "created session not observed")
                if prompt_exists(client, sid, mid):
                    db.execute("UPDATE tasks SET phase='running' WHERE task_key=?", (key,))
                    action = "observed"
                elif row[5] in ("submitting", "queued") and inbox_contains(client, sid, mid):
                    db.execute("UPDATE tasks SET phase='queued' WHERE task_key=?", (key,))
                    action = "observed_queued"
                elif row[5] == "reserved":
                    db.execute("UPDATE tasks SET phase='submitting' WHERE task_key=?", (key,))
                    action = "submit"
                else:
                    action = "uncertain"
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
            if action == "submit":
                # Serialize POST with cancellation; committed submitting survives a crash.
                db.execute("BEGIN IMMEDIATE")
                try:
                    require(task_row(db, key)[5] == "submitting", "task canceled before submission")
                    reply = client.request("POST", f"/api/session/{sid}/prompt", {"id": mid, "text": args.text})
                    require(reply and reply.get("data", {}).get("id") == mid and
                            reply["data"].get("sessionID") == sid, "prompt submission not confirmed")
                    observed = prompt_exists(client, sid, mid)
                    db.execute("UPDATE tasks SET phase=? WHERE task_key=?", ("running" if observed else "queued", key))
                    db.execute("COMMIT")
                except BridgeError:
                    db.execute("ROLLBACK")
                    raise BridgeError("prompt submission uncertain; inspect status before manual recovery") from None
                except Exception:
                    db.execute("ROLLBACK")
                    raise
            elif action == "uncertain":
                raise BridgeError("submission uncertain; no replay; inspect session and resolve manually")
            print(json.dumps(public(task_row(db, key), current)))
        else:
            row = task_row(db, key)
            require(row is not None and row[3] == str(directory) and row[6] == args.owner and
                    bool(re.fullmatch(r"ses_bridge_[0-9a-f]{32}", row[1])) and
                    bool(re.fullmatch(r"msg_[0-9a-f]{32}", row[2])), "unknown task in this workspace")
            session = owned_session(client, row[1], key, args.owner, directory)
            require(session is not None, "owned session not found")
            if args.command == "result":
                # Session/workspace come only from the private ledger/config;
                # --owner must match the configured owner before any service GET.
                print(json.dumps(owned_result(client, row, config["authorized_owner"], directory)))
            elif args.command == "status":
                result = public(row, session)
                result["prompt_observed"] = prompt_exists(client, row[1], row[2])
                if row[5] == "submitting" and result["prompt_observed"] and result["phase"] == "submitting":
                    result["phase"] = "submitted_observed"
                if row[5] == "queued" and result["prompt_observed"] and result["phase"] == "queued":
                    result["phase"] = "materialized_observed"
                print(json.dumps(result))
            elif args.command == "respond":
                import hashlib
                require(bool(args.text.strip()) and len(args.text) <= 16000, "response missing or too long")
                require(row[5] == "running" and prompt_exists(client, row[1], row[2]) and
                        session.get("outcome") not in ("failed", "interrupted"),
                        "task not accepting feedback")
                fkey = validate_key(args.feedback_key)
                admission(config, client)
                db.execute("BEGIN IMMEDIATE")
                latest = task_row(db, key)
                if latest[5] != "running":
                    db.execute("ROLLBACK")
                    raise BridgeError("task no longer accepting feedback")
                old = db.execute("SELECT prompt_id,phase,request_hash FROM feedback WHERE task_key=? AND feedback_key=?", (key, fkey)).fetchone()
                digest = hashlib.sha256(args.text.encode()).hexdigest()
                if old is None:
                    mid = "msg_" + uuid.uuid4().hex
                    db.execute("INSERT INTO feedback VALUES(?,?,?,?,?)", (key, fkey, mid, "submitting", digest))
                else:
                    if old[2] != digest:
                        db.execute("ROLLBACK")
                        raise BridgeError("feedback idempotency key reused for different response")
                    mid = old[0]
                db.execute("COMMIT")
                if not prompt_exists(client, row[1], mid):
                    require(old is None, "feedback submission uncertain; no automatic replay")
                    db.execute("BEGIN IMMEDIATE")
                    if task_row(db, key)[5] != "running":
                        db.execute("ROLLBACK")
                        raise BridgeError("task no longer accepting feedback")
                    try:
                        reply = client.request("POST", f"/api/session/{row[1]}/prompt", {"id": mid, "text": args.text})
                        require(reply and reply.get("data", {}).get("id") == mid and
                                reply["data"].get("sessionID") == row[1], "feedback submission not confirmed")
                    finally:
                        db.execute("ROLLBACK")  # reservation remains; uncertainty must be reconciled
                db.execute("UPDATE feedback SET phase='sent' WHERE task_key=? AND feedback_key=?", (key, fkey))
                print(json.dumps({"key": key, "session": row[1], "feedback": "observed" if old else "sent"}))
            elif args.command == "cancel":
                db.execute("BEGIN IMMEDIATE")
                current = task_row(db, key)
                if current[5] not in ("running", "queued", "submitting", "interrupt_pending"):
                    db.execute("ROLLBACK")
                    raise BridgeError("task is not bridge-running")
                if session.get("outcome") in ("succeeded", "failed", "interrupted"):
                    db.execute("ROLLBACK")
                    raise BridgeError("task already has terminal outcome")
                db.execute("UPDATE tasks SET phase='interrupt_pending' WHERE task_key=?", (key,))
                db.execute("COMMIT")
                # Interrupt only this exact owned session. Descendants are NOT interrupted or deleted.
                # A queued inbox entry can run after an interrupt(false). Remove only
                # this task's exact ID; a concurrent dequeue still needs interrupt.
                removed_queued = False
                if current[5] in ("queued", "submitting", "interrupt_pending"):
                    if inbox_contains(client, row[1], row[2]):
                        client.request("DELETE", f"/api/session/{row[1]}/inbox/{row[2]}")
                        removed_queued = not inbox_contains(client, row[1], row[2]) and not prompt_exists(client, row[1], row[2])
                reply = client.request("POST", f"/api/session/{row[1]}/interrupt?resume=false")
                if reply and reply.get("interrupted") is False and removed_queued:
                    db.execute("UPDATE tasks SET phase='canceled_queued' WHERE task_key=?", (key,))
                    print(json.dumps({"key": key, "session": row[1], "phase": "canceled_queued"}))
                    return 0
                require(reply and reply.get("interrupted") is True, "interrupt not acknowledged; inspect and retry")
                db.execute("UPDATE tasks SET phase='interrupt_acknowledged' WHERE task_key=?", (key,))
                print(json.dumps({"key": key, "session": row[1], "phase": "interrupt_acknowledged"}))
        return 0
    except (BridgeError, SupervisionError, KeyError, ValueError, sqlite3.Error) as exc:
        # Never print raw provider errors, URLs, tokens, workspace paths or task text.
        message = str(exc) if isinstance(exc, (BridgeError, SupervisionError)) else "invalid configuration or local state"
        print(json.dumps({"error": message}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
