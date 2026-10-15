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
                input=json.dumps({"method": method, "path": path, "body": body}),
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


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scoped local OpenCode task adapter")
    parser.add_argument("--config", default=os.environ.get("AGENT_COMPUTER_BRIDGE_CONFIG", ""))
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start")
    start.add_argument("--key", required=True)
    start.add_argument("--owner", required=True)
    start.add_argument("--text", required=True)
    status = commands.add_parser("status")
    status.add_argument("--key", required=True)
    status.add_argument("--owner", required=True)
    feedback = commands.add_parser("respond")
    feedback.add_argument("--key", required=True)
    feedback.add_argument("--owner", required=True)
    feedback.add_argument("--feedback-key", required=True)
    feedback.add_argument("--text", required=True)
    cancel = commands.add_parser("cancel")
    cancel.add_argument("--key", required=True)
    cancel.add_argument("--owner", required=True)
    args = parser.parse_args(argv)
    try:
        require(bool(args.config), "set --config to a private config file")
        config, token, directory, state = load_config(args.config)
        config["_private_path"] = str(Path(args.config).expanduser().resolve())
        db = database(state)
        client = InstalledClient(config) if config.get("transport") == "installed-client" else Client(config, token)
        key = validate_key(args.key)
        require(args.owner == config["authorized_owner"], "owner not authorized by private configuration")
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
            if args.command == "status":
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
    except (BridgeError, KeyError, ValueError, sqlite3.Error) as exc:
        # Never print raw provider errors, URLs, tokens, workspace paths or task text.
        message = str(exc) if isinstance(exc, BridgeError) else "invalid configuration or local state"
        print(json.dumps({"error": message}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
