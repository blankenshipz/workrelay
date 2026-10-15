"""Bounded, GET-only supervision of exact OpenCode V2 sessions.

The caller must authenticate the principal BEFORE supplying ``authorized_owner``;
an owner label from tool arguments is not authentication. Ledger rows and the
enrollment database are trusted private local state, never remote request data.
``local_admin_grant`` must come from a private local administrator's explicit
selection, not OAuth claims or tool arguments. Enrollment conveys READ access
only, never ownership transfer, permission reply, feedback, or cancellation.

Client contract: request(method, path) returns the installed V2 JSON envelope.
Only assistant text is returned, labeled untrusted; tool results, reasoning,
permission resources/metadata and provider errors are deliberately omitted.
Redaction is defense in depth, not a guarantee for arbitrary secrets in prose.
"""

import re
import secrets
import json
from pathlib import Path
from urllib.parse import urlencode


class SupervisionError(RuntimeError):
    """Safe diagnostic with no upstream body or transcript included."""


def _require(condition, message):
    if not condition:
        raise SupervisionError(message)


def _identity(sid, owner, workspace):
    _require(isinstance(sid, str) and re.fullmatch(r"ses[A-Za-z0-9_-]{1,160}", sid),
             "invalid session identity")
    _require(isinstance(owner, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", owner),
             "invalid authorized owner")
    workspace = str(workspace)
    _require(Path(workspace).is_absolute() and str(Path(workspace).resolve()) == workspace,
             "workspace must be an explicit canonical absolute path")
    return workspace


def _session(client, sid, workspace):
    envelope = client.request("GET", f"/api/session/{sid}")
    data = envelope.get("data") if isinstance(envelope, dict) else None
    _require(isinstance(data, dict), "session missing or stale")
    _require(data.get("id") == sid and
             isinstance(data.get("location"), dict) and
             data["location"].get("directory") == workspace,
             "session identity or workspace mismatch")
    return data


def _owned(client, row, authorized_owner, workspace):
    _require(isinstance(row, (tuple, list)) and len(row) == 8,
             "trusted task ledger row required")
    key, sid, _, directory, _, _, owner, _ = row
    workspace = _identity(sid, authorized_owner, workspace)
    _require(owner == authorized_owner and directory == workspace,
             "task owner or workspace mismatch")
    data = _session(client, sid, workspace)
    metadata = data.get("metadata")
    _require(isinstance(metadata, dict) and
             metadata.get("agentComputerBridge") == key and
             metadata.get("agentComputerBridgeOwner") == owner,
             "session ownership mismatch")
    return data


def redact_text(text, limit=8000):
    """Return bounded text, removing common credential formats before truncation."""
    _require(isinstance(limit, int) and 1 <= limit <= 16000, "invalid text limit")
    if not isinstance(text, str):
        return ""
    # Refuse oversized text rather than truncate an incomplete credential/PEM.
    if len(text) > 64000:
        return "[oversized assistant text omitted]"
    text = re.sub(r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?(?:-----END [^-\n]*PRIVATE KEY-----|\Z)",
                  "[REDACTED PRIVATE KEY]", text, flags=re.S)
    text = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED AUTH]", text)
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b",
                  "[REDACTED TOKEN]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED JWT]", text)
    text = re.sub(r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|secret|token|authorization)[\"']?\s*[:=]\s*)(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s&,;]+)",
                  r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    return text[:limit]


def _assistant_output(client, sid, max_pages, page_size, text_limit):
    cursor = None
    seen = set()
    for _ in range(max_pages):
        query = {"limit": page_size, "type": "assistant"}
        query.update({"cursor": cursor} if cursor else {"order": "desc"})
        page = client.request("GET", f"/api/session/{sid}/message?{urlencode(query)}")
        _require(isinstance(page, dict) and isinstance(page.get("data"), list) and
                 isinstance(page.get("cursor"), dict), "message page unavailable")
        _require(len(page["data"]) <= page_size, "message page exceeds bound")
        for message in page["data"]:
            _require(isinstance(message, dict), "invalid message projection")
            if message.get("type") != "assistant":
                continue
            _require(isinstance(message.get("id"), str) and
                     re.fullmatch(r"msg_[A-Za-z0-9_-]{1,160}", message["id"]),
                     "invalid message identity")
            # Partial streaming text and reasoning are not a finished response.
            if not isinstance(message.get("time"), dict) or not message["time"].get("completed"):
                continue
            content = message.get("content")
            _require(isinstance(content, list) and len(content) <= 1000,
                     "invalid assistant content")
            text = [part["text"] for part in content if isinstance(part, dict) and
                    part.get("type") == "text" and isinstance(part.get("text"), str)]
            if text:
                if sum(map(len, text)) > 64000:
                    safe = "[oversized assistant text omitted]"
                else:
                    safe = redact_text("\n".join(text), text_limit)
                return {"message_id": message["id"], "text": safe,
                        "trust": "untrusted_assistant_text", "complete": True}, False
        cursor = page["cursor"].get("next")
        if cursor is None:
            return None, False
        _require(isinstance(cursor, str) and 0 < len(cursor) <= 4096 and cursor not in seen,
                 "invalid or repeated message cursor")
        seen.add(cursor)
    return None, True


def _observe(client, session, phase, *, max_pages=5, page_size=20, text_limit=8000):
    _require(type(max_pages) is int and 1 <= max_pages <= 10 and
             type(page_size) is int and 1 <= page_size <= 50 and
             type(text_limit) is int and 1 <= text_limit <= 16000,
             "invalid supervision bounds")
    sid = session["id"]
    # Installed V2 permission.list is session-scoped and NOT paginated. Never use
    # the global permission list, which could disclose another project's data.
    pending = client.request("GET", f"/api/session/{sid}/permission")
    _require(isinstance(pending, dict) and isinstance(pending.get("data"), list) and
             len(pending["data"]) <= 1000, "permission state unavailable or exceeds bound")
    decisions = []
    for item in pending["data"]:
        _require(isinstance(item, dict) and item.get("sessionID") == sid and
                 isinstance(item.get("id"), str) and
                 re.fullmatch(r"per[A-Za-z0-9_-]{1,160}", item["id"]),
                 "permission ownership mismatch")
        decisions.append({"id": item["id"], "kind": "permission"})
    output, bounded = _assistant_output(client, sid, max_pages, page_size, text_limit)
    outcome = session.get("outcome")
    terminal = outcome in ("succeeded", "failed", "interrupted")
    if terminal:
        phase = outcome
    elif decisions:
        phase = "decision_needed"
    elif session.get("time", {}).get("idle"):
        phase = "idle"
    elif phase in ("succeeded", "failed", "interrupted"):
        phase = "unknown"  # ledger alone cannot prove remote completion
    return {"session": sid, "phase": phase, "terminal": terminal,
            "decision_needed": bool(decisions), "decisions": decisions,
            "assistant_output": output, "message_scan_bounded": bounded,
            "evidence": "OpenCode session outcome" if terminal else "OpenCode read-only observation",
            "capabilities": ["read"]}


def owned_result(client, row, authorized_owner, workspace, **bounds):
    """Observe an exact private CLI ledger row (task_row's eight-column tuple)."""
    session = _owned(client, row, authorized_owner, workspace)
    result = _observe(client, session, row[5], **bounds)
    _owned(client, row, authorized_owner, workspace)  # detect stale ownership during read
    return {**result, "key": row[0], "owner": authorized_owner, "access": "owned"}


def _enrollment_table(db):
    db.execute("""CREATE TABLE IF NOT EXISTS supervision_grants (
        grant_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, owner TEXT NOT NULL,
        workspace TEXT NOT NULL, project_id TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
        owner_snapshot TEXT NOT NULL DEFAULT ''
    )""")
    if "owner_snapshot" not in {row[1] for row in db.execute("PRAGMA table_info(supervision_grants)")}:
        db.execute("ALTER TABLE supervision_grants ADD COLUMN owner_snapshot TEXT NOT NULL DEFAULT ''")


def _owner_snapshot(session):
    # There is no OpenCode owner-transfer primitive. Preserve the existing
    # metadata/parent identity exactly; never rewrite it to impersonate ownership.
    snapshot = json.dumps({"metadata": session.get("metadata"), "parentID": session.get("parentID")},
                          sort_keys=True, separators=(",", ":"))
    _require(len(snapshot) <= 16000, "owner metadata exceeds enrollment bound")
    return snapshot


def enrollment_row(db, grant_id, authorized_owner, workspace):
    """Resolve only a live local grant; caller never supplies a session ID."""
    _require(isinstance(grant_id, str) and re.fullmatch(r"grant_[0-9a-f]{32}", grant_id),
             "invalid enrollment identity")
    _enrollment_table(db)
    row = db.execute("SELECT session_id,owner,workspace,project_id,revoked,owner_snapshot FROM supervision_grants WHERE grant_id=?",
                     (grant_id,)).fetchone()
    _require(row is not None and not row[4] and bool(row[5]), "enrollment missing or revoked")
    _identity(row[0], authorized_owner, workspace)
    _require(row[1] == authorized_owner and row[2] == str(workspace),
             "enrollment owner or workspace mismatch")
    return row


def grant_enrollment(db, client, session_id, authorized_owner, workspace, *, local_admin_grant):
    """LOCAL ADMIN ONLY: persist an explicit selected-session read-only grant.

    The trusted local grant is exactly {session_id, owner, workspace}; no wildcard
    or owner-label-only enrollment. This function must not be an MCP tool.
    Transactions/commit and private file permissions belong to the caller.
    """
    workspace = _identity(session_id, authorized_owner, workspace)
    _require(local_admin_grant == {"session_id": session_id, "owner": authorized_owner,
                                  "workspace": workspace}, "explicit local admin grant required")
    session = _session(client, session_id, workspace)
    project = session.get("projectID")
    _require(isinstance(project, str) and bool(project), "verified project identity required")
    _enrollment_table(db)
    grant_id = "grant_" + secrets.token_hex(16)
    db.execute("INSERT INTO supervision_grants(grant_id,session_id,owner,workspace,project_id,revoked,owner_snapshot) VALUES(?,?,?,?,?,0,?)",
               (grant_id, session_id, authorized_owner, workspace, project, _owner_snapshot(session)))
    return {"grant_id": grant_id, "session": session_id, "owner": authorized_owner,
            "access": "enrolled_read_only", "capabilities": ["read"]}


def revoke_enrollment(db, grant_id):
    """LOCAL ADMIN ONLY. Revoke without touching the OpenCode session/owner."""
    _enrollment_table(db)
    db.execute("UPDATE supervision_grants SET revoked=1 WHERE grant_id=?", (grant_id,))


def _enrolled(db, client, grant_id, authorized_owner, workspace):
    row = enrollment_row(db, grant_id, authorized_owner, workspace)
    session = _session(client, row[0], row[2])
    _require(session.get("projectID") == row[3], "enrollment project identity mismatch")
    _require(_owner_snapshot(session) == row[5], "existing session owner metadata changed")
    return session


def enrolled_result(db, client, grant_id, authorized_owner, workspace, **bounds):
    """Read a locally enrolled existing session. Never adopt or mutate its owner."""
    session = _enrolled(db, client, grant_id, authorized_owner, workspace)
    result = _observe(client, session, "unknown", **bounds)
    _enrolled(db, client, grant_id, authorized_owner, workspace)
    return {**result, "grant_id": grant_id, "owner": authorized_owner,
            "access": "enrolled_read_only"}
