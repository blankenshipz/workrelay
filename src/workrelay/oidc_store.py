"""Private SQLite backing for oidc-provider's adapter interface.

Only the locally spawned Node issuer may call this stdin JSON IPC. This module
does not expose OAuth endpoints or create accounts. Never echo records/errors.
"""
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time

MAX_RECORDS = 4096
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
PURGE_BATCH = 16
# At most 128 expired records (32 MiB of existing payload) can be removed in
# one transaction. More legacy expired records are reclaimed on later calls.
MAX_PURGE_BATCHES = 8
MAX_SQLITE_BYTES = 96 * 1024 * 1024
WRITE_ADMISSION_BYTES = 48 * 1024 * 1024
WAL_CHECKPOINT_BYTES = 8 * 1024 * 1024


def storage_bytes(db):
    base = Path(db.execute("PRAGMA database_list").fetchone()[2])
    total = 0
    wal = 0
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(base) + suffix)
        if path.exists() or path.is_symlink():
            entry = path.lstat()
            require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.getuid() and
                    not entry.st_mode & 0o077)
            total += entry.st_size
            if suffix == "-wal":
                wal = entry.st_size
    return total, wal


def require(ok):
    if not ok:
        raise ValueError("private issuer storage unavailable")


def connect(directory):
    root = Path(directory).expanduser()
    require(root.is_absolute() and not root.is_symlink())
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077)
    # SQLite opens its DB and -wal/-shm files by pathname on this macOS runtime.
    # Refuse every attacker-writable ancestor; only root-owned system symlinks
    # (e.g. macOS /var -> /private/var) may appear in the caller's path.
    for component in (root, *root.parents):
        node = component.lstat()
        if stat.S_ISLNK(node.st_mode):
            require(node.st_uid == 0)
        else:
            require(stat.S_ISDIR(node.st_mode) and node.st_uid in (0, os.getuid()) and
                    not node.st_mode & 0o022)
    resolved = root.resolve(strict=True)
    for component in (resolved, *resolved.parents):
        node = component.lstat()
        require(stat.S_ISDIR(node.st_mode) and node.st_uid in (0, os.getuid()) and
                not node.st_mode & 0o022)
    path = root / "issuer.sqlite"
    def check_file(file):
        if file.exists() or file.is_symlink():
            entry = file.lstat()
            require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.getuid() and
                    not entry.st_mode & 0o077)
    for name in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        check_file(name)
    old = os.umask(0o077)
    try:
        db = sqlite3.connect(path, timeout=10, isolation_level=None)
    finally:
        os.umask(old)
    check_file(path)
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA journal_mode=WAL")
    check_file(Path(str(path) + "-wal"))
    check_file(Path(str(path) + "-shm"))
    require(storage_bytes(db)[0] <= MAX_SQLITE_BYTES)
    db.execute("""CREATE TABLE IF NOT EXISTS records (
        model TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL,
        expires INTEGER, uid TEXT, user_code TEXT, PRIMARY KEY(model,id))""")
    db.execute("CREATE INDEX IF NOT EXISTS records_uid ON records(model,uid)")
    db.execute("CREATE INDEX IF NOT EXISTS records_user_code ON records(model,user_code)")
    db.execute("""CREATE TABLE IF NOT EXISTS admission (
        source TEXT PRIMARY KEY, window INTEGER NOT NULL, attempts INTEGER NOT NULL)""")
    return db


def execute(db, command, now=None):
    require(isinstance(command, dict))
    model, action = command.get("model"), command.get("action")
    require(isinstance(model, str) and re.fullmatch(r"[A-Za-z]{2,80}", model))
    require(action in ("upsert", "find", "findByUid", "findByUserCode", "consume", "destroy", "revokeByGrantId", "admit"))
    now = int(time.time()) if now is None else now
    size, wal = storage_bytes(db)
    if wal > WAL_CHECKPOINT_BYTES:
        db.execute("PRAGMA busy_timeout=100")
        try:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            db.execute("PRAGMA busy_timeout=10000")
        size, _ = storage_bytes(db)
    require(size <= WRITE_ADMISSION_BYTES)
    db.execute("BEGIN IMMEDIATE")
    quota_denied = False
    try:
        require(storage_bytes(db)[0] <= WRITE_ADMISSION_BYTES)
        # A bounded batch on every request prevents old OAuth artifacts from
        # accumulating forever. The writer lock serializes this and admission
        # across all issuer processes, including after restarts.
        def purge():
            return db.execute("""DELETE FROM records WHERE rowid IN (
                SELECT rowid FROM records WHERE expires IS NOT NULL AND expires<=? LIMIT ?)""",
                              (now, PURGE_BATCH)).rowcount

        if action != "admit":
            purge()
        if action == "admit":
            source = command.get("id")
            require(source in ("127.0.0.1", "::1"))
            kind = command.get("kind", "authorization")
            # Distinct bounded budgets let a burst of discovery/revocation
            # traffic consume neither login nor a pending code exchange.
            limits = {
                "authorization": (32, 24),
                "interaction": (64, 48),
                "token": (48, 36),
                "revocation": (24, 16),
                "discovery": (120, 96),
            }
            require(kind in limits)
            global_key = "global" if kind == "authorization" else "global:" + kind
            remote_key = source if kind == "authorization" else kind + ":" + source
            window = now // 60
            db.execute("DELETE FROM admission WHERE window<?", (window,))
            db.execute("""INSERT INTO admission(source,window,attempts) VALUES(?,?,1)
                ON CONFLICT(source) DO UPDATE SET window=excluded.window,
                attempts=CASE WHEN admission.window=excluded.window THEN admission.attempts+1 ELSE 1 END""", (global_key, window))
            db.execute("""INSERT INTO admission(source,window,attempts) VALUES(?,?,1)
                ON CONFLICT(source) DO UPDATE SET window=excluded.window,
                attempts=CASE WHEN admission.window=excluded.window THEN admission.attempts+1 ELSE 1 END""", (remote_key, window))
            global_count = db.execute("SELECT attempts FROM admission WHERE source=?", (global_key,)).fetchone()[0]
            remote_count = db.execute("SELECT attempts FROM admission WHERE source=?", (remote_key,)).fetchone()[0]
            global_limit, remote_limit = limits[kind]
            answer = global_count <= global_limit and remote_count <= remote_limit
        elif action == "upsert":
            identifier, payload, lifetime = (command.get(k) for k in ("id", "payload", "expiresIn"))
            require(isinstance(identifier, str) and 0 < len(identifier) <= 256 and
                    isinstance(payload, dict) and
                    (lifetime is None or (type(lifetime) is int and 0 < lifetime <= 31536000)))
            content = json.dumps(payload, separators=(",", ":"))
            content_bytes = len(content.encode())
            require(content_bytes <= 262144)
            for attempt in range(MAX_PURGE_BATCHES):
                existing = db.execute("SELECT length(CAST(payload AS BLOB)) FROM records WHERE model=? AND id=?",
                                      (model, identifier)).fetchone()
                count, used = db.execute("SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records").fetchone()
                if (count + (existing is None) <= MAX_RECORDS and
                        used - (existing[0] if existing else 0) + content_bytes <= MAX_PAYLOAD_BYTES):
                    break
                if attempt + 1 == MAX_PURGE_BATCHES or not purge():
                    quota_denied = True
                    break
            if not quota_denied:
                db.execute("""INSERT INTO records VALUES(?,?,?,?,?,?) ON CONFLICT(model,id) DO UPDATE SET
                    payload=excluded.payload,expires=excluded.expires,uid=excluded.uid,user_code=excluded.user_code""",
                    (model, identifier, content, now + lifetime if lifetime is not None else None,
                     payload.get("uid"), payload.get("userCode")))
            answer = None
        elif action in ("find", "findByUid", "findByUserCode"):
            field = {"find": "id", "findByUid": "uid", "findByUserCode": "user_code"}[action]
            identifier = command.get("id")
            require(isinstance(identifier, str) and 0 < len(identifier) <= 256)
            row = db.execute(f"SELECT payload FROM records WHERE model=? AND {field}=? AND (expires IS NULL OR expires>?)",
                             (model, identifier, now)).fetchone()
            answer = json.loads(row[0]) if row else None
        elif action == "consume":
            identifier = command.get("id")
            require(isinstance(identifier, str) and 0 < len(identifier) <= 256)
            row = db.execute("SELECT payload FROM records WHERE model=? AND id=? AND (expires IS NULL OR expires>?)",
                             (model, identifier, now)).fetchone()
            value = json.loads(row[0]) if row else None
            if model == "RefreshToken" and (value is None or "consumed" in value):
                # Concurrent requests can both find an unused token before either
                # consumes it. This is a protocol replay, not a storage outage.
                # Match the provider's replay revocation in this same transaction.
                # Deleting Grant also invalidates any late-saved successor; never
                # revive the old grant or permit two successful consumers.
                if value is not None:
                    grant = value.get("grantId")
                    require(isinstance(grant, str) and 0 < len(grant) <= 256)
                    db.execute("DELETE FROM records WHERE model='Grant' AND id=?", (grant,))
                    for record_model, record_id, content in db.execute(
                            "SELECT model,id,payload FROM records").fetchall():
                        if json.loads(content).get("grantId") == grant:
                            db.execute("DELETE FROM records WHERE model=? AND id=?", (record_model, record_id))
                answer = {"error": "refresh_token_unavailable"}
            else:
                require(isinstance(value, dict) and "consumed" not in value)
                value["consumed"] = now
                db.execute("UPDATE records SET payload=? WHERE model=? AND id=?",
                           (json.dumps(value, separators=(",", ":")), model, identifier))
                answer = None
        elif action == "destroy":
            db.execute("DELETE FROM records WHERE model=? AND id=?", (model, command.get("id")))
            answer = None
        else:
            grant = command.get("grantId")
            require(isinstance(grant, str) and 0 < len(grant) <= 256)
            # JSON payload is authoritative; do not match substrings from unrelated records.
            for identifier, content in db.execute("SELECT id,payload FROM records WHERE model=?", (model,)).fetchall():
                if json.loads(content).get("grantId") == grant:
                    db.execute("DELETE FROM records WHERE model=? AND id=?", (model, identifier))
            answer = None
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    # Commit the bounded expired-record cleanup even on quota denial; a legacy
    # over-quota database can then recover across repeated requests/restarts.
    require(not quota_denied)
    return answer


def main():
    try:
        require(len(sys.argv) == 2)
        raw = sys.stdin.buffer.read(300001)
        require(len(raw) <= 300000)
        text = raw.decode("utf-8")
        command, end = json.JSONDecoder().raw_decode(text)
        require(end == len(text))  # one complete framed command, no trailing data
        db = connect(sys.argv[1])
        try:
            answer = execute(db, command)
        finally:
            db.close()
        print(json.dumps(answer, separators=(",", ":")))
        return 0
    except Exception:
        print('{"error":"private issuer storage unavailable"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
