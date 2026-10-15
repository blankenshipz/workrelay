"""Private subscription/outbox storage. JSON commands arrive on stdin, never argv.

This is a storage primitive only: it MUST NOT be exposed as MCP events/subscribe
until callback verification, current task authorization, and signed delivery exist.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time


class StoreError(Exception):
    pass


def insist(ok):
    if not ok:
        raise StoreError("private event storage unavailable")


def canonical(value):
    insist(isinstance(value, dict) and all(isinstance(k, str) for k in value))
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def identity(principal, name, arguments, url):
    return "sub_" + hashlib.sha256(canonical({"principal": principal, "name": name,
        "arguments": arguments, "url": url}).encode()).hexdigest()


def connect(directory):
    root = Path(directory).expanduser().resolve(strict=True)
    entry = root.stat()
    insist(root.is_dir() and entry.st_uid == os.getuid() and entry.st_mode & 0o077 == 0)
    db_path = root / "events.sqlite"
    if db_path.exists() or db_path.is_symlink():
        found = db_path.lstat()
        insist(stat.S_ISREG(found.st_mode) and found.st_uid == os.getuid() and found.st_mode & 0o077 == 0)
    old_umask = os.umask(0o077)
    try:
        db = sqlite3.connect(db_path, isolation_level=None, timeout=10)
    finally:
        os.umask(old_umask)
    os.chmod(db_path, 0o600)
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
      id TEXT PRIMARY KEY, principal TEXT NOT NULL, name TEXT NOT NULL,
      arguments TEXT NOT NULL, url TEXT NOT NULL, secret TEXT NOT NULL,
      expires INTEGER NOT NULL, verified INTEGER NOT NULL DEFAULT 0,
      revoked INTEGER NOT NULL DEFAULT 0)""")
    db.execute("""CREATE TABLE IF NOT EXISTS outbox (
      id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
      principal TEXT NOT NULL, payload TEXT NOT NULL, due INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0, terminal INTEGER NOT NULL DEFAULT 0)""")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def execute(db, item, now=None):
    """Internal adapter API. Callers must authenticate principal AND check task grants.

    Store intentionally cannot activate a subscription. The verification worker may
    mark verified only after a signed, one-use HTTPS challenge has succeeded.
    """
    insist(isinstance(item, dict) and isinstance(item.get("principal"), str) and item["principal"])
    principal = item["principal"]
    op = item.get("op")
    now = int(time.time() * 1000) if now is None else now
    db.execute("BEGIN IMMEDIATE")
    try:
        if op == "reserve":
            name, args, url, secret = (item[k] for k in ("name", "arguments", "url", "secret"))
            insist(all(isinstance(x, str) and x for x in (name, url, secret)) and len(secret) <= 128)
            args_json = canonical(args)
            insist(len(args_json) <= 4096 and len(url) <= 2048)
            ttl = item.get("ttl_ms")
            insist(type(ttl) is int and 0 < ttl <= 86400000)
            ident = identity(principal, name, args, url)
            old = db.execute("SELECT principal,secret,verified,revoked FROM subscriptions WHERE id=?", (ident,)).fetchone()
            insist(old is None or old[0] == principal)
            # Any refresh is inert until verified, especially after signing-key rotation.
            db.execute("""INSERT INTO subscriptions(id,principal,name,arguments,url,secret,expires,verified,revoked)
                VALUES(?,?,?,?,?,?,?,0,0) ON CONFLICT(id) DO UPDATE SET
                secret=excluded.secret, expires=excluded.expires, verified=0, revoked=0""",
                (ident, principal, name, args_json, url, secret, now + ttl))
            result = {"id": ident, "refreshBefore": now + ttl, "verified": False}
        elif op == "get":
            row = db.execute("""SELECT id,name,arguments,url,expires,verified FROM subscriptions
                WHERE id=? AND principal=? AND revoked=0 AND expires>?""",
                (item["id"], principal, now)).fetchone()
            result = None if row is None else {"id": row[0], "name": row[1], "arguments": json.loads(row[2]),
                "url": row[3], "refreshBefore": row[4], "verified": bool(row[5])}
        elif op == "revoke":
            ident = item["id"]
            db.execute("UPDATE subscriptions SET revoked=1,verified=0 WHERE id=? AND principal=?", (ident, principal))
            db.execute("DELETE FROM outbox WHERE subscription_id=? AND principal=?", (ident, principal))
            result = {}
        elif op == "queue":
            ident, event_id, payload = (item[k] for k in ("id", "event_id", "payload"))
            insist(isinstance(payload, dict) and len(canonical(payload).encode()) <= 262144)
            row = db.execute("SELECT verified FROM subscriptions WHERE id=? AND principal=? AND revoked=0 AND expires>?",
                (ident, principal, now)).fetchone()
            insist(row is not None and row[0] == 1)
            db.execute("INSERT OR IGNORE INTO outbox VALUES(?,?,?,?,?,0,0)",
                (event_id, ident, principal, canonical(payload), now))
            result = {"eventId": event_id}
        elif op == "due":
            rows = db.execute("""SELECT o.id,o.subscription_id,o.payload,o.attempts FROM outbox o
                JOIN subscriptions s ON s.id=o.subscription_id WHERE o.principal=? AND s.principal=?
                AND s.verified=1 AND s.revoked=0 AND s.expires>? AND o.terminal=0 AND o.due<=?
                ORDER BY o.due,o.id LIMIT 32""", (principal, principal, now, now)).fetchall()
            result = [{"eventId": r[0], "subscriptionId": r[1], "payload": json.loads(r[2]), "attempts": r[3]} for r in rows]
        else:
            raise StoreError("private event storage unavailable")
        db.execute("COMMIT")
        return result
    except Exception:
        db.execute("ROLLBACK")
        raise


def main():
    try:
        insist(len(sys.argv) == 2)
        command = json.loads(sys.stdin.read(300000))
        with connect(sys.argv[1]) as db:
            answer = execute(db, command)
        print(json.dumps(answer, separators=(",", ":")))
    except Exception:
        # Never echo arguments, webhook secret, database path, or provider responses.
        print(json.dumps({"error": "private event storage unavailable"}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
