"""Durable control engine; caller supplies bound-server authorization and transport.

Not a CLI or unrestricted remote entry point. Financial admission is the existing
Workrelay admission routine. No new session, ownership, model or permission edits.
"""
import hashlib
import json
import re
import sqlite3
import os

from .cli import admission, BridgeError, require


def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS managed_operations (
      binding TEXT NOT NULL, session TEXT NOT NULL, operation TEXT NOT NULL,
      kind TEXT NOT NULL, digest TEXT NOT NULL, message TEXT NOT NULL,
      phase TEXT NOT NULL, identity TEXT NOT NULL, reservation_pid INTEGER,
      PRIMARY KEY(binding,session,operation))""")
    db.execute('BEGIN IMMEDIATE')
    try:
        if 'reservation_pid' not in {row[1] for row in db.execute('PRAGMA table_info(managed_operations)')}:
            db.execute('ALTER TABLE managed_operations ADD COLUMN reservation_pid INTEGER')
        db.execute('COMMIT')
    except Exception:
        db.execute('ROLLBACK')
        raise


def reservation_owner_dead(pid):
    """Only ESRCH is proof of absence in this local ledger's process namespace.

    A reused PID is deliberately treated as live, not matched by age or guessed
    command name. Legacy/missing owners and permission/probe errors are unknown.
    No clock expiry, heartbeat, or timeout is sufficient to recover ownership.
    """
    if type(pid) is not int or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except (OSError, OverflowError):
        return False
    return False


def identity(session, sid):
    require(isinstance(session, dict) and session.get('id') == sid, 'session unavailable')
    # Compare, never disclose or rewrite the existing owner, model, agent, intent,
    # permissions, project and parent. Changes require fresh operator review.
    selected = {key: session.get(key) for key in
                ('id', 'parentID', 'projectID', 'agent', 'model', 'metadata', 'permissions', 'location')}
    return hashlib.sha256(json.dumps(selected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def control(db, config, client, authorize, session_id, operation_id, *, text=None, interrupt=False):
    """authorize() must revalidate pinned JWT/capability/registration and return
    a stable opaque binding ID. Failure must raise, never return a user owner label.
    client is the same authorized managed endpoint for every GET/POST.
    """
    require(bool(re.fullmatch(r'ses[A-Za-z0-9_-]{1,160}', session_id or '')), 'invalid session')
    require(bool(re.fullmatch(r'[A-Za-z0-9_-]{1,80}', operation_id or '')), 'invalid operation')
    require(type(interrupt) is bool, 'invalid control')
    require(db.isolation_level is None, 'durable autocommit ledger required')
    db.execute('PRAGMA synchronous=FULL')
    require(text is None if interrupt else isinstance(text, str) and 0 < len(text.strip()) <= 16000,
            'invalid message')
    binding = authorize()
    require(isinstance(binding, str) and bool(re.fullmatch(r'[0-9a-f]{64}', binding)), 'bound authorization required')
    def check():
        require(authorize() == binding, 'authority changed')
    def get(path):
        check()
        result = client.request('GET', path)
        check()
        return result
    def snapshot():
        result = get('/api/session/' + session_id)
        session = result.get('data') if isinstance(result, dict) else None
        if not interrupt:
            require(isinstance(session, dict) and session.get('model') == config.get('model') and
                    isinstance(config.get('model'), dict) and config['model'].get('providerID') == 'openai',
                    'existing model is not the financially attested route')
        return identity(session, session_id)
    kind = 'interrupt' if interrupt else 'queue'
    digest = hashlib.sha256((kind + '\0' + (text or '')).encode()).hexdigest()
    message = 'msg_' + hashlib.sha256((binding + '\0' + session_id + '\0' + operation_id).encode()).hexdigest()[:32]
    initialize(db)
    db.execute('BEGIN IMMEDIATE')
    try:
        row = db.execute('SELECT kind,digest,message,phase,identity,reservation_pid FROM managed_operations WHERE binding=? AND session=? AND operation=?',
                          (binding, session_id, operation_id)).fetchone()
        recovering = False
        if row:
            require(row[0] == kind and row[1] == digest, 'operation conflict')
            if row[3] == 'reserved' and reservation_owner_dead(row[5]):
                # BEGIN IMMEDIATE serializes takeover. Before 'sending' no POST
                # was permitted. Keep the original ID/hash/identity and repeat
                # all financial, authority and identity checks before any send.
                current, message = row[4], row[2]
                db.execute('UPDATE managed_operations SET reservation_pid=? WHERE binding=? AND session=? AND operation=?',
                           (os.getpid(), binding, session_id, operation_id))
                recovering = True
        if row and not recovering:
            db.execute('COMMIT')
            phase = row[3]
            if phase in ('sending', 'uncertain') and kind == 'queue':
                # Read-only reconciliation; absence is not permission to replay.
                require(snapshot() == row[4], 'session identity changed')
                exact = get(f'/api/session/{session_id}/message/{row[2]}')
                found = isinstance(exact, dict) and exact.get('data', {}).get('id') == row[2]
                if not found:
                    inbox = get(f'/api/session/{session_id}/inbox')
                    found = isinstance(inbox, dict) and isinstance(inbox.get('data'), list) and any(
                        isinstance(item, dict) and item.get('id') == row[2] and item.get('sessionID') == session_id
                        for item in inbox['data'])
                if found:
                    check()
                    phase = 'queued_observed'
                    db.execute('UPDATE managed_operations SET phase=? WHERE binding=? AND session=? AND operation=?',
                               (phase, binding, session_id, operation_id))
            return {'operation_id': operation_id, 'session_id': session_id, 'message_id': row[2], 'phase': phase}
        if not recovering:
            busy = db.execute("SELECT 1 FROM managed_operations WHERE session=? AND phase IN ('reserved','sending','uncertain') LIMIT 1",
                              (session_id,)).fetchone()
            require(not busy, 'session has unresolved control operation')
            current = snapshot()
            db.execute('INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity,reservation_pid) VALUES(?,?,?,?,?,?,?,?,?)',
                       (binding, session_id, operation_id, kind, digest, message, 'reserved', current, os.getpid()))
        db.execute('COMMIT')  # Durable intent precedes financial admission and POST.
    except Exception:
        if db.in_transaction:
            db.execute('ROLLBACK')
        raise
    try:
        if not interrupt:
            admission(config, client)  # Existing quota + installed OAuth/guard attestation, no fallback.
        check()
        require(snapshot() == current, 'session identity changed')
    except Exception:
        db.execute("UPDATE managed_operations SET phase='denied' WHERE binding=? AND session=? AND operation=?",
                   (binding, session_id, operation_id))
        raise
    db.execute("UPDATE managed_operations SET phase='sending' WHERE binding=? AND session=? AND operation=?",
               (binding, session_id, operation_id))
    try:
        check()
        path = f'/api/session/{session_id}/interrupt?resume=false' if interrupt else f'/api/session/{session_id}/prompt'
        body = None if interrupt else {'id': message, 'text': text, 'delivery': 'queue'}
        response = client.request('POST', path, body)
        check()
        if not interrupt:
            require(isinstance(response, dict) and response.get('data', {}).get('id') == message and
                    response['data'].get('sessionID') == session_id and response['data'].get('delivery') == 'queue',
                    'queue acknowledgement unavailable')
        else:
            require(isinstance(response, dict) and type(response.get('interrupted')) is bool, 'interrupt acknowledgement unavailable')
        phase = 'interrupt_acknowledged' if interrupt else 'queued'
    except Exception:
        db.execute("UPDATE managed_operations SET phase='uncertain' WHERE binding=? AND session=? AND operation=?",
                   (binding, session_id, operation_id))
        raise BridgeError('control outcome uncertain; reconcile exact ID, never blindly replay') from None
    db.execute('UPDATE managed_operations SET phase=? WHERE binding=? AND session=? AND operation=?',
               (phase, binding, session_id, operation_id))
    return {'operation_id': operation_id, 'session_id': session_id, 'message_id': message, 'phase': phase}
