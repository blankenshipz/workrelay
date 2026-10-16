"""Durable control engine; caller supplies bound-server authorization and transport.

Not a CLI or unrestricted remote entry point. Financial admission is the existing
Workrelay admission routine. Existing owners/models/permissions are never edited.
"""
import hashlib
import json
import re
import sqlite3
import os
import math
from pathlib import Path

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


def protected_metadata(metadata):
    """Ignore ONLY schema-valid OpenChamber sidebar work presentation.

    Verified against OpenChamber session-work/state.js: work tracks sidebar
    membership and end-of-turn hints, not owner identity, approvals or outcomes.
    Unknown namespaces/keys and malformed work remain protected verbatim. In
    particular goal/task/owner/binding metadata is never discarded. Pruning the
    empty namespace preserves pre-UI legacy fingerprints; old hashes containing
    UI data cannot be safely migrated without a stored snapshot and fail closed.
    """
    if not isinstance(metadata, dict) or not isinstance(metadata.get('openchamber'), dict):
        return metadata
    namespace = metadata['openchamber']
    work = namespace.get('work')
    allowed = {'state', 'openedAt', 'openedBy', 'doneAt', 'suggestDoneAt'}
    if not isinstance(work, dict) or not set(work) <= allowed or work.get('state') not in ('open', 'done'):
        return metadata
    if 'openedBy' in work and work['openedBy'] not in ('auto', 'jev', 'user'):
        return metadata
    for key in ('openedAt', 'doneAt', 'suggestDoneAt'):
        if key in work and work[key] is not None and not (
                type(work[key]) in (int, float) and math.isfinite(work[key]) and work[key] >= 0):
            return metadata
    namespace = {key: value for key, value in namespace.items() if key != 'work'}
    projected = {key: value for key, value in metadata.items() if key != 'openchamber'}
    if namespace:
        projected['openchamber'] = namespace
    return projected


def identity(session, sid):
    require(isinstance(session, dict) and session.get('id') == sid, 'session unavailable')
    # Compare, never disclose or rewrite the existing owner, model, agent, intent,
    # permissions, project and parent. Changes require fresh operator review.
    selected = {key: session.get(key) for key in
                 ('id', 'parentID', 'projectID', 'agent', 'model', 'metadata', 'permissions', 'location')}
    selected['metadata'] = protected_metadata(selected['metadata'])
    return hashlib.sha256(json.dumps(selected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def control(db, config, client, authorize, session_id, operation_id, *, text=None, interrupt=False, steer=False):
    """authorize() must revalidate pinned JWT/capability/registration and return
    a stable opaque binding ID. Failure must raise, never return a user owner label.
    client is the same authorized managed endpoint for every GET/POST.
    """
    require(bool(re.fullmatch(r'ses[A-Za-z0-9_-]{1,160}', session_id or '')), 'invalid session')
    require(bool(re.fullmatch(r'[A-Za-z0-9_-]{1,80}', operation_id or '')), 'invalid operation')
    require(type(interrupt) is bool, 'invalid control')
    require(type(steer) is bool and not (steer and interrupt), 'invalid control')
    require(db.isolation_level is None, 'durable autocommit ledger required')
    db.execute('PRAGMA synchronous=FULL')
    require(text is None if interrupt else isinstance(text, str) and 0 < len(text.strip()) and len(text) <= 16000,
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
    kind = 'interrupt' if interrupt else 'steer' if steer else 'queue'
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
            if phase in ('sending', 'uncertain') and kind in ('queue', 'steer'):
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
        body = None if interrupt else {'id': message, 'text': text, 'delivery': kind}
        response = client.request('POST', path, body)
        check()
        if not interrupt:
            require(isinstance(response, dict) and response.get('data', {}).get('id') == message and
                    response['data'].get('sessionID') == session_id and response['data'].get('delivery') == kind,
                    'queue acknowledgement unavailable')
        else:
            require(isinstance(response, dict) and type(response.get('interrupted')) is bool, 'interrupt acknowledgement unavailable')
        phase = ('interrupt_acknowledged' if response['interrupted'] else 'idle_noop') if interrupt else 'steering' if steer else 'queued'
    except Exception:
        db.execute("UPDATE managed_operations SET phase='uncertain' WHERE binding=? AND session=? AND operation=?",
                   (binding, session_id, operation_id))
        raise BridgeError('control outcome uncertain; reconcile exact ID, never blindly replay') from None
    db.execute('UPDATE managed_operations SET phase=? WHERE binding=? AND session=? AND operation=?',
               (phase, binding, session_id, operation_id))
    return {'operation_id': operation_id, 'session_id': session_id, 'message_id': message, 'phase': phase}


def creation_session_id(binding, operation_id):
    require(isinstance(binding, str) and bool(re.fullmatch(r'[0-9a-f]{64}', binding)), 'bound authorization required')
    require(isinstance(operation_id, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,80}', operation_id)), 'invalid operation')
    return 'ses_workrelay_' + hashlib.sha256((binding + '\0create\0' + operation_id).encode()).hexdigest()[:32]


def create_body(config, binding, operation_id, directory, title):
    require(isinstance(directory, str) and Path(directory).is_dir() and str(Path(directory).resolve()) == directory,
            'canonical existing workspace required')
    allowed = config.get('managed_allowed_directories', [config.get('directory')])
    require(isinstance(allowed, list) and directory in allowed, 'workspace not authorized for creation')
    require(isinstance(title, str) and 0 < len(title.strip()) <= 160 and not any(ord(c) < 32 for c in title), 'invalid title')
    require(config.get('agent', 'quick-builder') in ('quick-builder', 'builder') and
            isinstance(config.get('model'), dict) and config['model'].get('providerID') == 'openai', 'invalid attested create route')
    return {'id': creation_session_id(binding, operation_id), 'title': title,
            'location': {'directory': directory}, 'model': config['model'],
            'agent': config.get('agent', 'quick-builder'),
            'metadata': {'workrelayOperation': operation_id, 'workrelayBinding': binding}}


def create_session(db, config, client, authorize, operation_id, *, directory, title, project_id):
    """Create an isolated root session, never fork/adopt/replace an existing owner.

    Creation does not run inference. A later message/steer uses normal admission.
    A sending/uncertain POST is reconciled by exact ID, never blindly replayed.
    """
    binding = authorize()
    body = create_body(config, binding, operation_id, directory, title)
    require(isinstance(project_id, str) and 0 < len(project_id) <= 200, 'explicit discovered project required')
    sid = body['id']
    def check():
        require(authorize() == binding, 'authority changed')
    def get(path):
        check(); result = client.request('GET', path); check(); return result
    def verified(session):
        require(isinstance(session, dict) and session.get('id') == sid and session.get('projectID') == project_id and
                all(session.get(k) == body[k] for k in ('location', 'model', 'agent', 'metadata')) and
                not session.get('parentID'), 'created session identity mismatch')
    require(db.isolation_level is None, 'durable autocommit ledger required')
    db.execute('PRAGMA synchronous=FULL'); initialize(db)
    digest = hashlib.sha256(json.dumps({'body': body, 'project_id': project_id}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    db.execute('BEGIN IMMEDIATE')
    try:
        row = db.execute('SELECT kind,digest,phase,reservation_pid FROM managed_operations WHERE binding=? AND session=? AND operation=?',
                         (binding, sid, operation_id)).fetchone()
        if row:
            require(row[0] == 'create' and row[1] == digest, 'operation conflict')
            recover = row[2] == 'reserved' and reservation_owner_dead(row[3])
            if recover:
                db.execute('UPDATE managed_operations SET reservation_pid=? WHERE binding=? AND session=? AND operation=?',
                           (os.getpid(), binding, sid, operation_id))
        else:
            recover = True
            maximum = config.get('managed_max_pending_creations', 4)
            require(type(maximum) is int and 1 <= maximum <= 20, 'invalid creation capacity')
            pending = db.execute("SELECT COUNT(*) FROM managed_operations WHERE binding=? AND kind='create' AND phase IN ('reserved','sending','uncertain')", (binding,)).fetchone()[0]
            require(pending < maximum, 'creation capacity reached; reconcile pending operations')
            db.execute('INSERT INTO managed_operations VALUES(?,?,?,?,?,?,?,?,?)',
                       (binding, sid, operation_id, 'create', digest, project_id, 'reserved', json.dumps(body, sort_keys=True, separators=(',', ':')), os.getpid()))
        db.execute('COMMIT')
    except Exception:
        db.execute('ROLLBACK'); raise
    phase = row[2] if row else 'reserved'
    if not recover:
        if phase in ('sending', 'uncertain', 'created'):
            found = get('/api/session/' + sid)
            if found is not None:
                verified(found.get('data'))
                check(); phase = 'created'
                db.execute("UPDATE managed_operations SET phase='created' WHERE binding=? AND session=? AND operation=?", (binding, sid, operation_id))
            else:
                require(phase != 'created', 'created session disappeared; refusing to recreate')
        return {'operation_id': operation_id, 'session_id': sid, 'phase': phase, 'inference_started': False}
    try:
        projects = get('/api/project')
        require(isinstance(projects, list) and any(isinstance(p, dict) and p.get('id') == project_id and
                isinstance(p.get('canonical'), str) and Path(directory).is_relative_to(Path(p['canonical'])) for p in projects),
                'workspace does not belong to selected discovered project')
        require(get('/api/session/' + sid) is None, 'creation identity already exists')
        check()
    except Exception:
        db.execute("UPDATE managed_operations SET phase='denied' WHERE binding=? AND session=? AND operation=?", (binding, sid, operation_id)); raise
    db.execute("UPDATE managed_operations SET phase='sending' WHERE binding=? AND session=? AND operation=?", (binding, sid, operation_id))
    try:
        check(); reply = client.request('POST', '/api/session', body); check()
        verified(reply.get('data') if isinstance(reply, dict) else None)
        found = get('/api/session/' + sid); verified(found.get('data') if isinstance(found, dict) else None)
    except Exception:
        db.execute("UPDATE managed_operations SET phase='uncertain' WHERE binding=? AND session=? AND operation=?", (binding, sid, operation_id))
        raise BridgeError('creation uncertain; reconcile same operation ID, never blindly replay') from None
    db.execute("UPDATE managed_operations SET phase='created' WHERE binding=? AND session=? AND operation=?", (binding, sid, operation_id))
    return {'operation_id': operation_id, 'session_id': sid, 'phase': 'created', 'inference_started': False}


def inspect_operation(db, config, client, authorize, session_id, operation_id):
    """Read/reconcile a known principal-bound operation without prompt text or inference."""
    binding = authorize(); creation_session_id(binding, operation_id)
    require(isinstance(session_id, str) and bool(re.fullmatch(r'ses[A-Za-z0-9_-]{1,160}', session_id)), 'invalid session')
    initialize(db)
    row = db.execute('SELECT kind,digest,message,phase,identity FROM managed_operations WHERE binding=? AND session=? AND operation=?',
                     (binding, session_id, operation_id)).fetchone()
    require(row is not None, 'unknown operation for this principal')
    phase = row[3]
    def get(path):
        require(authorize() == binding, 'authority changed'); result = client.request('GET', path)
        require(authorize() == binding, 'authority changed'); return result
    if row[0] in ('queue', 'steer') and phase in ('sending', 'uncertain', 'queued', 'steering', 'queued_observed'):
        remote = get('/api/session/' + session_id)
        require(identity(remote.get('data') if isinstance(remote, dict) else None, session_id) == row[4], 'session identity changed')
        exact = get(f'/api/session/{session_id}/message/{row[2]}')
        if isinstance(exact, dict) and exact.get('data', {}).get('id') == row[2]:
            phase = 'message_observed'  # Materialization, not completion or task success.
        else:
            inbox = get(f'/api/session/{session_id}/inbox')
            if isinstance(inbox, dict) and isinstance(inbox.get('data'), list) and any(
                    isinstance(item, dict) and item.get('id') == row[2] and item.get('sessionID') == session_id for item in inbox['data']):
                phase = 'queued_observed'
    require(authorize() == binding, 'authority changed')
    return {'operation_id': operation_id, 'session_id': session_id, 'kind': row[0], 'phase': phase,
            'message_id': row[2] if row[0] in ('queue', 'steer') else None,
            'task_outcome': 'unverified', 'cancellation_is_rollback': False,
            'queued_inputs_removed': False}
