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
import time
from pathlib import Path

from .cli import admission, BridgeError, require, GuardFailure, CONTROL_DENIAL_CODES, ATTESTATION_CHECK_IDS
from .supervision import redact_text


def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS managed_operations (
      binding TEXT NOT NULL, session TEXT NOT NULL, operation TEXT NOT NULL,
      kind TEXT NOT NULL, digest TEXT NOT NULL, message TEXT NOT NULL,
      phase TEXT NOT NULL, identity TEXT NOT NULL, reservation_pid INTEGER,
      PRIMARY KEY(binding,session,operation))""")
    db.execute('BEGIN IMMEDIATE')
    try:
        columns = {row[1] for row in db.execute('PRAGMA table_info(managed_operations)')}
        if 'reservation_pid' not in columns:
            db.execute('ALTER TABLE managed_operations ADD COLUMN reservation_pid INTEGER')
        if 'denial_code' not in columns:
            choices = ','.join("'" + code + "'" for code in sorted(CONTROL_DENIAL_CODES))
            db.execute('ALTER TABLE managed_operations ADD COLUMN denial_code TEXT CHECK(denial_code IS NULL OR denial_code IN (' + choices + '))')
        if 'denied_at_ms' not in columns:
            db.execute('ALTER TABLE managed_operations ADD COLUMN denied_at_ms INTEGER CHECK(denied_at_ms IS NULL OR denied_at_ms >= 0)')
        if 'attestation_check_id' not in columns:
            choices = ','.join("'" + value + "'" for value in sorted(ATTESTATION_CHECK_IDS))
            db.execute('ALTER TABLE managed_operations ADD COLUMN attestation_check_id TEXT CHECK(attestation_check_id IS NULL OR attestation_check_id IN (' + choices + '))')
        if 'guard_diagnostic' not in columns:
            db.execute('ALTER TABLE managed_operations ADD COLUMN guard_diagnostic TEXT')
        db.execute('COMMIT')
    except Exception:
        db.execute('ROLLBACK')
        raise


def record_denial(db, binding, session_id, operation_id, error):
    """One atomic phase/code/time fact, only before POST. Never infer from text."""
    code = error.denial_code if isinstance(error, GuardFailure) and error.denial_code in CONTROL_DENIAL_CODES else 'UNEXPECTED_PREPOST'
    detail = getattr(error, 'attestation_check_id', None) if isinstance(error, GuardFailure) else None
    detail = detail if code == 'ATTESTATION_FAILED' and isinstance(detail, str) and detail in ATTESTATION_CHECK_IDS else None
    updated = db.execute("UPDATE managed_operations SET phase='denied',denial_code=?,denied_at_ms=?,attestation_check_id=? WHERE binding=? AND session=? AND operation=? AND phase='reserved'",
               (code, int(time.time() * 1000), detail, binding, session_id, operation_id))
    # Optional evidence is separate from the authoritative atomic denial update.
    # The row key and denied_at_ms provide exact operation/session correlation.
    try:
        from .guard_diagnostic import sanitize
        diagnostic = sanitize(getattr(error, 'guard_diagnostic', None)) if updated.rowcount == 1 and detail == 'GUARD_PLUGIN_STATE' else None
        if diagnostic is not None:
            db.execute("UPDATE managed_operations SET guard_diagnostic=? WHERE binding=? AND session=? AND operation=? AND phase='denied' AND guard_diagnostic IS NULL",
                       (json.dumps(diagnostic, sort_keys=True), binding, session_id, operation_id))
    except Exception:
        pass  # Evidence persistence failure cannot replace or undo a denial.


def denial_fields(phase, code, timestamp, attestation_check_id=None):
    if phase != 'denied':
        return {}
    known = code in CONTROL_DENIAL_CODES
    return {'denial_code': code if known else 'DENIAL_REASON_NOT_RECORDED',
            'denied_at_ms': timestamp if known and type(timestamp) is int and timestamp >= 0 else None,
            'attestation_check_id': attestation_check_id if code == 'ATTESTATION_FAILED' and isinstance(
                attestation_check_id, str) and attestation_check_id in ATTESTATION_CHECK_IDS else None}


def stored_denial_fields(db, binding, session_id, operation_id):
    row = db.execute('SELECT phase,denial_code,denied_at_ms,attestation_check_id FROM managed_operations WHERE binding=? AND session=? AND operation=?',
                     (binding, session_id, operation_id)).fetchone()
    return denial_fields(*row) if row else {}


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


def native_waits(client, authorize, session_id, *, limit=20):
    """Bounded actionable native permission waits; NEVER replies or approves.

    The installed V2 schema provides session.permission.list/get/reply, but no
    question list/reply/reject route. Do not manufacture question responses by
    treating ordinary owner messages as native decisions. Human permission
    decisions stay in the native approval UI; no model-supplied approval boolean.
    """
    require(isinstance(session_id, str) and bool(re.fullmatch(r'ses[A-Za-z0-9_-]{1,160}', session_id)), 'invalid session')
    require(type(limit) is int and 1 <= limit <= 50, 'invalid wait limit')
    binding = authorize(); creation_session_id(binding, 'native-waits-read')
    def get(path):
        require(authorize() == binding, 'authority changed')
        value = client.request('GET', path)
        require(authorize() == binding, 'authority changed')
        return value
    first = get('/api/session/' + session_id)
    session = first.get('data') if isinstance(first, dict) else None
    snapshot = identity(session, session_id)
    pending = get(f'/api/session/{session_id}/permission')
    require(isinstance(pending, dict) and isinstance(pending.get('data'), list) and len(pending['data']) <= 1000,
            'native permission state unavailable or exceeds bound')
    seen = set(); items = []
    for item in pending['data']:
        require(isinstance(item, dict) and item.get('sessionID') == session_id and isinstance(item.get('id'), str) and
                bool(re.fullmatch(r'per[A-Za-z0-9_-]{1,160}', item['id'])) and item['id'] not in seen,
                'native permission ownership mismatch')
        seen.add(item['id'])
        require(isinstance(item.get('action'), str) and isinstance(item.get('resources'), list) and
                len(item['resources']) <= 1000 and all(isinstance(resource, str) for resource in item['resources']),
                'native permission projection unavailable')
        if len(items) < limit:
            items.append({'request_id': item['id'], 'action': redact_text(item['action'], 200),
                          'resource_preview': [redact_text(resource, 400) for resource in item['resources'][:3]],
                          'resources_omitted': max(0, len(item['resources']) - 3),
                          'content_trust': 'untrusted_native_request_text',
                          'requires_explicit_human_decision': True,
                          'respond_via': 'native_opencode_or_openchamber_permission_ui'})
    last = get('/api/session/' + session_id)
    require(identity(last.get('data') if isinstance(last, dict) else None, session_id) == snapshot, 'session identity changed')
    return {'session_id': session_id, 'pending_permission_count': len(seen), 'items': items,
            'truncated': len(seen) > len(items), 'inference_started': False,
            'native_permission_reply_exposed': False, 'native_question_reply_exposed': False,
            'guidance': 'Open this exact session/request in the native OpenCode/OpenChamber approval UI. Review and explicitly decide there; then read waits again. Messages, resume, and server-wide authorization do not approve permission requests. No blanket approval is available.',
            'ordinary_follow_up': 'Use same-session message/steer for normal visible conversation only, not as a native permission/question reply.',
            'task_outcome': 'unverified'}


def control_result(operation_id, session_id, message_id, phase, interrupt, *, denial_code=None, denied_at_ms=None, attestation_check_id=None):
    value = {'operation_id': operation_id, 'session_id': session_id, 'message_id': message_id, 'phase': phase}
    if interrupt:
        value.update(cancellation_is_rollback=False, queued_inputs_removed=False,
                     guidance='Only this session active execution is interrupted with resume=false. Queued inputs are preserved and may run on later resume. No file edits are rolled back; idle_noop is not active-cancel proof.')
    value.update(denial_fields(phase, denial_code, denied_at_ms, attestation_check_id))
    return value


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
        try:
            current_binding = authorize()
        except (BridgeError, OSError, TimeoutError):
            raise GuardFailure('AUTHORITY_UNAVAILABLE_OR_CHANGED') from None
        if current_binding != binding:
            raise GuardFailure('AUTHORITY_UNAVAILABLE_OR_CHANGED')
    def get(path):
        check()
        try:
            result = client.request('GET', path)
        except (BridgeError, OSError, TimeoutError):
            raise GuardFailure('SESSION_READ_FAILED') from None
        check()
        return result
    route_model = None
    def snapshot():
        nonlocal route_model
        result = get('/api/session/' + session_id)
        session = result.get('data') if isinstance(result, dict) else None
        if not isinstance(session, dict):
            raise GuardFailure('SESSION_READ_FAILED')
        if not interrupt:
            model = session.get('model')
            if not (isinstance(model, dict) and model.get('providerID') == 'openai' and
                    set(model) <= {'providerID', 'id', 'variant'} and isinstance(model.get('id'), str) and model['id']):
                raise GuardFailure('MODEL_MISMATCH')
            if route_model is None:
                route_model = json.loads(json.dumps(model))
            elif route_model != model:
                raise GuardFailure('IDENTITY_CHANGED')
        if session.get('id') != session_id:
            raise GuardFailure('IDENTITY_CHANGED')
        return identity(session, session_id)
    kind = 'interrupt' if interrupt else 'steer' if steer else 'queue'
    digest = hashlib.sha256((kind + '\0' + (text or '')).encode()).hexdigest()
    message = 'msg_' + hashlib.sha256((binding + '\0' + session_id + '\0' + operation_id).encode()).hexdigest()[:32]
    initialize(db)
    db.execute('BEGIN IMMEDIATE')
    try:
        row = db.execute('SELECT kind,digest,message,phase,identity,reservation_pid,denial_code,denied_at_ms,attestation_check_id FROM managed_operations WHERE binding=? AND session=? AND operation=?',
                          (binding, session_id, operation_id)).fetchone()
        recovering = False
        if row:
            if not (row[0] == kind and row[1] == digest):
                raise GuardFailure('OPERATION_ARGUMENT_CONFLICT')
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
            return control_result(operation_id, session_id, row[2], phase, interrupt, denial_code=row[6], denied_at_ms=row[7], attestation_check_id=row[8])
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
        if snapshot() != current:
            raise GuardFailure('IDENTITY_CHANGED')
        if not interrupt:
            # Existing-session model is authoritative. Creation keeps its configured
            # default; every write freshly attests this exact full native reference.
            admission({**config, 'model': route_model}, client)
        check()
        if snapshot() != current:
            raise GuardFailure('IDENTITY_CHANGED')
    except Exception as exc:
        record_denial(db, binding, session_id, operation_id, exc)
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
    return control_result(operation_id, session_id, message, phase, interrupt)


def creation_session_id(binding, operation_id):
    require(isinstance(binding, str) and bool(re.fullmatch(r'[0-9a-f]{64}', binding)), 'bound authorization required')
    require(isinstance(operation_id, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,80}', operation_id)), 'invalid operation')
    return 'ses_workrelay_' + hashlib.sha256((binding + '\0create\0' + operation_id).encode()).hexdigest()[:32]


def create_body(config, binding, operation_id, directory, title, *, verified_project_root=None):
    require(isinstance(directory, str) and Path(directory).is_dir() and str(Path(directory).resolve()) == directory,
            'canonical existing workspace required')
    allowed = config.get('managed_allowed_directories', [config.get('directory')])
    require(isinstance(allowed, list) and (directory in allowed or directory == verified_project_root), 'workspace not authorized for creation')
    require(isinstance(title, str) and 0 < len(title.strip()) <= 160 and not any(ord(c) < 32 for c in title), 'invalid title')
    require(config.get('agent', 'quick-builder') in ('quick-builder', 'builder') and
            isinstance(config.get('model'), dict) and config['model'].get('providerID') == 'openai', 'invalid attested create route')
    metadata = {'workrelayOperation': operation_id, 'workrelayBinding': binding}
    if verified_project_root is not None:
        metadata['workrelayProjectRootHash'] = hashlib.sha256(verified_project_root.encode()).hexdigest()
    return {'id': creation_session_id(binding, operation_id), 'title': title,
            'location': {'directory': directory}, 'model': config['model'],
            'agent': config.get('agent', 'quick-builder'),
            'metadata': metadata}


def validated_create_target(config, binding, operation_id, directory, title, project_id, authorize_native_projects, get):
    """Fallible project/path policy runs only AFTER durable argument reservation."""
    project_root = None
    if authorize_native_projects is not None:
        require(callable(authorize_native_projects) and authorize_native_projects() == binding, 'server-wide project authority required')
        projects = get('/api/project')
        require(isinstance(projects, list) and len(projects) <= 10000, 'native project inventory unavailable')
        matches = [p for p in projects if isinstance(p, dict) and p.get('id') == project_id]
        require(len(matches) == 1, 'selected native project unavailable or ambiguous')
        project_root = matches[0].get('canonical')
        require(isinstance(project_root, str) and Path(project_root).is_absolute() and Path(project_root).is_dir() and
                str(Path(project_root).resolve()) == project_root, 'native project canonical directory unavailable')
        # A native global project is not a filesystem wildcard. Explicit profile
        # allowlisted locations still work within it; root itself is not inferred.
        if directory is None:
            require(project_root != '/', 'global project requires an explicit profile-authorized workspace')
            directory = project_root
        if not Path(directory).is_relative_to(Path(project_root)):
            raise GuardFailure('CREATE_PROJECT_WORKSPACE_MISMATCH')
        roots = [p for p in projects if isinstance(p, dict) and isinstance(p.get('canonical'), str) and
                 Path(directory).is_relative_to(Path(p['canonical']))]
        require(roots and max(roots, key=lambda p: len(p['canonical'])).get('id') == project_id,
                'workspace belongs to a different native project')
    elif directory is None:
        directory = config.get('directory')
    body = create_body(config, binding, operation_id, directory, title,
                       verified_project_root=project_root if project_root != '/' else None)
    return body, project_root, directory


def create_session(db, config, client, authorize, operation_id, *, directory=None, title, project_id, authorize_native_projects=None):
    """Reserve bounded attempted arguments before fallible semantic validation.

    Malformed/unbounded or unauthenticated requests are unbound rejections. Every
    safely bounded authenticated attempt is immutable, including pre-POST denial.
    Legacy rows have only a derived-body digest: inspect remains supported, but
    create retries fail closed rather than guessing omitted original arguments.
    """
    binding = authorize(); sid = creation_session_id(binding, operation_id)
    require(isinstance(project_id, str) and 0 < len(project_id) <= 200, 'explicit discovered project required')
    require(isinstance(title, str) and 0 < len(title) <= 160, 'bounded title required')
    require(directory is None or isinstance(directory, str) and 0 < len(directory) <= 4096, 'bounded directory required')
    def check():
        require(authorize() == binding, 'authority changed')
    def get(path):
        check(); result = client.request('GET', path); check(); return result
    def verified(session):
        require(isinstance(session, dict) and session.get('id') == sid and session.get('projectID') == project_id and
                all(session.get(k) == body[k] for k in ('location', 'model', 'agent')) and
                protected_metadata(session.get('metadata')) == protected_metadata(body['metadata']) and
                session.get('permissions') == body.get('permissions') and not session.get('parentID'), 'created session identity mismatch')
    require(db.isolation_level is None, 'durable autocommit ledger required')
    db.execute('PRAGMA synchronous=FULL'); initialize(db)
    attempted = {'directory': directory, 'title': title, 'project_id': project_id,
                 'model': config.get('model'), 'agent': config.get('agent', 'quick-builder'),
                 'scope': 'native_projects' if authorize_native_projects is not None else 'profile',
                 'profile_default': config.get('directory')}
    digest = 'args-v2:' + hashlib.sha256(json.dumps(attempted, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    check()
    db.execute('BEGIN IMMEDIATE')
    try:
        row = db.execute('SELECT kind,digest,phase,reservation_pid,identity FROM managed_operations WHERE binding=? AND session=? AND operation=?',
                          (binding, sid, operation_id)).fetchone()
        if row:
            require(row[1].startswith('args-v2:'), 'legacy create arguments unavailable; inspect original operation')
            if not (row[0] == 'create' and row[1] == digest):
                raise GuardFailure('OPERATION_ARGUMENT_CONFLICT')
            recover = row[2] == 'reserved' and reservation_owner_dead(row[3])
            if recover:
                db.execute('UPDATE managed_operations SET reservation_pid=? WHERE binding=? AND session=? AND operation=?',
                           (os.getpid(), binding, sid, operation_id))
        else:
            recover = True
            maximum = config.get('managed_max_pending_creations', 4)
            require(type(maximum) is int and 1 <= maximum <= 20, 'invalid creation capacity')
            pending = db.execute("SELECT COUNT(*) FROM managed_operations WHERE binding=? AND kind='create' AND phase IN ('reserved','sending','uncertain')", (binding,)).fetchone()[0]
            db.execute('INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity,reservation_pid) VALUES(?,?,?,?,?,?,?,?,?)',
                       (binding, sid, operation_id, 'create', digest, project_id, 'reserved', '{}', os.getpid()))
            if pending >= maximum:
                error = GuardFailure('CREATE_CAPACITY_DENIED')
                record_denial(db, binding, sid, operation_id, error)
                db.execute('COMMIT')
                raise error
        db.execute('COMMIT')
    except Exception:
        if db.in_transaction:
            db.execute('ROLLBACK')
        raise
    phase = row[2] if row else 'reserved'
    if not recover:
        if phase in ('sending', 'uncertain', 'created'):
            body = json.loads(row[4])
            require(isinstance(body, dict) and body.get('id') == sid, 'validated creation body unavailable')
            found = get('/api/session/' + sid)
            if found is not None:
                verified(found.get('data'))
                check(); phase = 'created'
                db.execute("UPDATE managed_operations SET phase='created' WHERE binding=? AND session=? AND operation=?", (binding, sid, operation_id))
            else:
                require(phase != 'created', 'created session disappeared; refusing to recreate')
        return {'operation_id': operation_id, 'session_id': sid, 'phase': phase, 'inference_started': False,
                **stored_denial_fields(db, binding, sid, operation_id)}
    try:
        body, project_root, directory = validated_create_target(config, binding, operation_id, directory,
            title, project_id, authorize_native_projects, get)
        encoded_body = json.dumps(body, sort_keys=True, separators=(',', ':'))
        require(not row or row[4] == '{}' or row[4] == encoded_body, 'creation target changed')
        check()
        db.execute('UPDATE managed_operations SET identity=? WHERE binding=? AND session=? AND operation=?',
                   (encoded_body, binding, sid, operation_id))
        projects = get('/api/project')
        if not (isinstance(projects, list) and any(isinstance(p, dict) and p.get('id') == project_id and
                isinstance(p.get('canonical'), str) and Path(directory).is_relative_to(Path(p['canonical'])) for p in projects)):
            raise GuardFailure('CREATE_PROJECT_WORKSPACE_MISMATCH')
        if authorize_native_projects is not None:
            require(authorize_native_projects() == binding and any(isinstance(p, dict) and p.get('id') == project_id and
                    p.get('canonical') == project_root for p in projects) and
                    str(Path(project_root).resolve()) == project_root and str(Path(directory).resolve()) == directory,
                    'native project identity changed')
        require(get('/api/session/' + sid) is None, 'creation identity already exists')
        check()
    except Exception as exc:
        record_denial(db, binding, sid, operation_id, exc)
        raise
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


class OperationLookupError(BridgeError):
    def __init__(self, code):
        self.code = code
        super().__init__('operation lookup unavailable within current authenticated binding')


def resolve_operation(db, authorize, operation_id, session_id=None):
    """Resolve within a freshly verified principal/server binding, never globally.

    An operation ID reused on different sessions is ambiguous without a selected
    session. No titles, prompt text, digests or other principals are disclosed.
    """
    binding = authorize(); creation_session_id(binding, operation_id)
    initialize(db)
    if session_id is not None:
        require(isinstance(session_id, str) and bool(re.fullmatch(r'ses[A-Za-z0-9_-]{1,160}', session_id)), 'invalid session')
        rows = db.execute('SELECT session,kind,digest,message,phase,identity,denial_code,denied_at_ms,attestation_check_id FROM managed_operations WHERE binding=? AND operation=? AND session=? LIMIT 2',
                          (binding, operation_id, session_id)).fetchall()
    else:
        rows = db.execute('SELECT session,kind,digest,message,phase,identity,denial_code,denied_at_ms,attestation_check_id FROM managed_operations WHERE binding=? AND operation=? LIMIT 2',
                          (binding, operation_id)).fetchall()
    require(authorize() == binding, 'authority changed')
    if not rows:
        raise OperationLookupError('CONTROL_OPERATION_NOT_FOUND_CURRENT_BINDING')
    if len(rows) != 1:
        raise OperationLookupError('CONTROL_OPERATION_AMBIGUOUS_CURRENT_BINDING')
    sid, *row = rows[0]
    if row[0] == 'create':
        require(sid == creation_session_id(binding, operation_id), 'creation ledger identity mismatch')
    return binding, sid, row


class ControlFailure(BridgeError):
    def __init__(self, details):
        super().__init__('managed control rejected; inspect original operation ID without retrying a write')
        self.control_details = details


def classified_failure(db, authorize, operation_id, session_id, error):
    """Safe diagnostics based on durable phase, never upstream exception bodies."""
    details = {'code': 'CONTROL_AUTHORIZATION_OR_VALIDATION_DENIED', 'effect': 'not_established'}
    if isinstance(operation_id, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', operation_id):
        details['operation_id'] = operation_id
    try:
        _, sid, row = resolve_operation(db, authorize, operation_id, session_id)
        phase = row[3]
        details.update(session_id=sid, phase=phase)
        if phase in ('reserved', 'denied'):
            details.update(code='CONTROL_NOT_SENT', effect='no_post_permitted')
            details.update(denial_fields(phase, row[5], row[6], row[7]))
        elif phase in ('sending', 'uncertain'):
            details.update(code='CONTROL_UNCERTAIN', effect='may_have_been_applied')
        else:
            details.update(code='CONTROL_RECONCILE_EXISTING', effect='recorded_existing_operation')
    except Exception:
        pass  # No global lookup or guessed session if authority/identity is unknown.
    if isinstance(error, GuardFailure) and error.denial_code == 'CREATE_PROJECT_WORKSPACE_MISMATCH':
        details['reason'] = 'PROJECT_WORKSPACE_MISMATCH'
    elif isinstance(error, GuardFailure) and error.denial_code == 'OPERATION_ARGUMENT_CONFLICT':
        details['reason'] = 'OPERATION_ARGUMENT_CONFLICT'
    return ControlFailure(details)


def inspect_operation(db, config, client, authorize, session_id, operation_id, *, receipt_only=False):
    """Read/reconcile a known principal-bound operation without prompt text or inference."""
    try:
        binding, session_id, row = resolve_operation(db, authorize, operation_id, session_id)
    except OperationLookupError as error:
        # These facts are established only after successful authorization before
        # and after the scoped query. Never convert an auth failure to absence.
        return {'operation_id': operation_id, 'session_id': session_id, 'code': error.code,
                'phase': 'unknown', 'effect': 'not_established',
                'lookup_scope': 'current_authenticated_binding', 'task_outcome': 'unverified',
                'native_observation': 'not_run', 'replay_permitted': False}
    phase = row[3]
    if receipt_only:
        require(authorize() == binding, 'authority changed')
        code, effect = ('CONTROL_NOT_SENT', 'no_post_permitted') if phase in ('reserved', 'denied') else (
            ('CONTROL_UNCERTAIN', 'may_have_been_applied') if phase in ('sending', 'uncertain') else
            ('CONTROL_RECONCILE_EXISTING', 'recorded_existing_operation'))
        return {'operation_id': operation_id, 'session_id': session_id, 'kind': row[0],
                'phase': phase, 'recorded_phase': phase, 'code': code, 'effect': effect,
                **denial_fields(phase, row[5], row[6], row[7]),
                'lookup_scope': 'current_authenticated_binding', 'native_observation': 'not_run',
                'message_id': row[2] if row[0] in ('queue', 'steer') else None,
                'task_outcome': 'unverified', 'replay_permitted': False,
                'cancellation_is_rollback': False, 'queued_inputs_removed': False}
    def get(path):
        require(authorize() == binding, 'authority changed'); result = client.request('GET', path)
        require(authorize() == binding, 'authority changed'); return result
    session_exists = None
    if row[0] == 'create':
        remote = get('/api/session/' + session_id)
        session_exists = remote is not None
        if session_exists:
            data = remote.get('data') if isinstance(remote, dict) else None
            body = json.loads(row[4])
            require(isinstance(data, dict) and data.get('id') == session_id and data.get('projectID') == row[2] and
                    all(data.get(k) == body.get(k) for k in ('location', 'agent', 'model', 'permissions')) and not data.get('parentID') and
                    protected_metadata(data.get('metadata')) == protected_metadata(body.get('metadata')),
                    'created session identity mismatch')
            require(phase not in ('reserved', 'denied'), 'session exists despite no-POST phase; operator review required')
            phase = 'created_observed'
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
            **denial_fields(row[3], row[5], row[6], row[7]),
            'recorded_phase': row[3], 'exact_session_exists': session_exists,
            'effect': ('created_observed' if session_exists else 'not_applied' if row[3] in ('reserved', 'denied') else 'unknown') if row[0] == 'create' else 'not_evaluated',
            'message_id': row[2] if row[0] in ('queue', 'steer') else None,
            'task_outcome': 'unverified', 'cancellation_is_rollback': False,
            'queued_inputs_removed': False}
