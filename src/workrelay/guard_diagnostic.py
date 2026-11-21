"""Finite evidence only. Never serialize a plugin, identifier, state or exception."""
REASONS = frozenset(('inventory_not_list', 'entry_not_object', 'guard_missing',
    'guard_duplicate', 'state_not_object', 'status_missing', 'status_not_active'))
STATES = frozenset(('active', 'inactive', 'disabled', 'failed', 'pending', 'other', 'missing'))


def sanitize(value):
    try:
        if not isinstance(value, dict):
            return None
        reason, shape, state = value.get('reason'), value.get('inventory_shape'), value.get('state')
        if type(reason) is not str or reason not in REASONS:
            return None
        count = lambda v: v if type(v) is int and 0 <= v <= 100000 else None
        return {'version': 1, 'reason': reason,
                'inventory_shape': shape if type(shape) is str and shape in ('list', 'object', 'other') else 'other',
                'inventory_count': count(value.get('inventory_count')),
                'guard_count': count(value.get('guard_count')),
                'state': state if type(state) is str and state in STATES else 'other'}
    except Exception:
        return None


def plugin_evidence(guard):
    """Called only after the original predicate denied; never makes admission."""
    try:
        reason = 'inventory_not_list'; matches = []
        if isinstance(guard, list):
            if not all(isinstance(p, dict) for p in guard):
                reason = 'entry_not_object'
            else:
                matches = [p for p in guard if p.get('id') == 'subscription.guard']
                if not matches: reason = 'guard_missing'
                elif len(matches) != 1: reason = 'guard_duplicate'
                elif not isinstance(matches[0].get('state'), dict): reason = 'state_not_object'
                elif 'status' not in matches[0]['state']: reason = 'status_missing'
                else: reason = 'status_not_active'
        state = matches[0].get('state') if len(matches) == 1 else None
        status = state.get('status') if isinstance(state, dict) else None
        return sanitize({'reason': reason,
            'inventory_shape': 'list' if isinstance(guard, list) else 'object' if isinstance(guard, dict) else 'other',
            'inventory_count': len(guard) if isinstance(guard, list) else None,
            'guard_count': len(matches) if isinstance(guard, list) and all(isinstance(p, dict) for p in guard) else None,
            'state': status if type(status) is str and status in STATES else 'missing' if status is None else 'other'})
    except Exception:
        return None


# UNEXPECTED_PREPOST evidence (r28). The denial code is the catch-all for any
# non-guard exception before POST; record WHICH exception class, transport
# failure kind and workrelay code site raised it. Only allowlisted class
# names, a finite transport reason and this package's own module/function
# names and line numbers are kept: never exception text, paths, IDs or data.
EXCEPTIONS = frozenset(('BridgeError', 'TransportFailure', 'GuardFailure', 'ControlFailure', 'OperationLookupError',
    'AttestationError', 'SupervisionError', 'ValueError', 'JSONDecodeError', 'KeyError', 'TypeError', 'AttributeError',
    'IndexError', 'LookupError', 'UnicodeError', 'UnicodeDecodeError', 'OSError', 'FileNotFoundError', 'PermissionError',
    'TimeoutError', 'TimeoutExpired', 'CalledProcessError', 'ConnectionError', 'RecursionError', 'OverflowError',
    'ZeroDivisionError', 'NotImplementedError', 'RuntimeError', 'AssertionError', 'OperationalError',
    'IntegrityError', 'DatabaseError', 'ProgrammingError'))
TRANSPORT_REASONS = frozenset(('transport_timeout', 'transport_os_error', 'transport_exit', 'transport_output_too_large',
    'transport_output_not_json', 'transport_response_malformed', 'native_http_status'))
MODULES = frozenset(('cli', 'managed_control', 'attestor', 'supervision', 'guard_diagnostic', 'provider_diagnostic',
    'event_store', 'oidc_store'))


def _identifier(value):
    return type(value) is str and 0 < len(value) <= 64 and value.isascii() and (value.isidentifier() or value == '<module>')


def sanitize_unexpected(value):
    try:
        if not isinstance(value, dict) or value.get('reason') != 'unexpected_prepost':
            return None
        exception, transport, frames = value.get('exception'), value.get('transport'), value.get('frames')
        clean = []
        for frame in frames if isinstance(frames, list) else []:
            if not isinstance(frame, dict):
                continue
            module, function, line = frame.get('module'), frame.get('function'), frame.get('line')
            if type(module) is str and module in MODULES and _identifier(function) and type(line) is int and 0 < line <= 100000:
                clean.append({'module': module, 'function': function, 'line': line})
        return {'version': 1, 'reason': 'unexpected_prepost',
                'exception': exception if type(exception) is str and exception in EXCEPTIONS else 'other',
                'transport': transport if type(transport) is str and transport in TRANSPORT_REASONS else None,
                'frames': clean[-4:]}
    except Exception:
        return None


def unexpected_evidence(error):
    """Class/site evidence for a non-guard pre-POST exception; never its text."""
    try:
        import traceback
        from pathlib import Path
        package = Path(__file__).resolve().parent
        frames = []
        for frame in traceback.extract_tb(getattr(error, '__traceback__', None)):
            path = Path(frame.filename).resolve()
            if path.parent == package and path.suffix == '.py':
                frames.append({'module': path.stem, 'function': frame.name, 'line': frame.lineno})
        return sanitize_unexpected({'reason': 'unexpected_prepost', 'exception': type(error).__name__,
                                    'transport': getattr(error, 'transport_reason', None), 'frames': frames})
    except Exception:
        return None
