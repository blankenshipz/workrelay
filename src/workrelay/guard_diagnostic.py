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
