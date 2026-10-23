"""Finite provider-metadata evidence only; never serialize native values."""
SHAPES = frozenset(('unknown', 'null', 'object', 'list', 'string', 'number', 'boolean', 'other'))
STAGES = frozenset(('read', 'envelope', 'provider_data'))
MISSING = object()


def shape(value):
    if value is MISSING:
        return 'unknown'
    if value is None:
        return 'null'
    return {dict: 'object', list: 'list', str: 'string', int: 'number',
            float: 'number', bool: 'boolean'}.get(type(value), 'other')


def sanitize(value):
    if type(value) is not dict:
        return None
    stage = dict.get(value, 'stage')
    if type(stage) is not str or stage not in STAGES:
        return None
    status = dict.get(value, 'http_status')
    def finite(name):
        item = dict.get(value, name)
        return item if type(item) is str and item in SHAPES else 'unknown'
    return {'version': 1, 'stage': stage,
            'http_status': status if type(status) is int and 100 <= status <= 599 else None,
            'envelope_shape': finite('envelope_shape'), 'data_shape': finite('data_shape')}


def attach(error, client, stage, response=MISSING, data=MISSING):
    try:
        # Bypass user-defined get()/attribute hooks; projection is optional.
        state = object.__getattribute__(client, '__dict__')
        status = dict.get(state, '_provider_http_status') if type(state) is dict else None
        if type(response) is dict:
            data = dict.get(response, 'data', MISSING)
        error.provider_diagnostic = sanitize({'stage': stage, 'http_status': status,
            'envelope_shape': 'object' if stage == 'provider_data' else shape(response),
            'data_shape': shape(data)})
    except Exception:
        pass  # Never alter admission because diagnostics failed.
