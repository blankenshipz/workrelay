import pytest


@pytest.fixture(autouse=True)
def _no_plugin_warmup_wait(monkeypatch):
    """Keep the GUARD_PLUGIN_STATE warm-up retry path, without its real backoff.

    Tests that assert the backoff schedule pass explicit delays/sleep.
    """
    import workrelay.cli
    monkeypatch.setattr(workrelay.cli, 'PLUGIN_WARMUP_DELAYS', (0, 0, 0))
