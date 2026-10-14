"""Shared test fixtures: each test starts with no caller secret known."""

import pytest


@pytest.fixture(autouse=True)
def _no_request_secrets_known():
    """Forget the caller keys earlier tests' calls left in the recent-call ring
    (they are meant to outlive a call, not a test)."""
    from enlace_metering import middleware as mw

    def reset():
        with mw._INFLIGHT_LOCK:
            mw._INFLIGHT.clear()
            mw._RECENT.clear()
            mw._refresh_inflight_view()

    reset()
    yield
    reset()
