"""Tests for the FastMCP metering middleware (needs fastmcp)."""

import asyncio
from datetime import datetime, timezone

import pytest

pytest.importorskip("fastmcp")

from fastmcp.exceptions import ToolError  # noqa: E402

from enlace_metering import UsageLedger, credit_cap, unlimited  # noqa: E402
from enlace_metering import middleware as mw_mod  # noqa: E402
from enlace_metering.middleware import MeteringMiddleware  # noqa: E402


class _Msg:
    def __init__(self, name, arguments=None):
        self.name = name
        self.arguments = arguments or {}


class _Ctx:
    def __init__(self, name, arguments=None):
        self.message = _Msg(name, arguments)


class _Result:
    def __init__(self, structured_content=None):
        self.structured_content = structured_content


def _run(coro):
    return asyncio.run(coro)


async def _ok_call_next(ctx):
    return _Result({"cost_usd": 1.25})


def test_authorize_fail_closed(monkeypatch):
    mw = MeteringMiddleware(UsageLedger({}), allowed={"owner@x.com"})
    monkeypatch.setattr(mw_mod, "token_email", lambda: None)
    with pytest.raises(ToolError):  # unauthenticated
        mw._authorize()
    monkeypatch.setattr(mw_mod, "token_email", lambda: "intruder@x.com")
    with pytest.raises(ToolError):  # not allowlisted
        mw._authorize()
    monkeypatch.setattr(mw_mod, "token_email", lambda: "Owner@X.com")
    assert mw._authorize() == "owner@x.com"  # allowlisted, normalized


def test_deny_by_default_no_allowlist(monkeypatch):
    mw = MeteringMiddleware(UsageLedger({}))  # no allowed, no local_user, no allow_any
    monkeypatch.setattr(mw_mod, "token_email", lambda: "someone@x.com")
    with pytest.raises(ToolError):
        mw._authorize()


def test_allow_records_writeahead_and_cost(monkeypatch):
    store = {}
    mw = MeteringMiddleware(
        UsageLedger(store), policy=unlimited(), allowed={"owner@x.com"}
    )
    monkeypatch.setattr(mw_mod, "token_email", lambda: "owner@x.com")
    result = _run(mw.on_call_tool(_Ctx("render", {"x": 1}), _ok_call_next))
    assert isinstance(result, _Result)
    assert len(store) == 1  # one row (started then done, same id -> overwrite)
    (entry,) = store.values()
    assert entry["principal"] == "owner@x.com"
    assert entry["tool"] == "render"
    assert entry["status"] == "done"
    assert entry["cost_usd"] == pytest.approx(1.25)


def test_policy_denial_refuses_before_running(monkeypatch):
    # Preload the ledger so the owner is already at a $1 monthly cap.
    store = {}
    led = UsageLedger(store)
    now = datetime.now(timezone.utc)
    led.record(
        {
            "principal": "owner@x.com",
            "id": "prev",
            "month": now.strftime("%Y-%m"),
            "ts": now.isoformat(),
            "cost_usd": 1.0,
            "status": "done",
        }
    )
    ran = {"called": False}

    async def _track(ctx):
        ran["called"] = True
        return _Result({"cost_usd": 9.0})

    mw = MeteringMiddleware(
        led, policy=credit_cap(1.0, period="month"), allowed={"owner@x.com"}
    )
    monkeypatch.setattr(mw_mod, "token_email", lambda: "owner@x.com")
    with pytest.raises(ToolError, match="usage limit reached"):
        _run(mw.on_call_tool(_Ctx("render"), _track))
    assert ran["called"] is False  # gated BEFORE running
    assert len(store) == 1  # no new write-ahead row for the denied call


def test_writeahead_refuses_if_ledger_unavailable(monkeypatch):
    class _BrokenLedger:
        def spend_since(self, p, s):
            return 0.0

        def count_since(self, p, s):
            return 0

        def record(self, entry):
            raise RuntimeError("store down")

    mw = MeteringMiddleware(
        _BrokenLedger(), policy=unlimited(), allowed={"owner@x.com"}
    )
    monkeypatch.setattr(mw_mod, "token_email", lambda: "owner@x.com")
    with pytest.raises(ToolError, match="ledger unavailable"):
        _run(mw.on_call_tool(_Ctx("render"), _ok_call_next))


def test_current_email_requires_context():
    with pytest.raises(ToolError):
        mw_mod.current_email()
