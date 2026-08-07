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


def test_default_extract_cost_reads_either_key(monkeypatch):
    # reelee emits cost_usd_actual; braidio emits cost_usd — both must be metered by
    # the default extractor (the #232 review's headline bug: reelee's cap was a no-op).
    for key in ("cost_usd_actual", "cost_usd"):
        store = {}
        mw = MeteringMiddleware(
            UsageLedger(store), policy=unlimited(), allowed={"o@x.com"}
        )
        monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")

        async def _next(ctx, _k=key):
            return _Result({_k: 2.5})

        _run(mw.on_call_tool(_Ctx("render"), _next))
        (entry,) = store.values()
        assert entry["cost_usd"] == pytest.approx(2.5), key


def test_cap_fires_with_cost_usd_actual(monkeypatch):
    # End-to-end: a capped principal is denied after cost_usd_actual accumulates past
    # the cap (this is exactly what silently failed for reelee before the extractor fix).
    from enlace_metering import credit_cap

    store = {}
    mw = MeteringMiddleware(
        UsageLedger(store), policy=credit_cap(1.0, period="month"), allowed={"o@x.com"}
    )
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")

    async def _spendy(ctx):
        return _Result({"cost_usd_actual": 1.5})

    _run(mw.on_call_tool(_Ctx("run_stage"), _spendy))  # records $1.50
    with pytest.raises(ToolError, match="usage limit"):  # now over the $1 cap
        _run(mw.on_call_tool(_Ctx("run_stage"), _spendy))


def test_metered_tools_exempts_free_tools(monkeypatch):
    # A capped principal must still be able to call FREE/read-only tools (list/get/help)
    # to retrieve what they already made — only metered tools are gated.
    from enlace_metering import credit_cap

    store = {}
    led = UsageLedger(store)
    now = datetime.now(timezone.utc)
    led.record(
        {
            "principal": "o@x.com",
            "id": "prev",
            "month": now.strftime("%Y-%m"),
            "ts": now.isoformat(),
            "cost_usd": 5.0,
            "status": "done",
        }
    )  # already over a $1 cap
    mw = MeteringMiddleware(
        led, policy=credit_cap(1.0), allowed={"o@x.com"}, metered_tools={"render"}
    )
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")

    async def _next(ctx):
        return _Result({})

    with pytest.raises(ToolError, match="usage limit"):  # metered tool: denied
        _run(mw.on_call_tool(_Ctx("render"), _next))
    r = _run(mw.on_call_tool(_Ctx("list_assets"), _next))  # free tool: allowed
    assert isinstance(r, _Result)


def test_hostile_tool_name_cannot_escape_the_ledger_prefix(monkeypatch):
    # `tools/call` carries a client-supplied name and the middleware runs BEFORE the
    # tool is resolved, so the name reaches the write-ahead row even when no such tool
    # exists. It must not flow verbatim into the storage key (a dol file store would
    # write outside the ledger tree).
    store = {}
    mw = MeteringMiddleware(UsageLedger(store), policy=unlimited(), allowed={"o@x.com"})
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")

    async def _boom(ctx):
        raise RuntimeError("no such tool")

    with pytest.raises(RuntimeError):
        _run(mw.on_call_tool(_Ctx("../../../etc/pwn"), _boom))
    (key,) = store
    principal, month, entry_id = key.split("/")  # exactly three components
    assert principal == "o@x.com"
    assert entry_id.endswith(".json")
    assert "\\" not in key and ".." not in key.split("/")  # no traversal segment
    # the raw name is still recorded, so the audit trail is unchanged
    (entry,) = store.values()
    assert entry["tool"] == "../../../etc/pwn"


def test_current_email_requires_context():
    with pytest.raises(ToolError):
        mw_mod.current_email()
