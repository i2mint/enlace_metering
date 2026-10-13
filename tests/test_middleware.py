"""Tests for the FastMCP metering middleware (needs fastmcp)."""

import asyncio
import json
import sys
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


# --- caller secrets never reach the ledger or the re-raised error (tw_platform#183) ---

_KEY = "sk_live_0123456789abcdef"


def _in_flight_headers(monkeypatch, headers):
    """Make the default redactor see ``headers`` as the in-flight request's."""
    import fastmcp.server.dependencies as deps

    def _get(include_all=False, include=None):
        return {k.lower(): v for k, v in headers.items()}

    monkeypatch.setattr(deps, "get_http_headers", _get)


def _provider_401(exc_type=ToolError):
    async def _call(ctx):
        raise exc_type(f"ElevenLabs 401: invalid api key {_KEY}")

    return _call


def _failing_call(store, call_next, **mw_kwargs):
    mw = MeteringMiddleware(
        UsageLedger(store), policy=unlimited(), allowed={"o@x.com"}, **mw_kwargs
    )
    with pytest.raises(Exception) as info:
        _run(mw.on_call_tool(_Ctx("synthesize"), call_next))
    (entry,) = store.values()
    return entry, info.value


@pytest.mark.parametrize("header", ["X-Elevenlabs-Key", "X-Fal-Key", "X-Api-Key"])
def test_caller_key_redacted_from_ledger_and_reraise(monkeypatch, header):
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    _in_flight_headers(monkeypatch, {header: _KEY, "X-Request-Id": "abc"})
    store = {}
    entry, raised = _failing_call(store, _provider_401())

    assert entry["status"] == "error"
    assert _KEY not in entry["error"]
    assert f"<redacted:{header.lower()}>" in entry["error"]
    assert _KEY not in str(store)  # nowhere in the persisted row
    # The re-raised error (what the model sees) is clean, keeps its type, and does
    # not chain the dirty original.
    assert isinstance(raised, ToolError)
    assert _KEY not in str(raised) and _KEY not in repr(raised)
    assert raised.__context__ is None and raised.__cause__ is None


def test_bearer_token_redacted(monkeypatch):
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    _in_flight_headers(monkeypatch, {"Authorization": f"Bearer {_KEY}"})
    entry, raised = _failing_call({}, _provider_401())
    assert _KEY not in entry["error"] and _KEY not in str(raised)


def test_untyped_rebuild_falls_back_to_tool_error(monkeypatch):
    class _Picky(Exception):
        def __init__(self, status, detail):
            super().__init__(status, detail)

    async def _call(ctx):
        raise _Picky(401, f"bad key {_KEY}")

    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    _in_flight_headers(monkeypatch, {"X-Fal-Key": _KEY})
    entry, raised = _failing_call({}, _call)
    assert _KEY not in entry["error"]
    assert isinstance(raised, ToolError) and _KEY not in str(raised)


def test_clean_error_reraised_unchanged(monkeypatch):
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    _in_flight_headers(monkeypatch, {"X-Fal-Key": _KEY})
    original = RuntimeError("upstream timeout")

    async def _call(ctx):
        raise original

    entry, raised = _failing_call({}, _call)
    assert raised is original  # nothing to scrub: the very same object
    assert entry["error"] == repr(original)


def test_short_and_non_secret_headers_left_alone(monkeypatch):
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    # a non-credential header, and a credential-named one too short to be a key
    _in_flight_headers(monkeypatch, {"X-Request-Id": "upstream", "X-Fal-Key": "on"})

    async def _call(ctx):
        raise RuntimeError("upstream said on")

    entry, raised = _failing_call({}, _call)
    assert entry["error"] == repr(RuntimeError("upstream said on"))


def test_custom_redactor_and_failing_redactor_fail_closed(monkeypatch):
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    entry, raised = _failing_call(
        {}, _provider_401(), redact=lambda s: s.replace(_KEY, "<mine>")
    )
    assert "<mine>" in entry["error"] and "<mine>" in str(raised)

    def _broken(text):
        raise RuntimeError("redactor bug")

    entry, raised = _failing_call({}, _provider_401(), redact=_broken)
    assert entry["error"] == mw_mod.REDACTION_FAILED
    assert _KEY not in str(raised) and _KEY not in repr(raised)


def test_no_request_in_flight_is_a_noop(monkeypatch):
    # stdio / no HTTP request: get_http_headers returns {}, nothing to redact.
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    entry, raised = _failing_call({}, _provider_401())
    assert _KEY in entry["error"]  # no header carried it, so it is not a caller secret


def test_end_to_end_through_fastmcp(monkeypatch):
    # The real server path: fastmcp wraps a tool's exception before the middleware
    # sees it; what the client receives and what the ledger holds must both be clean.
    from fastmcp import Client, FastMCP

    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    store = {}
    server = FastMCP("t")
    server.add_middleware(
        MeteringMiddleware(
            UsageLedger(store),
            allowed={"o@x.com"},
            redact=lambda s: s.replace(_KEY, "<redacted>"),
        )
    )

    @server.tool
    def synthesize(text: str) -> str:
        raise ToolError(f"ElevenLabs 401: invalid api key {_KEY}")

    async def _go():
        async with Client(server) as client:
            return await client.call_tool(
                "synthesize", {"text": "hi"}, raise_on_error=False
            )

    result = _run(_go())
    assert result.is_error
    assert _KEY not in str(result.content) and "<redacted>" in str(result.content)
    (entry,) = store.values()
    assert _KEY not in entry["error"]


def test_dirty_cause_or_note_is_not_reraised(monkeypatch):
    # fastmcp's mask_error_details shape: a clean message whose __cause__ quotes the
    # key. A traceback printer would print the chain, so it must not escape.
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    _in_flight_headers(monkeypatch, {"X-Fal-Key": _KEY})

    async def _masked(ctx):
        try:
            raise RuntimeError(f"401 invalid key {_KEY}")
        except RuntimeError as dirty:
            raise ToolError("Error calling tool 'synthesize'") from dirty

    async def _noted(ctx):
        err = RuntimeError("upstream failed")
        err.add_note(f"key was {_KEY}")
        raise err

    for call in (_masked, _noted):
        entry, raised = _failing_call({}, call)
        chain = [raised, raised.__cause__, raised.__context__]
        assert not any(_KEY in repr(e) for e in chain if e is not None)
        assert not any(_KEY in n for n in getattr(raised, "__notes__", []))


def test_rebuilt_tool_error_keeps_its_log_level(monkeypatch):
    import logging

    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    _in_flight_headers(monkeypatch, {"X-Fal-Key": _KEY})

    async def _call(ctx):
        raise ToolError(f"bad key {_KEY}", log_level=logging.WARNING)

    entry, raised = _failing_call({}, _call)
    assert _KEY not in str(raised) and raised.log_level == logging.WARNING


def test_redactor_returning_non_text_withholds(monkeypatch):
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    entry, raised = _failing_call({}, _provider_401(), redact=lambda s: None)
    assert entry["error"] == mw_mod.REDACTION_FAILED
    assert _KEY not in str(raised)


def _real_http_failing_call(monkeypatch, *, error_text, headers):
    """Serve a metered tool that raises ``error_text`` over real streamable HTTP,
    with the DEFAULT redactor, and call it with ``headers``.

    Returns ``(client result, ledger row, everything fastmcp logged)``.
    """
    import io
    import logging
    import socket
    import threading
    import time

    uvicorn = pytest.importorskip("uvicorn")
    from fastmcp import Client, FastMCP
    from fastmcp.client.transports import StreamableHttpTransport

    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    store = {}
    server = FastMCP("t")
    server.add_middleware(MeteringMiddleware(UsageLedger(store), allowed={"o@x.com"}))

    @server.tool
    def synthesize(text: str) -> str:
        raise RuntimeError(error_text)

    # What a journald handler on the fastmcp logger would receive, traceback included.
    logs = io.StringIO()
    handler = logging.StreamHandler(logs)
    handler.setFormatter(logging.Formatter("%(name)s %(message)s"))
    fastmcp_logger = logging.getLogger("fastmcp")
    fastmcp_logger.addHandler(handler)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    http = uvicorn.Server(
        uvicorn.Config(
            server.http_app(), host="127.0.0.1", port=port, log_level="error"
        )
    )
    thread = threading.Thread(target=http.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not http.started and time.time() < deadline:
        time.sleep(0.05)

    async def _go():
        transport = StreamableHttpTransport(
            f"http://127.0.0.1:{port}/mcp", headers=headers
        )
        async with Client(transport) as client:
            return await client.call_tool(
                "synthesize", {"text": "hi"}, raise_on_error=False
            )

    try:
        result = _run(_go())
    finally:
        http.should_exit = True
        thread.join(timeout=10)
        fastmcp_logger.removeHandler(handler)
    (entry,) = store.values()
    return result, entry, logs.getvalue()


def test_default_redactor_over_real_http(monkeypatch):
    # The production path end to end: a real streamable-HTTP request carrying the
    # caller's key as a header, the DEFAULT redactor (no fakes for header reading).
    result, entry, logs = _real_http_failing_call(
        monkeypatch,
        error_text=f"ElevenLabs 401: invalid api key {_KEY}",
        headers={"X-Elevenlabs-Key": _KEY},
    )
    assert result.is_error and _KEY not in str(result.content)
    assert _KEY not in entry["error"]
    assert "<redacted:x-elevenlabs-key>" in entry["error"]
    assert "Error calling tool" in logs and _KEY not in logs  # enlace_metering#3


# ---------------------------------------------------------------------------
# The host's own keys, from its environment (tw_platform#307)
# ---------------------------------------------------------------------------

_ENV_KEY = "sk_server_fedcba9876543210"


def test_server_env_key_redacted_over_real_http(monkeypatch):
    """THE acceptance for tw_platform#307: the connector's own provider key comes
    from its environment, not a header; a provider quoting it back must reach
    neither the ledger row, the client, nor fastmcp's traceback log."""
    monkeypatch.setenv("ELEVENLABS_API_KEY", _ENV_KEY)
    result, entry, logs = _real_http_failing_call(
        monkeypatch,
        error_text=f"ElevenLabs 401: invalid api key {_ENV_KEY}",
        headers={},
    )
    assert result.is_error and _ENV_KEY not in str(result.content)
    assert _ENV_KEY not in entry["error"]
    assert "<redacted:env:ELEVENLABS_API_KEY>" in entry["error"]
    assert "Error calling tool" in logs and _ENV_KEY not in logs


@pytest.mark.parametrize(
    "name",
    [
        "ELEVENLABS_API_KEY", "ELEVEN_API_KEY", "FAL_KEY", "SUNO_API_KEY",
        "OPENAI_API_KEY", "ENLACE_SIGNING_KEY", "REELEE_MCP_DOWNLOAD_SECRET",
        "SHARED_PW_PDF_TOOLS", "GITHUB_TOKEN", "DB_PASSWORD", "fal_key",
    ],
)
def test_env_credentials_are_recognised_by_name(monkeypatch, name):
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    _in_flight_headers(monkeypatch, {})
    monkeypatch.setenv(name, _ENV_KEY)

    async def _call(ctx):
        raise RuntimeError(f"401: bad key {_ENV_KEY}")

    entry, raised = _failing_call({}, _call)
    assert _ENV_KEY not in entry["error"] and _ENV_KEY not in str(raised)
    # Windows upper-cases environment variable names.
    assert f"<redacted:env:{name}>".lower() in entry["error"].lower()


@pytest.mark.parametrize(
    "name", ["HOME", "PWD", "OLDPWD", "CONNECTOR_ISSUER", "KEYBOARD_LAYOUT", "MONKEY"]
)
def test_other_env_vars_are_left_alone(monkeypatch, name):
    value = "/srv/some/ordinary/value"
    monkeypatch.setenv(name, value)
    redact = mw_mod.secret_redactor(headers=dict)
    assert redact(f"failed in {value}") == f"failed in {value}"


def test_env_names_adds_a_secret_the_pattern_misses(monkeypatch):
    monkeypatch.setenv("SUNO_CALLBACK_URL", "https://hooks.example/abcdef123")
    redact = mw_mod.secret_redactor(headers=dict, env_names=["SUNO_CALLBACK_URL"])
    assert redact("posted to https://hooks.example/abcdef123") == (
        "posted to <redacted:env:SUNO_CALLBACK_URL>"
    )


def test_short_env_values_are_left_alone(monkeypatch):
    monkeypatch.setenv("FEATURE_KEY", "on")
    assert mw_mod.secret_redactor(headers=dict)("turned on") == "turned on"


def test_headers_and_env_redact_in_one_pass_longest_first():
    """A caller key that is a substring of the server key must not leave the rest
    of the server key behind (and vice versa)."""
    inner, outer = "abcdefgh12", "XYZ-abcdefgh12-SERVER"
    redact = mw_mod.secret_redactor(
        headers=lambda: {"x-fal-key": inner}, environ=lambda: {"FAL_KEY": outer}
    )
    assert redact(f"{outer} / {inner}") == (
        "<redacted:env:FAL_KEY> / <redacted:x-fal-key>"
    )


def test_request_secret_redactor_still_ignores_the_environment(monkeypatch):
    monkeypatch.setenv("FAL_KEY", _ENV_KEY)
    redact = mw_mod.request_secret_redactor(headers=dict)
    assert redact(_ENV_KEY) == _ENV_KEY


def test_the_middleware_default_is_redact_secrets():
    mw = MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"})
    assert mw.redact is mw_mod.redact_secrets


# ---------------------------------------------------------------------------
# fastmcp's own traceback log (enlace_metering#3)
# ---------------------------------------------------------------------------


def _log_through_fastmcp(monkeypatch, emit):
    import io
    import logging

    MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"})  # installs the filter
    logger = logging.getLogger("fastmcp.server.server")
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    try:
        emit(logger)
    finally:
        logger.removeHandler(handler)
    return out.getvalue()


def test_a_logged_traceback_is_redacted(monkeypatch):
    monkeypatch.setenv("FAL_KEY", _ENV_KEY)

    def emit(logger):
        try:
            raise RuntimeError(f"fal 401: key {_ENV_KEY}")
        except RuntimeError:
            logger.exception("Error calling tool %r", "synthesize")

    text = _log_through_fastmcp(monkeypatch, emit)
    assert "Error calling tool 'synthesize'" in text  # message and args kept
    assert "RuntimeError" in text and "<redacted:env:FAL_KEY>" in text
    assert _ENV_KEY not in text


def test_a_clean_record_is_untouched(monkeypatch):
    def emit(logger):
        try:
            raise RuntimeError("nothing secret")
        except RuntimeError:
            logger.exception("Error calling tool %r", "synthesize")

    text = _log_through_fastmcp(monkeypatch, emit)
    assert "Error calling tool 'synthesize'" in text and "nothing secret" in text


def test_a_failing_redactor_withholds_the_log_text(monkeypatch):
    monkeypatch.setattr(mw_mod, "redact_secrets", lambda s: 1 / 0)

    def emit(logger):
        logger.error("key %s", _ENV_KEY)

    text = _log_through_fastmcp(monkeypatch, emit)
    assert _ENV_KEY not in text and mw_mod.REDACTION_FAILED in text


def test_log_redaction_is_installed_once():
    import logging

    for _ in range(3):
        MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"})
    depth, factory = 0, logging.getLogRecordFactory()
    assert getattr(factory, "_enlace_metering_redacting", False)
    while getattr(factory, "_enlace_metering_redacting", False):
        depth += 1
        factory = factory.__closure__[0].cell_contents if factory.__closure__ else None
        if depth > 5:
            break
    assert depth == 1


def test_a_logger_created_after_the_middleware_is_redacted(monkeypatch):
    """fastmcp 4.x creates the logger that writes the tool traceback lazily, after
    the middleware exists: the redaction must not depend on creation order."""
    import io
    import logging
    import uuid

    MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"})
    monkeypatch.setenv("FAL_KEY", _ENV_KEY)
    late = logging.getLogger(f"fastmcp.late_{uuid.uuid4().hex}")
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    late.addHandler(handler)
    try:
        try:
            raise RuntimeError(f"fal 401 {_ENV_KEY}")
        except RuntimeError:
            late.exception("Error calling tool")
    finally:
        late.removeHandler(handler)
    assert "<redacted:env:FAL_KEY>" in out.getvalue() and _ENV_KEY not in out.getvalue()


def test_redact_logs_can_name_the_connectors_own_namespace(monkeypatch):
    import io
    import logging

    MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"}, redact_logs=("braidio_t",))
    monkeypatch.setenv("ELEVENLABS_API_KEY", _ENV_KEY)
    logger = logging.getLogger("braidio_t.synth")
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    logger.addHandler(handler)
    try:
        logger.error("provider said %s", _ENV_KEY)
    finally:
        logger.removeHandler(handler)
    assert _ENV_KEY not in out.getvalue()


def test_other_namespaces_are_untouched():
    import logging

    MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"})
    record = logging.getLogger("unrelated.lib").makeRecord(
        "unrelated.lib", logging.INFO, __file__, 1, "x %s", ("y",), None
    )
    assert record.msg == "x %s" and record.args == ("y",)


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="ExceptionGroup and add_note are 3.11+"
)
def test_a_key_inside_an_exception_group_is_not_reraised(monkeypatch):
    import traceback

    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    _in_flight_headers(monkeypatch, {})
    monkeypatch.setenv("FAL_KEY", _ENV_KEY)

    async def _call(ctx):
        inner = RuntimeError("provider failed")
        inner.add_note(f"key was {_ENV_KEY}")
        raise ExceptionGroup("tool failed", [inner])  # noqa: F821 -- 3.11+, skipped below that

    entry, raised = _failing_call({}, _call)
    assert _ENV_KEY not in "".join(traceback.format_exception(raised))


@pytest.mark.parametrize(
    "quoted",
    ["fal-id%3A" + "s3cr3t-part-0123", "s3cr3t-part-0123"],
    ids=["url-encoded", "secret-segment"],
)
def test_transformed_forms_of_a_key_are_redacted(quoted):
    redact = mw_mod.secret_redactor(
        headers=dict, environ=lambda: {"FAL_KEY": "fal-id:s3cr3t-part-0123"}
    )
    assert "s3cr3t-part-0123" not in redact(f"401 for {quoted}")


@pytest.mark.parametrize(
    "name",
    ["SMTP_PASS", "GPG_PASSPHRASE", "SENTRY_DSN", "API_KEYS", "APP_SECRETS",
     "GITHUB_PAT", "DB_CREDS", "SSH_PRIVATE_KEY", "PRIVATEKEY"],
)
def test_more_credential_names(monkeypatch, name):
    redact = mw_mod.secret_redactor(headers=dict, environ=lambda: {name: _ENV_KEY})
    assert _ENV_KEY not in redact(_ENV_KEY)


@pytest.mark.parametrize(
    "name", ["S3_KEY_PREFIX", "SSH_KEY_PATH", "TOKEN_URL", "AWS_ACCESS_KEY_ID", "KEY_FILE"]
)
def test_names_about_a_credential_are_not_one(name):
    redact = mw_mod.secret_redactor(headers=dict, environ=lambda: {name: "uploads/area"})
    assert redact("wrote uploads/area") == "wrote uploads/area"


def test_a_password_in_any_url_is_redacted():
    url = "postgres://app:hunter2hunter2@db.internal/main"
    redact = mw_mod.secret_redactor(headers=dict, environ=lambda: {"DATABASE_URL": url})
    assert "hunter2hunter2" not in redact(f"cannot connect: {url}")


#: A credential with the characters repr() and JSON escape.
_ESCAPED_KEY = 'pa\\ss"wo\'rd-0123456'


@pytest.mark.parametrize(
    "render",
    [lambda k: f"smtp refused {k}", lambda k: "provider said " + json.dumps({"k": k})],
    ids=["plain", "json-body"],
)
def test_a_key_with_escaped_characters_is_redacted_everywhere(monkeypatch, render):
    """The ledger stores repr(exc), and a provider may quote a key inside a JSON
    body: both escape a backslash or quote, so the raw value never matches."""
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    monkeypatch.setenv("SMTP_PASS", _ESCAPED_KEY)

    async def _call(ctx):
        raise RuntimeError(render(_ESCAPED_KEY))

    store = {}
    entry, raised = _failing_call(store, _call, redact_logs=False)
    for text in (str(store), str(raised), repr(raised)):
        assert "wo\\'rd-0123456" not in text and "wo'rd-0123456" not in text, text
    assert "<redacted:env:SMTP_PASS>" in entry["error"]
