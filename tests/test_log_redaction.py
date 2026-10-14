"""Log redaction across the whole process: ``redact_logs="*"`` (#5).

Every finding in #5 was a path by which a provider key reached the journal
without passing a namespace-limited redactor: provider SDK loggers, the root
logger, ``uvicorn.error``/``asyncio`` tracebacks, ``warnings.warn``, ``extra=``
fields, and tracebacks printed by an uncaught exception.
"""

from __future__ import annotations

import io
import logging
import sys
import threading
import warnings

import pytest

from enlace_metering import ALL_LOGGERS, UsageLedger, install_log_redaction
from enlace_metering import middleware as mw_mod
from enlace_metering.middleware import MeteringMiddleware

_KEY = "fal-sk-0123456789abcdefSECRET"


@pytest.fixture
def secret_env(monkeypatch):
    monkeypatch.setenv("FAL_KEY", _KEY)
    install_log_redaction(namespaces=ALL_LOGGERS)


def _emit(logger_name: str, *args, **kwargs) -> str:
    logger = logging.getLogger(logger_name)
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    logger.addHandler(handler)
    try:
        logger.warning(*args, **kwargs)
    finally:
        logger.removeHandler(handler)
    return out.getvalue()


@pytest.mark.parametrize(
    "name", ["", "httpx", "fal_client.client", "fern", "uvicorn.error", "asyncio"]
)
def test_every_logger_is_redacted(secret_env, name):
    text = _emit(name, "Upload failed to %s: %s", "https://x", f"401 key={_KEY}")
    assert _KEY not in text and "<redacted:env:FAL_KEY>" in text


def test_a_traceback_on_the_root_logger_is_redacted(secret_env):
    logger = logging.getLogger()
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    logger.addHandler(handler)
    try:
        try:
            raise RuntimeError(f"provider said {_KEY}")
        except RuntimeError:
            logger.exception("unhandled")
    finally:
        logger.removeHandler(handler)
    assert _KEY not in out.getvalue() and "RuntimeError" in out.getvalue()


def test_warnings_are_redacted_where_they_already_went(monkeypatch):
    """``showwarning`` is wrapped, not replaced: the previous one still gets the
    warning (redacted when dirty, the very same object when clean)."""
    monkeypatch.setenv("FAL_KEY", _KEY)
    seen = []

    def previous(message, category, filename, lineno, file=None, line=None):
        seen.append((message, category, line))

    with warnings.catch_warnings():  # restores showwarning on exit
        warnings.simplefilter("always")
        warnings.showwarning = previous
        install_log_redaction(namespaces=ALL_LOGGERS)
        warnings.warn(f"generation skipped: {_KEY}")
        clean = UserWarning("nothing secret")
        warnings.warn(clean)
    (dirty_msg, category, _), (clean_msg, _, line) = seen
    assert category is UserWarning and isinstance(dirty_msg, UserWarning)
    assert str(dirty_msg) == "generation skipped: <redacted:env:FAL_KEY>"
    assert clean_msg is clean and line is None


def test_warnings_captured_into_logging_are_redacted(monkeypatch):
    """A host that routes warnings into logging (``captureWarnings``) after the
    install still gets them redacted."""
    monkeypatch.setenv("FAL_KEY", _KEY)
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    logger = logging.getLogger("py.warnings")
    logger.addHandler(handler)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("always")
            install_log_redaction(namespaces=ALL_LOGGERS)
            logging.captureWarnings(True)
            try:
                warnings.warn(f"generation skipped: {_KEY}")
            finally:
                logging.captureWarnings(False)
    finally:
        logger.removeHandler(handler)
    assert "generation skipped" in out.getvalue() and _KEY not in out.getvalue()


_PROCESS_SCRIPT = """
import os, threading, warnings
from enlace_metering import install_log_redaction
install_log_redaction(namespaces="*")
key = os.environ["FAL_KEY"]
warnings.warn("a clean warning")
warnings.warn("a dirty warning " + key)
class Dying:
    def __del__(self):
        raise RuntimeError("del " + key)
d = Dying(); del d
def work():
    raise RuntimeError("thread " + key)
t = threading.Thread(target=work, name="raw-worker"); t.start(); t.join()
raise RuntimeError("uncaught " + key)
"""


def test_a_whole_process_with_unconfigured_logging():
    """In a plain process (no logging config, no pytest hooks) every path still
    prints, redacted: warnings (not swallowed by a ``NullHandler``), ``__del__``,
    a raw thread, and the uncaught exception."""
    import os
    import pathlib
    import subprocess

    root = pathlib.Path(__file__).resolve().parents[1]
    env = {**os.environ, "FAL_KEY": _KEY, "PYTHONPATH": str(root)}
    proc = subprocess.run(
        [sys.executable, "-c", _PROCESS_SCRIPT],
        capture_output=True, text=True, env=env, cwd=root, timeout=60,
    )
    err = proc.stderr
    assert proc.returncode == 1 and _KEY not in err and _KEY not in proc.stdout
    for shown in (
        "a clean warning",
        "a dirty warning <redacted:env:FAL_KEY>",
        "del <redacted:env:FAL_KEY>",
        "Exception in thread raw-worker",
        "thread <redacted:env:FAL_KEY>",
        "uncaught <redacted:env:FAL_KEY>",
    ):
        assert shown in err, (shown, err)


class _Url:
    def __str__(self):
        return f"https://api.example/v1?key={_KEY}"


def test_extra_fields_are_redacted_by_the_filter(monkeypatch):
    """``extra=`` is applied after the record factory runs, so only a filter on
    the (structured) handler sees it: ``RedactingLogFilter`` redacts it there."""
    monkeypatch.setenv("FAL_KEY", _KEY)
    record = logging.getLogger("fern").makeRecord(
        "fern", logging.WARNING, __file__, 1, "request", (), None,
        extra={"url": _Url(), "body": f"k={_KEY}", "status": 401, "ok": "fine"},
    )
    assert mw_mod.RedactingLogFilter().filter(record) is True
    assert _KEY not in record.url and _KEY not in record.body
    assert record.status == 401 and record.ok == "fine"


def test_the_middleware_covers_every_logger_by_default(monkeypatch):
    MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"})
    monkeypatch.setenv("FAL_KEY", _KEY)
    assert _KEY not in _emit("some.provider.sdk", "said %s", _KEY)


def test_a_bare_string_is_one_namespace():
    install_log_redaction(namespaces="zz_connector")
    assert "zz_connector" in mw_mod._REDACTED_NAMESPACES
    assert "z" not in mw_mod._REDACTED_NAMESPACES


def test_a_failing_redactor_does_not_recurse(secret_env, monkeypatch):
    monkeypatch.setattr(mw_mod, "redact_secrets", lambda s: 1 / 0)
    text = _emit("any.logger", "key %s", _KEY)
    assert _KEY not in text and mw_mod.REDACTION_FAILED in text


def test_an_uncaught_exception_prints_redacted(secret_env, capsys):
    try:
        raise RuntimeError(f"boom {_KEY}")
    except RuntimeError:
        sys.excepthook(*sys.exc_info())
    err = capsys.readouterr().err
    assert "boom" in err and _KEY not in err


def test_a_clean_uncaught_exception_goes_to_the_previous_hook(secret_env, capsys):
    try:
        raise RuntimeError("boom, nothing secret")
    except RuntimeError:
        sys.excepthook(*sys.exc_info())
    assert "nothing secret" in capsys.readouterr().err


def test_an_exception_in_a_thread_prints_redacted(monkeypatch, capsys):
    monkeypatch.setenv("FAL_KEY", _KEY)
    # pytest owns threading.excepthook during a test: install ours fresh on top
    # of the defaults, and let monkeypatch put everything back.
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    monkeypatch.setattr(threading, "excepthook", threading.__excepthook__)
    mw_mod._install_redacting_excepthooks()

    def boom():
        raise RuntimeError(f"thread boom {_KEY}")

    t = threading.Thread(target=boom, name="worker-1")
    t.start()
    t.join()
    err = capsys.readouterr().err
    assert "worker-1" in err and "thread boom" in err and _KEY not in err


# --- the adversarial review of #5 -------------------------------------------


def test_a_string_redact_logs_still_covers_fastmcp(monkeypatch):
    monkeypatch.setattr(mw_mod, "_REDACTED_NAMESPACES", set())
    MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"}, redact_logs="braidio_x")
    assert {"fastmcp", "braidio_x"} <= mw_mod._REDACTED_NAMESPACES
    assert ALL_LOGGERS not in mw_mod._REDACTED_NAMESPACES


def test_stack_info_is_redacted(secret_env):
    record = logging.getLogger("prov").makeRecord(
        "prov", logging.WARNING, __file__, 1, "x", (), None,
        sinfo=f"Stack (most recent call last):\n  key={_KEY}",
    )
    assert _KEY not in record.stack_info and "<redacted:env:FAL_KEY>" in record.stack_info


def test_dirty_args_keep_their_shape(secret_env):
    """Formatters such as uvicorn's access log unpack ``record.args``: a dirty
    argument is redacted in place, the others keep their type."""
    record = logging.getLogger("prov").makeRecord(
        "prov", logging.INFO, __file__, 1, '%s - "%s %s" %d', (
            "127.0.0.1:5000", "GET", f"/v1?key={_KEY}", 200,
        ), None,
    )
    assert record.msg == '%s - "%s %s" %d'
    assert record.args == (
        "127.0.0.1:5000", "GET", "/v1?key=<redacted:env:FAL_KEY>", 200
    )
    mapping = logging.getLogger("prov").makeRecord(
        "prov", logging.INFO, __file__, 1, "%(url)s %(n)d",
        ({"url": _Url(), "n": 3},), None,
    )
    assert mapping.args["n"] == 3 and _KEY not in mapping.getMessage()


def test_uvicorn_access_formatter_still_formats_a_dirty_record(secret_env, capsys):
    from uvicorn.logging import AccessFormatter

    logger = logging.getLogger("uvicorn.access.test")
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.setFormatter(AccessFormatter('%(client_addr)s "%(request_line)s" %(status_code)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        logger.info(
            '%s - "%s %s HTTP/%s" %d',
            "127.0.0.1:5000", "GET", f"/v1?key={_KEY}", "1.1", 401,
        )
    finally:
        logger.removeHandler(handler)
        logger.setLevel(logging.NOTSET)
    assert "Logging error" not in capsys.readouterr().err
    text = out.getvalue()
    assert "GET /v1?key=<redacted:env:FAL_KEY> HTTP/1.1" in text and "401" in text
    assert _KEY not in text


def test_a_secret_split_across_arguments_falls_back_to_the_whole_message(secret_env):
    half = len(_KEY) // 2
    record = logging.getLogger("prov").makeRecord(
        "prov", logging.INFO, __file__, 1, "%s%s", (_KEY[:half], _KEY[half:]), None
    )
    assert record.args is None and _KEY not in record.getMessage()


def test_a_dirty_traceback_keeps_the_arguments(secret_env):
    logger = logging.getLogger("prov")
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    logger.addHandler(handler)
    try:
        try:
            raise RuntimeError(f"100% failed: {_KEY}")
        except RuntimeError:
            logger.exception("Error calling tool %r", "synthesize")
    finally:
        logger.removeHandler(handler)
    text = out.getvalue()
    assert "Error calling tool 'synthesize'" in text and "100% failed" in text
    assert _KEY not in text


def test_a_record_logged_by_the_redactor_is_withheld(secret_env):
    def chatty(text):
        logging.getLogger("host.redactor").warning("redacting: %s", text)
        return mw_mod.redact_secrets(text)

    out = io.StringIO()
    handler = logging.StreamHandler(out)
    host = logging.getLogger("host.redactor")
    host.addHandler(handler)
    token = mw_mod._CURRENT_REDACTOR.set(chatty)
    try:
        prov = _emit("prov", "401 %s", _KEY)
    finally:
        mw_mod._CURRENT_REDACTOR.reset(token)
        host.removeHandler(handler)
    assert _KEY not in out.getvalue() and mw_mod.REDACTION_FAILED in out.getvalue()
    assert _KEY not in prov and "<redacted:env:FAL_KEY>" in prov


def test_the_redactor_failed_warning_itself_gets_through(secret_env, monkeypatch):
    monkeypatch.setattr(mw_mod, "redact_secrets", lambda s: 1 / 0)
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    mw_mod._logger.addHandler(handler)
    try:
        _emit("prov", "key %s", _KEY)
    finally:
        mw_mod._logger.removeHandler(handler)
    assert "redactor failed" in out.getvalue()


def test_an_unrenderable_extra_field_is_withheld_alone(monkeypatch):
    monkeypatch.setenv("FAL_KEY", _KEY)

    class Boom:
        def __str__(self):
            raise ValueError("no str")

    record = logging.getLogger("j").makeRecord(
        "j", logging.WARNING, __file__, 1, "clean message", (), None,
        extra={"obj": Boom(), "url": _Url()},
    )
    mw_mod.RedactingLogFilter().filter(record)
    assert record.getMessage() == "clean message"
    assert record.obj == mw_mod.REDACTION_FAILED and _KEY not in record.url


def test_records_that_bypass_the_factory_are_redacted_by_every_logger(monkeypatch):
    """``makeLogRecord`` and a logger's own ``makeRecord`` never call the record
    factory, and handlers configured after the install (uvicorn's ``dictConfig``)
    carry no filter: ``Logger.handle`` is wrapped, so every record routed through
    any logger is redacted, ``extra=`` fields included."""
    import logging.config

    monkeypatch.setenv("FAL_KEY", _KEY)
    install_log_redaction(namespaces=ALL_LOGGERS)
    logger = logging.getLogger("bypass.factory")
    out = io.StringIO()
    handler = logging.StreamHandler(out)  # created after the install
    handler.setFormatter(logging.Formatter("%(message)s | %(url)s"))
    logger.addHandler(handler)

    class OwnRecords(logging.Logger):
        def makeRecord(self, name, level, fn, lno, msg, args, exc_info,
                       func=None, extra=None, sinfo=None):
            record = logging.LogRecord(name, level, fn, lno, msg, args, exc_info)
            record.url = (extra or {}).get("url", "-")
            return record

    own = OwnRecords("bypass.factory.own")
    own.parent = logger
    try:
        logger.handle(logging.makeLogRecord(
            {"name": "bypass.factory", "levelno": 30, "msg": f"made {_KEY}",
             "url": f"https://x/?k={_KEY}"}
        ))
        own.warning("own %s", _KEY, extra={"url": f"https://x/?k={_KEY}"})
        logger.warning("extra", extra={"url": f"https://x/?k={_KEY}"})
    finally:
        logger.removeHandler(handler)
    text = out.getvalue()
    assert "made" in text and "own" in text and "extra |" in text
    assert _KEY not in text and text.count("<redacted:env:FAL_KEY>") == 5


def test_logger_handle_is_wrapped_once():
    for _ in range(3):
        install_log_redaction(namespaces=ALL_LOGGERS)
    handle = logging.Logger.handle
    assert getattr(handle, mw_mod._MARK, False)
    assert not getattr(handle.__wrapped__, mw_mod._MARK, False)


def test_last_resort_output_is_redacted(monkeypatch, capsys):
    """A logger with no handler anywhere falls back to ``logging.lastResort``."""
    monkeypatch.setenv("FAL_KEY", _KEY)
    install_log_redaction(namespaces=ALL_LOGGERS)
    monkeypatch.setattr(logging, "lastResort", logging.StreamHandler(sys.stderr))
    root = logging.getLogger()
    monkeypatch.setattr(root, "handlers", [])
    logger = logging.getLogger("no.handlers.anywhere")
    logger.handle(logging.makeLogRecord(
        {"name": logger.name, "levelno": 40, "msg": f"orphan {_KEY}"}
    ))
    err = capsys.readouterr().err
    assert "orphan <redacted:env:FAL_KEY>" in err and _KEY not in err


def test_a_changed_environment_is_picked_up(monkeypatch):
    redact = mw_mod.secret_redactor(headers=dict)
    monkeypatch.setenv("FAL_KEY", _KEY)
    assert redact(_KEY) == "<redacted:env:FAL_KEY>"
    assert redact(_KEY) == "<redacted:env:FAL_KEY>"  # cached
    other = "fal-sk-ANOTHERKEY-9876543210"
    monkeypatch.setenv("FAL_KEY", other)
    assert redact(other) == "<redacted:env:FAL_KEY>" and redact(_KEY) == _KEY
    monkeypatch.setenv("NEW_PROVIDER_TOKEN", _KEY)
    assert redact(_KEY) == "<redacted:env:NEW_PROVIDER_TOKEN>"


# --- hooks: excepthook, threading.excepthook, unraisablehook -----------------


@pytest.fixture
def fresh_hooks(monkeypatch):
    """Our hooks installed on top of recorders standing in for the previous ones
    (pytest owns the real ones during a test); monkeypatch restores them all."""
    monkeypatch.setenv("FAL_KEY", _KEY)
    seen = {"sys": [], "thread": [], "unraisable": []}
    monkeypatch.setattr(sys, "excepthook", lambda *a: seen["sys"].append(a))
    monkeypatch.setattr(threading, "excepthook", lambda a: seen["thread"].append(a))
    monkeypatch.setattr(sys, "unraisablehook", lambda u: seen["unraisable"].append(u))
    mw_mod._install_redacting_excepthooks()
    return seen


def _dirty_exc_info():
    try:
        raise RuntimeError(f"boom {_KEY}")
    except RuntimeError:
        return sys.exc_info()


def test_a_dirty_uncaught_exception_reaches_the_previous_hook_scrubbed(fresh_hooks):
    sys.excepthook(*_dirty_exc_info())
    ((exc_type, exc, tb),) = fresh_hooks["sys"]
    assert exc_type is RuntimeError and str(exc) == "boom <redacted:env:FAL_KEY>"
    assert tb is not None  # the frames are kept: their text is clean


def test_a_clean_uncaught_exception_reaches_the_previous_hook_as_is(fresh_hooks):
    try:
        raise RuntimeError("nothing secret")
    except RuntimeError:
        info = sys.exc_info()
    sys.excepthook(*info)
    assert fresh_hooks["sys"] == [info]


def test_the_thread_hook_passes_a_scrubbed_exception_on(fresh_hooks):
    exc_type, exc, tb = _dirty_exc_info()
    threading.excepthook(threading.ExceptHookArgs([exc_type, exc, tb, None]))
    ((args,),) = [fresh_hooks["thread"]]
    assert str(args.exc_value) == "boom <redacted:env:FAL_KEY>" and args.thread is None


def test_the_thread_hook_passes_system_exit_through(fresh_hooks):
    args = threading.ExceptHookArgs([SystemExit, SystemExit(f"bye {_KEY}"), None, None])
    threading.excepthook(args)
    assert fresh_hooks["thread"] == [args]


def test_a_failing_previous_hook_prints_redacted_with_no_thread(monkeypatch, capsys):
    monkeypatch.setenv("FAL_KEY", _KEY)

    def broken(*args):
        raise OSError("crash reporter down")

    monkeypatch.setattr(sys, "excepthook", broken)
    monkeypatch.setattr(threading, "excepthook", broken)
    monkeypatch.setattr(sys, "unraisablehook", sys.__unraisablehook__)
    mw_mod._install_redacting_excepthooks()
    exc_type, exc, tb = _dirty_exc_info()
    threading.excepthook(threading.ExceptHookArgs([exc_type, exc, tb, None]))
    sys.excepthook(exc_type, exc, tb)
    err = capsys.readouterr().err
    assert "Exception in thread <unknown>" in err and "boom" in err and _KEY not in err


def test_hooks_tolerate_a_missing_stderr(monkeypatch):
    monkeypatch.setenv("FAL_KEY", _KEY)

    def broken(*args):
        raise OSError("no reporter")

    monkeypatch.setattr(sys, "excepthook", broken)
    monkeypatch.setattr(threading, "excepthook", broken)
    monkeypatch.setattr(sys, "unraisablehook", broken)
    mw_mod._install_redacting_excepthooks()
    monkeypatch.setattr(sys, "stderr", None)
    exc_type, exc, tb = _dirty_exc_info()
    sys.excepthook(exc_type, exc, tb)
    threading.excepthook(threading.ExceptHookArgs([exc_type, exc, tb, None]))
    _unraisable(exc_type, exc, tb, f"err {_KEY}", None)


def _unraisable(exc_type, exc, tb, err_msg, obj):
    """Call ``sys.unraisablehook`` with real ``UnraisableHookArgs``."""
    captured = []
    saved = sys.unraisablehook
    sys.unraisablehook = captured.append

    class Dying:
        def __del__(self):
            raise RuntimeError("probe")

    d = Dying()
    del d
    sys.unraisablehook = saved
    (probe,) = captured
    sys.unraisablehook(type(probe)((exc_type, exc, tb, err_msg, obj)))


class _DirtyRepr:
    def __repr__(self):
        return f"<conn key={_KEY}>"


def test_an_exception_ignored_in_del_reaches_the_previous_hook_scrubbed(fresh_hooks):
    exc_type, exc, tb = _dirty_exc_info()
    _unraisable(exc_type, exc, tb, f"Exception ignored in {_KEY}", _DirtyRepr())
    (u,) = fresh_hooks["unraisable"]
    assert str(u.exc_value) == "boom <redacted:env:FAL_KEY>"
    assert _KEY not in u.err_msg and _KEY not in repr(u.object)
    assert "<redacted:env:FAL_KEY>" in repr(u.object)


def test_an_exception_ignored_in_del_prints_redacted(monkeypatch, capsys):
    monkeypatch.setenv("FAL_KEY", _KEY)
    monkeypatch.setattr(sys, "unraisablehook", sys.__unraisablehook__)
    mw_mod._install_redacting_excepthooks()

    class Dying:
        def __del__(self):
            raise RuntimeError(f"del {_KEY}")

    d = Dying()
    del d
    err = capsys.readouterr().err
    assert "del <redacted:env:FAL_KEY>" in err and _KEY not in err


# --- a raw thread's records know the caller's BYO header key ------------------


def test_a_raw_thread_redacts_the_callers_header_key(monkeypatch, capsys):
    """A ``threading.Thread`` does not copy the request's context, so the
    request's headers are invisible there: the middleware registers them
    process-wide for the duration of the call."""
    import asyncio
    import contextvars

    import fastmcp.server.dependencies as deps

    caller_key = "byo-CALLER-KEY-0123456789abcdef"
    in_request = contextvars.ContextVar("in_request", default=False)

    def headers(include_all=False, include=None):
        return {"x-fal-key": caller_key} if in_request.get() else {}

    monkeypatch.setattr(deps, "get_http_headers", headers)
    monkeypatch.setattr(mw_mod, "token_email", lambda: "o@x.com")
    monkeypatch.setattr(threading, "excepthook", threading.__excepthook__)
    mw = MeteringMiddleware(UsageLedger({}), allowed={"o@x.com"})
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    mw_mod._install_redacting_excepthooks()

    out = io.StringIO()
    handler = logging.StreamHandler(out)
    worker = logging.getLogger("provider.worker")
    worker.addHandler(handler)

    def work():
        assert not in_request.get()  # no context copied into the thread
        worker.warning("auth failed for key %s", caller_key)
        raise RuntimeError(f"thread boom {caller_key}")

    async def call_next(ctx):
        t = threading.Thread(target=work, name="raw-worker")
        t.start()
        t.join()
        return None

    class _Msg:
        name, arguments = "synthesize", {}

    class _Ctx:
        message = _Msg()

    async def run():
        in_request.set(True)
        return await mw.on_call_tool(_Ctx(), call_next)

    try:
        asyncio.run(run())
    finally:
        worker.removeHandler(handler)
    err = capsys.readouterr().err
    assert caller_key not in out.getvalue() and "<redacted:x-fal-key>" in out.getvalue()
    assert "thread boom <redacted:x-fal-key>" in err and caller_key not in err
    assert mw_mod._INFLIGHT == {}  # no longer in flight...
    # ...but still known for a while, for a worker that outlives the call
    assert (caller_key, "x-fal-key") in mw_mod.inflight_request_secrets()


# --- the second review of #5 -------------------------------------------------


def _capture(name: str, fmt: str = "%(message)s"):
    logger = logging.getLogger(name)
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    return logger, handler, out


def test_a_withheld_nested_record_withholds_its_extra_fields_too(secret_env):
    """A redactor that logs what it redacts, with ``extra=``: the record nested
    too deep is withheld whole, its fields included."""
    def chatty(text):
        logging.getLogger("hostred").warning("redacting", extra={"payload": f"p {_KEY}"})
        return mw_mod.redact_secrets(text)

    host, handler, out = _capture("hostred", "%(message)s | %(payload)s")
    token = mw_mod._CURRENT_REDACTOR.set(chatty)
    try:
        _emit("prov", "401 %s", _KEY)
    finally:
        mw_mod._CURRENT_REDACTOR.reset(token)
        host.removeHandler(handler)
    assert _KEY not in out.getvalue()
    assert f"{mw_mod.REDACTION_FAILED} | {mw_mod.REDACTION_FAILED}" in out.getvalue()


def test_a_record_logged_from_an_arguments_repr_is_redacted_not_withheld(secret_env):
    """SQLAlchemy-style echo from a ``__repr__``: one level of nesting is
    redacted normally, clean text kept, a key replaced."""
    class Model:
        def __repr__(self):
            logging.getLogger("sqlalchemy.engine").warning("SELECT 1 -- %s", _KEY)
            return "Model()"

    sql, handler, out = _capture("sqlalchemy.engine")
    try:
        text = _emit("app", "loaded %r", Model())
    finally:
        sql.removeHandler(handler)
    assert "loaded Model()" in text
    assert "SELECT 1 -- <redacted:env:FAL_KEY>" in out.getvalue()
    assert mw_mod.REDACTION_FAILED not in out.getvalue() and _KEY not in out.getvalue()


def test_a_warning_from_an_arguments_str_under_capture_warnings(secret_env):
    class Chatty:
        def __str__(self):
            warnings.warn("inner warning from __str__")
            return f"w {_KEY}"

    pyw, handler, out = _capture("py.warnings")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("always")
            logging.captureWarnings(True)
            try:
                text = _emit("x", "v=%s", Chatty())
            finally:
                logging.captureWarnings(False)
    finally:
        pyw.removeHandler(handler)
    assert "inner warning from __str__" in out.getvalue()
    assert mw_mod.REDACTION_FAILED not in out.getvalue()
    assert "v=w <redacted:env:FAL_KEY>" in text


def test_recently_ended_calls_stay_known_within_bounds(monkeypatch):
    import time

    first, second, third = (
        (f"byo-key-{n}-0123456789abcdef", "x-fal-key") for n in range(3)
    )
    monkeypatch.setattr(mw_mod, "RECENT_CALLS_KEPT", 2)
    for pair in (first, second, third):
        mw_mod._register_inflight([pair], +1)
        mw_mod._register_inflight([pair], -1)
    known = mw_mod.inflight_request_secrets()
    assert first not in known and second in known and third in known
    monkeypatch.setattr(mw_mod, "RECENT_CALLS_SECONDS", 0.05)
    fourth = ("byo-key-4-0123456789abcdef", "x-fal-key")
    mw_mod._register_inflight([fourth], +1)
    mw_mod._register_inflight([fourth], -1)
    time.sleep(0.1)
    assert fourth not in mw_mod.inflight_request_secrets()


def test_a_callers_key_is_not_kept_compiled_once_forgotten(monkeypatch):
    monkeypatch.setattr(mw_mod, "RECENT_CALLS_SECONDS", 0)  # no recent ring
    pair = ("byo-forgotten-0123456789abcdef", "x-fal-key")
    redact = mw_mod.secret_redactor(headers=dict, env_pattern=None)
    mw_mod._register_inflight([pair], +1)
    assert redact(f"k={pair[0]}") == "k=<redacted:x-fal-key>"
    assert any(key[0] == pair for key in mw_mod._REQUEST_FORMS)
    mw_mod._register_inflight([pair], -1)
    assert redact(f"k={pair[0]}") == f"k={pair[0]}"
    assert not any(key[0] == pair for key in mw_mod._REQUEST_FORMS)
    assert not hasattr(mw_mod.escape_tolerant_pattern, "cache_info")


def test_showwarning_redacts_the_source_line(monkeypatch, tmp_path):
    monkeypatch.setenv("FAL_KEY", _KEY)
    source = tmp_path / "provider_conf.py"
    source.write_text(f"KEY = '{_KEY}'\n")
    seen = []
    with warnings.catch_warnings():
        warnings.showwarning = lambda *a, **k: seen.append(a)
        mw_mod._install_redacting_showwarning()
        warnings.showwarning(UserWarning("clean"), UserWarning, str(source), 1)
    ((message, category, filename, lineno, file, line),) = seen
    assert str(message) == "clean" and line == "KEY = '<redacted:env:FAL_KEY>'\n"


def test_a_traceback_whose_source_is_dirty_is_dropped(fresh_hooks, tmp_path):
    """The exception renders clean but a frame's source line quotes the key:
    the previous hook gets the exception without that traceback."""
    source = tmp_path / "leaky.py"
    source.write_text(f"raise RuntimeError('clean message')  # {_KEY}\n")
    try:
        exec(compile(source.read_text(), str(source), "exec"), {})
    except RuntimeError:
        info = sys.exc_info()
    sys.excepthook(*info)
    ((exc_type, exc, tb),) = fresh_hooks["sys"]
    assert str(exc) == "clean message" and tb is None
