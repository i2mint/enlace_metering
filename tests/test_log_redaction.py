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


def test_warnings_go_through_the_redaction(monkeypatch):
    monkeypatch.setenv("FAL_KEY", _KEY)
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    logger = logging.getLogger("py.warnings")
    logger.addHandler(handler)
    try:
        # pytest swaps warnings.showwarning per test, so start from no capture.
        with warnings.catch_warnings():
            warnings.simplefilter("always")
            logging.captureWarnings(False)
            install_log_redaction(namespaces=ALL_LOGGERS)
            warnings.warn(f"generation skipped: {_KEY}")
            logging.captureWarnings(False)
    finally:
        logger.removeHandler(handler)
    assert "generation skipped" in out.getvalue() and _KEY not in out.getvalue()


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
