"""FastMCP metering middleware — the enforcement + recording glue for a connector.

Wires the three metering concerns into every tool call, **fail-closed**:

1. **Identity** — resolved ONCE from the verified OAuth token (``email`` claim, else
   ``sub``); no ambient fallback. Stashed in a context var; tools read it via
   :func:`current_email` (they never re-derive it), so authorization, gating, and
   per-user placement all key off the same identity.
2. **Authorization** — an ``allowed`` email set (defense-in-depth over the platform
   ``resource_allowlist``). Deny-by-default: a served connector with no ``allowed``,
   no ``local_user``, and ``allow_any_authenticated=False`` rejects everyone.
3. **Gating + metering** — the injected :data:`~enlace_metering.policy.GatePolicy`
   decides *before* the call runs (deny → refuse). Then a **write-ahead** ledger row
   is written (if that write fails the call is refused — money is never spent
   un-recordably), the tool runs, and the row is updated with the actual ``cost_usd``
   + outcome. A failed call's error text is passed through a **redactor** first: a
   provider can quote a key back in its error (ElevenLabs does on a 401) — the
   caller's bring-your-own key from a request header, or the host's own key from
   its environment — and neither the persistent ledger row nor the re-raised
   exception (which the model sees) may carry it.

This is the ``[mcp]`` layer (needs ``fastmcp``); the ledger + policy are pure and
import-free of it. Generalizes braidio's bespoke ``MeteringMiddleware`` (which only
recorded) by adding the policy gate + a proposed-cost estimate hook.
"""

from __future__ import annotations

import itertools
import linecache
import logging
import os
import re
import sys
import threading
import time
import traceback
import warnings
import weakref
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Callable, Iterable, Mapping, Optional, Union
from urllib.parse import quote

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

from .ledger import UsageLedger, safe_principal
from .policy import GatePolicy, GateRequest, unlimited

_logger = logging.getLogger(__name__)

#: Cost keys to look for in a tool result's ``structured_content``, in priority order.
#: Connectors emit different names for the ACTUAL spend of a call (braidio: ``cost_usd``;
#: reelee: ``cost_usd_actual``) — the default extractor tries each so a host's cap +
#: attribution work without a per-connector override. (NOT plan-estimate keys like
#: ``total_cost_usd`` — those are pre-spend estimates, not what was actually charged.)
COST_KEYS = ("cost_usd_actual", "cost_usd")

#: Set by :class:`MeteringMiddleware` for the duration of a tool call; read by
#: :func:`current_email`. Tools + per-user stores key off this one identity SSOT.
_CURRENT_EMAIL: ContextVar[Optional[str]] = ContextVar(
    "enlace_metering_email", default=None
)

#: A proposed-cost estimator: ``(tool_name, arguments) -> usd | None``. Host-supplied
#: so the gate can be forward-looking (deny a call that *would* cross the cap). Return
#: ``None`` when a call's cost can't be estimated — the gate then blocks on already-
#: accumulated usage instead.
CostEstimator = Callable[[str, Mapping[str, Any]], Optional[float]]

#: Pull the *actual* ``cost_usd`` out of a tool result for the ledger.
CostExtractor = Callable[[Any], Optional[float]]

#: Scrub caller secrets out of free text the connector did not author (a provider's
#: error message) before it is persisted or re-raised: ``text -> clean text``.
Redactor = Callable[[str], str]

#: Request headers whose values are caller credentials: ``Authorization`` and any
#: header named like ``X-<Provider>-Key`` / ``-Token`` / ``-Secret`` / ``-Password``
#: (``X-Elevenlabs-Key``, ``X-Fal-Key``, ``X-Api-Key``...), so a new BYO-key header is
#: covered without an edit here.
SECRET_HEADER_PATTERN = re.compile(
    r"^(proxy-)?authorization$|(^|-)(api-?key|key|token|secret|password)$",
    re.IGNORECASE,
)

#: Environment variables whose values are the HOST's own credentials (a connector's
#: provider keys): any name with a credential word as a whole ``_``-separated segment
#: (``ELEVENLABS_API_KEY``, ``FAL_KEY``, ``REELEE_MCP_DOWNLOAD_SECRET``, ``SHARED_PW_X``,
#: ``SMTP_PASS``, ``SENTRY_DSN``), so a new provider key is covered without an edit
#: here. ``PWD`` is not ``PW``.
SECRET_ENV_PATTERN = re.compile(
    r"(^|_)(api_?keys?|keys?|tokens?|secrets?|passwords?|passwd|pass|passphrase|pw|pat"
    r"|credentials?|creds|dsn|private_?key)(_|$)",
    re.IGNORECASE,
)

#: ...unless the name says the value is ABOUT a credential, not one (``S3_KEY_PREFIX``,
#: ``SSH_KEY_PATH``, ``TOKEN_URL``, ``AWS_ACCESS_KEY_ID``): redacting those would maul
#: every error that mentions an ordinary path or URL.
NOT_SECRET_ENV_SUFFIX = re.compile(
    r"_(prefix|path|file|dir|url|uri|id|name|type|header|ttl|seconds|size)$", re.IGNORECASE
)

#: A URL carrying a password in its userinfo (``DATABASE_URL=postgres://u:pw@h/db``):
#: redacted whatever the variable is called.
URL_WITH_PASSWORD = re.compile(r"://[^/@\s:]+:[^/@\s]+@")

#: Shorter header/env values are not redacted: no credential is that short, and
#: replacing a two-character value would maul every error text it happens to occur in.
MIN_SECRET_CHARS = 8

#: What a failed call's error becomes when the redactor itself fails: the text is
#: withheld rather than persisted unredacted (fail closed).
REDACTION_FAILED = "<error text withheld: redaction failed>"


#: The named escapes ``repr()`` and JSON write for control characters.
_NAMED_ESCAPES = {"\n": "n", "\r": "r", "\t": "t", "\b": "b", "\f": "f"}

#: How many stacked layers of escaping a quoted secret is still recognised under
#: (JSON body, embedded with ``!r``, in ``repr(exc)``, is three). Each layer
#: doubles a backslash, so this bounds every backslash run the matcher accepts,
#: which keeps matching linear on a hostile text full of backslashes.
ESCAPE_LAYERS = 4
_MAX_RUN = 2**ESCAPE_LAYERS  # backslashes one original backslash can become


_LOWER_HEX_ESCAPE = re.compile(r"%[0-9A-F]{2}")


def _escape_codes(c: str) -> list[str]:
    """How an escape writes *c* after its backslashes: named (``n``) or hex."""
    code = ord(c)
    codes = [_NAMED_ESCAPES[c]] if c in _NAMED_ESCAPES else []
    if code < 0x100:
        codes.append(f"x(?i:{code:02x})")
    codes.append(f"u(?i:{code:04x})" if code < 0x10000 else f"U(?i:{code:08x})")
    return codes


def _atom(backslashes: int, c: str = "") -> str:
    r"""A regex for *backslashes* backslashes of the secret followed by *c*.

    The backslash run and the character after it are ONE atom with ONE bounded
    quantifier: two quantifiers side by side could split a run of backslashes
    between them in many ways, and that multiplies across the secret. Each
    original backslash becomes up to :data:`_MAX_RUN` of them; a character
    other than an ASCII letter or digit may follow up to ``_MAX_RUN - 1`` more
    (each ``repr()`` layer doubles them; JSON escapes ``"`` and, in some
    serialisers, ``/``), or be written as a named or hex escape (``\n``,
    ``\x01``, ``\u00e9``).
    """
    k, top = backslashes, backslashes * _MAX_RUN
    if not c:
        return rf"\\{{{k},{top}}}"
    if c.isascii() and c.isalnum():
        return (rf"\\{{{k},{top}}}" if k else "") + c
    top += _MAX_RUN - 1
    codes = "|".join(_escape_codes(c))
    return rf"(?:\\{{{k},{top}}}{re.escape(c)}|\\{{{k + 1},{top}}}(?:{codes}))"


@lru_cache(maxsize=1024)
def escape_tolerant_pattern(secret: str) -> re.Pattern:
    r"""A pattern matching *secret* raw or escaped, up to :data:`ESCAPE_LAYERS` deep.

    Text that quotes a secret has often escaped it, sometimes more than once: a
    provider's JSON error body, embedded with ``!r`` in an exception message,
    then ``repr()`` of that exception in a ledger row. Matching each escape
    layer by layer always misses the next one, so this matches every layer at
    once. Every backslash run is bounded and owned by one atom (:func:`_atom`),
    so the match cannot backtrack super-linearly however many backslashes the
    text holds. Not matched: a character outside the Basic Multilingual Plane
    written as a JSON surrogate pair, and a backslash of the secret written as a
    hex code (``\x5c``), which neither ``repr()`` nor JSON produces.

    >>> p = escape_tolerant_pattern('pa"ss/wd')
    >>> [bool(p.search(t)) for t in ('pa"ss/wd', r'"pa\"ss\/wd"', r"'pa\\\"ss/wd'")]
    [True, True, True]
    """
    atoms, backslashes = [], 0
    for c in secret:
        if c == "\\":
            backslashes += 1
        else:
            atoms.append(_atom(backslashes, c))
            backslashes = 0
    if backslashes:
        atoms.append(_atom(backslashes))
    return re.compile("".join(atoms))


def _http_headers() -> dict[str, str]:
    """All headers of the in-flight HTTP request (lowercased names), or ``{}``."""
    try:
        from fastmcp.server.dependencies import get_http_headers

        return get_http_headers(include_all=True)
    except Exception:  # noqa: BLE001 — no HTTP request in flight (stdio, tests)
        return {}


def _environ() -> Mapping[str, str]:
    return os.environ


#: A source of ``(secret, label)`` pairs, read each time a redactor runs.
SecretSource = Callable[[], Iterable[tuple[str, str]]]


def _header_secrets(
    headers: Mapping[str, str], header_pattern: re.Pattern
) -> Iterable[tuple[str, str]]:
    """``(value, header name)`` for each credential header, and its bare token
    (``Authorization: Bearer <token>``)."""
    for name, value in headers.items():
        if header_pattern.search(name):
            value = str(value).strip()
            label = name.lower()
            yield value, label
            if value:
                yield value.rsplit(None, 1)[-1], label


#: Credential header values of every metered call in flight, process-wide
#: (``(value, header name) -> number of calls carrying it``). A record logged
#: from a thread the call did not copy its context into cannot see the request's
#: headers, so the fallback redactor reads them here.
_INFLIGHT: dict[tuple[str, str], int] = {}
_INFLIGHT_LOCK = threading.Lock()
#: Immutable view of :data:`_INFLIGHT`, rebuilt under the lock, read without it.
_INFLIGHT_VIEW: tuple[tuple[str, str], ...] = ()


def inflight_request_secrets() -> tuple[tuple[str, str], ...]:
    """The credential header values of every metered call in flight right now.

    :class:`MeteringMiddleware` registers a call's values on entry and removes
    them on exit, so a redactor running outside the request's context (a raw
    ``threading.Thread``, an uncaught-exception hook) still knows them.
    """
    return _INFLIGHT_VIEW


def _register_inflight(pairs: Iterable[tuple[str, str]], delta: int) -> None:
    global _INFLIGHT_VIEW
    with _INFLIGHT_LOCK:
        for pair in pairs:
            count = _INFLIGHT.get(pair, 0) + delta
            if count > 0:
                _INFLIGHT[pair] = count
            else:
                _INFLIGHT.pop(pair, None)
        _INFLIGHT_VIEW = tuple(_INFLIGHT)


def _variants(value: str) -> Iterable[str]:
    """The forms a provider may quote a secret in: as is, URL-encoded, and each
    ``:``-separated part (fal keys are ``id:secret``). Each is matched however it
    was escaped (:func:`escape_tolerant_pattern`)."""
    yield value
    encoded = quote(value, safe="")
    yield encoded
    yield _LOWER_HEX_ESCAPE.sub(lambda m: m.group().lower(), encoded)
    yield from value.split(":")


@lru_cache(maxsize=256)
def _replacements(
    pairs: tuple[tuple[str, str], ...], min_chars: int
) -> tuple[tuple[re.Pattern, str], ...]:
    """``(pattern, mark)`` for every form of every secret, longest first, so one
    that contains another is never half-replaced. Cached: the secrets rarely change
    between two records, and building this is most of a redaction's cost."""
    found: dict[str, str] = {}
    for value, label in pairs:
        for form in _variants(value):
            if len(form) >= min_chars:
                found.setdefault(form, label)
    return tuple(
        (escape_tolerant_pattern(form), f"<redacted:{label}>")
        for form, label in sorted(found.items(), key=lambda kv: -len(kv[0]))
    )


def secret_redactor(
    *,
    header_pattern: Optional[re.Pattern] = SECRET_HEADER_PATTERN,
    env_pattern: Optional[re.Pattern] = SECRET_ENV_PATTERN,
    env_names: Iterable[str] = (),
    min_chars: int = MIN_SECRET_CHARS,
    headers: Callable[[], Mapping[str, str]] = _http_headers,
    environ: Callable[[], Mapping[str, str]] = _environ,
    inflight: SecretSource = inflight_request_secrets,
) -> Redactor:
    """A :data:`Redactor` that scrubs every secret this process can know about.

    Two sources, both read when the redactor is *called*:

    - the in-flight request's credential headers (names matching ``header_pattern``):
      a caller's bring-your-own key, replaced by ``<redacted:{header name}>`` (an
      ``Authorization: Bearer <token>`` value is redacted both whole and as its bare
      token). This is why it must run while the request is still in flight — inside
      the middleware's error handling, which is where :class:`MeteringMiddleware`
      calls it. Outside the request's context (a raw thread), the credential
      headers of every metered call in flight (``inflight``, by default
      :func:`inflight_request_secrets`) stand in for them;
    - the process environment (names matching ``env_pattern``, plus ``env_names``):
      the host's own provider keys, replaced by ``<redacted:env:{NAME}>``. Which
      variables hold secrets is worked out again only when the environment changes.

    Each secret is also matched URL-encoded and per ``:``-separated part, and every
    form however it was escaped (:func:`escape_tolerant_pattern`). All are
    replaced longest first, so one that contains another is never half-replaced.
    A provider that quotes only a truncated prefix is out of reach. ``None`` for a
    pattern turns that source off.

    >>> r = secret_redactor(
    ...     headers=lambda: {"x-fal-key": "fal-CALLER-123"},
    ...     environ=lambda: {"FAL_KEY": "fal-SERVER-456", "HOME": "/home/someone"},
    ... )
    >>> r("401: invalid key fal-CALLER-123 (fallback fal-SERVER-456) in /home/someone")
    '401: invalid key <redacted:x-fal-key> (fallback <redacted:env:FAL_KEY>) in /home/someone'
    """
    extra_names = frozenset(env_names)
    use_env = env_pattern is not None or bool(extra_names)
    env_cache: list = [None, ()]  # [snapshot of the environment, its secrets]

    def is_env_secret(name: str, value: str) -> bool:
        return name in extra_names or (
            env_pattern is not None
            and (
                (env_pattern.search(name) and not NOT_SECRET_ENV_SUFFIX.search(name))
                or URL_WITH_PASSWORD.search(value) is not None
            )
        )

    def env_secrets() -> tuple[tuple[str, str], ...]:
        env = environ()
        # ``os.environ`` decodes every item it yields, which costs far more than
        # the redaction itself; its raw store compares in microseconds.
        raw = getattr(env, "_data", None)
        current = raw if isinstance(raw, dict) else dict(env)
        cached_snapshot, cached = env_cache
        if current == cached_snapshot:
            return cached
        snapshot = dict(current)  # taken before reading, so a change re-runs this
        found = []
        for name, value in env.items():
            value = str(value).strip()
            if is_env_secret(name, value):
                found.append((value, f"env:{name}"))
        env_cache[:] = [snapshot, tuple(found)]
        return env_cache[1]

    def candidates() -> tuple[tuple[str, str], ...]:
        pairs: list[tuple[str, str]] = []
        if header_pattern is not None:
            pairs.extend(_header_secrets(headers(), header_pattern))
            pairs.extend(inflight())
        if use_env:
            pairs.extend(env_secrets())
        return tuple(pairs)

    def redact(text: str) -> str:
        for pattern, mark in _replacements(candidates(), min_chars):
            text = pattern.sub(lambda _m: mark, text)
        return text

    return redact


def request_secret_redactor(
    *,
    header_pattern: re.Pattern = SECRET_HEADER_PATTERN,
    min_chars: int = MIN_SECRET_CHARS,
    headers: Callable[[], Mapping[str, str]] = _http_headers,
) -> Redactor:
    """A :data:`Redactor` for the in-flight request's credential headers only.

    :func:`secret_redactor` with the environment source off (kept for callers that
    want exactly that; the middleware's default also covers the environment).

    >>> r = request_secret_redactor(headers=lambda: {"x-fal-key": "fal-SECRET-123"})
    >>> r("fal 401: invalid key fal-SECRET-123")
    'fal 401: invalid key <redacted:x-fal-key>'
    >>> r("nothing to hide")
    'nothing to hide'
    """
    return secret_redactor(
        header_pattern=header_pattern, env_pattern=None, min_chars=min_chars,
        headers=headers,
    )


#: The in-flight request's credential headers only (see :func:`request_secret_redactor`).
redact_request_secrets: Redactor = request_secret_redactor()

#: The default :data:`Redactor`: the request's credential headers AND the host's own
#: credential env vars (see :func:`secret_redactor`).
redact_secrets: Redactor = secret_redactor()


def _redact_safely(redact: Redactor, text: str) -> str:
    """``redact(text)``, or :data:`REDACTION_FAILED` if the redactor fails.

    A redactor that raises or returns a non-string has failed: the text is
    withheld rather than persisted or re-raised unredacted.
    """
    try:
        clean = redact(text)
    except Exception:  # noqa: BLE001 — never persist or re-raise unredacted text
        clean = None
    if not isinstance(clean, str):
        _logger.warning("enlace_metering: redactor failed; error text withheld")
        return REDACTION_FAILED
    return clean


def _renderings(exc: BaseException):
    """Every text ``exc`` can render: str, repr and notes, down its whole chain.

    A traceback printer walks ``__cause__``/``__context__`` and prints notes, so a
    secret anywhere in there escapes with the exception even when its own message
    is clean (``ToolError("Error calling tool") from <dirty>`` under fastmcp's
    ``mask_error_details``).
    """
    try:  # the printer's own view: ExceptionGroup members, their notes and causes
        yield "".join(traceback.format_exception(exc))
    except Exception:  # noqa: BLE001
        pass
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        for render in (str, repr):
            try:
                yield render(exc)
            except Exception:  # noqa: BLE001 — an unrenderable link renders nothing
                pass
        for note in getattr(exc, "__notes__", None) or ():
            yield str(note)
        exc = exc.__cause__ or exc.__context__


def _scrubbed_exception(
    exc: BaseException, redact: Redactor
) -> Optional[BaseException]:
    """A stand-in for ``exc`` that renders no secret, or ``None`` if ``exc`` is clean.

    Rebuilt as ``type(exc)(clean_text)`` so a caller classifying on the type still
    can; falls back to :class:`ToolError` when the type will not construct that way
    or still renders something the redactor would change. The stand-in carries no
    cause/context chain (the caller raises it outside the ``except``), since the
    original — and whatever it chained — is exactly what must not escape.
    """
    if all(_redact_safely(redact, t) == t for t in _renderings(exc)):
        return None
    try:
        text = str(exc)
    except Exception:  # noqa: BLE001
        text = type(exc).__name__
    clean = _redact_safely(redact, text)
    try:
        new = type(exc)(clean)
        if str(new) != clean:
            raise TypeError("rebuilt exception renders differently")
    except Exception:  # noqa: BLE001 — typed fallback
        new = ToolError(clean)
    if hasattr(exc, "log_level"):  # fastmcp's ToolError carries its own log level
        try:
            new.log_level = exc.log_level
        except Exception:  # noqa: BLE001 — cosmetic
            pass
    notes = getattr(exc, "__notes__", None)
    if notes:
        new.__notes__ = [_redact_safely(redact, str(n)) for n in notes]
    return new


#: The redactor of the metered call in flight, for :func:`redact_log_record`. Unset
#: outside a call, where it falls back to :data:`redact_secrets`.
_CURRENT_REDACTOR: ContextVar[Optional[Redactor]] = ContextVar(
    "enlace_metering_redactor", default=None
)
#: Set while :func:`redact_log_record` runs (the re-entrancy guard).
_REDACTING_RECORD: ContextVar[bool] = ContextVar(
    "enlace_metering_redacting_record", default=False
)
#: Records the installed record factory has already redacted, with what it left
#: in them, so a :class:`RedactingLogFilter` on their handler only redacts their
#: ``extra=`` fields (set after the factory ran) rather than the whole record
#: again, unless something was put in after the factory (``makeLogRecord``).
_FACTORY_REDACTED: "weakref.WeakKeyDictionary[logging.LogRecord, tuple]" = (
    weakref.WeakKeyDictionary()
)


def _fingerprint(record: logging.LogRecord) -> tuple:
    return (record.msg, record.args, record.exc_info, record.stack_info)


def _unchanged_since_factory(record: logging.LogRecord) -> bool:
    try:
        before = _FACTORY_REDACTED.get(record)
    except TypeError:
        return False
    return before is not None and all(
        a is b for a, b in zip(before, _fingerprint(record))
    )

#: The marker every hook and factory this module installs carries (idempotence).
_MARK = "_enlace_metering_redacting"


def _current_redactor() -> Redactor:
    """The in-flight call's redactor, else :data:`redact_secrets` (read late, so a
    replaced module attribute is honoured)."""
    return _CURRENT_REDACTOR.get() or redact_secrets


def _withhold(record: logging.LogRecord) -> None:
    record.msg, record.args = REDACTION_FAILED, None
    record.exc_info = record.exc_text = record.stack_info = None


def redact_log_record(record: logging.LogRecord) -> None:
    """Redact ``record`` in place: message, arguments, traceback, stack and
    ``extra=`` fields, with the in-flight call's redactor (so it still sees the
    request's headers), else :data:`redact_secrets`.

    A dirty argument is replaced by its redacted text and the rest of
    ``record.args`` keeps its shape (formatters such as uvicorn's access log
    unpack it); a dirty traceback is replaced by its redacted text. If redaction
    fails, the record's text is withheld. A record logged *while* a record is
    being redacted (by a host redactor, say) cannot be redacted in turn, so its
    text is withheld too, except this module's own fixed-text warning. Never
    raises (it runs inside the caller's logging call) and never drops a record.
    """
    if _REDACTING_RECORD.get():
        if record.name != _logger.name:
            _withhold(record)
        return
    _redact_guarded(record, extras=True)


def _redact_guarded(record: logging.LogRecord, *, extras: bool) -> None:
    token = _REDACTING_RECORD.set(True)
    try:
        _redact_log_record(record, extras=extras)
    finally:
        _REDACTING_RECORD.reset(token)


def _redact_log_record(record: logging.LogRecord, *, extras: bool) -> None:
    redact = _current_redactor()
    try:
        message = record.getMessage()
        tb = (
            "".join(traceback.format_exception(*record.exc_info))
            if record.exc_info and record.exc_info[0] is not None
            else ""
        )
        stack = record.stack_info or ""
        clean_message = _redact_safely(redact, message)
        if clean_message is REDACTION_FAILED:
            _withhold(record)
            return
        clean_tb = _redact_safely(redact, tb) if tb else ""
        clean_stack = _redact_safely(redact, stack) if stack else ""
        if clean_message != message:
            _redact_message(record, redact, clean_message)
        if clean_tb != tb:
            tail = "\n" + clean_tb.rstrip()
            if record.args:  # the traceback text goes through %-formatting too
                tail = tail.replace("%", "%%")
            record.msg = f"{record.msg}{tail}"
            record.exc_info, record.exc_text = None, None
        if clean_stack != stack:
            record.stack_info = clean_stack
        if extras:
            _redact_extra_fields(record, redact)
    except Exception:  # noqa: BLE001 — never break the caller's logging call
        _withhold(record)


def _redact_message(
    record: logging.LogRecord, redact: Redactor, clean_message: str
) -> None:
    """Redact ``record.msg`` and each of ``record.args``, keeping the shape of
    ``args``; if what that renders is still not clean (a secret split across two
    arguments, a format that rejects the redacted text), fall back to the whole
    rendered message with no arguments."""
    msg = record.msg
    text = msg if isinstance(msg, str) else str(msg)
    clean = _redact_safely(redact, text)
    if clean != text:
        record.msg = clean
    args = record.args
    try:
        if isinstance(args, tuple):
            record.args = tuple(_redact_arg(a, redact) for a in args)
        elif isinstance(args, Mapping):
            record.args = {k: _redact_arg(v, redact) for k, v in args.items()}
        elif args:
            raise TypeError("unrecognised record.args")
        rendered = record.getMessage()
        if _redact_safely(redact, rendered) != rendered:
            raise ValueError("still dirty")
    except Exception:  # noqa: BLE001 — fall back to the redacted rendering
        record.msg, record.args = clean_message, None


def _redact_arg(value: Any, redact: Redactor) -> Any:
    """A log argument with no secret in it: unchanged if clean, else its redacted
    text (``str`` and ``repr`` are both checked, for ``%s`` and ``%r``)."""
    if isinstance(value, _INERT_TYPES):
        return value
    if isinstance(value, str):
        return _redact_safely(redact, value)
    text = str(value)
    clean = _redact_safely(redact, text)
    if clean != text:
        return clean
    shown = repr(value)
    clean = _redact_safely(redact, shown)
    return value if clean == shown else clean


#: The attributes every ``LogRecord`` has; anything else came from ``extra=``.
_STANDARD_RECORD_ATTRS = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__
) | {"message", "asctime"}

#: Values that cannot carry a secret, so ``extra=`` fields of these types are kept.
_INERT_TYPES = (bool, int, float, type(None))


def _redact_extra_fields(record: logging.LogRecord, redact: Redactor) -> None:
    """Redact the fields a caller passed with ``extra=`` (in place).

    A plain-text formatter never shows them, but a JSON handler emits every one,
    and provider SDKs pass things like the request ``url`` this way. ``logging``
    sets them *after* the record factory has run, so the factory installed by
    :func:`install_log_redaction` cannot see them: attach
    :class:`RedactingLogFilter` to any handler that emits them. A field whose
    text the redactor would change is replaced by the redacted text (so a URL
    object becomes a string); a clean field keeps its type; a field that cannot
    be rendered is withheld on its own.
    """
    for key, value in list(record.__dict__.items()):
        if key in _STANDARD_RECORD_ATTRS or isinstance(value, _INERT_TYPES):
            continue
        try:
            text = value if isinstance(value, str) else str(value)
            clean = _redact_safely(redact, text)
        except Exception:  # noqa: BLE001 — withhold this field, not the record
            clean, text = REDACTION_FAILED, None
        if clean != text:
            setattr(record, key, clean)


class RedactingLogFilter(logging.Filter):
    """:func:`redact_log_record` as a filter, for a host's own loggers or handlers
    (e.g. a connector's package logger that logs provider errors, or a JSON
    handler that emits ``extra=`` fields)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if _unchanged_since_factory(record):
            # Message and traceback already redacted; extra= came after.
            if not _REDACTING_RECORD.get():
                token = _REDACTING_RECORD.set(True)
                try:
                    _redact_extra_fields(record, _current_redactor())
                except Exception:  # noqa: BLE001
                    _withhold(record)
                finally:
                    _REDACTING_RECORD.reset(token)
        else:
            redact_log_record(record)
        return True


#: The loggers a failing tool's traceback is written to before the middleware sees
#: it: fastmcp's whole namespace (3.4.5 logs from ``fastmcp.server.server``, 4.x from
#: ``fastmcp.tools.base``).
LOG_NAMESPACES = ("fastmcp",)

#: Pass as ``namespaces`` (or a middleware's ``redact_logs``) to redact every
#: record in the process: the root logger, provider SDKs (``httpx``,
#: ``fal_client``, ElevenLabs' ``fern``), ``uvicorn.error``, ``asyncio``, and
#: ``warnings.warn``. See :func:`install_log_redaction`.
ALL_LOGGERS = "*"

#: The namespaces whose records the installed record factory redacts (grows only).
_REDACTED_NAMESPACES: set[str] = set()

#: The one filter :func:`install_log_redaction` attaches to existing handlers.
_HANDLER_FILTER = RedactingLogFilter()


def install_log_redaction(
    *, namespaces: Union[str, Iterable[str]] = LOG_NAMESPACES
) -> None:
    """Redact log records created under ``namespaces`` from now on, or every one.

    Wraps the process's ``LogRecordFactory`` (chained, installed once), so it
    covers loggers created *later* too — fastmcp 4.x creates the one that writes
    the tool traceback lazily — and whatever handler the host configures. Calling
    again only widens what is covered.

    ``namespaces=ALL_LOGGERS`` (``"*"``) covers every record in the process. It
    also redacts what ``warnings.warn`` shows (wrapping ``warnings.showwarning``,
    so a warning still goes where it went before), what an uncaught exception
    prints in the main thread or any other, and what an exception ignored in a
    ``__del__`` prints (``sys.unraisablehook``); and it attaches
    :class:`RedactingLogFilter` to every handler that exists at that point
    (``logging.lastResort`` included), which covers ``extra=`` fields and records
    that never went through the factory (``logging.makeLogRecord``, a logger
    class with its own ``makeRecord``). Call it as the first statement of a
    connector's ``server.py`` to cover records logged at import time too; a
    middleware constructed later only covers what follows it. The cost is one
    redaction per *emitted* record (records below the level are never created).

    >>> install_log_redaction(namespaces="*")  # doctest: +SKIP
    """
    if isinstance(namespaces, str):
        # A bare string is one namespace, not an iterable of one-letter ones.
        namespaces = (namespaces,)
    _REDACTED_NAMESPACES.update(namespaces)
    if ALL_LOGGERS in _REDACTED_NAMESPACES:
        _install_redacting_showwarning()
        _install_redacting_excepthooks()
        _filter_existing_handlers()
    previous = logging.getLogRecordFactory()
    if getattr(previous, _MARK, False):
        return

    def factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        name = record.name
        if ALL_LOGGERS in _REDACTED_NAMESPACES or any(
            name == ns or name.startswith(ns + ".") for ns in _REDACTED_NAMESPACES
        ):
            # extra= fields are set after the factory returns: none to redact yet.
            if _REDACTING_RECORD.get():
                redact_log_record(record)  # the nested-record rule
            else:
                _redact_guarded(record, extras=False)
            try:
                _FACTORY_REDACTED[record] = _fingerprint(record)
            except TypeError:  # a record type that takes no weak reference
                pass
        return record

    setattr(factory, _MARK, True)
    logging.setLogRecordFactory(factory)


def _filter_existing_handlers() -> None:
    """Attach :data:`_HANDLER_FILTER` to every live handler and to
    ``logging.lastResort`` (once each)."""
    refs = list(getattr(logging, "_handlerList", ()))
    handlers = [ref() for ref in refs] + [logging.lastResort]
    for handler in handlers:
        if handler is None:
            continue
        try:
            if not any(isinstance(f, RedactingLogFilter) for f in handler.filters):
                handler.addFilter(_HANDLER_FILTER)
        except Exception:  # noqa: BLE001 — a handler without filters is skipped
            pass


def _write_stderr(text: str) -> None:
    """Write to ``sys.stderr`` if there is one (there may be none at shutdown)."""
    err = sys.stderr
    if err is None:
        return
    try:
        err.write(text)
    except Exception:  # noqa: BLE001
        pass


def _printed(exc_type, exc, tb) -> str:
    return "".join(traceback.format_exception(exc_type, exc, tb))


def _safe_exc_info(exc_type, exc, tb) -> Optional[tuple]:
    """``(exc_type, exc, tb)`` itself if it prints no secret, else a stand-in that
    prints redacted (the exception rebuilt by :func:`_scrubbed_exception`, with the
    traceback dropped if its own text is dirty), or ``None`` if there is none."""
    redact = _current_redactor()

    def clean(t, e, b) -> bool:
        text = _printed(t, e, b)
        return _redact_safely(redact, text) == text

    if clean(exc_type, exc, tb):
        return exc_type, exc, tb
    if not isinstance(exc, BaseException):
        return None
    stand_in = _scrubbed_exception(exc, redact) or exc
    for b in (tb, None):
        if clean(type(stand_in), stand_in, b):
            return type(stand_in), stand_in, b
    return None


def _redacted_print(exc_type, exc, tb) -> str:
    """What an exception prints, redacted (or withheld if that fails)."""
    try:
        return _redact_safely(_current_redactor(), _printed(exc_type, exc, tb))
    except Exception:  # noqa: BLE001
        return REDACTION_FAILED + "\n"


def _install_redacting_excepthooks() -> None:
    """Redact what an uncaught exception prints (``sys.excepthook``,
    ``threading.excepthook``) and what an exception ignored in ``__del__`` prints
    (``sys.unraisablehook``). Each is wrapped once.

    These write straight to stderr, not through logging. A clean exception is
    handed to the previous hook unchanged; a dirty one is handed to it as a
    stand-in that prints redacted (so a crash reporter still sees it), or, if
    there is none or the previous hook fails on it, written redacted here.
    """
    if not getattr(sys.excepthook, _MARK, False):
        _wrap_sys_excepthook(sys.excepthook)
    if not getattr(threading.excepthook, _MARK, False):
        _wrap_thread_excepthook(threading.excepthook)
    if not getattr(sys.unraisablehook, _MARK, False):
        _wrap_unraisablehook(sys.unraisablehook)


def _wrap_sys_excepthook(previous) -> None:
    def sys_hook(exc_type, exc, tb):
        try:
            safe = _safe_exc_info(exc_type, exc, tb)
        except Exception:  # noqa: BLE001
            safe = None
        if safe is not None and safe[1] is exc and safe[2] is tb:
            return previous(exc_type, exc, tb)
        if safe is not None:
            try:
                return previous(*safe)
            except Exception:  # noqa: BLE001 — never let the original be printed
                pass
        _write_stderr(_redacted_print(exc_type, exc, tb))

    setattr(sys_hook, _MARK, True)
    sys.excepthook = sys_hook


def _wrap_thread_excepthook(previous) -> None:
    def thread_hook(args):
        if args.exc_type is SystemExit:
            return previous(args)
        exc_type, exc, tb = args.exc_type, args.exc_value, args.exc_traceback
        try:
            safe = _safe_exc_info(exc_type, exc, tb)
        except Exception:  # noqa: BLE001
            safe = None
        if safe is not None and safe[1] is exc and safe[2] is tb:
            return previous(args)
        thread = getattr(args, "thread", None)
        if safe is not None:
            try:
                return previous(type(args)((*safe, thread)))
            except Exception:  # noqa: BLE001
                pass
        name = getattr(thread, "name", None) or "<unknown>"
        _write_stderr(f"Exception in thread {name}:\n{_redacted_print(exc_type, exc, tb)}")

    setattr(thread_hook, _MARK, True)
    threading.excepthook = thread_hook


class _RedactedRepr:
    """Stands in for an object whose ``repr`` would print a secret."""

    __slots__ = ("text",)

    def __init__(self, text: str):
        self.text = text

    def __repr__(self) -> str:
        return self.text


def _wrap_unraisablehook(previous) -> None:
    def unraisable_hook(unraisable):
        redact = _current_redactor()
        exc_type, exc, tb = (
            unraisable.exc_type, unraisable.exc_value, unraisable.exc_traceback
        )
        err_msg, obj = unraisable.err_msg, unraisable.object
        shown, clean_shown, clean_msg, safe = "", "", REDACTION_FAILED, None
        try:
            try:
                shown = repr(obj) if obj is not None else ""
            except Exception:  # noqa: BLE001 — the default hook copes with this
                shown = ""
            clean_shown = _redact_safely(redact, shown) if shown else ""
            clean_msg = _redact_safely(redact, err_msg) if err_msg else err_msg
            safe = (
                _safe_exc_info(exc_type, exc, tb)
                if exc_type is not None
                else (exc_type, exc, tb)
            )
        except Exception:  # noqa: BLE001
            safe = None
        if safe is not None and safe[1] is exc and safe[2] is tb and (
            clean_shown == shown and clean_msg == err_msg
        ):
            return previous(unraisable)
        if safe is not None:
            stand_in_obj = obj if clean_shown == shown else _RedactedRepr(clean_shown)
            try:
                return previous(type(unraisable)((*safe, clean_msg, stand_in_obj)))
            except Exception:  # noqa: BLE001
                pass
        text = f"{clean_msg or 'Exception ignored in'}: {clean_shown}\n"
        if exc_type is not None:
            text += _redacted_print(exc_type, exc, tb)
        _write_stderr(text)

    setattr(unraisable_hook, _MARK, True)
    sys.unraisablehook = unraisable_hook


def _install_redacting_showwarning() -> None:
    """Redact what ``warnings.warn`` shows, by wrapping ``warnings.showwarning``
    (once): a clean warning is handed on unchanged, a dirty one with its message,
    file name and source line redacted, so it still goes where it went before
    (stderr, or the ``py.warnings`` logger under ``logging.captureWarnings``)."""
    previous = warnings.showwarning
    if getattr(previous, _MARK, False):
        return

    def showwarning(message, category, filename, lineno, file=None, line=None):
        redact = _current_redactor()
        try:
            shown_line = line
            if shown_line is None:  # what formatwarning would read
                shown_line = linecache.getline(filename, lineno) or ""
            parts = (str(message), str(filename), shown_line)
            clean = tuple(_redact_safely(redact, part) for part in parts)
        except Exception:  # noqa: BLE001
            parts, clean = (None,), (REDACTION_FAILED, "<withheld>", "")
        if clean == parts:
            return previous(message, category, filename, lineno, file, line)
        clean_message, clean_filename, clean_line = clean
        try:
            clean_message = category(clean_message)
        except Exception:  # noqa: BLE001 — a category that will not take text
            pass
        return previous(
            clean_message, category, clean_filename, lineno, file, clean_line or ""
        )

    setattr(showwarning, _MARK, True)
    warnings.showwarning = showwarning


def token_email() -> Optional[str]:
    """The verified caller's email from the OAuth token (``email`` claim, else ``sub``).

    Lowercased, or ``None`` when there is no request/token context — deliberately **no
    fallback**, so a caller is failed closed rather than handed a shared identity.
    """
    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
    except Exception:  # noqa: BLE001 — no active request/token context
        return None
    if token is None:
        return None
    claims = getattr(token, "claims", None) or {}
    ident = claims.get("email") or claims.get("sub")
    return str(ident).lower() if ident else None


def current_email() -> str:
    """The identity the middleware resolved for the in-flight call (SSOT for tools).

    Raises if called outside a metered tool call — a tool must never run, or place
    data, under an unauthenticated/unknown identity.
    """
    email = _CURRENT_EMAIL.get()
    if not email:
        raise ToolError("no caller identity in context (metering middleware inactive)")
    return email


def _default_extract_cost(result: Any) -> Optional[float]:
    """Read the actual spend from a tool result's ``structured_content``.

    Tries :data:`COST_KEYS` in order, so it meters connectors that emit either
    ``cost_usd_actual`` (reelee) or ``cost_usd`` (braidio) with no override.
    """
    out = getattr(result, "structured_content", None)
    if isinstance(out, dict):
        for key in COST_KEYS:
            cost = out.get(key)
            if isinstance(cost, (int, float)):
                return float(cost)
    return None


#: Characters allowed in the tool slug embedded in a ledger entry id. The tool name in
#: a ``tools/call`` is client-supplied and reaches the middleware *before* the tool is
#: resolved, so it must never flow verbatim into a storage key.
_TOOL_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]")

#: Cap on the tool slug so a pathological name can't produce an unwritable key.
_TOOL_SLUG_MAX = 64


def _tool_slug(tool: Optional[str]) -> str:
    """A key-safe slug for a client-supplied tool name (the raw name is still recorded).

    The ledger entry id is ``{ns}-{seq}-{slug}`` and the ledger key embeds that id, so
    an unresolved/hostile name like ``../../etc/x`` must not reach the store. Anything
    outside ``[A-Za-z0-9._-]`` becomes ``_``; the raw name stays in the entry's
    ``tool`` field, so the audit trail is unchanged.
    """
    return _TOOL_SLUG_RE.sub("_", str(tool) if tool is not None else "unknown")[
        :_TOOL_SLUG_MAX
    ]


class MeteringMiddleware(Middleware):
    """FastMCP middleware: authorize the caller, gate on usage policy, meter the call.

    Args:
        ledger: the durable :class:`~enlace_metering.ledger.UsageLedger`.
        policy: the :data:`~enlace_metering.policy.GatePolicy` to enforce (default
            :func:`~enlace_metering.policy.unlimited` — record only). Use a per-principal
            policy for tiered plans.
        allowed: authorized email set (defense-in-depth over the platform allowlist).
        local_user: an explicit identity for local/stdio dev (never inferred).
        allow_any_authenticated: permit any token-authenticated caller when no
            ``allowed`` set is given (still gated by ``policy``).
        estimate_cost: optional proposed-cost estimator for forward-looking gating.
        extract_cost: pull actual ``cost_usd`` from a tool result (default reads
            ``structured_content['cost_usd']``).
        metered_tools: when given, only these tools are gated (others are recorded,
            never denied); ``None`` gates every tool.
        redact: the :data:`Redactor` applied to a failed call's error text before it
            is written to the ledger and re-raised (default :data:`redact_secrets`:
            the in-flight request's credential headers and the host's credential
            env vars). Build one with :func:`secret_redactor` (e.g. ``env_names=``)
            when a secret arrives another way. The same redactor is installed on
            fastmcp's log records (:func:`install_log_redaction`), which carry a
            failing tool's traceback before this middleware sees it. The default,
            ``redact_logs=ALL_LOGGERS`` (``"*"``), covers every logger in the
            process, ``warnings.warn`` and uncaught exceptions (see
            :func:`install_log_redaction`). Logger namespaces
            (``redact_logs=("braidio",)``) limit it to fastmcp plus those;
            ``True`` to fastmcp alone; ``False`` opts out.
    """

    def __init__(
        self,
        ledger: UsageLedger,
        *,
        policy: Optional[GatePolicy] = None,
        allowed: Optional[set[str]] = None,
        local_user: Optional[str] = None,
        allow_any_authenticated: bool = False,
        estimate_cost: Optional[CostEstimator] = None,
        extract_cost: Optional[CostExtractor] = None,
        metered_tools: Optional[set[str]] = None,
        redact: Optional[Redactor] = None,
        redact_logs: Union[bool, str, Iterable[str]] = ALL_LOGGERS,
    ):
        self.ledger = ledger
        self.policy: GatePolicy = policy or unlimited()
        self.allowed = {e.lower() for e in allowed} if allowed is not None else None
        self.local_user = local_user.lower() if local_user else None
        self.allow_any = allow_any_authenticated
        self.estimate_cost = estimate_cost
        self.extract_cost = extract_cost or _default_extract_cost
        # When given, only these tools are GATED by the policy; others are still
        # recorded but never denied — so a principal who hit their cap can still call
        # free/read-only tools (list/get/help) to retrieve what they already made.
        # ``None`` gates every tool.
        self.metered_tools = set(metered_tools) if metered_tools is not None else None
        self.redact: Redactor = redact or redact_secrets
        if redact_logs:
            if redact_logs is True:
                namespaces = LOG_NAMESPACES
            elif isinstance(redact_logs, str):
                namespaces = (*LOG_NAMESPACES, redact_logs)
            else:
                namespaces = (*LOG_NAMESPACES, *redact_logs)
            install_log_redaction(namespaces=namespaces)
        self._seq = itertools.count()

    def _authorize(self) -> str:
        """Resolve the caller (fail-closed) and check authorization. Returns the email."""
        email = token_email()
        if email is None:
            if self.local_user is None:
                raise ToolError("authentication required")
            email = self.local_user
        try:
            email = safe_principal(email)
        except ValueError as exc:
            raise ToolError(f"invalid caller identity: {exc}") from exc
        if self.allowed is not None:
            if email not in self.allowed:
                raise ToolError(f"{email!r} is not authorized to use this server")
        elif not (self.local_user or self.allow_any):
            raise ToolError(
                "server has no allowlist and allow_any_authenticated is off — "
                "refusing (configure `allowed` or pass allow_any_authenticated=True)"
            )
        return email

    async def on_call_tool(self, context, call_next):
        email = self._authorize()
        token = _CURRENT_EMAIL.set(email)
        redactor = _CURRENT_REDACTOR.set(self.redact)
        # Known process-wide for the call's duration, so a record logged from a
        # thread that did not copy this context is still redacted of them.
        secrets = tuple(_header_secrets(_http_headers(), SECRET_HEADER_PATTERN))
        _register_inflight(secrets, +1)
        try:
            return await self._gate_and_meter(context, call_next, email)
        finally:
            _register_inflight(secrets, -1)
            _CURRENT_REDACTOR.reset(redactor)
            _CURRENT_EMAIL.reset(token)

    async def _gate_and_meter(self, context, call_next, email: str):
        tool = getattr(context.message, "name", None)
        args = getattr(context.message, "arguments", None) or {}
        now = datetime.now(timezone.utc)

        # Gate BEFORE spending — but only metered tools (when a set is configured);
        # free/read-only tools are recorded, never denied. A proposed-cost estimate
        # makes the gate forward-looking; otherwise the policy blocks on already-
        # accumulated usage.
        proposed = None
        if self.metered_tools is None or tool in self.metered_tools:
            if self.estimate_cost is not None:
                try:
                    proposed = self.estimate_cost(tool, args)
                except Exception:  # noqa: BLE001 — a bad estimate must not crash the gate
                    proposed = None
            decision = self.policy(
                GateRequest(
                    principal=email,
                    ledger=self.ledger,
                    now=now,
                    proposed_cost_usd=proposed,
                    tool=tool,
                )
            )
            if not decision.allow:
                raise ToolError(f"usage limit reached: {decision.reason}")

        t0 = time.time_ns()
        entry = {
            "id": f"{t0}-{next(self._seq)}-{_tool_slug(tool)}",
            "principal": email,
            "month": now.strftime("%Y-%m"),
            "ts": now.isoformat(),
            "tool": tool,
            "status": "started",
            "proposed_cost_usd": proposed,
        }
        # Write-ahead: refuse if we can't even record that it started — a costed call
        # must never spend on a shared key with no recoverable trace.
        try:
            self.ledger.record(entry)
        except Exception as exc:  # noqa: BLE001
            raise ToolError(
                "usage ledger unavailable; refusing to run to avoid untracked spend"
            ) from exc

        scrubbed: Optional[BaseException] = None
        try:
            result = await call_next(context)
            entry["cost_usd"] = self.extract_cost(result)
            out = getattr(result, "structured_content", None)
            if isinstance(out, dict):
                for k in ("cache_hit_savings_usd", "characters", "cost_basis"):
                    if k in out:
                        entry[k] = out.get(k)
                entry["artifact_ref"] = out.get("url") or out.get("path")
            entry["status"] = "done"
            entry["elapsed_s"] = (time.time_ns() - t0) / 1e9
            return result
        except Exception as exc:  # noqa: BLE001 — record the failure, then re-raise
            entry["status"] = "error"
            # The row is persistent and a provider may quote the caller's key back in
            # its error — redact while the request (and so the key) is still in flight.
            try:
                rendered = repr(exc)
            except Exception:  # noqa: BLE001 — a broken __repr__ must not chain exc
                rendered = type(exc).__name__
            entry["error"] = _redact_safely(self.redact, rendered)
            entry["elapsed_s"] = (time.time_ns() - t0) / 1e9
            scrubbed = _scrubbed_exception(exc, self.redact)
            if scrubbed is None:
                raise
        finally:
            try:
                self.ledger.record(entry)
            except Exception:  # noqa: BLE001 — the write-ahead 'started' row is the trace
                # Don't crash the call over a metering update, but don't hide it either:
                # a lost 'done' row means this call's cost_usd is absent from the ledger,
                # so spend_since undercounts (a cap could later be crossed silently).
                _logger.warning(
                    "enlace_metering: ledger update failed for entry %s "
                    "(started row retained; its cost_usd will be missing)",
                    entry.get("id"),
                )
        # Only reached when the call failed with an error that quoted a secret: raised
        # outside the handler, so the dirty original is not its __context__.
        raise scrubbed from None


__all__ = [
    "MeteringMiddleware",
    "token_email",
    "current_email",
    "CostEstimator",
    "CostExtractor",
    "Redactor",
    "secret_redactor",
    "redact_secrets",
    "request_secret_redactor",
    "redact_request_secrets",
    "SECRET_HEADER_PATTERN",
    "SECRET_ENV_PATTERN",
    "RedactingLogFilter",
    "redact_log_record",
    "install_log_redaction",
    "inflight_request_secrets",
    "ALL_LOGGERS",
]
