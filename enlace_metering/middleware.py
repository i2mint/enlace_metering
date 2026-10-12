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
   provider can quote the caller's bring-your-own key back in its error (ElevenLabs
   does on a 401), and both the persistent ledger row and the re-raised exception
   (which the model sees) must not carry it.

This is the ``[mcp]`` layer (needs ``fastmcp``); the ledger + policy are pure and
import-free of it. Generalizes braidio's bespoke ``MeteringMiddleware`` (which only
recorded) by adding the policy gate + a proposed-cost estimate hook.
"""

from __future__ import annotations

import itertools
import logging
import re
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

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

#: Shorter header values are not redacted: no credential is that short, and replacing
#: a two-character value would maul every error text it happens to occur in.
MIN_SECRET_CHARS = 8

#: What a failed call's error becomes when the redactor itself fails: the text is
#: withheld rather than persisted unredacted (fail closed).
REDACTION_FAILED = "<error text withheld: redaction failed>"


def _http_headers() -> dict[str, str]:
    """All headers of the in-flight HTTP request (lowercased names), or ``{}``."""
    try:
        from fastmcp.server.dependencies import get_http_headers

        return get_http_headers(include_all=True)
    except Exception:  # noqa: BLE001 — no HTTP request in flight (stdio, tests)
        return {}


def request_secret_redactor(
    *,
    header_pattern: re.Pattern = SECRET_HEADER_PATTERN,
    min_chars: int = MIN_SECRET_CHARS,
    headers: Callable[[], Mapping[str, str]] = _http_headers,
) -> Redactor:
    """A :data:`Redactor` that scrubs the in-flight request's credential headers.

    Every value of a header whose name matches ``header_pattern`` is replaced by
    ``<redacted:{header name}>`` (an ``Authorization: Bearer <token>`` value is
    redacted both whole and as its bare token). Headers are read when the redactor
    is *called*, so it must run while the request is still in flight — inside the
    middleware's error handling, which is where :class:`MeteringMiddleware` calls it.

    >>> r = request_secret_redactor(headers=lambda: {"x-fal-key": "fal-SECRET-123"})
    >>> r("fal 401: invalid key fal-SECRET-123")
    'fal 401: invalid key <redacted:x-fal-key>'
    >>> r("nothing to hide")
    'nothing to hide'
    """

    def secrets() -> dict[str, str]:
        found: dict[str, str] = {}
        for name, value in headers().items():
            if not header_pattern.search(name):
                continue
            value = str(value).strip()
            for candidate in (value, value.rsplit(None, 1)[-1] if value else ""):
                if len(candidate) >= min_chars:
                    found.setdefault(candidate, name.lower())
        return found

    def redact(text: str) -> str:
        # Longest first, so a secret that contains another is not half-replaced.
        for value, name in sorted(secrets().items(), key=lambda kv: -len(kv[0])):
            text = text.replace(value, f"<redacted:{name}>")
        return text

    return redact


#: The default :data:`Redactor`: the in-flight request's credential headers.
redact_request_secrets: Redactor = request_secret_redactor()


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
            is written to the ledger and re-raised (default
            :data:`redact_request_secrets`: the in-flight request's credential
            headers). Compose with a host's own when its secrets arrive another way.
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
        self.redact: Redactor = redact or redact_request_secrets
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
        try:
            return await self._gate_and_meter(context, call_next, email)
        finally:
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
    "request_secret_redactor",
    "redact_request_secrets",
    "SECRET_HEADER_PATTERN",
]
