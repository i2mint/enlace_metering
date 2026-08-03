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
   + outcome.

This is the ``[mcp]`` layer (needs ``fastmcp``); the ledger + policy are pure and
import-free of it. Generalizes braidio's bespoke ``MeteringMiddleware`` (which only
recorded) by adding the policy gate + a proposed-cost estimate hook.
"""

from __future__ import annotations

import itertools
import logging
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
            "id": f"{t0}-{next(self._seq)}-{tool}",
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
            entry["error"] = repr(exc)
            entry["elapsed_s"] = (time.time_ns() - t0) / 1e9
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


__all__ = [
    "MeteringMiddleware",
    "token_email",
    "current_email",
    "CostEstimator",
    "CostExtractor",
]
