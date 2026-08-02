"""Access-gating policies — the *enforcement* half of metering (deny before spend).

Usage-based systems separate **enforcement** (may this call proceed?) from
**billing/recording** (what did it cost?). The gate runs *before* the ledger ever
sees the event: entitlement/quota checks are a distinct layer from the meter that
records spend (see the package README for the research + sources). This module is
that gate — and it is a **strategy**: whether to let a principal use a resource is a
pure function ``GatePolicy = (GateRequest) -> Decision`` that a host plugs in, with a
library of parameterized constructors for the common credit-based formulas.

Everything here is **pure + dependency-free** (no fastmcp, no storage engine): a
policy reads usage through the small :class:`UsageQuery` protocol (which
:class:`~enlace_metering.ledger.UsageLedger` implements) and returns a
:class:`Decision`. That keeps the formulas unit-testable against a dict and reusable
outside any connector.

Progressive disclosure: default to :func:`unlimited` or a single
:func:`credit_cap`; compose with :func:`require_all` / :func:`per_principal` for
tiered plans (e.g. the owner unlimited, everyone else a monthly cap).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Mapping, Optional, Protocol


class UsageQuery(Protocol):
    """The read side a policy needs: a principal's spend / call-count since a time.

    :class:`~enlace_metering.ledger.UsageLedger` implements this; a test can pass any
    object with these two methods. ``since`` is timezone-aware UTC.
    """

    def spend_since(self, principal: str, since: datetime) -> float: ...

    def count_since(self, principal: str, since: datetime) -> int: ...


@dataclass(frozen=True)
class Decision:
    """A gate outcome. ``allow`` is the verdict; ``reason`` is a human-facing
    explanation (surfaced to the caller on denial, and useful as a remaining-budget
    note on approval). ``remaining_usd`` is set by cap policies when meaningful.
    """

    allow: bool
    reason: str = ""
    remaining_usd: Optional[float] = None

    def __bool__(self) -> bool:  # so `if policy(req): ...` reads naturally
        return self.allow


@dataclass(frozen=True)
class GateRequest:
    """Everything a policy needs to decide one call.

    ``ledger`` is the usage read-side (:class:`UsageQuery`); ``now`` is injected
    (timezone-aware UTC) so policies are deterministic + testable; ``proposed_cost_usd``
    is this call's *estimated* cost when the host can estimate it (else ``None`` — the
    gate then blocks on already-accumulated usage, the "you've hit your limit" model);
    ``tool`` is the operation name (for logging / per-tool policies).
    """

    principal: str
    ledger: UsageQuery
    now: datetime
    proposed_cost_usd: Optional[float] = None
    tool: Optional[str] = None


#: A gating strategy: decide whether ``request`` may proceed. Pure — no I/O beyond
#: the injected :class:`UsageQuery`. Host apps register one per connector (or per
#: principal via :func:`per_principal`).
GatePolicy = Callable[[GateRequest], Decision]


_PERIODS = ("hour", "day", "week", "month")


def _period_start(now: datetime, period: str) -> datetime:
    """Start of the calendar ``period`` containing ``now`` (UTC).

    ``month`` = first of the month; ``week`` = Monday; ``day`` = midnight; ``hour`` =
    top of the hour. A *calendar* boundary (not a rolling window — that's
    :func:`rolling_window_cap`), so a monthly cap resets on the 1st.
    """
    if period not in _PERIODS:
        raise ValueError(f"period must be one of {_PERIODS}, got {period!r}")
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "hour":
        return now.replace(minute=0, second=0, microsecond=0)
    if period == "day":
        return midnight
    if period == "week":
        return midnight - timedelta(days=now.weekday())
    return midnight.replace(day=1)  # month


def unlimited() -> GatePolicy:
    """Always allow — the meter still records, but nothing is gated (e.g. the owner)."""

    def policy(request: GateRequest) -> Decision:
        return Decision(True, "no usage limit")

    return policy


def credit_cap(usd_per_period: float, *, period: str = "month") -> GatePolicy:
    """Deny once spend in the current calendar ``period`` reaches ``usd_per_period``.

    The prepaid-credit / metered-cap formula: a principal gets ``usd_per_period`` of
    spend per calendar period (default monthly), resetting on the boundary. When the
    host supplies ``proposed_cost_usd`` the check is forward-looking (deny a call that
    *would* cross the cap); otherwise it denies the next call once already at/over the
    cap ("you've hit your limit").
    """
    if usd_per_period < 0:
        raise ValueError("usd_per_period must be >= 0")

    def policy(request: GateRequest) -> Decision:
        since = _period_start(request.now, period)
        spent = request.ledger.spend_since(request.principal, since)
        proposed = request.proposed_cost_usd or 0.0
        remaining = max(0.0, usd_per_period - spent)
        # Deny when the budget is exhausted (spent at/over the cap — the "you've hit
        # your limit" case, incl. proposed=None) OR when this call would cross it.
        if spent >= usd_per_period or spent + proposed > usd_per_period:
            return Decision(
                False,
                f"{period}ly credit cap of ${usd_per_period:.2f} reached "
                f"(spent ${spent:.2f} this {period})",
                remaining_usd=remaining,
            )
        return Decision(
            True,
            f"${remaining:.2f} of ${usd_per_period:.2f} left this {period}",
            remaining_usd=remaining,
        )

    return policy


def rolling_window_cap(usd: float, *, window: timedelta) -> GatePolicy:
    """Deny once spend in the trailing ``window`` reaches ``usd``.

    A sliding window (e.g. ``$5`` per rolling 24h) rather than a calendar reset —
    smoother rate control. Forward-looking when ``proposed_cost_usd`` is given.
    """
    if usd < 0:
        raise ValueError("usd must be >= 0")

    def policy(request: GateRequest) -> Decision:
        since = request.now - window
        spent = request.ledger.spend_since(request.principal, since)
        proposed = request.proposed_cost_usd or 0.0
        remaining = max(0.0, usd - spent)
        if spent >= usd or spent + proposed > usd:
            return Decision(
                False,
                f"rolling-window cap of ${usd:.2f} / {window} reached "
                f"(spent ${spent:.2f} in the last {window})",
                remaining_usd=remaining,
            )
        return Decision(
            True,
            f"${remaining:.2f} left in this {window} window",
            remaining_usd=remaining,
        )

    return policy


def per_call_cap(usd: float) -> GatePolicy:
    """Deny a single call whose *estimated* cost exceeds ``usd``.

    Needs ``proposed_cost_usd`` (the host must estimate); a call with no estimate is
    allowed (nothing to compare). Pair with a period cap via :func:`require_all` to
    bound both the per-call blast radius and the cumulative spend.
    """
    if usd < 0:
        raise ValueError("usd must be >= 0")

    def policy(request: GateRequest) -> Decision:
        proposed = request.proposed_cost_usd
        if proposed is not None and proposed > usd:
            return Decision(
                False, f"this call's estimated ${proposed:.2f} exceeds the "
                f"per-call cap of ${usd:.2f}"
            )
        return Decision(True, f"within the ${usd:.2f} per-call cap")

    return policy


def call_count_cap(max_calls: int, *, period: str = "day") -> GatePolicy:
    """Deny once the principal has made ``max_calls`` in the current calendar ``period``.

    A count-based quota (no cost model needed) — useful for free/rate-limited tools.
    """
    if max_calls < 0:
        raise ValueError("max_calls must be >= 0")

    def policy(request: GateRequest) -> Decision:
        since = _period_start(request.now, period)
        count = request.ledger.count_since(request.principal, since)
        if count >= max_calls:
            return Decision(
                False,
                f"{period}ly call cap of {max_calls} reached ({count} this {period})",
            )
        return Decision(True, f"{max_calls - count} of {max_calls} calls left this {period}")

    return policy


def balance_gate(get_balance: Callable[[str], float]) -> GatePolicy:
    """Deny when a principal's prepaid balance can't cover the call.

    ``get_balance(principal) -> remaining_usd`` is host-supplied (a credit store).
    Denies if the balance is non-positive, or (when estimable) below the call's
    ``proposed_cost_usd``. This is the true prepaid-credits model — burn-down lives in
    the host's balance store; this only gates.
    """

    def policy(request: GateRequest) -> Decision:
        balance = get_balance(request.principal)
        need = request.proposed_cost_usd or 0.0
        if balance <= 0 or balance < need:
            return Decision(
                False,
                f"insufficient credit: balance ${balance:.2f}"
                + (f", need ${need:.2f}" if need else ""),
                remaining_usd=max(0.0, balance),
            )
        return Decision(True, f"${balance:.2f} credit remaining", remaining_usd=balance)

    return policy


def per_principal(
    policies: Mapping[str, GatePolicy], *, default: Optional[GatePolicy] = None
) -> GatePolicy:
    """Route to a per-principal policy (tiered plans): ``{email: policy, ...}``.

    ``default`` handles principals not in the map (e.g. owner unlimited, everyone else
    a cap: ``per_principal({owner: unlimited()}, default=credit_cap(10))``). With no
    ``default``, an unlisted principal is **denied** (deny-by-default).
    """
    lowered = {k.lower(): v for k, v in policies.items()}

    def policy(request: GateRequest) -> Decision:
        chosen = lowered.get(request.principal.lower(), default)
        if chosen is None:
            return Decision(False, f"no usage policy configured for {request.principal!r}")
        return chosen(request)

    return policy


def require_all(*policies: GatePolicy) -> GatePolicy:
    """Allow only if every policy allows; first denial wins (AND / most-restrictive).

    E.g. ``require_all(per_call_cap(2), credit_cap(20))`` — bound both a single call
    and the monthly total. With no policies, allows (vacuous truth).
    """

    def policy(request: GateRequest) -> Decision:
        for p in policies:
            decision = p(request)
            if not decision.allow:
                return decision
        return Decision(True, "all policies satisfied")

    return policy


__all__ = [
    "UsageQuery",
    "Decision",
    "GateRequest",
    "GatePolicy",
    "unlimited",
    "credit_cap",
    "rolling_window_cap",
    "per_call_cap",
    "call_count_cap",
    "balance_gate",
    "per_principal",
    "require_all",
]
