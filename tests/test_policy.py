"""Tests for the gating strategy formulas (pure, no deps)."""

from datetime import datetime, timedelta, timezone

import pytest

from enlace_metering import policy as P

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)


class FakeUsage:
    """A stub UsageQuery returning preset spend/count (records what it was asked)."""

    def __init__(self, spend=0.0, count=0):
        self._spend = spend
        self._count = count
        self.since_seen = []

    def spend_since(self, principal, since):
        self.since_seen.append(since)
        return self._spend

    def count_since(self, principal, since):
        self.since_seen.append(since)
        return self._count


def _req(*, spend=0.0, count=0, proposed=None, principal="u@x.com"):
    return P.GateRequest(
        principal=principal,
        ledger=FakeUsage(spend=spend, count=count),
        now=NOW,
        proposed_cost_usd=proposed,
        tool="t",
    )


def test_unlimited_always_allows():
    assert P.unlimited()(_req(spend=1e9)).allow is True


def test_credit_cap_under_over_and_forward_looking():
    cap = P.credit_cap(10.0, period="month")
    assert cap(_req(spend=5.0)).allow is True  # under
    d = cap(_req(spend=10.0))
    assert d.allow is False and "credit cap" in d.reason  # at cap
    assert cap(_req(spend=8.0, proposed=3.0)).allow is False  # would cross (11>10)
    assert cap(_req(spend=8.0, proposed=1.0)).allow is True  # 9 <= 10
    assert cap(_req(spend=3.0)).remaining_usd == pytest.approx(7.0)


def test_credit_cap_queries_calendar_month_start():
    P.credit_cap(10.0)(_req(spend=0.0)).allow  # trigger the query
    req = _req(spend=0.0)
    P.credit_cap(10.0)(req)
    assert req.ledger.since_seen[-1] == datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)


def test_rolling_window_cap():
    cap = P.rolling_window_cap(5.0, window=timedelta(days=1))
    assert cap(_req(spend=4.0)).allow is True
    assert cap(_req(spend=5.0)).allow is False
    req = _req(spend=0.0)
    cap(req)
    assert req.ledger.since_seen[-1] == NOW - timedelta(days=1)  # sliding, not calendar


def test_per_call_cap_needs_estimate():
    cap = P.per_call_cap(2.0)
    assert cap(_req(proposed=3.0)).allow is False
    assert cap(_req(proposed=1.5)).allow is True
    assert cap(_req(proposed=None)).allow is True  # nothing to compare -> allow


def test_call_count_cap():
    cap = P.call_count_cap(3, period="day")
    assert cap(_req(count=2)).allow is True
    assert cap(_req(count=3)).allow is False


def test_balance_gate():
    empty = P.balance_gate(lambda p: 0.0)
    assert empty(_req()).allow is False
    funded = P.balance_gate(lambda p: 5.0)
    assert funded(_req(proposed=3.0)).allow is True
    assert funded(_req(proposed=10.0)).allow is False  # can't cover


def test_per_principal_routing_and_deny_by_default():
    pol = P.per_principal(
        {"Owner@X.com": P.unlimited()}, default=P.credit_cap(1.0)
    )
    assert pol(_req(principal="owner@x.com", spend=1e6)).allow is True  # owner, case-insensitive
    assert pol(_req(principal="other@x.com", spend=5.0)).allow is False  # default cap
    no_default = P.per_principal({"owner@x.com": P.unlimited()})
    assert no_default(_req(principal="stranger@x.com")).allow is False  # deny-by-default


def test_require_all_first_denial_wins():
    pol = P.require_all(P.per_call_cap(2.0), P.credit_cap(20.0))
    assert pol(_req(proposed=3.0, spend=0.0)).allow is False  # per-call denies first
    assert pol(_req(proposed=1.0, spend=25.0)).allow is False  # credit denies
    assert pol(_req(proposed=1.0, spend=5.0)).allow is True  # both ok
    assert P.require_all()(_req()).allow is True  # vacuous


def test_period_start_boundaries():
    assert P._period_start(NOW, "month") == datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert P._period_start(NOW, "day") == datetime(2026, 8, 15, tzinfo=timezone.utc)
    assert P._period_start(NOW, "hour") == datetime(2026, 8, 15, 12, tzinfo=timezone.utc)
    # 2026-08-15 is a Saturday -> week (Mon) start is 2026-08-10
    assert P._period_start(NOW, "week") == datetime(2026, 8, 10, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        P._period_start(NOW, "fortnight")


def test_decision_is_truthy():
    assert bool(P.Decision(True)) is True and bool(P.Decision(False)) is False
