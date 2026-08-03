"""Tests for the durable usage ledger (over a plain dict)."""

from datetime import datetime, timedelta, timezone

import pytest

from enlace_metering.ledger import UsageLedger, safe_key_component, safe_principal

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)


def _entry(principal, eid, *, cost=None, ts=NOW, month=None, status="done"):
    return {
        "principal": principal,
        "id": eid,
        "month": month or ts.strftime("%Y-%m"),
        "ts": ts.isoformat(),
        "cost_usd": cost,
        "status": status,
    }


def test_record_keys_by_principal_month_id_and_overwrites():
    store = {}
    led = UsageLedger(store)
    key = led.record(_entry("U@X.com", "abc", cost=None, status="started"))
    assert key == "u@x.com/2026-08/abc.json"  # lowercased principal
    led.record(
        _entry("U@X.com", "abc", cost=1.5, status="done")
    )  # same id -> overwrite
    assert len(store) == 1
    assert store[key]["cost_usd"] == 1.5


def test_spend_since_sums_costs_in_window():
    store = {}
    led = UsageLedger(store)
    led.record(_entry("a@x.com", "1", cost=2.0, ts=NOW))
    led.record(_entry("a@x.com", "2", cost=3.0, ts=NOW - timedelta(hours=1)))
    led.record(
        _entry("a@x.com", "3", cost=5.0, ts=NOW - timedelta(days=40))
    )  # older month
    led.record(_entry("b@x.com", "4", cost=99.0, ts=NOW))  # other principal
    # this calendar month (from Aug 1): entries 1 + 2 = 5.0; entry 3 (June/July) excluded
    since_month = datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert led.spend_since("a@x.com", since_month) == pytest.approx(5.0)
    # trailing 30 min: only entry 1
    assert led.spend_since("a@x.com", NOW - timedelta(minutes=30)) == pytest.approx(2.0)


def test_count_since_counts_entries():
    store = {}
    led = UsageLedger(store)
    led.record(_entry("a@x.com", "1", cost=None, ts=NOW))  # no cost still counts
    led.record(_entry("a@x.com", "2", cost=1.0, ts=NOW))
    assert led.count_since("a@x.com", datetime(2026, 8, 1, tzinfo=timezone.utc)) == 2


def test_month_pruning_skips_old_months():
    # An entry keyed to an older month must not be scanned when since is this month.
    store = {}
    led = UsageLedger(store)
    led.record(_entry("a@x.com", "old", cost=100.0, ts=NOW, month="2020-01"))
    assert led.spend_since("a@x.com", datetime(2026, 8, 1, tzinfo=timezone.utc)) == 0.0


def test_safe_principal_rejects_traversal():
    for bad in ("", "   ", "a/b", "..", ".", "a\\b", "x\x00y"):
        with pytest.raises(ValueError):
            safe_principal(bad)
    assert safe_principal("Owner@X.com") == "owner@x.com"


def test_record_rejects_traversal_in_id_and_month():
    # The entry id embeds the (client-supplied) tool name, so it is as
    # caller-influenced as the principal and must be traversal-checked too.
    store = {}
    led = UsageLedger(store)
    with pytest.raises(ValueError):
        led.record(_entry("a@x.com", "1-0-../../../etc/pwn"))
    with pytest.raises(ValueError):
        led.record(_entry("a@x.com", "ok", month="../.."))
    assert store == {}


def test_safe_key_component_preserves_case():
    # Unlike safe_principal, a generic component is not lowercased (ids are opaque).
    assert safe_key_component(" AbC ", what="id") == "AbC"
    with pytest.raises(ValueError):
        safe_key_component("a/b", what="id")


def test_naive_entry_timestamp_is_read_as_utc():
    # A ts written without an offset must not blow up the aware/naive comparison
    # (that would turn one bad row into a hard failure of every gated call).
    store = {}
    led = UsageLedger(store)
    entry = _entry("a@x.com", "naive", cost=1.5)
    entry["ts"] = NOW.replace(tzinfo=None).isoformat()  # "2026-08-15T12:00:00"
    led.record(entry)
    assert led.spend_since("a@x.com", NOW - timedelta(hours=1)) == pytest.approx(1.5)
    assert led.count_since("a@x.com", NOW - timedelta(hours=1)) == 1
    assert led.spend_since("a@x.com", NOW + timedelta(hours=1)) == 0.0


def test_naive_since_is_read_as_utc():
    store = {}
    led = UsageLedger(store)
    led.record(_entry("a@x.com", "1", cost=2.0))
    naive_since = (NOW - timedelta(hours=1)).replace(tzinfo=None)
    assert led.spend_since("a@x.com", naive_since) == pytest.approx(2.0)
    assert led.count_since("a@x.com", naive_since) == 1
