"""Durable usage ledger — the *recording* half of metering.

Records one entry per metered call into an injected ``MutableMapping`` (a ``dol``
file store in prod — which grows to ``s3dol`` / ``sqldol`` untouched; a plain
``dict`` in tests), keyed ``{principal}/{YYYY-MM}/{id}.json`` so "what did X spend
this month" is a cheap subtree scan. Implements
:class:`enlace_metering.policy.UsageQuery` (``spend_since`` / ``count_since``) so
policies gate on real accumulated usage.

**Storage-agnostic** — any ``MutableMapping``; there is no ``dol`` dependency (the
store is dependency-injected). *Every* key component is traversal-checked, so neither
a hostile identity nor a hostile operation name can escape the ledger prefix.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, MutableMapping, Optional


def safe_key_component(value: str, *, what: str = "key") -> str:
    """A traversal-safe key component: reject empty, separators, ``.``/``..``, NUL.

    The ledger key is ``{principal}/{month}/{id}.json``; every component is
    caller-influenced (the ``id`` embeds the tool name), so every component is
    checked. ``what`` names the component in the error message.
    """
    v = (value or "").strip()
    if not v or "/" in v or "\\" in v or v in (".", "..") or "\x00" in v:
        raise ValueError(f"unsafe {what} key: {value!r}")
    return v


def safe_principal(principal: str) -> str:
    """A traversal-safe, lowercased key component for a principal (email / ``sub``).

    Rejects empty, path-separator, ``.``/``..``, and NUL so a hostile identity can't
    escape its ledger prefix. Identity is case-insensitive (enlace_auth mints
    ``sub = email``), so this lowercases too.
    """
    return safe_key_component((principal or "").lower(), what="principal")


def _as_utc(dt: datetime) -> datetime:
    """Make ``dt`` timezone-aware, treating a naive value as UTC.

    The ledger's timestamps are UTC by construction (the middleware writes
    ``datetime.now(timezone.utc).isoformat()``), but an entry written by another
    producer — or a ``since`` passed by a host — may be naive. Normalizing here keeps
    the queries total: comparing a naive to an aware datetime raises ``TypeError``,
    which in a fail-closed middleware would turn one badly-stamped ledger row into a
    hard failure of every subsequent gated call.
    """
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _entry_ts(entry: dict) -> Optional[datetime]:
    """Parse an entry's ISO ``ts`` to an aware datetime, or ``None`` if absent/bad.

    ``None`` is treated as "include" by the queries (conservative — a call with an
    unparseable timestamp still counts toward usage). A parsed-but-naive timestamp is
    read as UTC (see :func:`_as_utc`).
    """
    raw = entry.get("ts")
    if not isinstance(raw, str):
        return None
    try:
        return _as_utc(datetime.fromisoformat(raw))
    except ValueError:
        return None


@dataclass(frozen=True)
class UsageLedger:
    """Append/overwrite usage ledger over an injected ``MutableMapping``.

    ``record`` writes one entry keyed ``{principal}/{month}/{id}.json``; the metering
    middleware calls it twice per call (write-ahead ``started`` then the ``done`` /
    ``error`` update) under the **same** ``id``, so the store ends with the final
    entry (its ``cost_usd`` is what ``spend_since`` sums). Entries need at least
    ``principal``, ``month`` (``YYYY-MM``), ``id``, and — for costed calls — ``ts``
    (ISO) and ``cost_usd``.
    """

    store: MutableMapping

    def record(self, entry: dict) -> str:
        principal = safe_principal(entry["principal"])
        month = safe_key_component(str(entry["month"]), what="month")
        entry_id = safe_key_component(str(entry["id"]), what="id")
        key = f"{principal}/{month}/{entry_id}.json"
        self.store[key] = entry
        return key

    def _entries_for(
        self, principal: str, *, since_month: Optional[str] = None
    ) -> Iterator[dict]:
        """Yield a principal's entries, pruning by month (``YYYY-MM`` string order) so
        a query scans only the relevant months, not the whole store."""
        prefix = safe_principal(principal) + "/"
        for key in list(self.store):
            if not key.startswith(prefix):
                continue
            if since_month is not None:
                parts = key.split("/")
                if len(parts) >= 2 and parts[1] < since_month:
                    continue
            yield self.store[key]

    def spend_since(self, principal: str, since: datetime) -> float:
        """Total ``cost_usd`` across the principal's entries at/after ``since``."""
        since = _as_utc(since)
        since_month = since.strftime("%Y-%m")
        total = 0.0
        for entry in self._entries_for(principal, since_month=since_month):
            ts = _entry_ts(entry)
            if ts is None or ts >= since:
                cost = entry.get("cost_usd")
                if isinstance(cost, (int, float)):
                    total += float(cost)
        return total

    def count_since(self, principal: str, since: datetime) -> int:
        """Number of the principal's entries at/after ``since``."""
        since = _as_utc(since)
        since_month = since.strftime("%Y-%m")
        n = 0
        for entry in self._entries_for(principal, since_month=since_month):
            ts = _entry_ts(entry)
            if ts is None or ts >= since:
                n += 1
        return n


__all__ = ["UsageLedger", "safe_principal", "safe_key_component"]
