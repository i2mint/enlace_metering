"""enlace_metering — usage tracking + credit/quota access-gating for enlace connectors.

The enlace platform's "usage & access-policy" layer — the sibling of ``enlace_auth``
(identity) and ``enlace_connector`` (deploy). Three cleanly separated concerns (the
research + sources are in the README):

- :mod:`~enlace_metering.policy` — the **gate** (strategy): pure ``GatePolicy`` formulas
  (:func:`~enlace_metering.policy.unlimited`, :func:`~enlace_metering.policy.credit_cap`,
  :func:`~enlace_metering.policy.rolling_window_cap`, ...) that decide allow/deny *before*
  a call runs. Enforcement is a distinct layer from recording.
- :mod:`~enlace_metering.ledger` — the **meter** (record): :class:`~enlace_metering.ledger.UsageLedger`
  over any ``MutableMapping`` (a ``dol`` store in prod → grows to blob storage untouched).
- :mod:`~enlace_metering.middleware` — the FastMCP glue (needs the ``[mcp]`` extra) tying
  identity → gate → write-ahead ledger, fail-closed.

The core (policy + ledger) is **dependency-free**; the middleware is imported lazily,
so ``import enlace_metering`` never requires ``fastmcp``.
"""

from __future__ import annotations

from .ledger import UsageLedger, safe_key_component, safe_principal
from .policy import (
    Decision,
    GatePolicy,
    GateRequest,
    UsageQuery,
    balance_gate,
    call_count_cap,
    credit_cap,
    per_call_cap,
    per_principal,
    require_all,
    rolling_window_cap,
    unlimited,
)

#: Middleware symbols live behind the ``[mcp]`` extra (they import ``fastmcp``); expose
#: them lazily so ``import enlace_metering`` (policy + ledger) stays dependency-free.
_LAZY = {
    "MeteringMiddleware": "enlace_metering.middleware",
    "token_email": "enlace_metering.middleware",
    "current_email": "enlace_metering.middleware",
    "CostEstimator": "enlace_metering.middleware",
    "CostExtractor": "enlace_metering.middleware",
    "Redactor": "enlace_metering.middleware",
    "secret_redactor": "enlace_metering.middleware",
    "redact_secrets": "enlace_metering.middleware",
    "SECRET_ENV_PATTERN": "enlace_metering.middleware",
    "RedactingLogFilter": "enlace_metering.middleware",
    "install_log_redaction": "enlace_metering.middleware",
    "request_secret_redactor": "enlace_metering.middleware",
    "redact_request_secrets": "enlace_metering.middleware",
    "SECRET_HEADER_PATTERN": "enlace_metering.middleware",
}


def __getattr__(name: str):
    """Lazily import the ``[mcp]`` middleware symbols on first access (PEP 562)."""
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module 'enlace_metering' has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(module), name)


def __dir__():
    return sorted(__all__)


__all__ = [
    # policy (the gate)
    "Decision",
    "GatePolicy",
    "GateRequest",
    "UsageQuery",
    "unlimited",
    "credit_cap",
    "rolling_window_cap",
    "per_call_cap",
    "call_count_cap",
    "balance_gate",
    "per_principal",
    "require_all",
    # ledger (the meter)
    "UsageLedger",
    "safe_principal",
    "safe_key_component",
    # middleware (lazy, [mcp])
    *_LAZY.keys(),
]
