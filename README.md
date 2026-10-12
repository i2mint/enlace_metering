# enlace_metering

Usage tracking **and** credit/quota access-gating for [enlace](https://github.com/i2mint/enlace) MCP connectors — the platform's "usage & access-policy" layer, sibling to `enlace_auth` (identity) and `enlace_connector` (deploy).

Whether a principal may use a resource is a **strategy** (a pure function), and *recording* what they spent is a **separate** concern from *deciding* whether to let them. That separation is the core design principle (see Research below).

```python
import enlace_metering as em

# 1. record (the meter) — a durable ledger over any MutableMapping (dict here; a
#    dol file store in prod, growing to s3dol/sqldol untouched).
ledger = em.UsageLedger(store={})

# 2. gate (the strategy) — parameterized credit formulas, composable.
policy = em.per_principal(
    {"owner@example.com": em.unlimited()},          # owner: no cap
    default=em.require_all(                          # everyone else:
        em.per_call_cap(2.00),                       #   ≤ $2 per call, AND
        em.credit_cap(20.00, period="month"),        #   ≤ $20 / calendar month
    ),
)

# 3. enforce (the glue) — one FastMCP middleware over EVERY tool call, fail-closed.
#    (needs `pip install enlace_metering[mcp]`)
from enlace_metering import MeteringMiddleware
mw = MeteringMiddleware(ledger, policy=policy, allowed={"owner@example.com"})
# app = py2mcp.http.mk_http_app(refs, auth=AUTH, middleware=[mw], stateless_http=True)
```

## Why (the three concerns)

| Concern | Where | Shape |
|---|---|---|
| **Enforce** — may this call proceed? | `policy` | pure `GatePolicy = (GateRequest) -> Decision` |
| **Record** — what did it cost? | `ledger` | `UsageLedger` over a `MutableMapping` |
| **Glue** — identity + gate + write-ahead | `middleware` (`[mcp]`) | a FastMCP `Middleware` |

The gate runs **before** the ledger sees the event — enforcement is a distinct layer from billing. The core (`policy` + `ledger`) is **dependency-free** and unit-testable against a `dict`; only the middleware needs `fastmcp`.

## Policies (the strategy library)

All are constructors returning a `GatePolicy`; compose with `require_all` / `per_principal`.

- `unlimited()` — always allow (record only).
- `credit_cap(usd_per_period, period="month")` — prepaid/metered cap per calendar period (resets on the boundary).
- `rolling_window_cap(usd, window=timedelta(days=1))` — sliding-window cap (rate control).
- `per_call_cap(usd)` — reject a single call whose *estimated* cost exceeds `usd`.
- `call_count_cap(n, period="day")` — count-based quota (no cost model needed).
- `balance_gate(get_balance)` — true prepaid credits: deny when a host-managed balance can't cover the call.
- `per_principal({email: policy}, default=…)` — tiered plans (owner unlimited, others capped).
- `require_all(*policies)` — AND / most-restrictive (first denial wins).

Forward-looking gating (deny a call that *would* cross a cap) needs a proposed-cost estimate — pass `estimate_cost=(tool, args) -> usd|None` to the middleware. Without one, caps block on already-accumulated usage ("you've hit your limit").

## Ledger layout

Keyed `{principal}/{YYYY-MM}/{id}.json` so "what did X spend this month" is a cheap subtree scan. The middleware writes **write-ahead** (`started` → `done`/`error` under one id): a costed call never spends on a shared key without a recoverable trace. The store is injected, so it grows from a local `dol.Files` to `s3dol`/`sqldol` without touching callers.

## Caller secrets in error text

A failed call's error is recorded in the ledger and re-raised to the client, and a provider can quote the caller's bring-your-own key back in it (ElevenLabs does on a 401). So the middleware passes that text through a **redactor** first, and re-raises a scrubbed stand-in (same type where it can be rebuilt, else `ToolError`) with no chain back to the dirty original.

The default, `redact_request_secrets`, replaces the value of every in-flight request header named like a credential (`Authorization`, `X-<Provider>-Key`, `-Token`, `-Secret`) with `<redacted:{header}>`, so a new BYO-key header is covered without configuration. Secrets that arrive some other way need their own: `MeteringMiddleware(ledger, redact=my_redactor)`, where `my_redactor(text) -> text`; build a header-based one with other rules via `request_secret_redactor(header_pattern=..., min_chars=...)`. If the redactor raises, the error text is withheld rather than recorded unredacted.

## Install

```bash
pip install enlace_metering           # core: policy + ledger (no deps)
pip install 'enlace_metering[mcp]'    # + the FastMCP middleware
```

## Research — how usage-based metering / quotas are built

The design follows the settled industry pattern: **entitlement/quota enforcement is a
separate layer from the billing meter** — enforcement decides *before* usage is
recorded [1][2]. Common formulas this package parameterizes:

- **Prepaid credits / credit blocks** — buy a bundle, burn down; blocks carry their own
  amount + expiry with priority burn-down [3][4]. → `credit_cap`, `balance_gate`.
- **Metered caps + real-time balance / grace** — per-feature quotas with live balance
  tracking [1][5]. → `credit_cap`, `call_count_cap`.
- **Token-bucket rate limiting** — tokens replenish at a rate; a request costs N; deny
  if insufficient [2]. → `rolling_window_cap` (the sliding-window cousin).

Keeping the decision a pure strategy (not baked into the middleware) is what lets a host
swap "owner unlimited" for "prepaid credits" or "monthly cap" without touching the
connector — the open-closed shape the enlace family favors.

### References

1. Lago. *How to architect billing systems to power usage-based pricing.* [getlago.com/blog/architect-billing-systems](https://getlago.com/blog/architect-billing-systems)
2. OpenMeter. *Metering and billing for AI, API and DevOps.* [github.com/openmeterio/openmeter](https://github.com/openmeterio/openmeter)
3. Kong. *Stop AI token overspend: prepaid credits in Konnect.* [konghq.com/blog/product-releases/metering-billing-prepaid-credits](https://konghq.com/blog/product-releases/metering-billing-prepaid-credits)
4. Solvimon. *AI billing software built for tokens, credits, and inference pricing.* [solvimon.com/blog/6-ai-billing-software-platforms-built-for-credits](https://www.solvimon.com/blog/6-ai-billing-software-platforms-built-for-credits)
5. Zuora. *Metered billing: architecture, metrics, and monetization models.* [zuora.com/glossary/metered-billing](https://www.zuora.com/glossary/metered-billing/)
