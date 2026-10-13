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

A failed call's error is recorded in the ledger and re-raised to the client, and a provider can quote a key back in it (ElevenLabs does on a 401): the caller's bring-your-own key, or the connector's own key. So the middleware passes that text through a **redactor** first, and re-raises a scrubbed stand-in (same type where it can be rebuilt, else `ToolError`) with no chain back to the dirty original.

The default, `redact_secrets`, replaces in one pass, longest first:

- the value of every in-flight request header named like a credential (`Authorization`, `X-<Provider>-Key`, `-Token`, `-Secret`) with `<redacted:{header}>`;
- the value of every environment variable named like one (a `_`-separated `KEY`, `API_KEY`, `TOKEN`, `SECRET`, `PASSWORD` or `PW` segment: `ELEVENLABS_API_KEY`, `FAL_KEY`, `SHARED_PW_X`) with `<redacted:env:{NAME}>`.

So a new BYO-key header or a new provider key in the environment is covered without configuration. For a secret named otherwise, `MeteringMiddleware(ledger, redact=secret_redactor(env_names=["MY_URL_WITH_TOKEN"]))`; any `redact(text) -> text` works. If the redactor raises, the error text is withheld rather than recorded unredacted.

Each secret is also matched URL-encoded and per `:`-separated part (fal keys are `id:secret`), and any env var whose value is a URL with a password in it is redacted whatever its name. Names that describe a credential rather than hold one (`S3_KEY_PREFIX`, `SSH_KEY_PATH`, `TOKEN_URL`, `AWS_ACCESS_KEY_ID`) are left alone. A provider that quotes only a truncated prefix is out of reach.

fastmcp logs a failing tool's traceback *before* the middleware sees the exception, so the middleware also redacts log records, with the in-flight call's redactor (`install_log_redaction()`, a chained `LogRecordFactory`, so loggers created later are covered too). By default (`redact_logs="*"`, i.e. `ALL_LOGGERS`) that is **every** record in the process: provider SDKs (`httpx`, `fal_client`, ElevenLabs' `fern`), the root logger, `uvicorn.error`, `asyncio`, plus what `warnings.warn` shows (`warnings.showwarning` is wrapped, so a warning still goes where it went before), the traceback an uncaught exception prints in any thread, and what an exception ignored in `__del__` prints (`sys.unraisablehook`). A dirty uncaught exception still reaches the previous hook (a crash reporter, say), as a stand-in that prints redacted. A dirty log argument is redacted in place, so formatters that unpack `record.args` (uvicorn's access log) keep working. To cover records logged at import time too, call `install_log_redaction(namespaces="*")` as the first statement of `server.py`. `redact_logs=("mypkg",)` limits it to fastmcp plus those namespaces, `redact_logs=True` to fastmcp alone, and `redact_logs=False` opts out. Fields passed with `extra=` are set after the factory runs, and some records never go through it (`logging.makeLogRecord`, a logger class with its own `makeRecord`), so the install also attaches `RedactingLogFilter` to every handler that exists at that point (and `logging.lastResort`); attach it yourself to a handler created later that emits them (a JSON handler, say). The filter also does the same job for any logger or handler you choose. A caller's bring-your-own header key is known process-wide while their call is in flight, so a record logged from a raw `threading.Thread` (which does not inherit the request's context) is redacted of it too; once the call has returned, it is not. Out of reach, like a truncated prefix: a key that a formatter shortened before it was logged, such as asyncio's default exception handler, whose `Handle` repr `reprlib`-truncates a callback's arguments to head and tail (`'sk-abcde...vwxyz'`), and text a program writes to stderr itself (`print(..., file=sys.stderr)`).

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
