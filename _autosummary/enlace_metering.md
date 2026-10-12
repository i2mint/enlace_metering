# enlace_metering

enlace_metering — usage tracking + credit/quota access-gating for enlace connectors.

The enlace platform’s “usage & access-policy” layer — the sibling of `enlace_auth`
(identity) and `enlace_connector` (deploy). Three cleanly separated concerns (the
research + sources are in the README):

- [`policy`](enlace_metering.policy.md#module-enlace_metering.policy) — the **gate** (strategy): pure `GatePolicy` formulas
  ([`unlimited()`](enlace_metering.policy.md#enlace_metering.policy.unlimited), [`credit_cap()`](enlace_metering.policy.md#enlace_metering.policy.credit_cap),
  [`rolling_window_cap()`](enlace_metering.policy.md#enlace_metering.policy.rolling_window_cap), …) that decide allow/deny *before*
  > a call runs. Enforcement is a distinct layer from recording.
- [`ledger`](enlace_metering.ledger.md#module-enlace_metering.ledger) — the **meter** (record): [`UsageLedger`](enlace_metering.ledger.md#enlace_metering.ledger.UsageLedger)
  over any `MutableMapping` (a `dol` store in prod → grows to blob storage untouched).
- `middleware` — the FastMCP glue (needs the `[mcp]` extra) tying
  identity → gate → write-ahead ledger, fail-closed.

The core (policy + ledger) is **dependency-free**; the middleware is imported lazily,
so `import enlace_metering` never requires `fastmcp`.

### *class* enlace_metering.Decision(allow, reason='', remaining_usd=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

A gate outcome. `allow` is the verdict; `reason` is a human-facing
explanation (surfaced to the caller on denial, and useful as a remaining-budget
note on approval). `remaining_usd` is set by cap policies when meaningful.

### *class* enlace_metering.GateRequest(principal, ledger, now, proposed_cost_usd=None, tool=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Everything a policy needs to decide one call.

`ledger` is the usage read-side ([`UsageQuery`](#enlace_metering.UsageQuery)); `now` is injected
(timezone-aware UTC) so policies are deterministic + testable; `proposed_cost_usd`
is this call’s *estimated* cost when the host can estimate it (else `None` — the
gate then blocks on already-accumulated usage, the “you’ve hit your limit” model);
`tool` is the operation name (for logging / per-tool policies).

### *class* enlace_metering.UsageLedger(store)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Append/overwrite usage ledger over an injected `MutableMapping`.

`record` writes one entry keyed `{principal}/{month}/{id}.json`; the metering
middleware calls it twice per call (write-ahead `started` then the `done` /
`error` update) under the **same** `id`, so the store ends with the final
entry (its `cost_usd` is what `spend_since` sums). Entries need at least
`principal`, `month` (`YYYY-MM`), `id`, and — for costed calls — `ts`
(ISO) and `cost_usd`.

#### count_since(principal, since)

Number of the principal’s entries at/after `since`.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### spend_since(principal, since)

Total `cost_usd` across the principal’s entries at/after `since`.

* **Return type:**
  [`float`](https://docs.python.org/3/builtins/functions.html#float)

### *class* enlace_metering.UsageQuery(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

The read side a policy needs: a principal’s spend / call-count since a time.

[`UsageLedger`](enlace_metering.ledger.md#enlace_metering.ledger.UsageLedger) implements this; a test can pass any
object with these two methods. `since` is timezone-aware UTC.

### enlace_metering.balance_gate(get_balance)

Deny when a principal’s prepaid balance can’t cover the call.

`get_balance(principal) -> remaining_usd` is host-supplied (a credit store).
Denies if the balance is non-positive, or (when estimable) below the call’s
`proposed_cost_usd`. This is the true prepaid-credits model — burn-down lives in
the host’s balance store; this only gates.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](enlace_metering.policy.md#enlace_metering.policy.GateRequest)], [`Decision`](enlace_metering.policy.md#enlace_metering.policy.Decision)]

### enlace_metering.call_count_cap(max_calls, , period='day')

Deny once the principal has made `max_calls` in the current calendar `period`.

A count-based quota (no cost model needed) — useful for free/rate-limited tools.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](enlace_metering.policy.md#enlace_metering.policy.GateRequest)], [`Decision`](enlace_metering.policy.md#enlace_metering.policy.Decision)]

### enlace_metering.credit_cap(usd_per_period, , period='month')

Deny once spend in the current calendar `period` reaches `usd_per_period`.

The prepaid-credit / metered-cap formula: a principal gets `usd_per_period` of
spend per calendar period (default monthly), resetting on the boundary. When the
host supplies `proposed_cost_usd` the check is forward-looking (deny a call that
*would* cross the cap); otherwise it denies the next call once already at/over the
cap (“you’ve hit your limit”).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](enlace_metering.policy.md#enlace_metering.policy.GateRequest)], [`Decision`](enlace_metering.policy.md#enlace_metering.policy.Decision)]

### enlace_metering.per_call_cap(usd)

Deny a single call whose *estimated* cost exceeds `usd`.

Needs `proposed_cost_usd` (the host must estimate); a call with no estimate is
allowed (nothing to compare). Pair with a period cap via [`require_all()`](#enlace_metering.require_all) to
bound both the per-call blast radius and the cumulative spend.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](enlace_metering.policy.md#enlace_metering.policy.GateRequest)], [`Decision`](enlace_metering.policy.md#enlace_metering.policy.Decision)]

### enlace_metering.per_principal(policies, , default=None)

Route to a per-principal policy (tiered plans): `{email: policy, ...}`.

`default` handles principals not in the map (e.g. owner unlimited, everyone else
a cap: `per_principal({owner: unlimited()}, default=credit_cap(10))`). With no
`default`, an unlisted principal is **denied** (deny-by-default).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](enlace_metering.policy.md#enlace_metering.policy.GateRequest)], [`Decision`](enlace_metering.policy.md#enlace_metering.policy.Decision)]

### enlace_metering.require_all(\*policies)

Allow only if every policy allows; first denial wins (AND / most-restrictive).

E.g. `require_all(per_call_cap(2), credit_cap(20))` — bound both a single call
and the monthly total. With no policies, allows (vacuous truth).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](enlace_metering.policy.md#enlace_metering.policy.GateRequest)], [`Decision`](enlace_metering.policy.md#enlace_metering.policy.Decision)]

### enlace_metering.rolling_window_cap(usd, , window)

Deny once spend in the trailing `window` reaches `usd`.

A sliding window (e.g. `$5` per rolling 24h) rather than a calendar reset —
smoother rate control. Forward-looking when `proposed_cost_usd` is given.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](enlace_metering.policy.md#enlace_metering.policy.GateRequest)], [`Decision`](enlace_metering.policy.md#enlace_metering.policy.Decision)]

### enlace_metering.safe_key_component(value, , what='key')

A traversal-safe key component: reject empty, separators, `.`/`..`, NUL.

The ledger key is `{principal}/{month}/{id}.json`; every component is
caller-influenced (the `id` embeds the tool name), so every component is
checked. `what` names the component in the error message.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_metering.safe_principal(principal)

A traversal-safe, lowercased key component for a principal (email / `sub`).

Rejects empty, path-separator, `.`/`..`, and NUL so a hostile identity can’t
escape its ledger prefix. Identity is case-insensitive (enlace_auth mints
`sub = email`), so this lowercases too.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_metering.unlimited()

Always allow — the meter still records, but nothing is gated (e.g. the owner).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](enlace_metering.policy.md#enlace_metering.policy.GateRequest)], [`Decision`](enlace_metering.policy.md#enlace_metering.policy.Decision)]

### Modules

| [`ledger`](enlace_metering.ledger.md#module-enlace_metering.ledger)   | Durable usage ledger — the *recording* half of metering.                         |
|-----------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| [`policy`](enlace_metering.policy.md#module-enlace_metering.policy)   | Access-gating policies — the *enforcement* half of metering (deny before spend). |
