# enlace_metering.policy

Access-gating policies — the *enforcement* half of metering (deny before spend).

Usage-based systems separate **enforcement** (may this call proceed?) from
**billing/recording** (what did it cost?). The gate runs *before* the ledger ever
sees the event: entitlement/quota checks are a distinct layer from the meter that
records spend (see the package README for the research + sources). This module is
that gate — and it is a **strategy**: whether to let a principal use a resource is a
pure function `GatePolicy = (GateRequest) -> Decision` that a host plugs in, with a
library of parameterized constructors for the common credit-based formulas.

Everything here is **pure + dependency-free** (no fastmcp, no storage engine): a
policy reads usage through the small [`UsageQuery`](#enlace_metering.policy.UsageQuery) protocol (which
[`UsageLedger`](enlace_metering.ledger.md#enlace_metering.ledger.UsageLedger) implements) and returns a
[`Decision`](#enlace_metering.policy.Decision). That keeps the formulas unit-testable against a dict and reusable
outside any connector.

Progressive disclosure: default to [`unlimited()`](#enlace_metering.policy.unlimited) or a single
[`credit_cap()`](#enlace_metering.policy.credit_cap); compose with [`require_all()`](#enlace_metering.policy.require_all) / [`per_principal()`](#enlace_metering.policy.per_principal) for
tiered plans (e.g. the owner unlimited, everyone else a monthly cap).

### Module Attributes

| [`GatePolicy`](#enlace_metering.policy.GatePolicy)   | decide whether `request` may proceed.   |
|---------------------------------------------------------------|-----------------------------------------|

### Functions

| [`unlimited`](#enlace_metering.policy.unlimited)()                              | Always allow — the meter still records, but nothing is gated (e.g. the owner).   |
|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| [`credit_cap`](#enlace_metering.policy.credit_cap)(usd_per_period, \*[, period]) | Deny once spend in the current calendar `period` reaches `usd_per_period`.       |
| [`rolling_window_cap`](#enlace_metering.policy.rolling_window_cap)(usd, \*, window)      | Deny once spend in the trailing `window` reaches `usd`.                          |
| [`per_call_cap`](#enlace_metering.policy.per_call_cap)(usd)                        | Deny a single call whose *estimated* cost exceeds `usd`.                         |
| [`call_count_cap`](#enlace_metering.policy.call_count_cap)(max_calls, \*[, period])  | Deny once the principal has made `max_calls` in the current calendar `period`.   |
| [`balance_gate`](#enlace_metering.policy.balance_gate)(get_balance)                | Deny when a principal's prepaid balance can't cover the call.                    |
| [`per_principal`](#enlace_metering.policy.per_principal)(policies, \*[, default])   | Route to a per-principal policy (tiered plans): `{email: policy, ...}`.          |
| [`require_all`](#enlace_metering.policy.require_all)(\*policies)                  | Allow only if every policy allows; first denial wins (AND / most-restrictive).   |

### Classes

| [`UsageQuery`](#enlace_metering.policy.UsageQuery)(\*args, \*\*kwargs)             | The read side a policy needs: a principal's spend / call-count since a time.   |
|---------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| [`Decision`](#enlace_metering.policy.Decision)(allow[, reason, remaining_usd])   | A gate outcome.                                                                |
| [`GateRequest`](#enlace_metering.policy.GateRequest)(principal, ledger, now[, ...]) | Everything a policy needs to decide one call.                                  |

### *class* enlace_metering.policy.Decision(allow, reason='', remaining_usd=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

A gate outcome. `allow` is the verdict; `reason` is a human-facing
explanation (surfaced to the caller on denial, and useful as a remaining-budget
note on approval). `remaining_usd` is set by cap policies when meaningful.

### enlace_metering.policy.GatePolicy

decide whether `request` may proceed. Pure — no I/O beyond
the injected [`UsageQuery`](#enlace_metering.policy.UsageQuery). Host apps register one per connector (or per
principal via [`per_principal()`](#enlace_metering.policy.per_principal)).

* **Type:**
  A gating strategy

alias of `Callable`[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]

### *class* enlace_metering.policy.GateRequest(principal, ledger, now, proposed_cost_usd=None, tool=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Everything a policy needs to decide one call.

`ledger` is the usage read-side ([`UsageQuery`](#enlace_metering.policy.UsageQuery)); `now` is injected
(timezone-aware UTC) so policies are deterministic + testable; `proposed_cost_usd`
is this call’s *estimated* cost when the host can estimate it (else `None` — the
gate then blocks on already-accumulated usage, the “you’ve hit your limit” model);
`tool` is the operation name (for logging / per-tool policies).

### *class* enlace_metering.policy.UsageQuery(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

The read side a policy needs: a principal’s spend / call-count since a time.

[`UsageLedger`](enlace_metering.ledger.md#enlace_metering.ledger.UsageLedger) implements this; a test can pass any
object with these two methods. `since` is timezone-aware UTC.

### enlace_metering.policy.balance_gate(get_balance)

Deny when a principal’s prepaid balance can’t cover the call.

`get_balance(principal) -> remaining_usd` is host-supplied (a credit store).
Denies if the balance is non-positive, or (when estimable) below the call’s
`proposed_cost_usd`. This is the true prepaid-credits model — burn-down lives in
the host’s balance store; this only gates.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]

### enlace_metering.policy.call_count_cap(max_calls, , period='day')

Deny once the principal has made `max_calls` in the current calendar `period`.

A count-based quota (no cost model needed) — useful for free/rate-limited tools.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]

### enlace_metering.policy.credit_cap(usd_per_period, , period='month')

Deny once spend in the current calendar `period` reaches `usd_per_period`.

The prepaid-credit / metered-cap formula: a principal gets `usd_per_period` of
spend per calendar period (default monthly), resetting on the boundary. When the
host supplies `proposed_cost_usd` the check is forward-looking (deny a call that
*would* cross the cap); otherwise it denies the next call once already at/over the
cap (“you’ve hit your limit”).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]

### enlace_metering.policy.per_call_cap(usd)

Deny a single call whose *estimated* cost exceeds `usd`.

Needs `proposed_cost_usd` (the host must estimate); a call with no estimate is
allowed (nothing to compare). Pair with a period cap via [`require_all()`](#enlace_metering.policy.require_all) to
bound both the per-call blast radius and the cumulative spend.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]

### enlace_metering.policy.per_principal(policies, , default=None)

Route to a per-principal policy (tiered plans): `{email: policy, ...}`.

`default` handles principals not in the map (e.g. owner unlimited, everyone else
a cap: `per_principal({owner: unlimited()}, default=credit_cap(10))`). With no
`default`, an unlisted principal is **denied** (deny-by-default).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]

### enlace_metering.policy.require_all(\*policies)

Allow only if every policy allows; first denial wins (AND / most-restrictive).

E.g. `require_all(per_call_cap(2), credit_cap(20))` — bound both a single call
and the monthly total. With no policies, allows (vacuous truth).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]

### enlace_metering.policy.rolling_window_cap(usd, , window)

Deny once spend in the trailing `window` reaches `usd`.

A sliding window (e.g. `$5` per rolling 24h) rather than a calendar reset —
smoother rate control. Forward-looking when `proposed_cost_usd` is given.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]

### enlace_metering.policy.unlimited()

Always allow — the meter still records, but nothing is gated (e.g. the owner).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`GateRequest`](#enlace_metering.policy.GateRequest)], [`Decision`](#enlace_metering.policy.Decision)]
