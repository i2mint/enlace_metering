# enlace_metering.ledger

Durable usage ledger — the *recording* half of metering.

Records one entry per metered call into an injected `MutableMapping` (a `dol`
file store in prod — which grows to `s3dol` / `sqldol` untouched; a plain
`dict` in tests), keyed `{principal}/{YYYY-MM}/{id}.json` so “what did X spend
this month” is a cheap subtree scan. Implements
[`enlace_metering.policy.UsageQuery`](enlace_metering.policy.html.md#enlace_metering.policy.UsageQuery) (`spend_since` / `count_since`) so
policies gate on real accumulated usage.

**Storage-agnostic** — any `MutableMapping`; there is no `dol` dependency (the
store is dependency-injected). *Every* key component is traversal-checked, so neither
a hostile identity nor a hostile operation name can escape the ledger prefix.

### Functions

| [`safe_principal`](#enlace_metering.ledger.safe_principal)(principal)             | A traversal-safe, lowercased key component for a principal (email / `sub`).   |
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [`safe_key_component`](#enlace_metering.ledger.safe_key_component)(value, \*[, what]) | A traversal-safe key component: reject empty, separators, `.`/`..`, NUL.      |

### Classes

| [`UsageLedger`](#enlace_metering.ledger.UsageLedger)(store)   | Append/overwrite usage ledger over an injected `MutableMapping`.   |
|-----------------------------------------------------------------------|--------------------------------------------------------------------|

### *class* enlace_metering.ledger.UsageLedger(store)

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

### enlace_metering.ledger.safe_key_component(value, , what='key')

A traversal-safe key component: reject empty, separators, `.`/`..`, NUL.

The ledger key is `{principal}/{month}/{id}.json`; every component is
caller-influenced (the `id` embeds the tool name), so every component is
checked. `what` names the component in the error message.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_metering.ledger.safe_principal(principal)

A traversal-safe, lowercased key component for a principal (email / `sub`).

Rejects empty, path-separator, `.`/`..`, and NUL so a hostile identity can’t
escape its ledger prefix. Identity is case-insensitive (enlace_auth mints
`sub = email`), so this lowercases too.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)
