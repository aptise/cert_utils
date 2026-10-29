# Machine-readable Let's Encrypt policy (schema 2)

Snapshot checked 2026-10-28 against the official production
[rate-limit document](https://letsencrypt.org/docs/rate-limits/) dated
2026-08-05 and website checkout bb7e7238. Profile size constraints additionally
reference [profiles](https://letsencrypt.org/docs/profiles/). This is a public
policy snapshot, not live server state or an executable distributed limiter.

## Representation alternatives and choice

| Representation | Advantages | Limitations here |
| --- | --- | --- |
| Old free-form dict, limit + timeframe | Familiar and compact | Mixes constraints, quotas and traffic; ambiguous scope and renewal semantics; cannot express burst/refill separately |
| Frozen dataclasses and enums | Immutable, rich methods and invariants | Additional serialization contract, more object-oriented API, awkward for consumers exporting policy to other languages |
| Flat rows/tuples | Easy to enumerate | Positional fields and many empty cells; poor fit for guard-specific state |
| Typed, tagged, JSON-compatible catalogue | Named fields, stable IDs, numeric units, easy JSON export, kind-specific extensions | Mutable; callers must copy before customizing, and TypedDict is static checking rather than runtime validation |

The catalogue is the last option. It separates **policy** from **state**.
Downstream projects can map it into their own Redis buckets, worker queues,
troubleshooting UI or database without this library choosing their clock,
locking, persistence, scheduling or Public Suffix List dependency. No runtime
HTTP fetch, new dependency or bundled-CA import is needed to read it.

```python
from cert_utils.letsencrypt_info.rate_limits import RATE_LIMITS

assert RATE_LIMITS["schema_version"] == 2
orders = RATE_LIMITS["limits"]["orders_per_account"]
capacity = orders["capacity"]                 # 300 orders
scope_dimensions = orders["scope"]["dimensions"]  # ["account"]
refill_seconds = orders["refill"]["period_seconds"]  # 36, per 1 token

new_order_http = RATE_LIMITS["endpoints"]["/acme/new-order"]
assert new_order_http["capacity"] == 200       # burst, NOT 300
assert new_order_http["refill"]["tokens"] == 300  # per second
```

Use `copy.deepcopy` before applying account/domain overrides. JSON export is
simply `json.dumps(RATE_LIMITS)`; all durations are integer seconds and all
values are JSON-compatible. The enum-like `kind` field distinguishes ordinary
quota buckets, consecutive-failure guards and endpoint buckets. Profile size
constraints are a separate section, not time-based quotas.

## Field meanings and safe use

- `schema_version` versions the shape, not upstream policy. `source` records
  the page date, review date and checkout; re-review the snapshot before use.
- `capacity` is the maximum allowance/burst in units named by `unit`.
  `cost_per_event=1` counts one unit of the documented `counted_event`.
  This describes the metric; it does **not** claim an exact server accounting
  transaction or that a failed request is free. `enforced_on` states the API
  operation where the public document says the constraint is checked.
- `refill.tokens / refill.period_seconds` is the **published** refill cadence.
  `nominal_window_seconds` retains the page's headline timeframe separately.
  The source rounds IPv6 registration to 22 seconds/token (500/3 hours),
  registered-domain issuance to 202 minutes (50/week), and exact-set issuance
  to 34 hours (5/week). These do not exactly equal window/capacity. Such records
  say `precision="published_rounded"`. Do not relabel these rounded values as
  exact server configuration. Using the slower rounded cadence is a planning
  choice, not a server-issued guarantee. No speculative subsecond rate is
  manufactured from the prose.
- `scope.dimensions` identifies the bucket key, including compound account +
  identifier scopes. `key_rules` records necessary grouping semantics. Domain
  issuance uses the Public Suffix List, exact IPv4 or IPv6 /64; registration's
  IPv6 range is /48. Global domain and exact-set quotas cross account boundaries.
  Count each distinct domain/IP-range bucket for multi-identifier certificates.
  Exact-set matching ignores capitalization and identifier order. Further IP
  string canonicalization is not specified by this source and is not invented.
- `override_scopes` records where an override can be requested; an empty list
  means the document offers none, not that the policy is unrestricted.
- The consecutive-failure guard is not a generic token bucket: it decays by one
  failure daily, resets consecutive failures to zero on authorization success,
  and can pause issuance. The source documents a self-service unpause link.
  Do not infer automatic unpause or count an authorization failure at request
  admission before its validation outcome is known.

A usable throttler must evaluate **all applicable scopes**, not just one named
limit, and needs atomic coordination across its workers. Registration can need
both per-address and IPv6 /48 checks; issuance can involve an account, multiple
global domain groups and an exact-set bucket. A local process cannot observe
issuance by unrelated clients, previously consumed capacity, per-account
exceptions, or all server-side policy. Initial capacity is **unknown**, not a
promise that the full bucket is available. Reservation/rollback behavior must
be designed separately from this snapshot. Always honor server errors and
Retry-After; when several limits are exhausted, wait for the latest deadline.
Revocation does not restore capacity.

## Renewals and transport are separate

An ARI-capable client is not automatically exempt. The order must explicitly
replace an eligible certificate, overlap at least one identifier, and not
replace a certificate already replaced through ARI. Server eligibility is
final. Ordinary same-identifier-set renewals exempt only the documented order
and registered-domain quotas; exact-set and authorization-failure limits still
matter. The catalogue records these exemptions per limit and in `renewals`.

The source broadly exempts eligible ARI renewals from rate limits, but does not
explain their interaction with generic load-balancer protection, paused
identifiers or endpoint overlap. Do not use that statement to disable HTTP
pacing or bypass a server pause/Retry-After response.

Endpoint records preserve exact endpoint paths, per-IP scope, refill and burst
separately, plus the documented 503/Retry-After behavior. `/acme/*` is a prefix
pattern, not a literal URL. Whether that fallback bucket replaces or also
applies to a specific endpoint is not specified on the page. Consequently this
module supplies data, not a selector falsely claiming first-match or additive
semantics. Integrators should choose/document their transport policy and
validate against server responses. Conservative local pacing can be stricter
than server policy but cannot guarantee availability.

## Migration from the old LIMITS

This is intentionally a breaking schema replacement authorized for this
release. The original `cert_utils.letsencrypt_info.LIMITS` and temporary
`cert_utils.rate_limits` locations are replaced by
`cert_utils.letsencrypt_info.rate_limits`. Both `LIMITS` and `RATE_LIMITS` there
reference the new catalogue; old schema keys are not preserved or silently
approximated. Importing the namespace or the rate module does not load CA files.
Shared TypedDict definitions live in `cert_utils.letsencrypt_info.types`.

| Old entry | Schema 2 location |
| --- | --- |
| registrations/ip_address | limits.registrations_per_ip |
| registrations/ip_range | limits.registrations_per_ipv6_range |
| new_orders | limits.orders_per_account |
| certificates/domain | limits.certificates_per_registered_domain |
| certificates/fqdn | limits.certificates_per_exact_identifier_set |
| failed_validation/account/hostname | limits.authorization_failures_per_identifier_account |
| names/certificate | constraints.identifiers_per_certificate.maximum_by_profile |
| endpoints | endpoints, now full ACME v2 paths with burst capacity |
| pending_authorizations/account | Removed: not documented by the current production page |

ACME v1 endpoints are removed. An absent rule is **unknown/not documented**,
not a zero limit or permission for unlimited traffic. Staging is not production:
this snapshot deliberately does not supply staging limits or silently reuse
production defaults for it. No claim is made that these are every operational
check applied by the CA.
