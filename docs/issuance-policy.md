# Issuance Policy via CEL Claim Mappers

Parsec enforces issuance policy in **CEL claim mappers**, not in a separate
policy interface. The same script that builds claims can deny issuance with
typed OAuth / token-exchange outcomes.

## Why mappers?

Issuance policy and claim mapping share the same inputs: validated subject,
optional actor, and request attributes (`MapperInput`). A separate
`IssuancePolicy` abstraction duplicated that surface without carrying enough
weight. Policy guards are CEL expressions evaluated before (or instead of)
producing claims.

## Structured result (not error) for OAuth denials

`ClaimMapper.Map` returns a `MappingResult` — claims plus a `MappingDecision`
— shaped like `AuthzCheckDecision`:

| Outcome | How it is expressed |
|---------|---------------------|
| Allow + claims | `Decision.Action == allow`, `error == nil` |
| OAuth denial (Layer A/B) | `Decision.Action == deny` + OAuth fields, `error == nil` |
| Unexpected failure (`fail()`, eval bugs, …) | `error != nil` |

Expected RFC outcomes are **not** stuffed into `error`. Use `error` only when
something is unexpectedly wrong.

Issuers may list multiple ordered mappers. Results are composed with
`MappingResult.Merge`: claims merge on Allow, and the **first non-Allow
decision wins** (further mappers are not called). Merge logic lives on the
result type, not buried only in `IssueContext.ToClaims`.

`Issuer.Issue` still returns `error` today: `ToClaims` adapts Deny to a
temporary `ClaimMappingError` for transport mapping. Threading Decision
through `Issue` is deferred until that adapter proves awkward.

## Two-layer OAuth abort API

Primary vocabulary is the **token exchange / OAuth** error response
([RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2),
[RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)) —
not HTTP status names.

### Layer A — direct OAuth error codes

| CEL function | Wire `error` |
|--------------|--------------|
| `invalidRequest(message)` | `invalid_request` |
| `invalidTarget(message)` | `invalid_target` |
| `invalidGrant(message)` | `invalid_grant` |
| `unauthorizedClient(message)` | `unauthorized_client` |
| `invalidClient(message)` | `invalid_client` |
| `unsupportedGrantType(message)` | `unsupported_grant_type` |
| `invalidScope(message)` | `invalid_scope` |

### Layer B — reason helpers (preferred for guards)

Easier to author correctly; sets a machine `Reason` for observability while
still terminating in a Layer A code:

| CEL function | Wire `error` | Reason |
|--------------|--------------|--------|
| `invalidSubject(message)` | `invalid_request` | `invalid_subject` |
| `invalidActor(message)` | `invalid_request` | `invalid_actor` |
| `invalidAudience(message)` | `invalid_target` | `invalid_audience` |
| `unsupportedTokenType(message)` | `invalid_request` | `unsupported_token_type` |

### `fail(message)`

Reserved for **mapping / system failures**. `Map` returns `error` (not a Deny
decision) → transports treat it as **Internal** (not an OAuth client error
body).

## Decision flow

```
CEL Layer A/B abort helper
  → MappingResult{Decision: Deny{OAuthError, Reason, Message}}
  → MappingResult.Merge across ordered mappers (first non-Allow wins)
  → ToClaims adapts Deny → ClaimMappingError (temporary, for Issuer.Issue)
  → Exchange: HTTP 400 + { "error", "error_description" } (via gRPC ErrorInfo)
  → ext_authz: InvalidArgument (OAuth) or Internal (fail)
  → logs/metrics: mapping.oauth_error, mapping.abort_reason

CEL fail() / unexpected failure
  → error → Internal / 500
```

## Example: 3scale-parity guards

```cel
// Layer B preferred for policy guards.
// Always guard with has(subject.claims) — empty claim maps omit the claims key.
has(subject.claims) && has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
: !(has(subject.claims) && has(subject.claims.idp))
  ? invalidSubject("claim 'idp' is required")
: {
    "identity": { /* ... */ },
    "entitlements": {}
  }
```

See `configs/scripts/redhat_identity.cel` for a full multi-token-type script
(impersonation globally; IdP required on the console API path).

## Configuration

No new Go config fields. Policy activates only when the CEL script contains
guard expressions. Scripts without guards behave as before.

Downstream (app-interface) CEL scripts must be updated separately to include
guards — until then, stage/prod keep previous behavior.

## Out of scope

Broader claim-policy helpers (`requireClaim`, …), Lua mappers, and a named
global policy registry are intentionally deferred. Widening `Issuer.Issue` to
return `MappingDecision` is an open follow-up.
