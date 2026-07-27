# RHCLOUD-47315: Reject impersonated tokens and enforce IdP claim presence in JWT validation

**JIRA**: https://redhat.atlassian.net/browse/RHCLOUD-47315
**Status**: In Review — v2.6 ExchangeResult + DenyOAuth/DenyReason
**Author**: AI Assistant
**Date**: 2026-07-08 (v1), 2026-07-14 (v2), 2026-07-16 (v2.1–v2.4), 2026-07-20 (v2.5), 2026-07-27 (v2.6)

## Context

Two security checks that insights-3scale enforces are absent from parsec:

1. **Impersonated tokens pass through unchecked.** When an SSO admin
   impersonates a user, Keycloak mints a JWT with `impersonated: true`.
   insights-3scale returns 401; parsec accepts the token and issues.

2. **No IdP enforcement.** When `APICAST_ENFORCE_IDP_AUTH=true`,
   insights-3scale requires tokens to carry an `idp` claim. Parsec has no
   equivalent.

### Acceptance Criteria

- [x] AC1: Tokens with `impersonated: true` are rejected before issuance when configured
- [x] AC2: Tokens missing `idp` claim are rejected before issuance when configured
- [x] AC3: Error messages are clear and descriptive
- [x] AC4: Both checks are observable via OpenTelemetry (histogram result attributes)
- [x] AC5: Config is documented with examples showing 3scale parity
- [x] AC6: Existing tests pass; new tests cover both positive and negative cases
- [x] AC7: Policy applies to both ext_authz and exchange flows

### External References

- Parent: [RHCLOUD-46385](https://redhat.atlassian.net/browse/RHCLOUD-46385) — Investigate matching OIDC to x-rh-identity parity with 3scale
- Meeting: _Gateway feature parity refinement_ (2026-07-14) — decided unified mapper/policy strategy

## Design

### Server Code vs. Configuration

> **Answer these questions FIRST before proceeding with any design.**

| Question | Answer |
|----------|--------|
| Does this modify server Go code or use configuration/policy? | **Both.** Policy *logic* stays in CEL scripts. Generic Go change: two-layer CEL abort API + a **structured `MappingResult` (claims + decision)** on `ClaimMapper` (shaped like `AuthzCheckDecision`), plus transport mapping of decisions to OAuth responses. |
| If server code: is the change generic (any IdP/vendor/deployment) or specific? | **Generic.** Helpers/decisions carry operator-defined messages and standard OAuth/token-exchange codes (and optional reason). They know nothing about claim names, IdPs, or vendors. Claim names appear only in CEL scripts. |
| Does any proposed server code hardcode claim names, issuer URLs, vendor behaviors, or deployment-specific logic? | **No.** |
| Which existing parsec policy/config layer fits? | **CEL claim mappers**, extended with abort helpers per [RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2) / [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2). Decision shape mirrors `AuthzCheckPolicy` (`Decide` → decision + `error` only for unexpected failures). |
| If none: does this need a new abstraction layer? | **No new policy layer.** Extend the mapper API with a result struct (not a separate `IssuancePolicy`). Ships with the policy-guard demo. |

### Architectural Decision: Unified Mapper/Policy

_This section reflects the team decision from the 2026-07-14 "Gateway feature
parity refinement" meeting. It supersedes the v1 design (separate
`IssuancePolicy` interface) from PR #157._

**Decision**: Merge issuance policy and claim mapping into a single CEL-based
abstraction. The claim mapper becomes the unified layer for both claim
transformation AND policy evaluation.

**Rationale** (from Alec Henninger): The inputs to issuance policy and claim
mapping are nearly identical — both receive the validated `trust.Result`
(subject), actor, and request attributes. Having two separate abstractions
creates redundancy and adds an interface that doesn't carry its weight.

**Why the unified approach works**:

1. The CEL mapper can abort with an OAuth **decision** (not an unexpected
   `error`) returned as part of a structured mapping result. Callers merge
   results across ordered mappers; the first non-allow decision wins.
2. The `MapperInput` already carries `subject`, `actor`, `request` — the
   same inputs an issuance policy would need.
3. A CEL expression naturally composes guards and mapping: check policy
   conditions first, then produce claims. If a guard fails, call an
   OAuth abort helper (error-code or reason helper) that becomes a Deny
   decision on the result.
4. No separate `IssuancePolicy` layer. Extend `ClaimMapper` to return
   claims **and** a decision (same pattern as `AuthzCheckPolicy`).

### Architectural Decision: Structured MappingResult (v2.5 — Alec)

_Supersedes the v2.4 approach of encoding OAuth client outcomes in
`ClaimMappingError` / `error` propagation._

**Problem with err-based OAuth outcomes**: OAuth denial codes
(`invalid_request`, `invalid_target`, …) are **expected** protocol
possibilities, not unexpected failures. Stuffing them into `error`
conflates "policy/RFC outcome" with "something went wrong" — the same
distinction `AuthzCheckPolicy` already draws:

```go
// AuthzCheckPolicy (existing pattern to mirror)
Decide(ctx, in) (AuthzCheckDecision, error)
// error  → evaluation/system failure only
// Decision.Action = issue | allow_without_issue | deny  (expected outcomes)
```

**Decision**: `ClaimMapper.Map` returns a structured result containing
claims **and** a decision. Use `error` only for unexpected failures
(`fail()`, CEL eval bugs, datasource failures, etc.).

```go
// MappingAction is the outcome of a claim mapper evaluation.
type MappingAction string

const (
	MappingAllow MappingAction = "allow"
	MappingDeny  MappingAction = "deny"
)

// MappingDecision is an expected mapper/policy outcome.
// Deny carries OAuth wire fields; Allow leaves them empty.
type MappingDecision struct {
	Action     MappingAction
	OAuthError string // wire "error" when Action == Deny
	Reason     string // machine reason (Layer B); observability
	Message    string // error_description
}

// MappingResult is the return value of ClaimMapper.Map.
type MappingResult struct {
	Claims   claims.Claims
	Decision MappingDecision
}

// Merge encodes ordered multi-mapper composition:
// - claims: merged when both sides Allow (same as today)
// - decision: first non-Allow wins (early-termination friendly)
// Do NOT bury this logic only inside ToClaims — keep it on the result.
func (r MappingResult) Merge(other MappingResult) MappingResult
```

**ClaimMapper interface change**:

```go
type ClaimMapper interface {
	Map(ctx context.Context, input *MapperInput) (MappingResult, error)
}
```

**Multi-mapper semantics** (issuers already have ordered mapper lists):

1. Start with `Allow` + empty claims.
2. For each mapper in order: `Map` → `Merge` into accumulator.
3. **Early termination**: stop calling further mappers when Decision is
   non-Allow (first non-allow wins).
4. `Merge` owns the merge rules so `ToClaims` stays a thin loop.

**Issuer interface — widen with `ExchangeResult`** (v2.6 — Alec PR #169):

v2.5 deferred widening `Issuer.Issue`; v2.6 resolves that: the translation
from Deny to error proved awkward (callers must `errors.As` + check empty
`OAuthError`). Per Alec's PR #169 review, widen the API to distinguish
three explicit outcomes:

1. Success with token
2. Known token-exchange denial (`*ExchangeError`)
3. Unexpected error (`error`)

```go
type ExchangeError struct {
    Message    string         // error_description
    OAuthError OAuthErrorCode // wire "error"
    Reason     AbortReason    // optional Layer B
}

type ExchangeResult struct {
    Token *Token
    Error *ExchangeError // non-nil when no token; nil on success
}

// Issuer
Issue(ctx, issueCtx) (ExchangeResult, error)

// TokenService — per-type results; top-level error = abort whole call
IssueTokens(ctx, req) (map[TokenType]ExchangeResult, error)
```

- Top-level `error` = something went wrong; abort (issuer not found, `fail()`, etc.).
- Per type: either `Token` or `ExchangeError` explaining why there is no token.
- ext_authz treats any type's `ExchangeError` as full request denial.
- Transports read `ExchangeResult.Error` directly instead of `errors.As`.

Rename `ClaimMappingError` → `ExchangeError` (token-exchange semantics).

**Shared deny constructors** (v2.6 — Alec PR #169):

Layer A/B OAuth knowledge must not live only in `internal/cel`. Move to
`service` so any mapper implementation can produce correct denials:

```go
type OAuthErrorCode string
type AbortReason string

func DenyOAuth(code OAuthErrorCode, message string) MappingResult
func DenyReason(reason AbortReason, message string) MappingResult
```

The reason→OAuth mapping table (`invalid_audience` → `invalid_target`, etc.)
lives once in `service`. CEL helpers register function names and call
`DenyOAuth` / `DenyReason` via a thin abort error type.

**Distinct CEL abort vs fail** (v2.6 — Alec PR #169):

CEL mapper error handling uses distinct types rather than checking
`OAuthError != ""` on a shared error type:

```go
if err != nil {
    if decision, ok := celhelpers.AbortDecision(err); ok {
        return service.MappingResult{Decision: decision}, nil
    }
    return service.MappingResult{}, err // fail() and unexpected
}
```

**Two-layer OAuth CEL aborts** (v2.4 vocabulary — retained; delivery via Decision):

Primary guidance remains **token exchange / OAuth** error responses
([RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2),
[RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2))
— not raw HTTP names.

RFC 8693:
- Invalid request, or `subject_token` / `actor_token` invalid **or
  unacceptable based on policy** → MUST `error=invalid_request`
- Unwilling/unable to issue for `resource` / `audience` → SHOULD
  `invalid_target`
- Other OAuth error codes MAY be used as appropriate
- `error_description` MAY carry the reason

**Decision: do both layers.** Low-level codes for power/completeness;
reason helpers for correct, ergonomic script authoring.

##### Layer A — OAuth / token-exchange error codes (direct)

Expose CEL functions that map **only** to appropriate protocol error
codes (camelCase in CEL ↔ snake_case in wire `error`):

| CEL function | OAuth `error` | Source |
|--------------|---------------|--------|
| `invalidRequest(message)` | `invalid_request` | RFC 6749 §5.2 / 8693 §2.2.2 |
| `invalidTarget(message)` | `invalid_target` | RFC 8693 §2.2.2 |
| `invalidGrant(message)` | `invalid_grant` | RFC 6749 §5.2 |
| `unauthorizedClient(message)` | `unauthorized_client` | RFC 6749 §5.2 |
| `invalidClient(message)` | `invalid_client` | RFC 6749 §5.2 |
| `unsupportedGrantType(message)` | `unsupported_grant_type` | RFC 6749 §5.2 |
| `invalidScope(message)` | `invalid_scope` | RFC 6749 §5.2 |
| `fail(message)` | _(none)_ | Mapping/system failure → Internal |

Ship the full Layer A set that is meaningful for token exchange (even if
this JIRA’s scripts only use a subset). Do **not** invent non-OAuth HTTP
names (`unauthorized`, `badRequest`, …).

##### Layer B — Reason helpers (map onto Layer A)

Easier to use correctly; richer `error_description` + observability
reason, while still terminating in a Layer A OAuth code:

| CEL reason helper (examples) | Maps to OAuth `error` | Notes |
|------------------------------|----------------------|-------|
| `invalidSubject(message)` | `invalid_request` | Per RFC 8693: bad/unacceptable **subject** token/policy |
| `invalidActor(message)` | `invalid_request` | Same for **actor** token |
| `invalidAudience(message)` | `invalid_target` | Resource/audience refusal (8693) |
| `unsupportedTokenType(message)` | `invalid_request` | Request/token type not usable |

Alec’s sketch used `invalidSubject → invalid_target` as an example of the
*pattern*; this plan maps subject/actor → `invalid_request` to match RFC
8693 §2.2.2 literally. Confirm with Alec if he intended a different code.

CEL abort helpers populate a **Deny** `MappingDecision` (not `error`):
- `OAuthError` — wire `error` (Layer A)
- `Reason` — stable machine reason for metrics/logs (e.g. `invalid_subject`)
- `Message` — human `error_description`

`fail()` remains an **unexpected** path → `error` (Internal). Scripts may
call Layer A or Layer B; Layer B is preferred for guards.

**3scale-parity script choice** (prefer Layer B):

```cel
has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
: !has(subject.claims.idp)
  ? invalidSubject("claim 'idp' is required")
: ...
```

Both become Deny + wire `error=invalid_request` with distinct reasons.

**Ripple clarity through the stack** (v2.5):

```
CEL Layer B invalidSubject() / Layer A invalidRequest()
    → MappingResult{Decision: Deny{OAuthError, Reason, Message}}
    → MappingResult.Merge across ordered mappers (first non-Allow wins)
    → ToClaims: early-stop; translate Deny for Issuer (unchanged Issue API)
    → Exchange: { error, error_description }  (+ reason in logs/metrics)
    → ext_authz: map OAuthError → gRPC → Envoy HTTP
    → spans/logs: mapping.oauth_error=<code> mapping.abort_reason=<reason>

CEL fail() / unexpected eval failure
    → error (not a Decision) → Internal / 500
```

**Scope of this change** (one PR, possibly two commits: abstraction then guards):
- `MappingResult` / `MappingDecision` + `Merge` + `ClaimMapper` signature
- Layer A + Layer B CEL helpers → Deny decisions; `fail()` → error
- Multi-mapper ordered merge + early termination
- Transport mapping of Deny decisions (via thin adapter until Issue widens)
- Observability for `oauth_error` + `abort_reason`
- Policy guards use Layer B (`invalidSubject`)

**Explicitly deferred**: Changing `Issuer.Issue` / `TokenService` return
types to carry `MappingDecision` — revisit after the ToClaims→exchange
translation is in place (Alec).

**Out of scope (much later)**: Broader claim-policy helpers (`requireClaim`,
…), Lua mappers, named global policy registry. Not part of this work.

**What this replaces** (GitHub PR #157):
- ~~`IssuancePolicy` interface~~ → not needed; `ClaimMapper.Map()` + decision handle denial
- ~~`ClaimAssertionPolicy`~~ → not needed; policy logic is in CEL expressions
- ~~`WithIssuancePolicy` option on `TokenService`~~ → not needed; mappers already wired
- ~~`IssuancePolicyDenied` probe method~~ → not needed; Deny decision path is observable
- ~~`IssuancePolicyConfig`~~ → not needed; policy lives in mapper scripts

GitHub PR #157 should be closed (or reworked) once this alternative lands,
per Adam's meeting action item.

### How Policy Works in Unified CEL Mappers

The CEL claim mapper evaluates a script that can both deny and produce
claims. Policy guards preferably call a **Layer B** reason helper (e.g.
`invalidSubject(message)`), which becomes a **Deny** `MappingDecision`
(OAuth `error` + reason). Layer A helpers remain available. `Map` returns
`(MappingResult, error)` — Deny is never an `error`. `ToClaims` merges
ordered mapper results (first non-Allow wins, early stop). For the first
cut, Deny is translated at the Issue boundary into the existing exchange /
ext_authz mapping path without changing `Issuer.Issue`'s signature.

**Flow**:

```
trust.Result (validated claims)
    │
    ▼
CELMapper.Map(ctx, mapperInput) → (MappingResult, error)
    │
    ├──► invalidSubject("...") → Result{Decision: Deny{invalid_request, invalid_subject, msg}}
    ├──► invalidRequest("...") → Result{Decision: Deny{invalid_request, ...}}
    ├──► invalidTarget("...")  → Result{Decision: Deny{invalid_target, ...}}
    ├──► fail("...") / panic   → error  (unexpected → Internal / 500)
    └──► Result{Claims: {...}, Decision: Allow} → merge & issue
                │
                ▼
IssueContext.ToClaims: accumulate.Merge(each); break on non-Allow
```

**Example CEL script with policy guards** (Layer B preferred):

```cel
// Policy: impersonated tokens → invalid_request + reason invalid_subject
has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
// Policy: require IdP claim
: !has(subject.claims.idp)
  ? invalidSubject("claim 'idp' is required")
// Mapping: produce claims
: {
    "identity": buildRHIdentity(subject),
    "entitlements": {}
  }
```

**Per-issuer vs. universal**: Policy checks are in the mapper, which is
per-issuer. Each issuer's CEL script includes the relevant guards. This is
actually correct — different token types may have different policy
requirements. For the 3scale-parity use case, the transaction token and
rh-identity issuers share the same guards, which can be factored into a
shared CEL snippet loaded via `script_file`.

### Approach

Single PR (refactor current branch) covering:

1. **`MappingResult` / `MappingDecision` + `Merge`** on `ClaimMapper`
   (mirror `AuthzCheckDecision` semantics: expected outcomes ≠ `error`)
2. **Layer A** OAuth CEL helpers + **Layer B** reason helpers → Deny
   decisions; `fail()` → `error` only
3. **`ToClaims`**: ordered merge + early termination; translate Deny for
   unchanged `Issuer.Issue` (revisit threading Decision through Issue later)
4. Shared CEL script: 3scale guards via `invalidSubject()`; unsupported
   token type via `unsupportedTokenType()` or `invalidRequest()`
5. Transport mapping + tests + docs

`fail()` remains for mapping/system failures only (not an OAuth decision).

**v2.6 additions**: `DenyOAuth` / `DenyReason` constructors in `service`;
`ExchangeResult` / `ExchangeError` widening of `Issue` / `IssueTokens`;
distinct CEL abort error type.

**Later (not this PR)**: Broader claim helpers (`requireClaim`, …),
Lua mappers, named policy registry — far-future.

### Alternatives Considered

| Alternative | Pros | Cons | Why not |
|-------------|------|------|---------|
| Separate `IssuancePolicy` interface (v1 / PR #157) | Clean separation of concerns; dedicated abstraction | Redundant with mapper inputs; adds interface + config + probe for logic achievable in CEL; team decided against (2026-07-14 meeting) | Superseded by unified approach |
| Keep only `fail()` for policy | Already exists; early draft used it | Overloads system failures; maps to `Internal` | Rejected — need client OAuth errors |
| Single `reject()` for all client denials | Simpler | Ambiguous error code / status | Rejected |
| HTTP-named helpers (`unauthorized`, `badRequest`, …) | Familiar; 3scale 401 mental model | Underspecifies token-exchange contract | Superseded (v2.3+) |
| Layer A only (no reason helpers) | Smaller API | Easy to pick wrong code; weaker observability | Rejected — Alec: do either **or both**; we do both |
| Layer B only (no direct codes) | Ergonomic | Can’t express every OAuth code without growing reason set | Rejected — keep Layer A for completeness |
| Encode OAuth denials in `ClaimMappingError` / `error` (v2.4) | Small delta; already sketched | Conflates expected RFC outcomes with unexpected failures; unlike `AuthzCheckPolicy` | **Superseded (v2.5)** — Alec: structured result + Decision |
| Keep `Issuer.Issue` unchanged (v2.5) | Smaller first cut | Callers must `errors.As` + branch on empty `OAuthError`; implicit contract | **Superseded (v2.6)** — Alec: widen now with `ExchangeResult` |
| Merge decision logic only inside `ToClaims` | Fewer exported types | Harder to reuse/test; hides multi-mapper rules | Rejected — `MappingResult.Merge` owns it |
| gRPC-named helpers | Match ext_authz codes | Wrong primary protocol for exchange | Prefer OAuth codes; derive gRPC |
| Per-validator config (`required_claims` / `rejected_claims` on `jwt_validator`) | Simple, follows `audiences` pattern | Wrong layer: validators establish trust, not policy | Conceptual mismatch |
| Extend `AuthzCheckPolicy` | Existing abstraction | ext_authz only — exchange flow not covered | Incomplete coverage |

### Interface Changes

**`ClaimMapper` changes** (breaking within `internal/`; all implementations updated):

| Change | Package | Notes |
|--------|---------|-------|
| `MappingResult`, `MappingDecision`, `MappingAction` | `internal/service` | Claims + Decision; mirror `AuthzCheckDecision` shape |
| `MappingResult.Merge` | `internal/service` | Ordered claims merge + first non-Allow wins |
| `ClaimMapper.Map` → `(MappingResult, error)` | `internal/service` | `error` = unexpected only |
| CEL Layer A / B helpers | `internal/cel` | Produce Deny decision (CEL still uses abort/err internally; mapper converts) |
| `fail()` | `internal/cel` | Remains unexpected → `error` from `Map` |
| `ToClaims` multi-mapper loop | `internal/service` | Uses `Merge` + early termination; translates Deny for `Issuer` |
| Transport mapping | `internal/server` | Exchange / ext_authz from Deny’s `OAuthError` (via adapter) |
| `ExchangeResult` / `ExchangeError` | `internal/service` | Explicit success-vs-denial-vs-error contract |
| `Issuer.Issue` | `internal/service` | Returns `(ExchangeResult, error)` (v2.6) |
| `TokenService.IssueTokens` | `internal/service` | Returns `(map[TokenType]ExchangeResult, error)` (v2.6) |
| `DenyOAuth` / `DenyReason` | `internal/service` | Shared deny constructors with reason→OAuth mapping |
| `OAuthErrorCode` / `AbortReason` | `internal/service` | Typed string constants |

`ErrClaimMapping` removed; `ExchangeError` replaces `ClaimMappingError`.

### Package Impact

| Package | Change Type | Description |
|---------|------------|-------------|
| `internal/service` | Modified | `MappingResult`/`Decision`/`Merge`; `ClaimMapper` + `ToClaims`; stub/passthrough/request mappers |
| `internal/cel` | Modified | Layer A/B helpers; CELMapper converts OAuth aborts → Deny, `fail` → error |
| `internal/mapper` | Modified | CEL mapper + tests (layers, Merge, early stop, guards) |
| `internal/server` | Modified | Map Deny / OAuth code → exchange body / ext_authz gRPC |
| `configs/scripts/` | Modified | Guards via `invalidSubject` (Layer B) |
| `configs/parsec.yaml` | Modified | Comments for policy-guard pattern |
| `docs/` | Modified | Result/decision model + two-layer abort API + RFC links |

## Implementation Steps

_Single PR on branch `RHCLOUD-47315-Cel-issuance-policy`. Per Adam's meeting
action item: demonstrate the unified mapper/policy alternative (closes
GitHub PR #157)._

v2.4 landed Layer A/B + transport mapping via `ClaimMappingError`. **v2.5
refactors that to `MappingResult`/`MappingDecision` before merge** (Alec).
Policy-guard CEL content stays; the Go delivery mechanism changes.

### PR 1: Structured MappingResult + policy guards (atomic for merge)

#### Step 1: Add `MappingResult` / `MappingDecision` + `Merge`

**Package**: `internal/service`
**Files**: `mapper.go`, `issuer.go` (and tests)
**Status**: Done

1. Add `MappingAction`, `MappingDecision`, `MappingResult`.
2. Implement `MappingResult.Merge`:
   - If receiver Decision is non-Allow → return receiver (first non-allow wins).
   - Else if other is non-Allow → keep receiver claims as-is (or document
     chosen claim policy), take other’s Decision.
   - Else merge claims (existing `claims.Claims.Merge` behavior).
3. Change `ClaimMapper.Map` to `(MappingResult, error)`.
4. Update stub / passthrough / request-attribute mappers → Allow + claims.
5. Rewrite `ToClaims` as a thin ordered loop: `Map` → `Merge` → break on
   non-Allow; on Deny, translate to the temporary Issue-facing adapter
   (see Step 3) so `Issuer.Issue` stays unchanged.

**Key deliverables**:
- Unit tests for `Merge` (allow+allow, allow+deny, deny+* short-circuit)
- All `ClaimMapper` implementors compile against new signature

#### Step 2: CEL Layer A/B → Deny decision; `fail` → error

**Package**: `internal/cel`, `internal/mapper`
**Files**: `mapper_input.go`, `cel_mapper.go` (and tests)
**Status**: Done

1. Keep Layer A / Layer B CEL helper inventory from v2.4.
2. `CELMapper.Map`: OAuth abort helpers → `MappingResult{Decision: Deny{...}}`
   with `error == nil`.
3. `fail()` / true eval failures → `error` (no Deny decision).
4. Table tests: Layer A codes, Layer B code+reason, `fail` is error not Deny.

**Key deliverables**:
- Deny never returned as `Map`’s `error`
- `fail()` never returns a Deny decision

#### Step 3: Translate Deny at Issue boundary; map transports

**Package**: `internal/service`, `internal/server`
**Files**: `issuer.go` / adapter helpers, `oauth_errors.go`, `authz.go`,
`exchange.go` (and tests)
**Status**: Done — `ToClaims` adapts Deny → `ClaimMappingError`; transports unchanged

**Exchange (primary — RFC 8693)**:

| Decision | Response |
|----------|----------|
| Deny `invalid_request` | HTTP 400 + `{ "error": "invalid_request", "error_description": "..." }` |
| Deny `invalid_target` | HTTP 400 + `{ "error": "invalid_target", "error_description": "..." }` |
| Allow | proceed |
| `error` from Map / Issue | Server error (not an OAuth client error body) |

**ext_authz (derived)** — see open question #16:

| Decision / error | gRPC | Typical Envoy HTTP |
|------------------|------|--------------------|
| Deny `invalid_request` | `InvalidArgument` (or `Unauthenticated` for 401) | 400 (or 401) |
| Deny `invalid_target` | `InvalidArgument` | 400 |
| unexpected `error` | `Internal` | 500 |

First cut: `ToClaims` (or a helper beside it) may still surface Deny via a
narrow adapter type for `Issuer`/`TokenService` so server code keeps working.
Document this as temporary; open question #19 covers widening `Issue`.

**Key deliverables**:
- Exchange / ext_authz tests still pass against Decision-driven path
- `fail()` still → Internal
- `oauth_error` + `abort_reason` visible end-to-end

#### Step 4: Multi-mapper early termination tests

**Package**: `internal/service`
**Files**: `mapper_result_test.go`
**Status**: Done

1. Two Allow mappers → claims merged.
2. Allow then Deny → Deny wins; third mapper **not** called.
3. Deny then (would-be) Allow → first Deny wins; second not called.

**Key deliverables**:
- Tests prove Merge + early-stop, not ad-hoc ToClaims logic

#### Step 5: Policy-guarded CEL script with Layer B aborts

**Package**: `configs/scripts/`
**Files**: `redhat_identity.cel`, `deploy/parsec-ephem.yaml`
**Status**: Done (content); verify still correct after refactor

1. `impersonated == true` → `invalidSubject(...)`
2. missing `idp` → `invalidSubject(...)` (console API path)
3. `unsupported_token_type` → `unsupportedTokenType(...)`
4. Produce claims if guards pass; reserve `fail()` for system failures

#### Step 6: TokenService / integration tests

**Package**: `internal/service`, `internal/mapper`
**Status**: Done — Deny→adapter path + CEL Deny unit tests

1. Mapper Deny `invalidSubject` → exchange-compatible `invalid_request` + reason
2. Mapper Allow → tokens issued
3. Multi-mapper Deny early-stop at service level

#### Step 7: Example config + documentation

**Package**: `configs/`, `docs/`, `internal/cel/README.md`, `AGENTS.md`
**Status**: Done — result/decision model documented

Document:
1. `MappingResult` / Decision vs `error` (AuthzCheck parallel)
2. Multi-mapper Merge + early termination
3. Layer A vs Layer B; wire mapping
4. RFC links; Issuer threading deferred (#19)

#### Step 8: Close or supersede GitHub PR #157

**Status**: Done — PR #157 closed (superseded by unified CEL mapper / MappingResult approach)

## Naming

| Entity | Name | Rationale |
|--------|------|-----------|
| Result type | `MappingResult` | Claims + Decision from one mapper |
| Decision type | `MappingDecision` | Parallel to `AuthzCheckDecision` |
| Action type | `MappingAction` | `allow` / `deny` (expected outcomes) |
| Method | `MappingResult.Merge` | Multi-mapper composition + first non-allow |
| CEL Layer A | `invalidRequest`, `invalidTarget`, `invalidGrant`, … | Direct OAuth / token-exchange `error` codes |
| CEL Layer B | `invalidSubject`, `invalidActor`, `invalidAudience`, … | Reason helpers; easier to use correctly |
| CEL function | `fail` | Unexpected mapping/system failure → `error` (retained) |
| Decision fields | `OAuthError`, `Reason`, `Message` | Wire `error`, machine reason, description |
| Adapter (temporary) | `ClaimMappingError` or equiv. | May remain only to bridge Deny → unchanged `Issuer` |
| CEL script | `redhat_identity.cel` | Existing script, extended with policy guards |

## Test Plan

Per `docs/testing.md`: hermetic, no I/O, no mocks, prefer real instances and fakes.

### Unit Tests

| Test | Package | What it verifies |
|------|---------|-----------------|
| `TestMappingResult_Merge/allow_allow_merges_claims` | `internal/service` | Claims merged; Decision stays Allow |
| `TestMappingResult_Merge/first_deny_wins` | `internal/service` | Deny + later Allow → first Deny |
| `TestToClaims/early_stop_on_deny` | `internal/service` | Later mappers not invoked after Deny |
| `TestCELMapper_PolicyGuard/rejects_impersonated_token` | `internal/mapper` | `invalidSubject()` → Deny `invalid_request` + reason; `err == nil` |
| `TestCELMapper_PolicyGuard/accepts_non_impersonated_token` | `internal/mapper` | Non-impersonated → Allow + claims |
| `TestCELMapper_PolicyGuard/rejects_missing_idp` | `internal/mapper` | Deny when `idp` absent |
| `TestCELMapper_PolicyGuard/accepts_with_idp` | `internal/mapper` | Allow + claims |
| `TestCELMapper_LayerA/invalid_request` | `internal/mapper` | Deny `OAuthError=invalid_request`, `err == nil` |
| `TestCELMapper_LayerA/invalid_target` | `internal/mapper` | Deny `OAuthError=invalid_target` |
| `TestCELMapper_LayerB/invalid_subject` | `internal/mapper` | Deny code + reason |
| `TestCELMapper_fail_is_error` | `internal/mapper` | `fail()` → `error`, not Deny |
| `TestTokenService_MapperPolicyRejection/invalid_subject` | `internal/service` | Deny surfaces as exchange `invalid_request` + reason |
| `TestTokenService_MapperPolicyRejection/mapper_succeeds` | `internal/service` | Allow → tokens issued |
| `TestAuthz_IssueResponse/invalid_request_not_internal` | `internal/server` | Deny → derived client gRPC (not Internal) |
| `TestAuthz_IssueResponse/fail_is_internal` | `internal/server` | `fail()` → `Internal` |
| `TestExchange_InvalidRequest` | `internal/server` | body `{error:invalid_request,...}` per RFC 8693 |

### Benchmarks

No new benchmarks. CEL evaluation is already sub-microsecond; adding
guard expressions to existing scripts has negligible overhead.

## Observability

Per `docs/observer-pattern.md`.

### No New Observers or Probes

When a CEL script calls an OAuth abort helper:

1. `CELMapper.Map()` returns `MappingResult{Decision: Deny{...}}`, `err == nil`
2. `ToClaims` merges / early-stops; translates Deny for Issue (first cut)
3. `TokenService.IssueTokens()` reports via existing issuance failure probes
4. Logs/metrics distinguish Deny outcomes from unexpected `error`

When `fail()` / unexpected failure: `Map` returns `error` → Internal path.

**No new probe methods required** for the first cut.

### Metric dimensions vs `result` values (Alec — 2026-07-23)

Current PR code adds **two new OTel metric attributes** on token-issuance
failure:

- `mapping.oauth_error=<wire code>`
- `mapping.abort_reason=<reason>`

alongside the existing `result` / `status` attributes.

**Alec’s feedback** (PR #169, not a thorough review yet; otherwise looked
right): unsure these new dimensions are necessary; **leans toward different
`result` values** instead. Correlated dimensions may not inflate time-series
cost much, but he does not want a pattern of “add a dimension just to reuse
existing result buckets.” No shared decision framework yet for
dimension-vs-result.

**Plan direction (prefer Alec’s lean until contradicted):**

| Signal | Prefer | Avoid as default |
|--------|--------|------------------|
| Metrics | Encode OAuth Deny / mapping failure in **`result`** (bounded enum-like values), e.g. `invalid_request`, `invalid_target`, `mapping_failed` / keep `issuance_failed` for unexpected | New metric dimensions `mapping.oauth_error` / `mapping.abort_reason` on histograms |
| Logs | Structured fields `mapping.oauth_error` / `mapping.abort_reason` remain useful (high cardinality OK in logs) | — |

Concrete follow-up before or just after merge (open question **#22**):

1. Drop `mapping.oauth_error` / `mapping.abort_reason` from the OTel
   `tokenIssuanceProbe` attribute set (keep them in zlog if desired).
2. Map Deny’s `OAuthError` (and optionally Layer B reason) onto distinct
   `result=…` constants — keep the set **bounded** (Layer A codes + one
   internal failure), not free-form script messages.
3. Document the choice in `docs/observer-pattern.md` when the team settles
   a dimension-vs-result rule of thumb.

Do **not** collapse everything to a single soft `policy_denied` if that
hides protocol-useful distinctions already expressed as OAuth codes.

## Security

- [x] Input validation: policy checks are in CEL scripts; claim names and
  values come from configuration, not user input.
- [x] Error handling: Deny `Message` becomes `error_description`; do not
  leak token contents or internal details. Transport layers must not
  stringify unexpected `error`s into OAuth client bodies.
- [x] Credential handling per `docs/CREDENTIAL_DESIGN.md`: no change.
- [x] TLS/mTLS considerations: N/A.
- [x] Error semantics: expected client denials are Decisions (OAuth codes);
  mapping/system failures use `fail()` / `error` (Internal) so infra bugs
  are not returned as `invalid_request`.

## Maintainability

- [x] Constructor pattern: no new constructors or options for `TokenService`.
- [x] Forward compatibility: `ClaimMapper` gains `MappingResult` (internal
  break, all impls updated); `fail()` retained; OAuth helpers additive;
  `Issuer.Issue` unchanged in first cut.
- [x] Config vs. domain separation: claim names are in CEL scripts
  (configuration); the mapper runtime is generic Go code.
- [x] Interface-driven: `ClaimMapper` implementations (CEL, passthrough,
  stub, request_attributes) all return `MappingResult`.
- [x] Decision merge logic lives on `MappingResult.Merge`, not buried in
  `ToClaims`.
- [x] Downstream app-interface: after merge, use OAuth abort helpers in
  script guards (see Configuration Impact).

## Configuration Impact

> **Fail-safe rule**: See [config-constraints.md](config-constraints.md).
> All config changes must be backward compatible.

### Backward Compatibility

| Changed Artifact | Type | Default / When Absent | Behavior When Absent |
|------------------|------|----------------------|----------------------|
| CEL script guards | Script content | No guards in script | No policy enforcement — all issuance proceeds as before |
| OAuth abort CEL helpers | Runtime | Ships with this change | Additive; scripts without them unchanged |

- [x] No new config fields in Go structs
- [x] No `panic` or `log.Fatal` on any config state
- [x] Behavior without guards matches previous version exactly
- [x] Abort helpers are additive; `fail()` retained for internal failures

The policy activates only when the CEL script contains guard expressions.
Existing scripts without guards continue to work unchanged.

### Local Config (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| `configs/scripts/redhat_identity.cel` | Modified | Guards via `invalidSubject` (Layer B) |
| `configs/parsec.yaml` | Modified | Update comments to document policy guard pattern |

### Deploy Templates (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| N/A | No changes | No new env vars, mounts, or template changes |

### Downstream app-interface (follow-up required)

> **Action required after merge**: Update the downstream app-interface CEL
> scripts to include policy guard expressions using Layer B helpers
> (e.g. `invalidSubject()`) or Layer A as appropriate. Until updated,
> parsec runs with previous behavior (no policy guards). Scripts that
> still call `fail()` for policy will deny issuance but surface as
> Internal until migrated.
>
> Refer to `.cursor/rules/deploy-config-sync.mdc` for specific paths and
> validation checks for stage and prod environments.

| Environment | What to update |
|-------------|----------------|
| Stage | CEL script(s): impersonation + IdP via `invalidSubject()` |
| Prod | Same as stage, after stage validation |

## Documentation

### New Documentation

| Doc | Path | Purpose |
|-----|------|---------|
| Issuance policy via CEL guards | `docs/issuance-policy.md` | Explains the unified pattern: how to write policy guards in CEL mappers, examples, and future direction |

### Documentation Updates

| Doc | Path | What changes |
|-----|------|-------------|
| CEL README | `internal/cel/README.md` | Policy guards; abort helper → OAuth error → transport table; RFC links |

### Config Examples

Example CEL script showing 3scale-parity policy guards:

```cel
// Policy guards — evaluated before claim mapping.
// Layer B: invalidSubject() → OAuth invalid_request + reason invalid_subject
// (RFC 8693: unacceptable subject token/policy).
// Reserve fail() for mapping/system failures (not an OAuth client error).
// Guard: impersonated tokens (3scale reject_impersonated)
has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
// Guard: require IdP claim (3scale APICAST_ENFORCE_IDP_AUTH)
: !has(subject.claims.idp)
  ? invalidSubject("claim 'idp' is required")
// Mapping: produce claims (only reached if all guards pass)
: {
    "identity": {
      "account_number": safeToString(subject.claims.account_number),
      "org_id": safeToString(subject.claims.org_id),
      "type": "User",
      "user": {
        "username": subject.subject,
        "email": safeToString(subject.claims.email),
        "is_org_admin": hasRole(subject.claims, "admin:org:all")
      },
      "internal": {
        "org_id": safeToString(subject.claims.org_id)
      }
    },
    "entitlements": {}
  }
```

Example YAML config referencing the script:

```yaml
issuers:
  - token_type: "urn:ietf:params:oauth:token-type:txn_token"
    type: stub
    issuer_url: "https://parsec.example.com"
    transaction_context:
      - type: cel
        name: redhat-identity-with-policy
        script_file: ./configs/scripts/redhat_identity.cel
```

## Completeness Checklist

- [x] **Server code vs. configuration gate passed**: policy *logic* in CEL
      scripts; generic two-layer OAuth abort helpers + `MappingResult` +
      transport mapping in Go (no claim/IdP hardcoding).
- [x] No separate `IssuancePolicy` layer — extend `ClaimMapper` with
      structured result (AuthzCheck-shaped), not a new policy interface.
- [x] Single PR: `MappingResult`/`Merge` + Layer A/B + policy-guard demo.
      Broader claim helpers / Lua / named policies out of scope.
- [x] Every acceptance criterion maps to at least one implementation step
- [x] Exported additions are generic (`MappingResult`/`Decision`, Layer A/B,
      OAuth fields)
- [x] `ClaimMapper` returns `(MappingResult, error)`; `error` = unexpected only
- [x] Multi-mapper: ordered merge + first non-Allow wins via `Merge`
- [x] `Issuer.Issue` left unchanged in first cut; revisit (#19)
- [x] Observability: distinguish Deny vs unexpected failure; prefer `result`
      values over new metric dimensions (#22 — Alec lean)
- [x] Test cases cover Merge, early-stop, Layer A/B, guards, exchange +
      ext_authz, `fail` vs Deny
- [x] Security implications addressed (OAuth Deny vs Internal `error`)
- [x] Documentation steps included (result model + two-layer API + RFCs)
- [x] Config impact assessed: no Go config fields; script content updates
- [x] All config changes are fail-safe (absent guards = previous behavior)
- [x] Downstream app-interface script update called out as a follow-up
- [x] Each step is a reviewable, self-contained unit
- [x] Plan can be executed top-to-bottom without ambiguity

## Risks & Open Questions

| # | Item | Status | Resolution |
|---|------|--------|------------|
| 1 | v1 placed checks in validator layer. Alec: "validators establish trusted claims, not policy over issuance." | Resolved | v1 PR #157 moved to `IssuancePolicy` on `TokenService`. v2 moves further: policy lives in CEL mappers, no separate abstraction. |
| 2 | Alec mentioned "issuer policy" as a discussed concept with Jozef for other use cases. Does `IssuancePolicy` align with that vision? | Resolved | 2026-07-14 meeting: team decided to unify issuance policy with claim mappers. No separate `IssuancePolicy` interface. |
| 3 | `TokenService.NewTokenService` changes. | Resolved (moot) | v2 makes no changes to `TokenService`. |
| 4 | `AuthzCheckPolicy` overlap: ext_authz flow would have had TWO policy checkpoints. | Resolved (moot) | v2 has no separate issuance policy checkpoint. Mapper guards handle it. |
| 5 | Should `IssuancePolicy.Evaluate` also receive `actor` and `request`? | Resolved (moot) | Mappers already receive all three via `MapperInput`. |
| 6 | Future: CEL-based `IssuancePolicy` implementation. | Resolved | The unified approach IS the CEL-based policy — no separate interface needed. |
| 7 | `rejected_claims` value comparison uses `reflect.DeepEqual`. | Resolved (moot) | v2 uses CEL's native `==` operator for value comparison. |
| 8 | Error messages differ from 3scale. | Resolved | Abort messages are operator-defined (`error_description`). |
| 9 | Per-issuer vs. universal policy guards — each issuer's mapper needs the same guards. Is this redundant? | **Resolved** | Alec: OK for now; per-issuer is more expressive. Share via `script_file` today. Disregard further for this work. |
| 10 | `fail()` is too generic — policy vs system failures; all `IssueTokens` errors map to Internal. | **Resolved (v2.5)** | OAuth denials are `MappingDecision` (Deny). `fail()` / unexpected → `error` only. Transport maps Deny → OAuth body; `error` → Internal. |
| 11 | Broader claim helpers / Lua / named policy registry. | Out of scope | Much later. Layer B reason helpers in this PR are the abort ergonomics; not full `requireClaim`-style policy DSL. |
| 12 | GitHub PR #157 disposition. | **Resolved** | PR #157 closed; superseded by unified CEL mapper / MappingResult approach (this PR). |
| 13 | 401 vs 403 for policy denials (HTTP-named helpers). | **Superseded** | Primary vocabulary is OAuth `error`. See #16. |
| 14 | Couples CEL surface to HTTP vocabulary. | **Superseded** | CEL surface is OAuth codes (+ reasons); HTTP/gRPC derived. |
| 15 | Should `fail()` be renamed to `internalError()` for symmetry? | Open | Prefer keep `fail()` for backward compatibility. |
| 16 | ext_authz / 3scale HTTP for `invalid_request` — OAuth typically **400**; 3scale used **401**. | Open | Exchange follows RFC (400 + `invalid_request`). ext_authz: default `InvalidArgument` (400) unless product wants `Unauthenticated` (401). |
| 17 | Alec example `invalidSubject → invalid_target` vs RFC 8693 subject → `invalid_request`. | Open | Plan uses RFC mapping (`invalidSubject` → `invalid_request`). Confirm with Alec. |
| 18 | Exact Layer A/B function inventory (which OAuth codes / reasons to ship in v1). | Open | Plan lists a full Layer A set + initial Layer B set; trim if review wants a smaller first cut. |
| 19 | **NEW (v2.5)**: Should `Issuer.Issue` / `TokenService` return `MappingDecision`? | **Resolved (v2.6)** | Alec (PR #169): yes, widen now. `Issue` → `(ExchangeResult, error)`; `IssueTokens` → `(map[TokenType]ExchangeResult, error)`. Rename `ClaimMappingError` → `ExchangeError`. |
| 20 | **NEW (v2.5)**: On Deny, discard later mappers’ claims — also discard claims already merged from earlier Allows? | **Resolved (v2.6)** | Alec (PR #169): clear claims on deny merge. `Merge` returns `MappingResult{Decision: d}` with no claims. Implemented. |
| 21 | **NEW (v2.5)**: Other multi-mapper concerns Alec flagged beyond first-non-allow. | Open | Start with first non-Allow wins + early stop; revisit if more merge rules needed. |
| 22 | **NEW (2026-07-23)**: New metric dimensions `mapping.oauth_error` / `mapping.abort_reason` vs distinct `result` values. | Open | Alec (PR #169): lean toward **`result` values**, not new dimensions; no decision framework yet. Plan prefers dropping those attrs from OTel histograms; keep richer detail in logs. Small code follow-up on the PR. |
| 23 | **NEW (v2.6)**: Name: `ExchangeResult` vs `IssueResult`. | Open | Prefer Alec’s `ExchangeResult`. |
| 24 | **NEW (v2.6)**: Layer A/B mapping table in `service` vs new package. | Resolved | In `service` next to `DenyOAuth` / `DenyReason` (Alec pointed at `service`). |

## Review Log

| Date | Reviewer | Feedback | Changes Made |
|------|----------|----------|--------------|
| 2026-07-08 | — | Initial draft (v1) — placed checks in jwt_validator | — |
| 2026-07-09 | Alec | Layer misplacement: validators are trust, not policy. Suggested pre-issuance policy, claims mapper, or new issuer policy layer. "Any time you see server go code referencing a specific claim for sso.redhat.com it is an immediate red flag." | Complete redesign: moved from trust/validator to new `IssuancePolicy` on `TokenService`. PR #157 created. |
| 2026-07-14 | Team (Alec, Jozef, Daniel, Adam, others) | Meeting: "Gateway feature parity refinement". Decision: merge issuance policy and claim mapping abstractions using CEL. Separate `IssuancePolicy` interface is redundant — `ClaimMapper` + `fail()` already handles rejection. | **v2 complete rewrite**: eliminated `IssuancePolicy` interface, `ClaimAssertionPolicy`, all related Go code. Policy is now CEL script guards in claim mappers. PR #157 to be closed. |
| 2026-07-16 | Jozef | Risk 10 is real: `fail()` is too generic (policy vs future system failures); want a `reject()` sibling that marks policy denial and returns a corresponding status code. | **v2.1**: Introduced typed policy denial concept; later superseded by OAuth-coded aborts. |
| 2026-07-16 | Alec | (1) Assumed `fail` would get typed failure siblings. (2) Risk 9 OK for now. (3) Keep ClaimMapper name. (4) Prefer token exchange / OAuth errors over HTTP names; ripple through the stack. (5) **Either or both**: direct OAuth-code helpers (`invalid_request`, `invalid_target`, `invalid_grant`, …) **and/or** reason helpers (e.g. `invalidSubject(...)`) that map to those codes with richer description/observability. | **v2.4**: Two-layer API — Layer A (OAuth codes) + Layer B (reason helpers); `OAuthError`+`Reason`; scripts prefer `invalidSubject`; open #17 (subject→`invalid_request` vs Alec’s `invalid_target` example), #16 (ext_authz 400 vs 401), #18 (inventory size). |
| 2026-07-20 | Alec | Use a structured result (like `AuthzCheckPolicy` / `AuthzCheckDecision`), not `error`, for expected OAuth outcomes. `error` only for unexpected failures. Return claims + Decision from mappers. Start without changing `Issuer.Issue`; translate Deny to token-exchange responses and revisit threading Decision through Issue. Multi-mapper: ordered merges as today, also merge decisions; first non-Allow wins + early termination; put that in `MappingResult.Merge`, not only in `ToClaims`. | **v2.5**: Redesign around `MappingResult`/`MappingDecision`/`Merge`; CEL Layer A/B → Deny; `fail` → error; Issuer unchanged initially (#19); open #20–#21 for merge edge cases. Implementation steps reset to Pending for the refactor. |
| 2026-07-23 | Alec | PR #169 skim: seemed right. Unsure new metric dimensions are necessary; leans toward different **`result` values** instead of adding dimensions to reuse existing buckets. Correlated dims may be cheap, but no good decision framework yet for dimension-vs-result. | **Plan iterate**: Observability section + open **#22** — prefer `result` enum for metrics; keep oauth/reason detail in logs; small OTel probe follow-up on the PR. |
| 2026-07-24 | Alec | PR #169 inline review (5 threads): (1) Widen `Issue`/`IssueTokens` with explicit `ExchangeResult`; rename `ClaimMappingError` → `ExchangeError`. (2) Clear claims on Deny merge. (3) Move Layer A/B OAuth knowledge from CEL to `service` (`DenyOAuth`/`DenyReason`). (4) Distinct abort error type vs `fail()`; `AbortDecision(err)`. (5) ext_authz: any token-type denial denies whole request. | **v2.6**: Widen Issue/IssueTokens (#19 resolved); clear claims on deny (#20 resolved); `DenyOAuth`/`DenyReason` + reason→code map in service; distinct CEL abort type; `ExchangeResult`/`ExchangeError`. |
