# RHCLOUD-47315: Reject impersonated tokens and enforce IdP claim presence in JWT validation

**JIRA**: https://redhat.atlassian.net/browse/RHCLOUD-47315
**Status**: Implemented (pending PR) — v2.4 two-layer OAuth aborts
**Author**: AI Assistant
**Date**: 2026-07-08 (v1), 2026-07-14 (v2), 2026-07-16 (v2.1–v2.4)

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
| Does this modify server Go code or use configuration/policy? | **Both.** Policy *logic* stays in CEL scripts. A small **generic** Go change adds a **two-layer** CEL abort API (OAuth error-code helpers + reason helpers) alongside `fail()`, plus typed errors and transport mapping. |
| If server code: is the change generic (any IdP/vendor/deployment) or specific? | **Generic.** Helpers take operator-defined messages and map to standard OAuth/token-exchange error codes (and optional reason). They know nothing about claim names, IdPs, or vendors. Claim names appear only in CEL scripts. |
| Does any proposed server code hardcode claim names, issuer URLs, vendor behaviors, or deployment-specific logic? | **No.** |
| Which existing parsec policy/config layer fits? | **CEL claim mappers**, extended with abort helpers per [RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2) / [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2). |
| If none: does this need a new abstraction layer? | **No new layer.** Focused addition to the mapper CEL library + error/transport mapping. Ships with the policy-guard demo. |

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

1. The CEL mapper can abort evaluation with a typed error that propagates
   through `IssueContext.ToClaims()` → `Issuer.Issue()` →
   `TokenService.IssueTokens()`. That is the policy rejection path.
2. The `MapperInput` already carries `subject`, `actor`, `request` — the
   same inputs an issuance policy would need.
3. A CEL expression naturally composes guards and mapping: check policy
   conditions first, then produce claims. If a guard fails, call an
   OAuth abort (error-code helper or reason helper).
4. No new Go interfaces or abstraction layers. A small extension to the
   existing mapper CEL library makes abort intent unambiguous per the
   protocol parsec implements.

**Two-layer OAuth CEL aborts** (v2.4 — Alec: either or both):

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

Reason helpers set on the error:
- `OAuthError` — wire `error` (Layer A)
- `Reason` — stable machine reason for metrics/logs (e.g. `invalid_subject`)
- `Message` — human `error_description`

Scripts may call Layer A or Layer B; Layer B is preferred for guards.

**3scale-parity script choice** (prefer Layer B):

```cel
has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
: !has(subject.claims.idp)
  ? invalidSubject("claim 'idp' is required")
: ...
```

Both become wire `error=invalid_request` with distinct reasons/descriptions.

**Ripple clarity through the stack**:

```
CEL Layer B invalidSubject() / Layer A invalidRequest() / fail()
    → ClaimMappingError{OAuthError, Reason, Message}
    → Exchange: { error, error_description }  (+ reason in logs/metrics)
    → ext_authz: map OAuthError → gRPC → Envoy HTTP
    → spans/logs: mapping.oauth_error=<code> mapping.abort_reason=<reason>
```

**Scope of this change** (single PR):
- Layer A + Layer B CEL helpers, typed error fields, transport mapping,
  observability for both `oauth_error` and `abort_reason`.
- Policy guards use Layer B (`invalidSubject`); unsupported token type may
  use `unsupportedTokenType` or Layer A `invalidRequest`.
- Local work initially used `fail()` for guards; switch before merge.

**Out of scope (much later)**: Broader claim-policy helpers (`requireClaim`,
…), Lua mappers, named global policy registry. Not part of this work.

**What this replaces** (GitHub PR #157):
- ~~`IssuancePolicy` interface~~ → not needed; `ClaimMapper.Map()` + abort helpers handle denial
- ~~`ClaimAssertionPolicy`~~ → not needed; policy logic is in CEL expressions
- ~~`WithIssuancePolicy` option on `TokenService`~~ → not needed; mappers already wired
- ~~`IssuancePolicyDenied` probe method~~ → not needed; mapper error path already observable; status enables metric distinction
- ~~`IssuancePolicyConfig`~~ → not needed; policy lives in mapper scripts

GitHub PR #157 should be closed (or reworked) once this alternative lands,
per Adam's meeting action item.

### How Policy Works in Unified CEL Mappers

The CEL claim mapper evaluates a script that can both abort and produce
claims. Policy guards preferably call a **Layer B** reason helper (e.g.
`invalidSubject(message)`), which produces a `ClaimMappingError` with
OAuth `error` + reason. Layer A helpers remain available. Errors propagate
through `IssueContext.ToClaims()` → `Issuer.Issue()` →
`TokenService.IssueTokens()`. Transports map `OAuthError` (exchange body;
ext_authz gRPC/HTTP) — not blanket `Internal`.

**Flow**:

```
trust.Result (validated claims)
    │
    ▼
CELMapper.Map(ctx, mapperInput)
    │
    ├──► invalidSubject("...") → {OAuthError: invalid_request, Reason: invalid_subject}
    ├──► invalidRequest("...") → {OAuthError: invalid_request, Reason: ""|invalid_request}
    ├──► invalidTarget("...")  → {OAuthError: invalid_target, ...}
    ├──► fail("...")           → {OAuthError: "", Reason: ""|mapping_failed}
    │                              → Internal / 500
    └──► { claims map } → issuance proceeds
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

Single PR covering:

1. **Layer A** OAuth/token-exchange error CEL helpers + **Layer B** reason
   helpers; `OAuthError` + `Reason` on `ClaimMappingError`; transport mapping
2. Shared CEL script: 3scale guards via `invalidSubject()`; unsupported
   token type via `unsupportedTokenType()` or `invalidRequest()`
3. Tests and docs (both layers, when to use which)

`fail()` remains for mapping/system failures only (not an OAuth `error`).

**Later (not this PR)**: Broader claim helpers (`requireClaim`, …), Lua
mappers, named policy registry — far-future.

### Alternatives Considered

| Alternative | Pros | Cons | Why not |
|-------------|------|------|---------|
| Separate `IssuancePolicy` interface (v1 / PR #157) | Clean separation of concerns; dedicated abstraction | Redundant with mapper inputs; adds interface + config + probe for logic achievable in CEL; team decided against (2026-07-14 meeting) | Superseded by unified approach |
| Keep only `fail()` for policy | Already exists; early draft used it | Overloads system failures; maps to `Internal` | Rejected — need client OAuth errors |
| Single `reject()` for all client denials | Simpler | Ambiguous error code / status | Rejected |
| HTTP-named helpers (`unauthorized`, `badRequest`, …) | Familiar; 3scale 401 mental model | Underspecifies token-exchange contract | Superseded (v2.3+) |
| Layer A only (no reason helpers) | Smaller API | Easy to pick wrong code; weaker observability | Rejected — Alec: do either **or both**; we do both |
| Layer B only (no direct codes) | Ergonomic | Can’t express every OAuth code without growing reason set | Rejected — keep Layer A for completeness |
| gRPC-named helpers | Match ext_authz codes | Wrong primary protocol for exchange | Prefer OAuth codes; derive gRPC |
| Per-validator config (`required_claims` / `rejected_claims` on `jwt_validator`) | Simple, follows `audiences` pattern | Wrong layer: validators establish trust, not policy | Conceptual mismatch |
| Extend `AuthzCheckPolicy` | Existing abstraction | ext_authz only — exchange flow not covered | Incomplete coverage |

### Interface Changes

**No new interfaces.** Small additive changes to existing types/functions:

| Change | Package | Notes |
|--------|---------|-------|
| CEL Layer A helpers | `internal/cel` | Direct OAuth codes (`invalidRequest`, `invalidTarget`, `invalidGrant`, …) |
| CEL Layer B helpers | `internal/cel` | Reason helpers (`invalidSubject`, `invalidActor`, `invalidAudience`, …) |
| `OAuthError` + `Reason` on `ClaimMappingError` | `internal/service` | Wire code + machine reason; `fail()` → empty OAuthError |
| Optional helpers | `internal/service` | e.g. `OAuthErrorCode(err)`, `AbortReason(err)` |
| Mapping in `AuthzServer` / exchange | `internal/server` | Exchange → `{error, error_description}`; ext_authz from `OAuthError`; empty → Internal |

`ClaimMapper` interface unchanged. Existing `errors.Is(..., ErrClaimMapping)`
remains valid for any mapper abort; transports read `OAuthError` (and logs
read `Reason`).

### Package Impact

| Package | Change Type | Description |
|---------|------------|-------------|
| `internal/cel` | Modified | Register Layer A + Layer B abort helpers |
| `internal/service` | Modified | `OAuthError` + `Reason` on `ClaimMappingError` |
| `internal/server` | Modified | Map OAuth error → exchange body / ext_authz gRPC |
| `internal/mapper` | Tests | Cover both layers + policy guards |
| `configs/scripts/` | Modified | Guards via `invalidSubject` (Layer B) |
| `configs/parsec.yaml` | Modified | Comments for policy-guard pattern |
| `docs/` | Modified | Two-layer abort API + RFC links |

## Implementation Steps

_Single PR. Per Adam's meeting action item: demonstrate the unified
mapper/policy alternative (closes GitHub PR #157)._

Impersonation rejection and IdP enforcement via CEL mapper configuration,
plus two-layer OAuth abort helpers (error codes + reason helpers).

_Note: Early local work used `fail()` for guards. Before merge, switch to
Layer B (`invalidSubject`) so we do not ship interim `fail()`-based policy._

#### Step 1: Add two-layer CEL aborts and typed error fields

**Package**: `internal/cel`, `internal/service`
**Files**: `mapper_input.go`, `mapper.go` (and tests)
**Status**: Done

1. **Layer A** — register direct OAuth/token-exchange error helpers next to
   `fail()`: `invalidRequest`, `invalidTarget`, `invalidGrant`,
   `unauthorizedClient`, `invalidClient`, `unsupportedGrantType`,
   `invalidScope` (each sets `OAuthError` to the matching snake_case code).
2. **Layer B** — register reason helpers that set `OAuthError` + `Reason`:
   - `invalidSubject` → `invalid_request` + reason `invalid_subject`
   - `invalidActor` → `invalid_request` + reason `invalid_actor`
   - `invalidAudience` → `invalid_target` + reason `invalid_audience`
   - `unsupportedTokenType` → `invalid_request` + reason `unsupported_token_type`
3. Extend `ClaimMappingError`:

```go
type ClaimMappingError struct {
	Message    string // error_description
	OAuthError string // wire "error" (empty = internal / fail)
	Reason     string // machine reason for observability (may be empty for Layer A)
}
```

4. Preserve `errors.Is(..., ErrClaimMapping)` for all mapper aborts.
5. Helpers: `OAuthErrorCode(err)`, `AbortReason(err)` for transports/probes.
6. Update `UnwrapMappingError` docs; keep CEL wrapping via `types.WrapErr`.

**Backward compatibility**: Additive. `fail()` → empty `OAuthError` (internal).

**Key deliverables**:
- Layer A + Layer B available in mapper CEL env
- Unit tests: Layer A codes; Layer B code+reason pairs

#### Step 2: Map OAuth error at transport boundaries

**Package**: `internal/server`
**Files**: `authz.go`, `exchange.go`, `oauth_errors.go` (and tests)
**Status**: Done

Today `AuthzServer.issueResponse` maps every `IssueTokens` error to
`codes.Internal`. Change:

**Exchange (primary — RFC 8693)**:

| `OAuthError` | Response |
|--------------|----------|
| `invalid_request` | HTTP 400 + `{ "error": "invalid_request", "error_description": "..." }` |
| `invalid_target` | HTTP 400 + `{ "error": "invalid_target", "error_description": "..." }` |
| empty / other | Server error (not an OAuth client error body) |

**ext_authz (derived)** — recommended default map (see open question #16):

| `OAuthError` | gRPC | Typical Envoy HTTP |
|--------------|------|--------------------|
| `invalid_request` | `InvalidArgument` (or `Unauthenticated` if product wants 401) | 400 (or 401) |
| `invalid_target` | `InvalidArgument` | 400 |
| empty | `Internal` | 500 |

1. Unwrap `ClaimMappingError`; branch on `OAuthError`.
2. Exchange: return OAuth error JSON per RFC 6749 §5.2 / 8693 §2.2.2.
3. ext_authz: map to gRPC; expose `Message` as denial detail without leaks.
4. Non-mapping errors remain Internal.

**Key deliverables**:
- Exchange tests for `invalid_request` / `invalid_target` bodies
- ext_authz tests for derived codes
- `fail()` still → Internal
- `oauth_error` + `abort_reason` visible end-to-end

#### Step 3: Policy-guarded CEL script with Layer B aborts

**Package**: `configs/scripts/`
**Files**: `redhat_identity.cel`
**Status**: Done — Layer B guards; IdP required on console API path

1. `impersonated == true` → `invalidSubject(...)`
2. missing `idp` → `invalidSubject(...)`
3. `unsupported_token_type` → `unsupportedTokenType(...)` (or Layer A)
4. Produce claims if guards pass

Reserve `fail()` for true mapping/system failures.

**Key deliverables**:
- Script prefers Layer B reason helpers
- Policy checks clearly separated from mapping logic

#### Step 4: Unit tests for policy guard behavior

**Package**: `internal/mapper`
**Files**: `cel_mapper_test.go` (extend)
**Status**: Done

1. Impersonation / missing idp via `invalidSubject` → code+reason
2. Layer A `invalidTarget` / `fail` → expected fields
3. Passing guards → claims produced
4. Multiple guards → first abort wins
5. Presence/value claim checks behave correctly

**Key deliverables**:
- Table-driven tests for Layer A, Layer B, and guard scenarios

#### Step 5: Integration test — TokenService with policy-guarded mapper

**Package**: `internal/service`
**Files**: `service_test.go` (extend)
**Status**: Done

1. Mapper `invalidSubject` → `IssueTokens` error with `invalid_request` + reason
2. Mapper succeeds → tokens issued
3. Multiple issuers, one mapper aborts → issuance fails with that code

**Key deliverables**:
- Integration tests for error propagation + OAuth code/reason

#### Step 6: Update example config

**Package**: root
**Files**: `configs/parsec.yaml`
**Status**: Done

**Key deliverables**:
- Comments explaining two-layer OAuth abort pattern

#### Step 7: Documentation

**Package**: `docs/`
**Files**: `docs/issuance-policy.md`, `internal/cel/README.md`
**Status**: Done

Document:
1. Policy guard pattern in CEL mappers
2. Layer A vs Layer B tables; when to use which
3. Wire mapping: OAuth `error` → exchange / ext_authz
4. Link RFC 8693 §2.2.2 and RFC 6749 §5.2
5. Comparison with v1; out of scope notes

**Key deliverables**:
- Operator-facing docs with clear two-layer semantics

#### Step 8: Close or supersede GitHub PR #157

**Status**: Pending (after merge)

After this PR merges:
1. Close GitHub PR #157 with a comment explaining the unified approach
2. Reference this PR and the meeting decision

## Naming

| Entity | Name | Rationale |
|--------|------|-----------|
| CEL Layer A | `invalidRequest`, `invalidTarget`, `invalidGrant`, … | Direct OAuth / token-exchange `error` codes |
| CEL Layer B | `invalidSubject`, `invalidActor`, `invalidAudience`, … | Reason helpers; easier to use correctly |
| CEL function | `fail` | Mapping/system failure — not an OAuth client error (retained) |
| Error field | `OAuthError` | Wire `error`; transports derive HTTP/gRPC |
| Error field | `Reason` | Machine reason for observability (`invalid_subject`, …) |
| Error type | `ClaimMappingError` | **Already exists** — extended with `OAuthError` + `Reason` |
| CEL script | `redhat_identity.cel` | Existing script, extended with policy guards |

## Test Plan

Per `docs/testing.md`: hermetic, no I/O, no mocks, prefer real instances and fakes.

### Unit Tests

| Test | Package | What it verifies |
|------|---------|-----------------|
| `TestCELMapper_PolicyGuard/rejects_impersonated_token` | `internal/mapper` | `invalidSubject()` → `invalid_request` + reason `invalid_subject` |
| `TestCELMapper_PolicyGuard/accepts_non_impersonated_token` | `internal/mapper` | Non-impersonated → claims produced |
| `TestCELMapper_PolicyGuard/rejects_missing_idp` | `internal/mapper` | `invalidSubject()` when `idp` absent → same code/reason |
| `TestCELMapper_PolicyGuard/accepts_with_idp` | `internal/mapper` | `idp` present → claims produced |
| `TestCELMapper_PolicyGuard/rejects_first_failing_guard` | `internal/mapper` | Multiple guards, first abort wins |
| `TestCELMapper_PolicyGuard/passes_all_guards` | `internal/mapper` | All guards pass → claims produced |
| `TestCELMapper_LayerA/invalid_request` | `internal/mapper` | `invalidRequest()` → `OAuthError=invalid_request` |
| `TestCELMapper_LayerA/invalid_target` | `internal/mapper` | `invalidTarget()` → `OAuthError=invalid_target` |
| `TestCELMapper_LayerB/invalid_subject` | `internal/mapper` | `invalidSubject()` → code + reason |
| `TestCELMapper_AbortStatus/fail_empty` | `internal/mapper` | `fail()` → empty `OAuthError` |
| `TestTokenService_MapperPolicyRejection/invalid_subject` | `internal/service` | `IssueTokens` carries `invalid_request` + reason |
| `TestTokenService_MapperPolicyRejection/mapper_succeeds` | `internal/service` | `IssueTokens` succeeds when mapper produces claims |
| `TestAuthz_IssueResponse/invalid_request_not_internal` | `internal/server` | `invalid_request` → derived client gRPC (not Internal) |
| `TestAuthz_IssueResponse/fail_is_internal` | `internal/server` | `fail()` → `Internal` |
| `TestExchange_InvalidRequest` | `internal/server` | body `{error:invalid_request,...}` per RFC 8693 |

### Benchmarks

No new benchmarks. CEL evaluation is already sub-microsecond; adding
guard expressions to existing scripts has negligible overhead.

## Observability

Per `docs/observer-pattern.md`.

### No New Observers or Probes

The unified approach uses the **existing** mapper error path. When a CEL
script calls an abort helper or `fail()`:

1. `CELMapper.Map()` returns a `ClaimMappingError` (`OAuthError` + `Reason`)
2. `IssueContext.ToClaims()` propagates the error
3. `Issuer.Issue()` returns the error
4. `TokenService.IssueTokens()` reports via `TokenIssuanceProbe.TokenTypeIssuanceFailed()`

The existing `TokenTypeIssuanceFailed` probe method already:
- Records the error in OTel spans
- Sets the result attribute to error status
- Logs the failure at appropriate level

**No new probe methods required.** Ripple both fields into spans/logs:
- `mapping.oauth_error=<wire code>` (empty for internal/`fail`)
- `mapping.abort_reason=<reason>` when Layer B (or Layer A if we set one)

Do **not** collapse to a single soft `policy_denied`. Attributes stay
generic (OAuth code + reason strings), not claim-specific.

## Security

- [x] Input validation: policy checks are in CEL scripts; claim names and
  values come from configuration, not user input.
- [x] Error handling: abort messages become `error_description`; do not
  leak token contents or internal details. Transport layers must not
  stringify unrelated internal errors into client bodies.
- [x] Credential handling per `docs/CREDENTIAL_DESIGN.md`: no change.
- [x] TLS/mTLS considerations: N/A.
- [x] Error semantics: client aborts use OAuth codes; mapping/system
  failures use `fail()` (Internal) so infra bugs are not returned as
  `invalid_request`.

## Maintainability

- [x] Constructor pattern: no new constructors or options for `TokenService`.
- [x] Forward compatibility: `ClaimMapper` interface unchanged; `fail()`
  retained; OAuth abort helpers are additive.
- [x] Config vs. domain separation: claim names are in CEL scripts
  (configuration); the mapper runtime is generic Go code.
- [x] Interface-driven: `ClaimMapper` already supports multiple
  implementations (CEL, passthrough, stub, request_attributes).
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
      scripts; generic two-layer OAuth abort helpers + transport mapping in Go
      (no claim/IdP hardcoding).
- [x] No new abstraction *layer* — extend existing mapper CEL lib + error type.
- [x] Single PR: Layer A + Layer B + policy-guard demo (no interim `fail()`).
      Broader claim helpers / Lua / named policies out of scope.
- [x] Every acceptance criterion maps to at least one implementation step
- [x] Exported additions are generic (Layer A/B helpers, `OAuthError`,
      `Reason`)
- [x] No new interfaces — uses existing `ClaimMapper`
- [x] Observability: ripple `oauth_error` + `abort_reason` through the stack
- [x] Test cases cover Layer A, Layer B, guards, exchange + ext_authz
- [x] Security implications addressed (OAuth client errors vs Internal)
- [x] Documentation steps included (two-layer API + RFC links)
- [x] Config impact assessed: no Go config fields; script content updates
- [x] All config changes are fail-safe (absent guards = previous behavior)
- [x] Backward compat: scripts without guards / still using `fail()` work;
      in-repo policy uses Layer B before merge
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
| 10 | `fail()` is too generic — policy vs system failures; all `IssueTokens` errors map to Internal. | **Resolved (v2.4)** | Two-layer OAuth aborts (Layer A codes + Layer B reasons) + `OAuthError`/`Reason` + transport mapping. `fail()` = internal only. |
| 11 | Broader claim helpers / Lua / named policy registry. | Out of scope | Much later. Layer B reason helpers in this PR are the abort ergonomics; not full `requireClaim`-style policy DSL. |
| 12 | GitHub PR #157 disposition. | Open | Close after this PR merges. Reference meeting decision in closing comment. |
| 13 | 401 vs 403 for policy denials (HTTP-named helpers). | **Superseded** | Primary vocabulary is OAuth `error`. See #16. |
| 14 | Couples CEL surface to HTTP vocabulary. | **Superseded** | CEL surface is OAuth codes (+ reasons); HTTP/gRPC derived. |
| 15 | Should `fail()` be renamed to `internalError()` for symmetry? | Open | Prefer keep `fail()` for backward compatibility. |
| 16 | ext_authz / 3scale HTTP for `invalid_request` — OAuth typically **400**; 3scale used **401**. | Open | Exchange follows RFC (400 + `invalid_request`). ext_authz: default `InvalidArgument` (400) unless product wants `Unauthenticated` (401). |
| 17 | **NEW**: Alec example `invalidSubject → invalid_target` vs RFC 8693 subject → `invalid_request`. | Open | Plan uses RFC mapping (`invalidSubject` → `invalid_request`). Confirm with Alec. |
| 18 | **NEW**: Exact Layer A/B function inventory (which OAuth codes / reasons to ship in v1). | Open | Plan lists a full Layer A set + initial Layer B set; trim if review wants a smaller first cut. |

## Review Log

| Date | Reviewer | Feedback | Changes Made |
|------|----------|----------|--------------|
| 2026-07-08 | — | Initial draft (v1) — placed checks in jwt_validator | — |
| 2026-07-09 | Alec | Layer misplacement: validators are trust, not policy. Suggested pre-issuance policy, claims mapper, or new issuer policy layer. "Any time you see server go code referencing a specific claim for sso.redhat.com it is an immediate red flag." | Complete redesign: moved from trust/validator to new `IssuancePolicy` on `TokenService`. PR #157 created. |
| 2026-07-14 | Team (Alec, Jozef, Daniel, Adam, others) | Meeting: "Gateway feature parity refinement". Decision: merge issuance policy and claim mapping abstractions using CEL. Separate `IssuancePolicy` interface is redundant — `ClaimMapper` + `fail()` already handles rejection. | **v2 complete rewrite**: eliminated `IssuancePolicy` interface, `ClaimAssertionPolicy`, all related Go code. Policy is now CEL script guards in claim mappers. PR #157 to be closed. |
| 2026-07-16 | Jozef | Risk 10 is real: `fail()` is too generic (policy vs future system failures); want a `reject()` sibling that marks policy denial and returns a corresponding status code. | **v2.1**: Introduced typed policy denial concept; later superseded by OAuth-coded aborts. |
| 2026-07-16 | Alec | (1) Assumed `fail` would get typed failure siblings. (2) Risk 9 OK for now. (3) Keep ClaimMapper name. (4) Prefer token exchange / OAuth errors over HTTP names; ripple through the stack. (5) **Either or both**: direct OAuth-code helpers (`invalid_request`, `invalid_target`, `invalid_grant`, …) **and/or** reason helpers (e.g. `invalidSubject(...)`) that map to those codes with richer description/observability. | **v2.4**: Two-layer API — Layer A (OAuth codes) + Layer B (reason helpers); `OAuthError`+`Reason`; scripts prefer `invalidSubject`; open #17 (subject→`invalid_request` vs Alec’s `invalid_target` example), #16 (ext_authz 400 vs 401), #18 (inventory size). |
