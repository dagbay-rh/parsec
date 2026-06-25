# Registry Auth Design

## Overview

Registry auth extends parsec's credential system to authenticate users via HTTP Basic Auth against an external container registry authorization service. It adds a `BasicAuthCredentialSource` for credential extraction and a `RegistryValidator` for validation, reusing the same `CredentialSource` / trust store / CEL mapper pipeline as bearer tokens.

The external registry service is a POST endpoint that accepts `{"credentials":{"username":"...","password":"..."}}` and returns `{"access":{"pull":"granted"}}` on success.

## End-to-End Flow

```
Envoy CheckRequest (Authorization: Basic <base64>)
  |
  v
[BasicAuthCredentialSource.Extract]
  - Decodes base64 → username:password
  - Returns BasicAuthCredential + marks "authorization" header for removal
  |
  v
[TrustStore.Validate]
  - Routes by credential type (basic_auth → RegistryValidator)
  |
  v
[RegistryValidator.Validate]
  - Checks username against regex pattern
  - Checks HMAC-keyed cache → returns cached Result on hit
  - POSTs credentials to registry service
  - Verifies access.pull == "granted"
  - Parses "org_id|username" format
  - Returns trust.Result with org_id and auth_type claims
  |
  v
[AuthzServer.Check]
  - Populates request.Additional:
      credential_source = "authorization_basic_auth"
      credential_type   = "basic_auth"
      auth_time_ms      = <elapsed ms>
  |
  v
[CEL Claim Mapper]
  - Detects registry auth via:
      request.additional.credential_type == "basic_auth"
      && subject.claims.auth_type == "registry-auth"
  - Maps claims into x-rh-identity envelope
  |
  v
[Response]
  - Issued tokens set as response headers
  - Original Authorization header removed (security boundary)
```

## Components

### BasicAuthCredentialSource

Implements `CredentialSource`. Extracts HTTP Basic Auth credentials from the `Authorization` header.

```go
type BasicAuthCredentialSource struct {
    SourceName string  // default: "authorization_basic_auth"
}
```

**Extraction logic:**
1. Read `authorization` header (normalized to lowercase)
2. Split on first space: `scheme value`
3. Case-insensitive check: scheme must be `"basic"`
4. Trim whitespace from value, reject if empty
5. Base64-decode the value
6. Split on first colon: `username:password`
7. Return `CredentialExtraction` with `BasicAuthCredential` and `HeadersToRemove: ["authorization"]`

Returns `nil, nil` when the header is absent or the scheme is not Basic, allowing coexistence with `BearerCredentialSource` in the same source chain.

### RegistryValidator

Validates `BasicAuthCredential` by calling an external registry authorization service over HTTPS.

```go
type RegistryValidator struct {
    url             string
    trustDomain     string
    usernamePattern *regexp.Regexp
    httpClient      *http.Client
    cacheTTL        time.Duration
    cacheHMACKey    []byte        // random 32-byte key, generated at startup
    entries         map[string]*cacheEntry
    clock           clock.Clock
    observer        RegistryValidatorObserver
}
```

**Validation steps:**
1. Type-assert credential to `*BasicAuthCredential`
2. Reject empty username or password
3. Match username against compiled regex pattern
4. Check cache (HMAC-SHA256 keyed on `username:password`)
5. POST `{"credentials":{"username":"...","password":"..."}}` to registry URL
6. Reject non-200 status codes before reading body
7. Read body with `LimitReader` (1 MB max), reject oversized responses
8. Parse JSON response, verify `access.pull == "granted"`
9. Parse username as `org_id|username` (split on first `|`)
10. Build and cache `trust.Result`

**Result claims:**

| Claim | Value | Source |
|-------|-------|--------|
| `org_id` | Parsed from username prefix | `"123\|alice"` → `"123"` |
| `auth_type` | `"registry-auth"` | Hardcoded |

### Username Format

Usernames follow the pattern `org_id|username`:

```
123|alice       → org_id="123", subject="alice"
999|bob         → org_id="999", subject="bob"
123|alice|extra → org_id="123", subject="alice|extra"  (split on first |)
```

The `username_pattern` config validates the raw username before parsing. The default pattern for Red Hat is `^\d+\|.+$` (numeric org ID, pipe, non-empty username).

### Caching

Successful validations are cached to avoid repeated calls to the registry service.

- **Key**: HMAC-SHA256 of `username:password` using a random 32-byte key generated at validator startup. Passwords are never stored in plaintext.
- **TTL**: Configurable, defaults to 5 minutes. Zero or negative disables caching.
- **Eviction**: Expired entries are lazily removed on access. `Cleanup()` can be called periodically for bulk eviction.
- **Scope**: Only successful validations are cached. Failed attempts always hit the registry.

### Credential Type Metadata

The authz server populates `request.Additional` after credential extraction:

```go
reqAttrs.Additional["credential_source"] = ext.SourceName       // "authorization_basic_auth"
reqAttrs.Additional["credential_type"]   = string(ext.Credential.Type()) // "basic_auth"
reqAttrs.Additional["auth_time_ms"]      = time.Since(authStart).Milliseconds()
```

These are flattened to top-level claims by `RequestAttributesMapper` (via `maps.Copy`) and accessible in CEL expressions as `request.additional.credential_source`, `request.additional.credential_type`, etc.

### CEL Integration

Registry auth is detected in CEL mapper expressions using a dual check on credential type and validator-set claims:

```cel
has(request.additional.credential_type)
  && request.additional.credential_type == "basic_auth"
  && has(subject.claims.auth_type)
  && subject.claims.auth_type == "registry-auth"
```

This avoids a dedicated CEL function. `credential_type` is transport-level metadata (how the credential was presented), while `auth_type` is a validator-set claim (what kind of auth the registry service confirmed). Both must match to prevent a bearer token with spoofed claims from being treated as registry auth.

### Observability

`RegistryValidatorObserver` and `RegistryValidateProbe` track validation lifecycle:

| Probe Method | When |
|---|---|
| `RegistryValidateStarted` | Validation begins (returns probe) |
| `UsernamePatternRejected` | Username failed regex |
| `CacheHit` | Cached result returned |
| `RegistryCallFailed(err)` | HTTP call or response parsing failed |
| `AccessDenied` | Registry returned non-200 or pull != "granted" |
| `UsernameParseFailed(err)` | `org_id\|username` parsing failed |
| `End` | Validation complete (deferred) |

## Configuration

```yaml
trust_store:
  type: stub_store
  validators:
    - name: registry-auth
      type: registry_validator
      registry_url: "https://registry.example.com/v1/authorization"
      trust_domain: "registry.example.com"
      username_pattern: "^[0-9]+\\|.+"
      cache_ttl: "5m"          # optional, default 5m
      http_timeout: "10s"      # optional, default 30s
      registry_tls:            # optional
        insecure_skip_verify: false
        sni: "registry.example.com"
        client_cert_path: "./certs/client.crt"
        client_key_path: "./certs/client.key"

credential_sources:
  - name: basic-auth
    type: authorization_basic_auth
  - name: authorization-bearer
    type: authorization_bearer_opaque
```

| Field | Required | Description |
|-------|----------|-------------|
| `registry_url` | Yes | HTTPS URL of the registry authorization service |
| `trust_domain` | Yes | Trust domain assigned to validated results |
| `username_pattern` | Yes | Regex pattern usernames must match |
| `cache_ttl` | No | Cache duration for successful validations (default `5m`, `0` disables) |
| `http_timeout` | No | HTTP client timeout (default `30s`) |
| `registry_tls` | No | TLS configuration for the registry HTTP client |

**Validation at startup:**
- `registry_url` must use `https` scheme and include a host
- `username_pattern` must be a valid regex
- `registry_tls.client_cert_path` and `client_key_path` must both be provided or both omitted

### TLS Client Configuration

When `registry_tls` is configured, the HTTP client's transport is built by cloning the caller's `http.Transport` (or `http.DefaultTransport` as fallback), then overlaying TLS settings. This preserves proxy, connection pooling, and other transport configuration from the parent.

## Security Considerations

- **Credential removal**: The `Authorization` header is stripped from requests forwarded to backends.
- **Cache key security**: Credentials are cached using HMAC-SHA256 with a per-instance random key. No plaintext passwords are stored.
- **HTTPS only**: `registry_url` must use the `https` scheme. Rejected at startup otherwise.
- **Response size limit**: Registry responses are capped at 1 MB to prevent memory exhaustion.
- **Status-first check**: Non-200 responses are rejected before reading the body.
- **mTLS support**: Optional client certificate authentication to the registry service.

## Testing

The `RegistryValidator` uses `httpfixture` for deterministic HTTP tests and `clock.FixtureClock` for time-dependent cache tests. `BasicAuthCredentialSource` is tested with plain `CredentialContext` structs.

Key test scenarios:
- Successful validation with claim extraction
- Username pattern rejection
- Cache hit / cache expiry / cache disabled
- Registry returns non-200 / denies access / returns malformed JSON
- Username parsing edge cases (multiple pipes, empty parts)
- BasicAuth extraction (case-insensitive scheme, invalid base64, coexistence with bearer)
- Credential metadata flows through to issued tokens
