# CEL Package

This package provides CEL (Common Expression Language) support for the Parsec token exchange service.

## Overview

CEL is a non-Turing complete expression language designed to be fast, portable, and safe to execute. It's ideal for performance-critical applications where user-provided expressions need to be evaluated safely.

## Custom Functions and Variables

This package provides CEL extensions specifically for claim mapping in Parsec:

### Variables

- **`subject`** - Subject identity information (map)
  - `subject.subject` - Subject identifier
  - `subject.issuer` - Issuer URL
  - `subject.trust_domain` - Trust domain
  - `subject.claims` - Additional claims from the credential
  - `subject.audience` - Intended audience
  - `subject.scope` - OAuth2 scope

- **`actor`** - Actor identity information (map, same structure as subject)

- **`request`** - Request attributes (map)
  - `request.method` - HTTP method
  - `request.path` - Request path
  - `request.ip_address` - Client IP address
  - `request.user_agent` - User agent string
  - `request.headers` - HTTP headers
  - `request.additional` - Additional context

### Functions

- **`datasource(name)`** - Fetches data from a named data source
  - Takes a string argument (datasource name)
  - Returns the fetched data (typically a map or list)
  - Returns null if the datasource doesn't exist
  - Results are automatically cached within a single evaluation

- **`fail(message)`** - Mapping / system failure abort
  - Returns a `ClaimMappingError` with empty `OAuthError`
  - Transports map this to Internal (not an OAuth client error)
  - Prefer Layer A/B helpers for policy denials

#### Layer A — OAuth / token-exchange error codes

Direct helpers for [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) /
[RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2)
wire `error` values:

| CEL | Wire `error` |
|-----|--------------|
| `invalidRequest(message)` | `invalid_request` |
| `invalidTarget(message)` | `invalid_target` |
| `invalidGrant(message)` | `invalid_grant` |
| `unauthorizedClient(message)` | `unauthorized_client` |
| `invalidClient(message)` | `invalid_client` |
| `unsupportedGrantType(message)` | `unsupported_grant_type` |
| `invalidScope(message)` | `invalid_scope` |

#### Layer B — reason helpers (preferred for policy guards)

| CEL | Wire `error` | Reason |
|-----|--------------|--------|
| `invalidSubject(message)` | `invalid_request` | `invalid_subject` |
| `invalidActor(message)` | `invalid_request` | `invalid_actor` |
| `invalidAudience(message)` | `invalid_target` | `invalid_audience` |
| `unsupportedTokenType(message)` | `invalid_request` | `unsupported_token_type` |

### Transport mapping

| `OAuthError` | Exchange (HTTP) | ext_authz (gRPC) |
|--------------|-----------------|------------------|
| `invalid_request` / `invalid_target` / … | 400 + `{error, error_description}` | `InvalidArgument` |
| empty (`fail`) | 500 (default gRPC error JSON) | `Internal` |

See [docs/issuance-policy.md](../../docs/issuance-policy.md) for the full
policy-guard pattern.

## Example CEL Expressions

### Simple Claims from Subject

```cel
{
  "user": subject.subject,
  "domain": subject.trust_domain
}
```

### Conditional Logic

```cel
subject.trust_domain == "prod" 
  ? {"env": "production", "level": "high"} 
  : {"env": "dev", "level": "low"}
```

### Policy Guards (Layer B)

```cel
has(subject.claims) && has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
: !(has(subject.claims) && has(subject.claims.idp))
  ? invalidSubject("claim 'idp' is required")
: { "identity": { /* ... */ }, "entitlements": {} }
```

### Rejecting Unsupported Input

```cel
isSupportedToken(subject.claims)
  ? { "identity": { /* ... */ }, "entitlements": {} }
  : unsupportedTokenType("unsupported_token_type")
```

### Fetching from Data Sources

```cel
{
  "user": subject.subject,
  "roles": datasource("user_roles").roles,
  "region": datasource("geo_lookup").region
}
```

### Deployment Policy via Static Data Sources

Deployment-specific policy (for example Red Hat identity mapping thresholds) belongs in a `static` data source, not top-level parsec config:

```yaml
data_sources:
  - name: identity-policy
    type: static
    data:
      internal_idp_target: "https://sso.redhat.com/auth/realms/internal"
      role_fallback_enabled: true
```

CEL mappers read it like any other datasource:

```cel
subject.claims.idp == datasource("identity-policy").internal_idp_target
```

### Complex Expressions

```cel
{
  "identity": subject.subject + "@" + subject.trust_domain,
  "source_ip": request.ip_address,
  "permissions": datasource("permissions").for_user(subject.subject),
  "is_admin": "admin" in datasource("user_roles").roles
}
```

## Performance Considerations

The CEL mapper compiles and evaluates expressions for each token issuance. While CEL evaluation is very fast (nanoseconds to microseconds), for high-throughput scenarios, consider:

1. Keeping expressions simple and focused
2. Minimizing datasource calls
3. Using caching datasources when appropriate

Datasource results are automatically cached within a single evaluation, so calling the same datasource multiple times in one expression only fetches once.

## References

- [CEL Language Specification](https://github.com/google/cel-spec)
- [CEL-Go Documentation](https://pkg.go.dev/github.com/google/cel-go/cel)
- [CEL-Go Codelab](https://codelabs.developers.google.com/codelabs/cel-go)
- [RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2) — token exchange errors
- [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) — OAuth error response
- [Issuance policy via CEL](../../docs/issuance-policy.md)
