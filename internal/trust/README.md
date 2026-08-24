# Trust Package

This package provides trust management and credential validation for the Parsec token exchange service.

## Components

### Validators

Validators authenticate external credentials and return validation results.

#### JSON Validator

The `JSONValidator` validates unsigned JSON credentials with a well-defined `Result` structure. It supports filtering claims based on configuration.

**Features:**
- Validates JSON structure against the `Result` type
- Filters claims using configurable filters (allow list, deny list, or passthrough)
- Optional trust domain validation
- Optional issuer requirement

**Example:**
```go
// Create a validator with an allow list of claims
validator := NewJSONValidator(
    WithClaimsFilter(NewAllowListClaimsFilter([]string{"email", "role"})),
    WithTrustDomain("production"),
    WithRequireIssuer(true),
)

// Validate a JSON credential
credential := &JSONCredential{
    RawJSON: []byte(`{
        "subject": "user@example.com",
        "issuer": "https://idp.example.com",
        "trust_domain": "production",
        "claims": {"email": "user@example.com", "role": "admin", "internal": "secret"}
    }`),
}

result, err := validator.Validate(ctx, credential)
// result.Claims will only contain "email" and "role"
```

#### Unsigned JSON Validator

The `UnsignedJSONValidator` validates IETF unsigned JSON subject tokens (`urn:ietf:params:oauth:token-type:unsigned_json`). The JSON object MUST contain a string `sub`; other fields become claims. `Result.Issuer` defaults to that URN (a type discriminator, not a vendor domain). `trust_domain` is required and is stamped onto the result.

**Security:** unsigned JSON is an assertion by the authenticated actor. Production deployments must ForActor-filter this validator so only trusted clients (for example a scheduler) can use it. Without a filter, any caller can assert any `sub`.

```go
validator, err := NewUnsignedJSONValidator("parsec.example.com")
credential := &JSONCredential{
    RawJSON: []byte(`{"sub":"redhat:user:sso:123","azp":"scheduler"}`),
}
result, err := validator.Validate(ctx, credential)
// result.Subject == "redhat:user:sso:123"
// result.Issuer == UnsignedJSONTokenTypeURN
```

Claim mappers interpret `sub` namespaces (for example `redhat:user:sso:{user_id}` vs a future `redhat:system:{cn}`). The validator itself accepts any non-empty `sub`.

### Store

The `Store` interface manages trust domains and their associated validators.

#### ForActor Method

The `ForActor` method returns a filtered Store that only includes validators the given actor is allowed to use. This enables actor-based access control for trust validators.

```go
// Get a store filtered for a specific actor
actorResult := &Result{
    Subject: "workload-123",
    TrustDomain: "production",
    Claims: claims.Claims{"role": "service"},
}

filteredStore, err := store.ForActor(ctx, actorResult)
// filteredStore only includes validators this actor is allowed to use
```

#### FilteredStore

The `FilteredStore` implementation uses CEL (Common Expression Language) expressions to filter validators based on actor context.

**Features:**
- Associates names with validators
- Uses CEL scripts to define access policies
- Evaluates policies against actor's Result object

**CEL Variables:**
- `actor` - The actor's Result object as a map (subject, issuer, trust_domain, claims, etc.)
- `validator_name` - The name of the validator being evaluated (string)

**Example:**
```go
// Create a filtered store with a CEL policy
store, err := NewFilteredStore(
    WithCELFilter(`
        (actor.trust_domain == "prod" && validator_name == "prod-validator") ||
        (actor.claims.role == "admin")
    `),
)

// Add named validators
store.AddValidator("prod-validator", prodValidator)
store.AddValidator("dev-validator", devValidator)
store.AddValidator("admin-validator", adminValidator)

// Get filtered store for an actor
prodActor := &Result{
    Subject: "prod-service",
    TrustDomain: "prod",
    Claims: claims.Claims{},
}

filtered, err := store.ForActor(ctx, prodActor)
// filtered only includes "prod-validator"

adminActor := &Result{
    Subject: "admin-user",
    TrustDomain: "admin",
    Claims: claims.Claims{"role": "admin"},
}

filtered, err = store.ForActor(ctx, adminActor)
// filtered includes all validators because of admin role
```

## CEL Policy Examples

### Filter by Trust Domain
```cel
actor.trust_domain == "production" && validator_name in ["prod-validator-1", "prod-validator-2"]
```

### Filter by Role
```cel
actor.claims.role == "admin" || (actor.claims.role == "developer" && validator_name == "dev-validator")
```

### Filter by Issuer
```cel
actor.issuer == "https://trusted-idp.example.com" && validator_name != "untrusted-validator"
```

### Complex Multi-Condition Filter
```cel
(actor.trust_domain == "prod" && actor.claims.service_tier == "premium") ||
(actor.claims.role == "admin") ||
(actor.trust_domain == "dev" && validator_name == "dev-validator")
```

## Testing

All components have comprehensive test coverage:
- `json_validator_test.go` - Tests for JSON validator and claims filters
- `unsigned_json_validator_test.go` - Tests for IETF unsigned JSON subject tokens
- `filtered_store_test.go` - Tests for filtered store and CEL policies

Run tests:
```bash
go test ./internal/trust/...
```

