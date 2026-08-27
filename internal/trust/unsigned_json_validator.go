package trust

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/project-kessel/parsec/internal/claims"
)

// UnsignedJSONTokenTypeURN is the IETF subject token type for an unsigned JSON
// object (draft-ietf-oauth-transaction-tokens §11.2.2). It is also the default
// Result.Issuer so claim mappers can distinguish this assertion type without
// encoding a vendor domain into the token type.
const UnsignedJSONTokenTypeURN = "urn:ietf:params:oauth:token-type:unsigned_json"

// UnsignedJSONValidator validates IETF unsigned JSON subject tokens.
// The JSON object MUST contain a string "sub" field; remaining fields become claims.
type UnsignedJSONValidator struct {
	credTypes    []CredentialType
	claimsFilter claims.ClaimsFilter
	trustDomain  string
	issuer       string
}

// UnsignedJSONValidatorOption is a functional option for UnsignedJSONValidator.
type UnsignedJSONValidatorOption func(*UnsignedJSONValidator)

// WithUnsignedJSONClaimsFilter sets the claims filter applied to extra JSON fields.
func WithUnsignedJSONClaimsFilter(filter claims.ClaimsFilter) UnsignedJSONValidatorOption {
	return func(v *UnsignedJSONValidator) {
		v.claimsFilter = filter
	}
}

// WithUnsignedJSONIssuer overrides the Result.Issuer stamped onto validated
// results. The zero value is ignored in favor of UnsignedJSONTokenTypeURN.
func WithUnsignedJSONIssuer(issuer string) UnsignedJSONValidatorOption {
	return func(v *UnsignedJSONValidator) {
		v.issuer = issuer
	}
}

// NewUnsignedJSONValidator creates a validator for IETF unsigned JSON credentials.
// trustDomain is required and is stamped onto every successful Result.
func NewUnsignedJSONValidator(trustDomain string, opts ...UnsignedJSONValidatorOption) (*UnsignedJSONValidator, error) {
	if trustDomain == "" {
		return nil, fmt.Errorf("trust domain is required")
	}
	v := &UnsignedJSONValidator{
		credTypes:    []CredentialType{CredentialTypeJSON},
		trustDomain:  trustDomain,
		issuer:       UnsignedJSONTokenTypeURN,
		claimsFilter: &claims.PassthroughClaimsFilter{},
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.issuer == "" {
		v.issuer = UnsignedJSONTokenTypeURN
	}
	if v.claimsFilter == nil {
		v.claimsFilter = &claims.PassthroughClaimsFilter{}
	}
	return v, nil
}

// Validate implements the Validator interface.
func (v *UnsignedJSONValidator) Validate(_ context.Context, credential Credential) (*Result, error) {
	jsonCred, ok := credential.(*JSONCredential)
	if !ok {
		return nil, fmt.Errorf("expected JSONCredential, got %T", credential)
	}

	if len(jsonCred.RawJSON) == 0 {
		return nil, fmt.Errorf("empty JSON credential")
	}

	var obj map[string]any
	if err := json.Unmarshal(jsonCred.RawJSON, &obj); err != nil {
		return nil, fmt.Errorf("failed to parse unsigned JSON credential: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("unsigned JSON credential must be an object")
	}

	subVal, ok := obj["sub"]
	if !ok {
		return nil, fmt.Errorf("sub is required")
	}
	sub, ok := subVal.(string)
	if !ok {
		return nil, fmt.Errorf("sub must be a string")
	}
	if sub == "" {
		return nil, fmt.Errorf("sub is required")
	}

	remaining := make(claims.Claims, len(obj)-1)
	for k, val := range obj {
		if k == "sub" {
			continue
		}
		remaining[k] = val
	}

	return &Result{
		Subject:     sub,
		Issuer:      v.issuer,
		TrustDomain: v.trustDomain,
		Claims:      v.claimsFilter.Filter(remaining),
	}, nil
}

// CredentialTypes implements the Validator interface.
func (v *UnsignedJSONValidator) CredentialTypes() []CredentialType {
	return v.credTypes
}
