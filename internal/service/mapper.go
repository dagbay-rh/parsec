package service

import (
	"context"
	"errors"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

var (
	// ErrClaimMapping is returned when claim mapping fails unexpectedly
	// (e.g. CEL fail()), or as a temporary adapter when a Deny decision is
	// translated for Issuer.Issue (which still returns error).
	ErrClaimMapping = errors.New("claim mapping failed")
)

// OAuth / token-exchange error codes (RFC 6749 §5.2, RFC 8693 §2.2.2).
const (
	OAuthInvalidRequest       = "invalid_request"
	OAuthInvalidTarget        = "invalid_target"
	OAuthInvalidGrant         = "invalid_grant"
	OAuthUnauthorizedClient   = "unauthorized_client"
	OAuthInvalidClient        = "invalid_client"
	OAuthUnsupportedGrantType = "unsupported_grant_type"
	OAuthInvalidScope         = "invalid_scope"
)

// Machine-readable abort reasons for Layer B CEL helpers (observability).
const (
	AbortReasonInvalidSubject       = "invalid_subject"
	AbortReasonInvalidActor         = "invalid_actor"
	AbortReasonInvalidAudience      = "invalid_audience"
	AbortReasonUnsupportedTokenType = "unsupported_token_type"
)

// MappingAction is the expected outcome of a claim mapper evaluation.
// Analogous to AuthzCheckAction: denials are normal outcomes, not errors.
type MappingAction string

const (
	// MappingAllow means the mapper contributed claims (or nothing) and
	// issuance may proceed.
	MappingAllow MappingAction = "allow"

	// MappingDeny means the mapper rejected the input with an OAuth client
	// error. This is an expected protocol outcome, not an unexpected failure.
	MappingDeny MappingAction = "deny"
)

// MappingDecision is an expected mapper/policy outcome.
// Deny carries OAuth wire fields; Allow leaves them empty.
type MappingDecision struct {
	Action     MappingAction
	OAuthError string // wire "error" when Action == Deny
	Reason     string // machine reason (Layer B); observability
	Message    string // error_description
}

// IsAllow reports whether the decision permits continuing mapper merge /
// issuance. Empty Action is treated as Allow.
func (d MappingDecision) IsAllow() bool {
	return d.Action == MappingAllow || d.Action == ""
}

// AsClaimMappingError adapts a Deny decision for callers that still use error
// returns (Issuer.Issue). Returns nil when the decision is Allow.
func (d MappingDecision) AsClaimMappingError() *ClaimMappingError {
	if d.IsAllow() {
		return nil
	}
	return &ClaimMappingError{
		Message:    d.Message,
		OAuthError: d.OAuthError,
		Reason:     d.Reason,
	}
}

// MappingResult is the structured return value of ClaimMapper.Map.
// Expected OAuth denials are expressed via Decision; error is reserved for
// unexpected failures (fail(), eval bugs, datasource failures, …).
type MappingResult struct {
	Claims   claims.Claims
	Decision MappingDecision
}

// AllowResult returns an Allow MappingResult with the given claims.
func AllowResult(c claims.Claims) MappingResult {
	return MappingResult{
		Claims:   c,
		Decision: MappingDecision{Action: MappingAllow},
	}
}

// DenyResult returns a Deny MappingResult with OAuth wire fields.
func DenyResult(oauthError, reason, message string) MappingResult {
	return MappingResult{
		Decision: MappingDecision{
			Action:     MappingDeny,
			OAuthError: oauthError,
			Reason:     reason,
			Message:    message,
		},
	}
}

// Merge combines another mapper's result into r (ordered composition).
//
// Rules:
//   - If r is already non-Allow, r is returned unchanged (first non-allow wins).
//   - If other is non-Allow, r's claims are kept and other's Decision is taken.
//   - If both Allow, claims are merged (other overwrites on key conflict).
func (r MappingResult) Merge(other MappingResult) MappingResult {
	if !r.Decision.IsAllow() {
		return r
	}
	if !other.Decision.IsAllow() {
		out := r
		out.Decision = other.Decision
		if out.Decision.Action == "" {
			out.Decision.Action = MappingDeny
		}
		return out
	}

	out := r
	if out.Decision.Action == "" {
		out.Decision.Action = MappingAllow
	}
	if out.Claims == nil {
		out.Claims = make(claims.Claims)
	} else {
		// Copy so Merge does not mutate the receiver's underlying map when
		// callers reuse MappingResult values.
		out.Claims = out.Claims.Copy()
		if out.Claims == nil {
			out.Claims = make(claims.Claims)
		}
	}
	out.Claims.Merge(other.Claims)
	return out
}

// ClaimMappingError carries detail about a mapping failure or a Deny adapted
// for error-returning APIs (Issuer.Issue). It satisfies
// errors.Is(err, ErrClaimMapping) via its Is method.
//
// OAuthError is the wire "error" value for token exchange (empty means an
// internal/mapping failure from fail(), not an OAuth client error). Reason is
// an optional machine-readable abort reason for logs and metrics.
type ClaimMappingError struct {
	Message    string // error_description
	OAuthError string // wire "error" (empty = internal / fail)
	Reason     string // machine reason for observability (may be empty for Layer A)
}

func (e *ClaimMappingError) Error() string {
	return e.Message
}

func (e *ClaimMappingError) Is(target error) bool {
	return target == ErrClaimMapping
}

// OAuthErrorCode returns the OAuth wire error code from err when it wraps a
// ClaimMappingError, or "" otherwise (including fail()-style mapping errors).
func OAuthErrorCode(err error) string {
	var me *ClaimMappingError
	if errors.As(err, &me) {
		return me.OAuthError
	}
	return ""
}

// AbortReason returns the machine-readable abort reason from err when it wraps
// a ClaimMappingError, or "" otherwise.
func AbortReason(err error) string {
	var me *ClaimMappingError
	if errors.As(err, &me) {
		return me.Reason
	}
	return ""
}

// MappingMessage returns the human-readable message from err when it wraps a
// ClaimMappingError, or "" otherwise.
func MappingMessage(err error) string {
	var me *ClaimMappingError
	if errors.As(err, &me) {
		return me.Message
	}
	return ""
}

// ClaimMapper transforms inputs into claims for the token.
// Claim mappers implement policy logic — what information to include in tokens
// and whether issuance should be denied with an OAuth client error.
type ClaimMapper interface {
	// Map produces a MappingResult. Decision carries expected Allow/Deny
	// outcomes; error is only for unexpected failures.
	Map(ctx context.Context, input *MapperInput) (MappingResult, error)
}

// MapperInput contains all inputs available to a claim mapper
type MapperInput struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Actor identity (attested claims from actor credential)
	Actor *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *request.RequestAttributes

	// DataSourceRegistry provides access to data sources for lazy fetching
	// Mappers can fetch only the data sources they need
	DataSourceRegistry *DataSourceRegistry

	// DataSourceInput is the input to use when fetching from data sources
	DataSourceInput *DataSourceInput
}
