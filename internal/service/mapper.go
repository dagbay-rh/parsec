package service

import (
	"context"
	"errors"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

var (
	// ErrClaimMapping is returned when a claim mapper rejects the input
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

// ClaimMappingError carries detail about a specific claim mapping failure.
// It satisfies errors.Is(err, ErrClaimMapping) via its Is method.
//
// OAuthError is the wire "error" value for token exchange (empty means an
// internal/mapping failure, not an OAuth client error). Reason is an optional
// machine-readable abort reason for logs and metrics (typically set by Layer B
// CEL helpers).
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

// ClaimMapper transforms inputs into claims for the token
// Claim mappers implement policy logic - what information to include in tokens
type ClaimMapper interface {
	// Map produces claims based on the input
	// Returns nil if the mapper has no claims to contribute
	Map(ctx context.Context, input *MapperInput) (claims.Claims, error)
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
