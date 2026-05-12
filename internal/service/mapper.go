package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

var (
	// ErrClaimMapping is returned when a claim mapper rejects the input
	ErrClaimMapping = errors.New("claim mapping failed")
)

// MappingFailureKind distinguishes categories of claim-mapping failures.
type MappingFailureKind string

const (
	// MappingFailureInvalid means the input was not usable for this mapper
	// (e.g. unrecognised token type). Returned by the CEL fail() function.
	MappingFailureInvalid MappingFailureKind = "invalid"

	// MappingFailureForbidden means the caller is not permitted to obtain
	// tokens from this mapper. Returned by the CEL forbidden() function.
	MappingFailureForbidden MappingFailureKind = "forbidden"
)

// ClaimMappingError carries detail about a specific claim mapping failure.
// It satisfies errors.Is(err, ErrClaimMapping) via its Is method.
type ClaimMappingError struct {
	Kind    MappingFailureKind
	Message string
}

func (e *ClaimMappingError) Error() string {
	if e.Kind == "" {
		return e.Message
	}
	return fmt.Sprintf("%s (%s)", e.Message, e.Kind)
}

func (e *ClaimMappingError) Is(target error) bool {
	return target == ErrClaimMapping
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
