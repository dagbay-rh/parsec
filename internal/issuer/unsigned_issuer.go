package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

var never = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// UnsignedIssuerConfig is the configuration for creating an unsigned issuer
type UnsignedIssuerConfig struct {
	// TokenType is the token type to issue
	TokenType string

	// ClaimMappers are the mappers to apply to generate claims
	ClaimMappers []service.ClaimMapper

	// Clock is the time source for token timestamps
	// If nil, uses system clock
	Clock clock.Clock
}

// UnsignedIssuer issues unsigned tokens containing claim-mapped data
// The token is the base64-encoded JSON representation of the mapped claims
type UnsignedIssuer struct {
	tokenType    string
	claimMappers []service.ClaimMapper
	clock        clock.Clock
}

// NewUnsignedIssuer creates a new unsigned issuer
func NewUnsignedIssuer(cfg UnsignedIssuerConfig) *UnsignedIssuer {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	return &UnsignedIssuer{
		tokenType:    cfg.TokenType,
		claimMappers: cfg.ClaimMappers,
		clock:        clk,
	}
}

// Issue implements the Issuer interface.
// Returns a token containing base64-encoded JSON of the mapped claims.
func (i *UnsignedIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (service.ExchangeResult, error) {
	mappedClaims, exchErr, err := issueCtx.ToClaims(ctx, i.claimMappers)
	if err != nil {
		return service.ExchangeResult{}, fmt.Errorf("failed to map claims: %w", err)
	}
	if exchErr != nil {
		return service.ExchangeResult{Error: exchErr}, nil
	}

	claimsJSON, err := json.Marshal(mappedClaims)
	if err != nil {
		return service.ExchangeResult{}, fmt.Errorf("failed to marshal claims: %w", err)
	}

	encodedToken := base64.StdEncoding.EncodeToString(claimsJSON)

	return service.ExchangeResult{Token: &service.Token{
		Value:     encodedToken,
		Type:      i.tokenType,
		ExpiresAt: never,
		IssuedAt:  i.clock.Now(),
	}}, nil
}

// PublicKeys implements the Issuer interface
// Unsigned issuer returns an empty slice since tokens are not signed
func (i *UnsignedIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	return []service.PublicKey{}, nil
}
