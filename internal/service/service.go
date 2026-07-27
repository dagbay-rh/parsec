package service

import (
	"context"
	"fmt"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// TokenService orchestrates token issuance
// This is the core business logic that brings together data sources
// and issuers to produce tokens
type TokenService struct {
	trustDomain    string
	dataSources    *DataSourceRegistry
	issuerRegistry Registry
	observer       TokenServiceObserver
}

// NewTokenService creates a new token service
func NewTokenService(
	trustDomain string,
	dataSources *DataSourceRegistry,
	issuerRegistry Registry,
	observer TokenServiceObserver,
) *TokenService {
	// Use null object pattern - default to no-op observer if none provided
	if observer == nil {
		observer = NoOpTokenServiceObserver{}
	}
	return &TokenService{
		trustDomain:    trustDomain,
		dataSources:    dataSources,
		issuerRegistry: issuerRegistry,
		observer:       observer,
	}
}

// TrustDomain returns the trust domain for this token service
// The trust domain is used as the audience for all issued tokens
func (ts *TokenService) TrustDomain() string {
	return ts.trustDomain
}

// IssueRequest contains the inputs for token issuance
type IssueRequest struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Actor identity (attested claims from actor credential, e.g., mTLS)
	// May be nil if actor identity is not available
	Actor *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *request.RequestAttributes

	// TokenTypes specifies which token types to issue
	TokenTypes []TokenType

	// Scope for the tokens
	Scope string
}

// IssueTokens orchestrates the complete token issuance process.
// Returns per-type ExchangeResults: each contains either a Token (success) or
// an ExchangeError (known denial). Top-level error is for unexpected failures
// only (issuer not found, signing failures, etc.).
func (ts *TokenService) IssueTokens(ctx context.Context, req *IssueRequest) (map[TokenType]ExchangeResult, error) {
	ctx, p := ts.observer.TokenIssuanceStarted(ctx, req.Subject, req.Actor, req.Scope, req.TokenTypes)
	defer p.End()

	issueCtx := &IssueContext{
		Subject:            req.Subject,
		Actor:              req.Actor,
		RequestAttributes:  req.RequestAttributes,
		Audience:           ts.trustDomain,
		Scope:              req.Scope,
		DataSourceRegistry: ts.dataSources,
	}

	results := make(map[TokenType]ExchangeResult)
	for _, tokenType := range req.TokenTypes {
		p.TokenTypeIssuanceStarted(tokenType)

		iss, err := ts.issuerRegistry.GetIssuer(tokenType)
		if err != nil {
			p.IssuerNotFound(tokenType, err)
			return nil, fmt.Errorf("no issuer for token type %s: %w", tokenType, err)
		}

		result, err := iss.Issue(ctx, issueCtx)
		if err != nil {
			p.TokenTypeIssuanceFailed(tokenType, err)
			return nil, fmt.Errorf("failed to issue %s: %w", tokenType, err)
		}

		if result.Error != nil {
			p.TokenTypeIssuanceFailed(tokenType, result.Error)
		} else {
			p.TokenTypeIssuanceSucceeded(tokenType, result.Token)
		}
		results[tokenType] = result
	}

	return results, nil
}
