package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestTokenService_IssueTokens_Observability(t *testing.T) {
	ctx := context.Background()

	t.Run("successful issuance calls probe methods in correct order", func(t *testing.T) {
		// Setup
		fakeObs := NewFakeObserver(t)
		subject := &trust.Result{Subject: "user-123", TrustDomain: "prod"}
		actor := &trust.Result{Subject: "workload-456", TrustDomain: "prod"}

		stubToken := &Token{
			Value:     "token-value",
			Type:      string(TokenTypeTransactionToken),
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		issuer := &testIssuerStub{token: stubToken}
		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, issuer)

		service := NewTokenService("trust.example.com", nil, registry, fakeObs)

		// Execute
		req := &IssueRequest{
			Subject:    subject,
			Actor:      actor,
			Scope:      "read write",
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		}

		tokens, err := service.IssueTokens(ctx, req)

		// Verify business logic succeeded
		if err != nil {
			t.Fatalf("IssueTokens failed: %v", err)
		}
		if len(tokens) != 1 {
			t.Fatalf("expected 1 token, got %d", len(tokens))
		}

		// Verify observer saw probe started with correct parameters and method sequence
		p := fakeObs.AssertSingleProbe("TokenIssuanceStarted", map[string]any{
			"subject": subject,
			"actor":   actor,
			"scope":   "read write",
		})

		p.AssertProbeSequence(
			ProbeCall("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
			ProbeCall("TokenTypeIssuanceSucceeded", TokenTypeTransactionToken, stubToken),
			"End",
		)
	})

	t.Run("issuer not found calls probe correctly", func(t *testing.T) {
		fakeObs := NewFakeObserver(t)
		registry := NewSimpleRegistry() // Empty registry - no issuers

		service := NewTokenService("trust.example.com", nil, registry, fakeObs)

		req := &IssueRequest{
			Subject:    &trust.Result{Subject: "user-123"},
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		}

		_, err := service.IssueTokens(ctx, req)

		// Verify business logic failed as expected
		if err == nil {
			t.Fatal("expected error when issuer not found")
		}

		// Verify observer saw probe with correct method sequence including error
		p := fakeObs.AssertSingleProbe("TokenIssuanceStarted", nil)
		p.AssertProbeSequence(
			ProbeCall("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
			ProbeCall("IssuerNotFound", TokenTypeTransactionToken, ErrorContaining("no issuer")),
			"End",
		)
	})

	t.Run("token issuance failure calls probe correctly", func(t *testing.T) {
		fakeObs := NewFakeObserver(t)
		issueErr := errors.New("signing failed")
		issuer := &testIssuerStub{err: issueErr}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, issuer)

		service := NewTokenService("trust.example.com", nil, registry, fakeObs)

		req := &IssueRequest{
			Subject:    &trust.Result{Subject: "user-123"},
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		}

		_, err := service.IssueTokens(ctx, req)

		// Verify business logic failed as expected
		if err == nil {
			t.Fatal("expected error when token issuance fails")
		}

		// Verify observer saw probe with correct method sequence including error
		p := fakeObs.AssertSingleProbe("TokenIssuanceStarted", nil)
		p.AssertProbeSequence(
			ProbeCall("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
			ProbeCall("TokenTypeIssuanceFailed", TokenTypeTransactionToken, issueErr),
			"End",
		)
	})

	t.Run("multiple token types are observed independently", func(t *testing.T) {
		fakeObs := NewFakeObserver(t)

		token1 := &Token{Value: "token1", Type: string(TokenTypeTransactionToken)}
		token2 := &Token{Value: "token2", Type: string(TokenTypeAccessToken)}

		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, &testIssuerStub{token: token1})
		registry.Register(TokenTypeAccessToken, &testIssuerStub{token: token2})

		service := NewTokenService("trust.example.com", nil, registry, fakeObs)

		req := &IssueRequest{
			Subject:    &trust.Result{Subject: "user-123"},
			TokenTypes: []TokenType{TokenTypeTransactionToken, TokenTypeAccessToken},
		}

		_, err := service.IssueTokens(ctx, req)
		if err != nil {
			t.Fatalf("IssueTokens failed: %v", err)
		}

		// Verify observer saw probe with correct method sequence
		// Should have: (Started + Succeeded) * 2 + End = 5 calls
		p := fakeObs.AssertSingleProbe("TokenIssuanceStarted", nil)
		p.AssertProbeSequence(
			ProbeCall("TokenTypeIssuanceStarted", TokenTypeTransactionToken),
			ProbeCall("TokenTypeIssuanceSucceeded", TokenTypeTransactionToken, token1),
			ProbeCall("TokenTypeIssuanceStarted", TokenTypeAccessToken),
			ProbeCall("TokenTypeIssuanceSucceeded", TokenTypeAccessToken, token2),
			"End",
		)
	})

}

func TestTokenService_MapperPolicyRejection(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid_subject", func(t *testing.T) {
		exchErr := &ExchangeError{
			Message:    "impersonated tokens are not accepted",
			OAuthError: OAuthInvalidRequest,
			Reason:     AbortReasonInvalidSubject,
		}
		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, &testIssuerStub{exchErr: exchErr})
		svc := NewTokenService("trust.example.com", nil, registry, nil)

		results, err := svc.IssueTokens(ctx, &IssueRequest{
			Subject:    &trust.Result{Subject: "user-1", Claims: claims.Claims{"impersonated": true}},
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		})
		if err != nil {
			t.Fatalf("unexpected top-level error: %v", err)
		}
		r := results[TokenTypeTransactionToken]
		if r.Error == nil {
			t.Fatal("expected ExchangeError")
		}
		if r.Error.OAuthError != OAuthInvalidRequest {
			t.Errorf("OAuthErrorCode: got %q", r.Error.OAuthError)
		}
		if r.Error.Reason != AbortReasonInvalidSubject {
			t.Errorf("AbortReason: got %q", r.Error.Reason)
		}
	})

	t.Run("mapper_succeeds", func(t *testing.T) {
		token := &Token{Value: "ok", Type: string(TokenTypeTransactionToken)}
		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, &testIssuerStub{token: token})
		svc := NewTokenService("trust.example.com", nil, registry, nil)

		results, err := svc.IssueTokens(ctx, &IssueRequest{
			Subject:    &trust.Result{Subject: "user-1"},
			TokenTypes: []TokenType{TokenTypeTransactionToken},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if results[TokenTypeTransactionToken].Token.Value != "ok" {
			t.Errorf("unexpected token: %+v", results)
		}
	})

	t.Run("one_issuer_denies_among_multiple_issuers", func(t *testing.T) {
		exchErr := &ExchangeError{
			Message:    "claim 'idp' is required",
			OAuthError: OAuthInvalidRequest,
			Reason:     AbortReasonInvalidSubject,
		}
		registry := NewSimpleRegistry()
		registry.Register(TokenTypeTransactionToken, &testIssuerStub{
			token: &Token{Value: "txn", Type: string(TokenTypeTransactionToken)},
		})
		registry.Register(TokenTypeAccessToken, &testIssuerStub{exchErr: exchErr})
		svc := NewTokenService("trust.example.com", nil, registry, nil)

		results, err := svc.IssueTokens(ctx, &IssueRequest{
			Subject:    &trust.Result{Subject: "user-1"},
			TokenTypes: []TokenType{TokenTypeTransactionToken, TokenTypeAccessToken},
		})
		if err != nil {
			t.Fatalf("unexpected top-level error: %v", err)
		}
		txnResult := results[TokenTypeTransactionToken]
		if txnResult.Token == nil {
			t.Error("expected transaction token to succeed")
		}
		accessResult := results[TokenTypeAccessToken]
		if accessResult.Error == nil {
			t.Fatal("expected ExchangeError for access token")
		}
		if accessResult.Error.OAuthError != OAuthInvalidRequest {
			t.Errorf("OAuthErrorCode: got %q", accessResult.Error.OAuthError)
		}
	})
}

// testIssuerStub is a simple stub issuer for testing
type testIssuerStub struct {
	token    *Token
	err      error
	exchErr  *ExchangeError
}

func (i *testIssuerStub) Issue(ctx context.Context, issueCtx *IssueContext) (ExchangeResult, error) {
	if i.err != nil {
		return ExchangeResult{}, i.err
	}
	if i.exchErr != nil {
		return ExchangeResult{Error: i.exchErr}, nil
	}
	return ExchangeResult{Token: i.token}, nil
}

func (i *testIssuerStub) PublicKeys(ctx context.Context) ([]PublicKey, error) {
	return nil, nil
}
