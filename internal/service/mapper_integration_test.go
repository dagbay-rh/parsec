package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestTokenService_CELMapperRejection(t *testing.T) {
	t.Parallel()

	newService := func(t *testing.T, celScript string) *service.TokenService {
		t.Helper()
		celMapper, err := mapper.NewCELMapper(celScript)
		if err != nil {
			t.Fatalf("create CEL mapper: %v", err)
		}
		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL:                 "https://parsec.test",
			TTL:                       time.Minute,
			TransactionContextMappers: []service.ClaimMapper{celMapper},
		}))
		return service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), registry, nil)
	}

	t.Run("impersonated_subject_denied", func(t *testing.T) {
		t.Parallel()
		svc := newService(t, `
			has(subject.claims) && has(subject.claims.impersonated) && subject.claims.impersonated
			  ? invalidSubject("impersonated tokens are not accepted")
			  : {"user": subject.subject}
		`)

		results, err := svc.IssueTokens(context.Background(), &service.IssueRequest{
			Subject: &trust.Result{
				Subject: "user-1",
				Claims:  claims.Claims{"impersonated": true},
			},
			TokenTypes: []service.TokenType{service.TokenTypeTransactionToken},
		})
		if err != nil {
			t.Fatalf("unexpected top-level error: %v", err)
		}

		r := results[service.TokenTypeTransactionToken]
		if r.ExchangeErr == nil {
			t.Fatal("expected ExchangeError for impersonated subject")
		}
		if r.ExchangeErr.OAuthError != service.OAuthInvalidRequest {
			t.Errorf("OAuthError: got %q, want %q", r.ExchangeErr.OAuthError, service.OAuthInvalidRequest)
		}
		if r.ExchangeErr.Reason != service.AbortReasonInvalidSubject {
			t.Errorf("AbortReason: got %q, want %q", r.ExchangeErr.Reason, service.AbortReasonInvalidSubject)
		}
	})

	t.Run("non_impersonated_subject_allowed", func(t *testing.T) {
		t.Parallel()
		svc := newService(t, `
			has(subject.claims) && has(subject.claims.impersonated) && subject.claims.impersonated
			  ? invalidSubject("impersonated tokens are not accepted")
			  : {"user": subject.subject}
		`)

		results, err := svc.IssueTokens(context.Background(), &service.IssueRequest{
			Subject:    &trust.Result{Subject: "user-1"},
			TokenTypes: []service.TokenType{service.TokenTypeTransactionToken},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		r := results[service.TokenTypeTransactionToken]
		if r.Token == nil {
			t.Fatal("expected token for non-impersonated subject")
		}
		if r.ExchangeErr != nil {
			t.Errorf("unexpected ExchangeError: %+v", r.ExchangeErr)
		}
	})
}
