package issuer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestStubIssuer(t *testing.T) {
	ctx := context.Background()

	t.Run("issues token successfully", func(t *testing.T) {
		txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
		reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
		issuer := NewStubIssuer(StubIssuerConfig{
			IssuerURL:                 "https://parsec.example.com",
			TTL:                       5 * time.Minute,
			TransactionContextMappers: txnMappers,
			RequestContextMappers:     reqMappers,
		})

		issueCtx := &service.IssueContext{
			Subject: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "example-domain",
			},
			Audience:           "test-audience",
			DataSourceRegistry: service.NewDataSourceRegistry(),
		}

		result, err := issuer.Issue(ctx, issueCtx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ExchangeErr != nil {
			t.Fatalf("unexpected ExchangeError: %v", result.ExchangeErr)
		}
		token := result.Token

		if token == nil {
			t.Fatal("expected token, got nil")
		}

		if token.Value == "" {
			t.Error("expected non-empty token value")
		}

		if token.Type != "urn:ietf:params:oauth:token-type:txn_token" {
			t.Errorf("expected txn_token type, got %s", token.Type)
		}

		if strings.Contains(token.Value, issueCtx.Subject.Subject) == false {
			t.Error("expected token to contain subject")
		}
	})

	t.Run("token expires after configured TTL", func(t *testing.T) {
		ttl := 10 * time.Minute
		txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
		reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
		issuer := NewStubIssuer(StubIssuerConfig{
			IssuerURL:                 "https://parsec.example.com",
			TTL:                       ttl,
			TransactionContextMappers: txnMappers,
			RequestContextMappers:     reqMappers,
		})

		issueCtx := &service.IssueContext{
			Subject: &trust.Result{
				Subject: "test-user",
			},
			DataSourceRegistry: service.NewDataSourceRegistry(),
		}

		result, err := issuer.Issue(ctx, issueCtx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		token := result.Token

		expectedExpiry := time.Now().Add(ttl)
		diff := token.ExpiresAt.Sub(expectedExpiry)
		if diff > time.Second || diff < -time.Second {
			t.Errorf("expected expiry around %v, got %v (diff: %v)",
				expectedExpiry, token.ExpiresAt, diff)
		}
	})

	t.Run("returns empty public keys for unsigned tokens", func(t *testing.T) {
		issuerURL := "https://parsec.example.com"
		txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
		reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
		issuer := NewStubIssuer(StubIssuerConfig{
			IssuerURL:                 issuerURL,
			TTL:                       5 * time.Minute,
			TransactionContextMappers: txnMappers,
			RequestContextMappers:     reqMappers,
		})

		keys, err := issuer.PublicKeys(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if keys == nil {
			t.Fatal("expected keys slice, got nil")
		}

		// Stub issuer should return empty slice (unsigned tokens)
		if len(keys) != 0 {
			t.Errorf("expected empty keys slice, got %d keys", len(keys))
		}
	})

	t.Run("generates unique token values", func(t *testing.T) {
		// Use a fake clock to deterministically advance time
		clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

		txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
		reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
		issuer := NewStubIssuer(StubIssuerConfig{
			IssuerURL:                 "https://parsec.example.com",
			TTL:                       5 * time.Minute,
			TransactionContextMappers: txnMappers,
			RequestContextMappers:     reqMappers,
			Clock:                     clk,
		})

		issueCtx := &service.IssueContext{
			Subject: &trust.Result{
				Subject: "test-user",
			},
			DataSourceRegistry: service.NewDataSourceRegistry(),
		}

		r1, _ := issuer.Issue(ctx, issueCtx)
		clk.Advance(10 * time.Millisecond)
		r2, _ := issuer.Issue(ctx, issueCtx)

		if r1.Token.Value == r2.Token.Value {
			t.Error("expected unique token values")
		}
	})
}
