package trust

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/httpfixture"
)

const registryURL = "https://registry.example.com/v1/authorization"

func registryFixtureProvider(statusCode int, body string) *httpfixture.FuncProvider {
	return httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.URL.String() == registryURL && req.Method == http.MethodPost {
			return &httpfixture.Fixture{
				StatusCode: statusCode,
				Body:       body,
			}
		}
		return nil
	})
}

func countingFixtureProvider(statusCode int, body string, counter *atomic.Int32) *httpfixture.FuncProvider {
	return httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.URL.String() == registryURL && req.Method == http.MethodPost {
			counter.Add(1)
			return &httpfixture.Fixture{
				StatusCode: statusCode,
				Body:       body,
			}
		}
		return nil
	})
}

func fixtureHTTPClient(provider httpfixture.FixtureProvider) *http.Client {
	return &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}
}

func createRegistryValidator(t *testing.T, provider httpfixture.FixtureProvider, opts ...RegistryValidatorOption) *RegistryValidator {
	t.Helper()

	opts = append([]RegistryValidatorOption{WithHTTPClient(fixtureHTTPClient(provider))}, opts...)

	v, err := NewRegistryValidator(registryURL, "test-domain", `^\d+\|.+$`, opts...)
	if err != nil {
		t.Fatalf("failed to create registry validator: %v", err)
	}
	return v
}

func TestRegistryValidator_SuccessfulValidation(t *testing.T) {
	provider := registryFixtureProvider(200, `{"access":{"pull":"granted"}}`)
	v := createRegistryValidator(t, provider)

	result, err := v.Validate(context.Background(), &BasicAuthCredential{
		Username: "123|alice",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Subject != "alice" {
		t.Errorf("expected subject 'alice', got %q", result.Subject)
	}
	if result.TrustDomain != "test-domain" {
		t.Errorf("expected trust domain 'test-domain', got %q", result.TrustDomain)
	}
	if result.Issuer != registryURL {
		t.Errorf("expected issuer %q, got %q", registryURL, result.Issuer)
	}
	if orgID, ok := result.Claims["org_id"]; !ok || orgID != "123" {
		t.Errorf("expected org_id '123', got %v", result.Claims["org_id"])
	}
	if authType, ok := result.Claims["auth_type"]; !ok || authType != "registry-auth" {
		t.Errorf("expected auth_type 'registry-auth', got %v", result.Claims["auth_type"])
	}
}

func TestRegistryValidator_CredentialTypes(t *testing.T) {
	provider := registryFixtureProvider(200, `{"access":{"pull":"granted"}}`)
	v := createRegistryValidator(t, provider)

	types := v.CredentialTypes()
	if len(types) != 1 || types[0] != CredentialTypeBasicAuth {
		t.Errorf("expected [basic_auth], got %v", types)
	}
}

func TestRegistryValidator_WrongCredentialType(t *testing.T) {
	provider := registryFixtureProvider(200, `{"access":{"pull":"granted"}}`)
	v := createRegistryValidator(t, provider)

	_, err := v.Validate(context.Background(), &BearerCredential{Token: "some-token"})
	if err == nil {
		t.Fatal("expected error for wrong credential type")
	}
}

func TestRegistryValidator_EmptyCredentials(t *testing.T) {
	provider := registryFixtureProvider(200, `{"access":{"pull":"granted"}}`)
	v := createRegistryValidator(t, provider)

	tests := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "secret"},
		{"empty password", "123|alice", ""},
		{"both empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), &BasicAuthCredential{
				Username: tt.username,
				Password: tt.password,
			})
			if err == nil {
				t.Error("expected error for empty credentials")
			}
		})
	}
}

func TestRegistryValidator_UsernamePatternRejection(t *testing.T) {
	provider := registryFixtureProvider(200, `{"access":{"pull":"granted"}}`)
	v := createRegistryValidator(t, provider)

	tests := []struct {
		name      string
		username  string
		wantError bool
	}{
		{"valid pattern", "123|alice", false},
		{"no pipe", "alice", true},
		{"non-numeric org", "abc|alice", true},
		{"numeric org with pipe", "999|bob", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), &BasicAuthCredential{
				Username: tt.username,
				Password: "secret",
			})
			if tt.wantError && err == nil {
				t.Error("expected error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRegistryValidator_RegistryReturnsNon200(t *testing.T) {
	provider := registryFixtureProvider(401, `{"error":"unauthorized"}`)
	v := createRegistryValidator(t, provider)

	_, err := v.Validate(context.Background(), &BasicAuthCredential{
		Username: "123|alice",
		Password: "wrong",
	})
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestRegistryValidator_RegistryDeniesAccess(t *testing.T) {
	provider := registryFixtureProvider(200, `{"access":{"pull":"denied"}}`)
	v := createRegistryValidator(t, provider)

	_, err := v.Validate(context.Background(), &BasicAuthCredential{
		Username: "123|alice",
		Password: "secret",
	})
	if err == nil {
		t.Fatal("expected error for denied access")
	}
}

func TestRegistryValidator_MalformedResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"invalid json", "not json"},
		{"missing access", `{"other":"field"}`},
		{"missing pull", `{"access":{}}`},
		{"empty body", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := registryFixtureProvider(200, tt.body)
			v := createRegistryValidator(t, provider)

			_, err := v.Validate(context.Background(), &BasicAuthCredential{
				Username: "123|alice",
				Password: "secret",
			})
			if err == nil {
				t.Error("expected error for malformed response")
			}
		})
	}
}

func TestRegistryValidator_UsernameParsing(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		wantOrgID string
		wantUser  string
		wantError bool
	}{
		{"standard format", "123|alice", "123", "alice", false},
		{"multiple pipes", "123|alice|extra", "123", "alice|extra", false},
		{"no pipe", "alice", "", "", true},
		{"empty org", "|alice", "", "", true},
		{"empty username", "123|", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orgID, username, err := parseRegistryUsername(tt.username)
			if tt.wantError {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if orgID != tt.wantOrgID {
				t.Errorf("expected orgID %q, got %q", tt.wantOrgID, orgID)
			}
			if username != tt.wantUser {
				t.Errorf("expected username %q, got %q", tt.wantUser, username)
			}
		})
	}
}

func TestRegistryValidator_Caching(t *testing.T) {
	var callCount atomic.Int32
	provider := countingFixtureProvider(200, `{"access":{"pull":"granted"}}`, &callCount)

	clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))
	v := createRegistryValidator(t, provider,
		WithCacheTTL(5*time.Minute),
		WithClock(clk),
	)

	cred := &BasicAuthCredential{Username: "123|alice", Password: "secret"}

	// First call should hit registry
	_, err := v.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("first validate: %v", err)
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", callCount.Load())
	}

	// Second call should use cache
	_, err = v.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("second validate: %v", err)
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 call (cached), got %d", callCount.Load())
	}
}

func TestRegistryValidator_CacheExpiry(t *testing.T) {
	var callCount atomic.Int32
	provider := countingFixtureProvider(200, `{"access":{"pull":"granted"}}`, &callCount)

	clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))
	v := createRegistryValidator(t, provider,
		WithCacheTTL(5*time.Minute),
		WithClock(clk),
	)

	cred := &BasicAuthCredential{Username: "123|alice", Password: "secret"}

	// First call
	_, err := v.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("first validate: %v", err)
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", callCount.Load())
	}

	// Advance past TTL
	clk.Advance(6 * time.Minute)

	// Should hit registry again
	_, err = v.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("validate after expiry: %v", err)
	}
	if callCount.Load() != 2 {
		t.Fatalf("expected 2 calls after cache expiry, got %d", callCount.Load())
	}
}

func TestRegistryValidator_NoCaching(t *testing.T) {
	var callCount atomic.Int32
	provider := countingFixtureProvider(200, `{"access":{"pull":"granted"}}`, &callCount)

	zero := time.Duration(0)
	v := createRegistryValidator(t, provider, WithCacheTTL(zero))

	cred := &BasicAuthCredential{Username: "123|alice", Password: "secret"}

	_, _ = v.Validate(context.Background(), cred)
	_, _ = v.Validate(context.Background(), cred)

	if callCount.Load() != 2 {
		t.Fatalf("expected 2 calls without caching, got %d", callCount.Load())
	}
}

func TestNewRegistryValidator_ConfigValidation(t *testing.T) {
	tests := []struct {
		name            string
		registryURL     string
		trustDomain     string
		usernamePattern string
		wantErr         bool
	}{
		{
			name:            "missing URL",
			registryURL:     "",
			trustDomain:     "test",
			usernamePattern: `^\d+\|.+$`,
			wantErr:         true,
		},
		{
			name:            "missing trust domain",
			registryURL:     "https://example.com",
			trustDomain:     "",
			usernamePattern: `^\d+\|.+$`,
			wantErr:         true,
		},
		{
			name:            "missing username pattern",
			registryURL:     "https://example.com",
			trustDomain:     "test",
			usernamePattern: "",
			wantErr:         true,
		},
		{
			name:            "invalid username pattern",
			registryURL:     "https://example.com",
			trustDomain:     "test",
			usernamePattern: "[invalid",
			wantErr:         true,
		},
		{
			name:            "non-https URL",
			registryURL:     "http://example.com",
			trustDomain:     "test",
			usernamePattern: `^\d+\|.+$`,
			wantErr:         true,
		},
		{
			name:            "valid config",
			registryURL:     "https://example.com",
			trustDomain:     "test",
			usernamePattern: `^\d+\|.+$`,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRegistryValidator(tt.registryURL, tt.trustDomain, tt.usernamePattern)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
