package trust

import (
	"context"
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/claims"
)

func TestNewUnsignedJSONValidator_RequiresTrustDomain(t *testing.T) {
	_, err := NewUnsignedJSONValidator("")
	if err == nil {
		t.Fatal("expected error for empty trust domain")
	}
	if !strings.Contains(err.Error(), "trust domain is required") {
		t.Fatalf("err=%q, want containing %q", err.Error(), "trust domain is required")
	}
}

func TestUnsignedJSONValidator_Validate(t *testing.T) {
	ctx := context.Background()
	validator, err := NewUnsignedJSONValidator("parsec.example.com")
	if err != nil {
		t.Fatalf("NewUnsignedJSONValidator: %v", err)
	}

	tests := []struct {
		name       string
		validator  *UnsignedJSONValidator
		credential Credential
		wantErr    string
		check      func(t *testing.T, result *Result)
	}{
		{
			name:      "valid sub and extra claims",
			validator: validator,
			credential: &JSONCredential{
				RawJSON: []byte(`{"sub":"redhat:user:sso:123","azp":"scheduler"}`),
			},
			check: func(t *testing.T, result *Result) {
				if result.Subject != "redhat:user:sso:123" {
					t.Errorf("Subject=%q, want redhat:user:sso:123", result.Subject)
				}
				if result.Issuer != UnsignedJSONTokenTypeURN {
					t.Errorf("Issuer=%q, want %q", result.Issuer, UnsignedJSONTokenTypeURN)
				}
				if result.TrustDomain != "parsec.example.com" {
					t.Errorf("TrustDomain=%q, want parsec.example.com", result.TrustDomain)
				}
				if result.Claims.GetString("azp") != "scheduler" {
					t.Errorf("claims.azp=%q, want scheduler", result.Claims.GetString("azp"))
				}
				if result.Claims.Has("sub") {
					t.Error("sub must not be duplicated into claims")
				}
			},
		},
		{
			name:      "sub only",
			validator: validator,
			credential: &JSONCredential{
				RawJSON: []byte(`{"sub":"alice"}`),
			},
			check: func(t *testing.T, result *Result) {
				if result.Subject != "alice" {
					t.Errorf("Subject=%q, want alice", result.Subject)
				}
				if result.Claims.Has("sub") {
					t.Error("sub must not be duplicated into claims")
				}
			},
		},
		{
			name: "claims filter",
			validator: mustUnsignedJSONValidator(t, "parsec.example.com",
				WithUnsignedJSONClaimsFilter(claims.NewAllowListClaimsFilter([]string{"azp"}))),
			credential: &JSONCredential{
				RawJSON: []byte(`{"sub":"alice","azp":"scheduler","internal":"secret"}`),
			},
			check: func(t *testing.T, result *Result) {
				if result.Claims.GetString("azp") != "scheduler" {
					t.Errorf("claims.azp=%q, want scheduler", result.Claims.GetString("azp"))
				}
				if result.Claims.Has("internal") {
					t.Error("internal claim should be filtered out")
				}
			},
		},
		{
			name: "issuer override",
			validator: mustUnsignedJSONValidator(t, "parsec.example.com",
				WithUnsignedJSONIssuer("https://scheduler.example.com")),
			credential: &JSONCredential{
				RawJSON: []byte(`{"sub":"alice"}`),
			},
			check: func(t *testing.T, result *Result) {
				if result.Issuer != "https://scheduler.example.com" {
					t.Errorf("Issuer=%q, want https://scheduler.example.com", result.Issuer)
				}
			},
		},
		{
			name:       "empty JSON",
			validator:  validator,
			credential: &JSONCredential{RawJSON: []byte{}},
			wantErr:    "empty JSON credential",
		},
		{
			name:       "null JSON",
			validator:  validator,
			credential: &JSONCredential{RawJSON: []byte(`null`)},
			wantErr:    "must be an object",
		},
		{
			name:       "non-object JSON array",
			validator:  validator,
			credential: &JSONCredential{RawJSON: []byte(`["alice"]`)},
			wantErr:    "failed to parse",
		},
		{
			name:       "invalid JSON",
			validator:  validator,
			credential: &JSONCredential{RawJSON: []byte(`{"sub":`)},
			wantErr:    "failed to parse",
		},
		{
			name:       "JWT compact serialization",
			validator:  validator,
			credential: &JSONCredential{RawJSON: []byte(`eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.`)},
			wantErr:    "failed to parse",
		},
		{
			name:       "missing sub",
			validator:  validator,
			credential: &JSONCredential{RawJSON: []byte(`{"azp":"scheduler"}`)},
			wantErr:    "sub is required",
		},
		{
			name:       "empty sub",
			validator:  validator,
			credential: &JSONCredential{RawJSON: []byte(`{"sub":""}`)},
			wantErr:    "sub is required",
		},
		{
			name:       "non-string sub",
			validator:  validator,
			credential: &JSONCredential{RawJSON: []byte(`{"sub":123}`)},
			wantErr:    "sub must be a string",
		},
		{
			name:       "wrong credential type",
			validator:  validator,
			credential: &BearerCredential{Token: "test-token"},
			wantErr:    "expected JSONCredential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.validator.Validate(ctx, tt.credential)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err=%q, want containing %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected result, got nil")
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestUnsignedJSONValidator_CredentialTypes(t *testing.T) {
	validator, err := NewUnsignedJSONValidator("parsec.example.com")
	if err != nil {
		t.Fatalf("NewUnsignedJSONValidator: %v", err)
	}
	types := validator.CredentialTypes()
	if len(types) != 1 {
		t.Fatalf("expected 1 credential type, got %d", len(types))
	}
	if types[0] != CredentialTypeJSON {
		t.Errorf("expected CredentialTypeJSON, got %s", types[0])
	}
}

func mustUnsignedJSONValidator(t *testing.T, trustDomain string, opts ...UnsignedJSONValidatorOption) *UnsignedJSONValidator {
	t.Helper()
	v, err := NewUnsignedJSONValidator(trustDomain, opts...)
	if err != nil {
		t.Fatalf("NewUnsignedJSONValidator: %v", err)
	}
	return v
}
