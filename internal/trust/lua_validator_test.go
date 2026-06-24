package trust

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	luaservices "github.com/project-kessel/parsec/internal/lua"
)

func TestNewLuaValidator(t *testing.T) {
	tests := []struct {
		name    string
		ctor    func() (*LuaValidator, error)
		wantErr string
	}{
		{
			name: "valid",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("test", `function validate(input) return nil end`, []CredentialType{CredentialTypeBearer})
			},
		},
		{
			name: "missing name",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("", `function validate(input) return nil end`, []CredentialType{CredentialTypeBearer})
			},
			wantErr: "validator name is required",
		},
		{
			name: "missing script",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("test", "", []CredentialType{CredentialTypeBearer})
			},
			wantErr: "script is required",
		},
		{
			name: "missing credential types",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("test", `function validate(input) return nil end`, nil)
			},
			wantErr: "at least one credential type is required",
		},
		{
			name: "missing validate function",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("test", `function other(input) return nil end`, []CredentialType{CredentialTypeBearer})
			},
			wantErr: "script must define a 'validate' function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := tt.ctor()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if validator == nil {
				t.Fatal("expected validator")
			}
		})
	}
}

func TestLuaValidator_Validate(t *testing.T) {
	const script = `
function validate(input)
  if input.credential.type ~= "bearer" then
    error("unexpected credential type")
  end
  if input.credential.token ~= "valid-token" then
    return nil
  end
  return {
    subject = "user@example.com",
    issuer = "https://issuer.example.com",
    trust_domain = "example.com",
    claims = {
      email = "user@example.com",
      groups = {"admin", "user"}
    },
    expires_at = 4102444800,
    issued_at = "2024-01-01T00:00:00Z",
    audience = {"parsec"},
    scope = "read write"
  }
end
`

	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	result, err := validator.Validate(context.Background(), &BearerCredential{Token: "valid-token"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "user@example.com" {
		t.Fatalf("Subject=%q, want user@example.com", result.Subject)
	}
	if result.Issuer != "https://issuer.example.com" {
		t.Fatalf("Issuer=%q", result.Issuer)
	}
	if result.TrustDomain != "example.com" {
		t.Fatalf("TrustDomain=%q", result.TrustDomain)
	}
	if result.Claims.GetString("email") != "user@example.com" {
		t.Fatalf("email claim=%v", result.Claims["email"])
	}
	if len(result.Audience) != 1 || result.Audience[0] != "parsec" {
		t.Fatalf("Audience=%v", result.Audience)
	}
	if result.Scope != "read write" {
		t.Fatalf("Scope=%q", result.Scope)
	}

	_, err = validator.Validate(context.Background(), &BearerCredential{Token: "bad-token"})
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err=%v, want ErrInvalidToken", err)
	}
}

func TestLuaValidator_HTTPConfigAndJSONServices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"active":true,"sub":"http-user","email":"http@example.com"}`))
	}))
	defer server.Close()

	script := `
function validate(input)
  local body = json.encode({token = input.credential.token})
  local resp = http.post(config.get("introspection_url"), body, {["Content-Type"] = "application/json"})
  if resp.status ~= 200 then
    return nil
  end
  local decoded = json.decode(resp.body)
  if not decoded.active then
    return nil
  end
  return {
    subject = decoded.sub,
    issuer = config.get("issuer"),
    trust_domain = config.get("trust_domain"),
    claims = {email = decoded.email},
    expires_at = 4102444800
  }
end
`

	validator, err := NewLuaValidator("http", script, []CredentialType{CredentialTypeBearer},
		WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"introspection_url": server.URL,
			"issuer":            "https://issuer.example.com",
			"trust_domain":      "example.com",
		})),
		WithLuaHTTPOptions(luaservices.WithRequestOptions(func(req *http.Request) error {
			req.Header.Set("X-API-Key", "secret")
			return nil
		})),
	)
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	result, err := validator.Validate(context.Background(), &BearerCredential{Token: "valid"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "http-user" {
		t.Fatalf("Subject=%q", result.Subject)
	}
	if result.Claims.GetString("email") != "http@example.com" {
		t.Fatalf("email=%v", result.Claims["email"])
	}
}

func TestCacheableLuaValidator_CacheKey(t *testing.T) {
	const script = `
function validate(input)
  return {subject = "user", expires_at = 4102444800}
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      token = input.credential.token
    }
  }
end
`

	validator, err := NewCacheableLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewCacheableLuaValidator: %v", err)
	}

	key, err := validator.CacheKey(&BearerCredential{Token: "abc"})
	if err != nil {
		t.Fatalf("CacheKey: %v", err)
	}
	bearer, ok := key.Credential.(*BearerCredential)
	if !ok {
		t.Fatalf("expected *BearerCredential, got %T", key.Credential)
	}
	if bearer.Token != "abc" {
		t.Fatalf("Token=%q, want abc", bearer.Token)
	}
	if validator.CacheTTL() != defaultLuaValidatorTTL {
		t.Fatalf("CacheTTL=%v, want %v", validator.CacheTTL(), defaultLuaValidatorTTL)
	}
}

func TestNewCacheableLuaValidator_RequiresValidateCacheKey(t *testing.T) {
	_, err := NewCacheableLuaValidator("test", `function validate(input) return nil end`, []CredentialType{CredentialTypeBearer})
	if err == nil || !strings.Contains(err.Error(), "script must define a 'validate_cache_key' function") {
		t.Fatalf("err=%v, want validate_cache_key error", err)
	}
}

type countingCacheableValidator struct {
	count     int
	ttl       time.Duration
	expiresAt time.Time
}

func (v *countingCacheableValidator) CredentialTypes() []CredentialType {
	return []CredentialType{CredentialTypeBearer}
}

func (v *countingCacheableValidator) Validate(_ context.Context, credential Credential) (*Result, error) {
	v.count++
	bearer, ok := credential.(*BearerCredential)
	if !ok {
		return nil, ErrInvalidToken
	}
	return &Result{
		Subject:   bearer.Token,
		ExpiresAt: v.expiresAt,
	}, nil
}

func (v *countingCacheableValidator) CacheKey(credential Credential) (ValidatorInput, error) {
	return ValidatorInput{Credential: credential}, nil
}

func (v *countingCacheableValidator) CacheTTL() time.Duration {
	return v.ttl
}

func TestInMemoryCachingValidator(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	source := &countingCacheableValidator{
		ttl:       time.Minute,
		expiresAt: clk.Now().Add(time.Hour),
	}
	cached := NewInMemoryCachingValidator("test", source, NoOpTrustObserver{}, WithValidatorCacheClock(clk))

	cred := &BearerCredential{Token: "abc"}
	result, err := cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	if result.Subject != "abc" {
		t.Fatalf("Subject=%q", result.Subject)
	}
	if source.count != 1 {
		t.Fatalf("count=%d, want 1", source.count)
	}

	_, err = cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if source.count != 1 {
		t.Fatalf("count=%d, want cached count 1", source.count)
	}

	clk.Advance(2 * time.Minute)
	_, err = cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("third Validate: %v", err)
	}
	if source.count != 2 {
		t.Fatalf("count=%d, want 2 after expiry", source.count)
	}
}

func TestDistributedCachingValidator(t *testing.T) {
	source := &countingCacheableValidator{
		ttl:       time.Hour,
		expiresAt: time.Now().Add(time.Hour),
	}
	cached := NewDistributedCachingValidator("test-distributed", source, DistributedValidatorCachingConfig{
		GroupName:      "test-validator-distributed-cache",
		CacheSizeBytes: 1 << 20,
	})

	cred := &BearerCredential{Token: "abc"}
	_, err := cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	_, err = cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if source.count != 1 {
		t.Fatalf("count=%d, want 1", source.count)
	}
}
