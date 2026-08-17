package scripts_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/trust"
)

func scriptDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

func loadScript(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(scriptDir(), name))
	if err != nil {
		t.Fatalf("failed to read script %s: %v", name, err)
	}
	return string(data)
}

func TestTrustedUsername_HappyPath(t *testing.T) {
	script := loadScript(t, "trusted_username.lua")

	validator, err := trust.NewLuaValidator("trusted-username", script,
		[]trust.CredentialType{trust.CredentialTypeUsername},
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"trust_domain": "username.redhat.com",
			"issuer":       "urn:redhat:names:identity:username",
		})),
	)
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	result, err := validator.Validate(context.Background(),
		&trust.UsernameCredential{Username: "testuser123"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if result.Subject != "testuser123" {
		t.Fatalf("Subject=%q, want testuser123", result.Subject)
	}
	if result.Issuer != "urn:redhat:names:identity:username" {
		t.Fatalf("Issuer=%q, want urn:redhat:names:identity:username", result.Issuer)
	}
	if result.TrustDomain != "username.redhat.com" {
		t.Fatalf("TrustDomain=%q, want username.redhat.com", result.TrustDomain)
	}
}

func TestTrustedUsername_RejectsEmptyUsername(t *testing.T) {
	script := loadScript(t, "trusted_username.lua")

	validator, err := trust.NewLuaValidator("trusted-username", script,
		[]trust.CredentialType{trust.CredentialTypeUsername},
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"trust_domain": "username.redhat.com",
			"issuer":       "urn:redhat:names:identity:username",
		})),
	)
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(),
		&trust.UsernameCredential{Username: ""})
	if err == nil {
		t.Fatal("expected error for empty username")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("err=%v, want containing 'invalid token'", err)
	}
}

func TestTrustedUsername_RejectsJWTLookingValues(t *testing.T) {
	script := loadScript(t, "trusted_username.lua")

	validator, err := trust.NewLuaValidator("trusted-username", script,
		[]trust.CredentialType{trust.CredentialTypeUsername},
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"trust_domain": "username.redhat.com",
			"issuer":       "urn:redhat:names:identity:username",
		})),
	)
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(),
		&trust.UsernameCredential{Username: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"})
	if err == nil {
		t.Fatal("expected error for JWT-looking value")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("err=%v, want containing 'invalid token'", err)
	}
}

func TestTrustedUsername_AcceptsNonJWTWithDots(t *testing.T) {
	script := loadScript(t, "trusted_username.lua")

	validator, err := trust.NewLuaValidator("trusted-username", script,
		[]trust.CredentialType{trust.CredentialTypeUsername},
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"trust_domain": "username.redhat.com",
			"issuer":       "urn:redhat:names:identity:username",
		})),
	)
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	// A username with a dot (like an email) should be accepted —
	// only the three-segment base64 pattern is rejected.
	result, err := validator.Validate(context.Background(),
		&trust.UsernameCredential{Username: "user@example.com"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "user@example.com" {
		t.Fatalf("Subject=%q, want user@example.com", result.Subject)
	}
}
