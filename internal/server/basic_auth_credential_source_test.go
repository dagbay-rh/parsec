package server

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestBasicAuthCredentialSource_Extract(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	source := NewBasicAuthCredentialSource("test-basic-auth")

	t.Run("valid basic auth", func(t *testing.T) {
		t.Parallel()
		encoded := base64.StdEncoding.EncodeToString([]byte("123|alice:secret"))
		ext, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "Basic " + encoded},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ba, ok := ext.Credential.(*trust.BasicAuthCredential)
		if !ok {
			t.Fatalf("expected *BasicAuthCredential, got %T", ext.Credential)
		}
		if ba.Username != "123|alice" {
			t.Fatalf("Username=%q", ba.Username)
		}
		if ba.Password != "secret" {
			t.Fatalf("Password=%q", ba.Password)
		}
		if ext.SourceName != "test-basic-auth" {
			t.Fatalf("SourceName=%q", ext.SourceName)
		}
		if len(ext.HeadersToRemove) != 1 || ext.HeadersToRemove[0] != "authorization" {
			t.Fatalf("HeadersToRemove=%v", ext.HeadersToRemove)
		}
	})

	t.Run("scheme is case-insensitive", func(t *testing.T) {
		t.Parallel()
		encoded := base64.StdEncoding.EncodeToString([]byte("user:pass"))
		ext, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "basic " + encoded},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext == nil {
			t.Fatal("expected extraction, got nil")
		}
	})

	t.Run("missing authorization header returns nil", func(t *testing.T) {
		t.Parallel()
		ext, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatalf("expected nil extraction, got %+v", ext)
		}
	})

	t.Run("non-basic scheme returns nil", func(t *testing.T) {
		t.Parallel()
		ext, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "Bearer some-token"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatalf("expected nil for Bearer scheme, got %+v", ext)
		}
	})

	t.Run("invalid base64 returns error", func(t *testing.T) {
		t.Parallel()
		_, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "Basic !!!invalid!!!"},
		})
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})

	t.Run("missing colon separator returns error", func(t *testing.T) {
		t.Parallel()
		encoded := base64.StdEncoding.EncodeToString([]byte("no-colon-here"))
		_, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "Basic " + encoded},
		})
		if err == nil {
			t.Fatal("expected error for missing colon")
		}
	})

	t.Run("empty value returns error", func(t *testing.T) {
		t.Parallel()
		_, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "Basic "},
		})
		if err == nil {
			t.Fatal("expected error for empty value")
		}
	})

	t.Run("empty username is allowed", func(t *testing.T) {
		t.Parallel()
		encoded := base64.StdEncoding.EncodeToString([]byte(":password"))
		ext, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "Basic " + encoded},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ba := ext.Credential.(*trust.BasicAuthCredential)
		if ba.Username != "" {
			t.Fatalf("Username=%q, want empty", ba.Username)
		}
		if ba.Password != "password" {
			t.Fatalf("Password=%q", ba.Password)
		}
	})

	t.Run("password with colons", func(t *testing.T) {
		t.Parallel()
		encoded := base64.StdEncoding.EncodeToString([]byte("user:pass:with:colons"))
		ext, err := source.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "Basic " + encoded},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ba := ext.Credential.(*trust.BasicAuthCredential)
		if ba.Username != "user" {
			t.Fatalf("Username=%q", ba.Username)
		}
		if ba.Password != "pass:with:colons" {
			t.Fatalf("Password=%q", ba.Password)
		}
	})

	t.Run("default source name", func(t *testing.T) {
		t.Parallel()
		defaultSource := NewBasicAuthCredentialSource("")
		encoded := base64.StdEncoding.EncodeToString([]byte("user:pass"))
		ext, err := defaultSource.Extract(ctx, CredentialContext{
			Headers: map[string]string{"authorization": "Basic " + encoded},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext.SourceName != CredentialSourceTypeBasicAuth {
			t.Fatalf("SourceName=%q, want %q", ext.SourceName, CredentialSourceTypeBasicAuth)
		}
	})
}
