package server

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestForwardedClientCertCredentialSource_Extract(t *testing.T) {
	headers := []string{"x-rh-certauth-cn", "x-rh-certauth-issuer"}
	src, err := NewForwardedClientCertCredentialSource("cert-auth", headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("valid cert auth headers", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"x-rh-certauth-cn":     "/CN=test-system",
				"x-rh-certauth-issuer": "CN=Red Hat CA",
			},
		}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext == nil {
			t.Fatal("expected extraction, got nil")
		}

		cred, ok := ext.Credential.(*trust.ForwardedClientCertCredential)
		if !ok {
			t.Fatalf("expected *ForwardedClientCertCredential, got %T", ext.Credential)
		}
		if cred.Headers["x-rh-certauth-cn"] != "/CN=test-system" {
			t.Errorf("expected cn '/CN=test-system', got %q", cred.Headers["x-rh-certauth-cn"])
		}
		if cred.Headers["x-rh-certauth-issuer"] != "CN=Red Hat CA" {
			t.Errorf("expected issuer 'CN=Red Hat CA', got %q", cred.Headers["x-rh-certauth-issuer"])
		}
		if ext.SourceName != "cert-auth" {
			t.Errorf("expected SourceName 'cert-auth', got %q", ext.SourceName)
		}
		if len(ext.HeadersUsed) != 2 {
			t.Fatalf("expected 2 headers used, got %d", len(ext.HeadersUsed))
		}
	})

	t.Run("both headers absent returns nil", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{},
		}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatal("expected nil extraction, got non-nil")
		}
	})

	t.Run("cn present but issuer missing returns error", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"x-rh-certauth-cn": "/CN=test",
			},
		}

		_, err := src.Extract(context.Background(), cc)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("issuer present but cn missing returns error", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"x-rh-certauth-issuer": "CN=Red Hat CA",
			},
		}

		_, err := src.Extract(context.Background(), cc)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("unrelated headers returns nil", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"authorization": "Bearer token123",
			},
		}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext != nil {
			t.Fatal("expected nil extraction, got non-nil")
		}
	})
}

func TestNewForwardedClientCertCredentialSource_EmptyName(t *testing.T) {
	_, err := NewForwardedClientCertCredentialSource("", []string{"x-rh-certauth-cn"})
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestNewForwardedClientCertCredentialSource_EmptyHeaders(t *testing.T) {
	_, err := NewForwardedClientCertCredentialSource("cert-auth", nil)
	if err == nil {
		t.Fatal("expected error for empty headers, got nil")
	}
}
