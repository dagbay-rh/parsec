package server

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestForwardedClientCertCredentialSource_Extract(t *testing.T) {
	src, err := NewForwardedClientCertCredentialSource("cert-auth", "x-rh-certauth-cn", "x-rh-certauth-issuer")
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
		if cred.Subject != "/CN=test-system" {
			t.Errorf("expected subject '/CN=test-system', got %q", cred.Subject)
		}
		if cred.Issuer != "CN=Red Hat CA" {
			t.Errorf("expected issuer 'CN=Red Hat CA', got %q", cred.Issuer)
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

	t.Run("subject present but issuer missing returns error", func(t *testing.T) {
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

	t.Run("issuer present but subject missing returns error", func(t *testing.T) {
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

func TestForwardedClientCertCredentialSource_MixedCaseHeaders(t *testing.T) {
	src, err := NewForwardedClientCertCredentialSource("cert-auth", "X-RH-CertAuth-CN", "X-RH-CertAuth-Issuer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if cred.Subject != "/CN=test-system" {
		t.Errorf("expected subject '/CN=test-system', got %q", cred.Subject)
	}
	if cred.Issuer != "CN=Red Hat CA" {
		t.Errorf("expected issuer 'CN=Red Hat CA', got %q", cred.Issuer)
	}
}

func TestNewForwardedClientCertCredentialSource_EmptyName(t *testing.T) {
	_, err := NewForwardedClientCertCredentialSource("", "x-rh-certauth-cn", "x-rh-certauth-issuer")
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestNewForwardedClientCertCredentialSource_EmptySubjectHeader(t *testing.T) {
	_, err := NewForwardedClientCertCredentialSource("cert-auth", "", "x-rh-certauth-issuer")
	if err == nil {
		t.Fatal("expected error for empty subject_header, got nil")
	}
}

func TestNewForwardedClientCertCredentialSource_EmptyIssuerHeader(t *testing.T) {
	_, err := NewForwardedClientCertCredentialSource("cert-auth", "x-rh-certauth-cn", "")
	if err == nil {
		t.Fatal("expected error for empty issuer_header, got nil")
	}
}
