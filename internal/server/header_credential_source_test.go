package server

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestHeaderCredentialSource_Extract(t *testing.T) {
	headers := []HeaderSpec{{Name: "x-custom-header-a"}, {Name: "x-custom-header-b"}}
	src, err := NewHeaderCredentialSource("custom-headers", headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("all headers present", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"x-custom-header-a": "value-a",
				"x-custom-header-b": "value-b",
			},
		}

		ext, err := src.Extract(context.Background(), cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ext == nil {
			t.Fatal("expected extraction, got nil")
		}

		cred, ok := ext.Credential.(*trust.HeaderCredential)
		if !ok {
			t.Fatalf("expected *HeaderCredential, got %T", ext.Credential)
		}
		if cred.Headers["x-custom-header-a"] != "value-a" {
			t.Errorf("expected 'value-a', got %q", cred.Headers["x-custom-header-a"])
		}
		if cred.Headers["x-custom-header-b"] != "value-b" {
			t.Errorf("expected 'value-b', got %q", cred.Headers["x-custom-header-b"])
		}
		if ext.SourceName != "custom-headers" {
			t.Errorf("expected SourceName 'custom-headers', got %q", ext.SourceName)
		}
		if len(ext.HeadersUsed) != 2 {
			t.Fatalf("expected 2 headers used, got %d", len(ext.HeadersUsed))
		}
	})

	t.Run("no headers present returns nil", func(t *testing.T) {
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

	t.Run("partial headers returns error", func(t *testing.T) {
		cc := CredentialContext{
			Headers: map[string]string{
				"x-custom-header-a": "value-a",
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

func TestHeaderCredentialSource_MixedCaseHeaders(t *testing.T) {
	src, err := NewHeaderCredentialSource("custom-headers", []HeaderSpec{{Name: "X-Custom-Header-A"}, {Name: "X-Custom-Header-B"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cc := CredentialContext{
		Headers: map[string]string{
			"x-custom-header-a": "value-a",
			"x-custom-header-b": "value-b",
		},
	}

	ext, err := src.Extract(context.Background(), cc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ext == nil {
		t.Fatal("expected extraction, got nil")
	}

	cred, ok := ext.Credential.(*trust.HeaderCredential)
	if !ok {
		t.Fatalf("expected *HeaderCredential, got %T", ext.Credential)
	}
	if cred.Headers["x-custom-header-a"] != "value-a" {
		t.Errorf("expected 'value-a', got %q", cred.Headers["x-custom-header-a"])
	}
	if cred.Headers["x-custom-header-b"] != "value-b" {
		t.Errorf("expected 'value-b', got %q", cred.Headers["x-custom-header-b"])
	}
}

func TestNewHeaderCredentialSource_EmptyName(t *testing.T) {
	_, err := NewHeaderCredentialSource("", []HeaderSpec{{Name: "x-header"}})
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestNewHeaderCredentialSource_EmptyHeaders(t *testing.T) {
	_, err := NewHeaderCredentialSource("test", nil)
	if err == nil {
		t.Fatal("expected error for empty headers, got nil")
	}
}
