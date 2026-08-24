package config

import (
	"context"
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestNewUnsignedJSONValidator_RequiresTrustDomain(t *testing.T) {
	_, err := newUnsignedJSONValidator(ValidatorConfig{Type: "unsigned_json_validator"})
	if err == nil {
		t.Fatal("expected error when trust_domain is absent")
	}
	if !strings.Contains(err.Error(), "unsigned_json_validator requires trust_domain") {
		t.Fatalf("err=%q, want containing trust_domain requirement", err.Error())
	}
}

func TestNewUnsignedJSONValidator_DefaultIssuer(t *testing.T) {
	v, err := newUnsignedJSONValidator(ValidatorConfig{
		Type:        "unsigned_json_validator",
		TrustDomain: "parsec.example.com",
	})
	if err != nil {
		t.Fatalf("newUnsignedJSONValidator: %v", err)
	}

	result, err := v.Validate(context.Background(), &trust.JSONCredential{
		RawJSON: []byte(`{"sub":"alice"}`),
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Issuer != trust.UnsignedJSONTokenTypeURN {
		t.Errorf("Issuer=%q, want %q", result.Issuer, trust.UnsignedJSONTokenTypeURN)
	}
	if result.TrustDomain != "parsec.example.com" {
		t.Errorf("TrustDomain=%q, want parsec.example.com", result.TrustDomain)
	}
}

func TestNewUnsignedJSONValidator_IssuerOverride(t *testing.T) {
	v, err := newUnsignedJSONValidator(ValidatorConfig{
		Type:        "unsigned_json_validator",
		TrustDomain: "parsec.example.com",
		Issuer:      "https://scheduler.example.com",
	})
	if err != nil {
		t.Fatalf("newUnsignedJSONValidator: %v", err)
	}

	result, err := v.Validate(context.Background(), &trust.JSONCredential{
		RawJSON: []byte(`{"sub":"alice"}`),
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Issuer != "https://scheduler.example.com" {
		t.Errorf("Issuer=%q, want https://scheduler.example.com", result.Issuer)
	}
}
