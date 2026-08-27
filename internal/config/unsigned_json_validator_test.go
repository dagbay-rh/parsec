package config

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestNewUnsignedJSONValidator_RequiresTrustDomain(t *testing.T) {
	_, err := newUnsignedJSONValidator("unsigned-json", ValidatorConfig{Type: "unsigned_json_validator"}, TrustStoreConfig{Type: "stub_store"})
	if err == nil {
		t.Fatal("expected error when trust_domain is absent")
	}
	if err.Error() != "unsigned_json_validator requires trust_domain" {
		t.Fatalf("err=%q, want trust_domain requirement", err.Error())
	}
}

func TestNewUnsignedJSONValidator_DefaultIssuer(t *testing.T) {
	v, err := newUnsignedJSONValidator("unsigned-json", ValidatorConfig{
		Type:        "unsigned_json_validator",
		TrustDomain: "parsec.example.com",
	}, TrustStoreConfig{Type: "stub_store"})
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
	v, err := newUnsignedJSONValidator("unsigned-json", ValidatorConfig{
		Type:        "unsigned_json_validator",
		TrustDomain: "parsec.example.com",
		Issuer:      "https://scheduler.example.com",
	}, TrustStoreConfig{Type: "stub_store"})
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

func TestNewTrustStore_UnsignedJSONInStubStore(t *testing.T) {
	cfg := TrustStoreConfig{
		Type: "stub_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "unsigned-json",
				ValidatorConfig: ValidatorConfig{
					Type:        "unsigned_json_validator",
					TrustDomain: "parsec.example.com",
				},
			},
		},
	}
	store, err := NewTrustStore(cfg, testHTTPRegistry(t), observer.NoOp())
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	result, err := store.Validate(context.Background(), &trust.JSONCredential{
		RawJSON: []byte(`{"sub":"alice"}`),
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "alice" {
		t.Errorf("Subject=%q, want alice", result.Subject)
	}
	if result.Issuer != trust.UnsignedJSONTokenTypeURN {
		t.Errorf("Issuer=%q, want %q", result.Issuer, trust.UnsignedJSONTokenTypeURN)
	}
}

func TestNewStubValidator_IssuerFromConfig(t *testing.T) {
	v, err := newStubValidator(ValidatorConfig{
		Type:            "stub_validator",
		Issuer:          "https://scheduler.example.com",
		TrustDomain:     "scheduler.example.com",
		CredentialTypes: []string{"bearer"},
	})
	if err != nil {
		t.Fatalf("newStubValidator: %v", err)
	}

	result, err := v.Validate(context.Background(), &trust.BearerCredential{Token: "hermetic-scheduler"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Issuer != "https://scheduler.example.com" {
		t.Errorf("Issuer=%q, want https://scheduler.example.com", result.Issuer)
	}
	if result.TrustDomain != "scheduler.example.com" {
		t.Errorf("TrustDomain=%q, want scheduler.example.com", result.TrustDomain)
	}
}

func TestNewStubValidator_AbsentIssuerKeepsDefault(t *testing.T) {
	v, err := newStubValidator(ValidatorConfig{Type: "stub_validator"})
	if err != nil {
		t.Fatalf("newStubValidator: %v", err)
	}

	result, err := v.Validate(context.Background(), &trust.BearerCredential{Token: "any"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Issuer != "https://test-issuer.example.com" {
		t.Errorf("Issuer=%q, want default https://test-issuer.example.com", result.Issuer)
	}
}
