package config

import (
	"context"
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/trust"
)

func schedulerForActorStore(validatorName string) TrustStoreConfig {
	return TrustStoreConfig{
		Type: "filtered_store",
		Filter: &ValidatorFilterConfig{
			Type: "cel",
			Script: `validator_name != "` + validatorName + `" || (` +
				`has(actor.issuer) && actor.issuer.contains("scheduler"))`,
		},
	}
}

func TestNewUnsignedJSONValidator_RequiresTrustDomain(t *testing.T) {
	_, err := newUnsignedJSONValidator("unsigned-json", ValidatorConfig{Type: "unsigned_json_validator"}, schedulerForActorStore("unsigned-json"))
	if err == nil {
		t.Fatal("expected error when trust_domain is absent")
	}
	if !strings.Contains(err.Error(), "unsigned_json_validator requires trust_domain") {
		t.Fatalf("err=%q, want containing trust_domain requirement", err.Error())
	}
}

func TestNewUnsignedJSONValidator_RequiresActorGate(t *testing.T) {
	cfg := ValidatorConfig{Type: "unsigned_json_validator", TrustDomain: "parsec.example.com"}

	t.Run("missing name", func(t *testing.T) {
		_, err := newUnsignedJSONValidator("", cfg, schedulerForActorStore("unsigned-json"))
		if err == nil || !strings.Contains(err.Error(), "validator name") {
			t.Fatalf("err=%v, want validator name requirement", err)
		}
	})

	t.Run("stub_store", func(t *testing.T) {
		_, err := newUnsignedJSONValidator("unsigned-json", cfg, TrustStoreConfig{Type: "stub_store"})
		if err == nil || !strings.Contains(err.Error(), "filtered_store") {
			t.Fatalf("err=%v, want filtered_store requirement", err)
		}
	})

	t.Run("filtered_store without filter", func(t *testing.T) {
		_, err := newUnsignedJSONValidator("unsigned-json", cfg, TrustStoreConfig{Type: "filtered_store"})
		if err == nil || !strings.Contains(err.Error(), "trust_store.filter") {
			t.Fatalf("err=%v, want filter requirement", err)
		}
	})

	t.Run("passthrough filter", func(t *testing.T) {
		_, err := newUnsignedJSONValidator("unsigned-json", cfg, TrustStoreConfig{
			Type:   "filtered_store",
			Filter: &ValidatorFilterConfig{Type: "passthrough"},
		})
		if err == nil || !strings.Contains(err.Error(), "passthrough") {
			t.Fatalf("err=%v, want passthrough rejection", err)
		}
	})

	t.Run("cel without validator name", func(t *testing.T) {
		_, err := newUnsignedJSONValidator("unsigned-json", cfg, TrustStoreConfig{
			Type: "filtered_store",
			Filter: &ValidatorFilterConfig{
				Type:   "cel",
				Script: `has(actor.issuer) && actor.issuer.contains("scheduler")`,
			},
		})
		if err == nil || !strings.Contains(err.Error(), "name") {
			t.Fatalf("err=%v, want CEL to name the validator", err)
		}
	})

	t.Run("cel without actor", func(t *testing.T) {
		_, err := newUnsignedJSONValidator("unsigned-json", cfg, TrustStoreConfig{
			Type: "filtered_store",
			Filter: &ValidatorFilterConfig{
				Type:   "cel",
				Script: `validator_name == "unsigned-json"`,
			},
		})
		if err == nil || !strings.Contains(err.Error(), "actor") {
			t.Fatalf("err=%v, want CEL to constrain by actor", err)
		}
	})
}

func TestNewUnsignedJSONValidator_DefaultIssuer(t *testing.T) {
	v, err := newUnsignedJSONValidator("unsigned-json", ValidatorConfig{
		Type:        "unsigned_json_validator",
		TrustDomain: "parsec.example.com",
	}, schedulerForActorStore("unsigned-json"))
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
	}, schedulerForActorStore("unsigned-json"))
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

func TestNewTrustStore_UnsignedJSONRequiresActorGate(t *testing.T) {
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
	_, err := NewTrustStore(cfg, testHTTPRegistry(t), observer.NoOp())
	if err == nil || !strings.Contains(err.Error(), "filtered_store") {
		t.Fatalf("err=%v, want stub_store rejected", err)
	}
}

func TestNewTrustStore_UnsignedJSONWithSchedulerFilter(t *testing.T) {
	storeCfg := schedulerForActorStore("unsigned-json")
	storeCfg.Validators = []NamedValidatorConfig{
		{
			Name: "unsigned-json",
			ValidatorConfig: ValidatorConfig{
				Type:        "unsigned_json_validator",
				TrustDomain: "parsec.example.com",
			},
		},
	}
	store, err := NewTrustStore(storeCfg, testHTTPRegistry(t), observer.NoOp())
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	filtered, err := store.ForActor(context.Background(), &trust.Result{
		Issuer: "https://scheduler.example.com",
	}, nil)
	if err != nil {
		t.Fatalf("ForActor: %v", err)
	}
	if _, err := filtered.Validate(context.Background(), &trust.JSONCredential{
		RawJSON: []byte(`{"sub":"alice"}`),
	}); err != nil {
		t.Fatalf("scheduler actor should use unsigned-json: %v", err)
	}

	denied, err := store.ForActor(context.Background(), trust.AnonymousResult(), nil)
	if err != nil {
		t.Fatalf("ForActor anonymous: %v", err)
	}
	if _, err := denied.Validate(context.Background(), &trust.JSONCredential{
		RawJSON: []byte(`{"sub":"alice"}`),
	}); err == nil {
		t.Fatal("anonymous actor should not use unsigned-json")
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
