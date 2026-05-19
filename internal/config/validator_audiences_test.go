package config

import "testing"

func TestLoadValidatorAudiencesFromYAML(t *testing.T) {
	loader, err := NewLoader("../../configs/parsec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loader.Get()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustStore.Validators) != 1 {
		t.Fatalf("validators len=%d, want 1", len(cfg.TrustStore.Validators))
	}
	v := cfg.TrustStore.Validators[0]
	if v.Type != "jwt_validator" {
		t.Fatalf("type=%q, want jwt_validator", v.Type)
	}
	want := []string{"rhsm-api", "customer-portal", "api.console"}
	if len(v.Audiences) != len(want) {
		t.Fatalf("audiences=%v, want %v", v.Audiences, want)
	}
	for i := range want {
		if v.Audiences[i] != want[i] {
			t.Fatalf("audiences=%v, want %v", v.Audiences, want)
		}
	}
}
