package scripts_test

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestRedHatIdentityCEL_Compiles(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	if _, err := mapper.NewCELMapper(script); err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}
}

func TestRedHatIdentityCEL_UnsignedJSONSSO(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	bop, err := datasource.NewStaticDataSource("bop", map[string]any{
		"account_number": "540155",
		"org_id":         "54321",
		"username":       "testuser",
		"email":          "testuser@redhat.com",
		"first_name":     "Test",
		"last_name":      "User",
		"is_active":      true,
		"is_org_admin":   true,
		"is_internal":    false,
		"locale":         "en_US",
		"user_id":        "98765",
	})
	if err != nil {
		t.Fatalf("NewStaticDataSource: %v", err)
	}

	registry := service.NewDataSourceRegistry()
	registry.Register(bop)

	subject := &trust.Result{
		Subject: "redhat:user:sso:98765",
		Issuer:  trust.UnsignedJSONTokenTypeURN,
	}
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		Actor:              trust.AnonymousResult(),
		DataSourceRegistry: registry,
		DataSourceInput:    &service.DataSourceInput{Subject: subject},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if !result.Decision.IsAllow() {
		t.Fatalf("Decision=%+v, want Allow", result.Decision)
	}

	identity, ok := result.Claims["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity=%T, want map", result.Claims["identity"])
	}
	user, ok := identity["user"].(map[string]any)
	if !ok {
		t.Fatalf("identity.user=%T, want map", identity["user"])
	}
	if user["user_id"] != "98765" {
		t.Errorf("user_id=%v, want 98765", user["user_id"])
	}
	if user["username"] != "testuser" {
		t.Errorf("username=%v, want testuser", user["username"])
	}
	if identity["org_id"] != "54321" {
		t.Errorf("org_id=%v, want 54321", identity["org_id"])
	}
}

func TestRedHatIdentityCEL_UnsignedJSONUnsupportedNamespace(t *testing.T) {
	script := loadScript(t, "redhat_identity.cel")
	m, err := mapper.NewCELMapper(script)
	if err != nil {
		t.Fatalf("NewCELMapper: %v", err)
	}

	subject := &trust.Result{
		Subject: "redhat:system:cn-example",
		Issuer:  trust.UnsignedJSONTokenTypeURN,
	}
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject: subject,
		Actor:   trust.AnonymousResult(),
		DataSourceInput: &service.DataSourceInput{
			Subject: subject,
		},
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if result.Decision.Action != service.MappingDeny {
		t.Fatalf("Action=%q, want deny", result.Decision.Action)
	}
	if result.Decision.ExchangeError == nil {
		t.Fatal("expected ExchangeError")
	}
	if result.Decision.ExchangeError.Reason != service.AbortReasonInvalidSubject {
		t.Errorf("Reason=%q, want %q", result.Decision.ExchangeError.Reason, service.AbortReasonInvalidSubject)
	}
	if result.Decision.ExchangeError.Message != "unsupported unsigned_json subject namespace" {
		t.Errorf("Message=%q", result.Decision.ExchangeError.Message)
	}
}
