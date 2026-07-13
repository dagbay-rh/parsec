package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

type mockStaticDataSource struct {
	name string
	data any
}

func (m *mockStaticDataSource) Name() string {
	return m.name
}

func (m *mockStaticDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	data, err := json.Marshal(m.data)
	if err != nil {
		return nil, err
	}
	return &service.DataSourceResult{
		Data:        data,
		ContentType: service.ContentTypeJSON,
	}, nil
}

func loadIdentityCEL(t *testing.T) string {
	t.Helper()
	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("failed to read redhat_identity.cel: %v", err)
	}
	return string(celScript)
}

func newIdentityMapper(t *testing.T) *mapper.CELMapper {
	t.Helper()
	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)
	m, err := mapper.NewCELMapper(loadIdentityCEL(t), mapper.WithClock(clk))
	if err != nil {
		t.Fatalf("failed to create CEL mapper: %v", err)
	}
	return m
}

func newDataSourceRegistry() *service.DataSourceRegistry {
	registry := service.NewDataSourceRegistry()
	registry.Register(&mockStaticDataSource{
		name: "identity-policy",
		data: map[string]any{
			"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
			"role_fallback_enabled": true,
		},
	})
	return registry
}

func mapIdentity(t *testing.T, m *mapper.CELMapper, subject *trust.Result) map[string]any {
	t.Helper()
	registry := newDataSourceRegistry()
	result, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		DataSourceRegistry: registry,
		DataSourceInput:    &service.DataSourceInput{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return result
}

func mapIdentityExpectError(t *testing.T, m *mapper.CELMapper, subject *trust.Result) *service.ClaimMappingError {
	t.Helper()
	registry := newDataSourceRegistry()
	_, err := m.Map(context.Background(), &service.MapperInput{
		Subject:            subject,
		DataSourceRegistry: registry,
		DataSourceInput:    &service.DataSourceInput{},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, service.ErrClaimMapping) {
		t.Fatalf("expected ErrClaimMapping, got: %v", err)
	}
	var mappingErr *service.ClaimMappingError
	if !errors.As(err, &mappingErr) {
		t.Fatalf("expected ClaimMappingError, got: %T", err)
	}
	return mappingErr
}

func getIdentity(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	identity, ok := result["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity map, got %T", result["identity"])
	}
	return identity
}

func getNestedMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	child, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %s to be a map, got %T", key, parent[key])
	}
	return child
}

func TestRedHatIdentityCEL_ServiceAccountValid(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "service-account-myapp",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "service-account-myapp",
			"client_id":          "myapp",
			"sub":                "abc-123",
			"scope":              "api.console openid",
			"iat":                float64(1718442000),
			"organization": map[string]any{
				"id":             "org-1",
				"account_number": "12345",
			},
		},
	})

	identity := getIdentity(t, result)
	if identity["type"] != "ServiceAccount" {
		t.Errorf("expected type=ServiceAccount, got %v", identity["type"])
	}
	sa := getNestedMap(t, identity, "service_account")
	if sa["client_id"] != "myapp" {
		t.Errorf("expected client_id=myapp, got %v", sa["client_id"])
	}
	if sa["username"] != "service-account-myapp" {
		t.Errorf("expected username=service-account-myapp, got %v", sa["username"])
	}
}

func TestRedHatIdentityCEL_ServiceAccountDenyMissingClientID(t *testing.T) {
	m := newIdentityMapper(t)
	mappingErr := mapIdentityExpectError(t, m, &trust.Result{
		Subject:     "service-account-myapp",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "service-account-myapp",
			"sub":                "abc-123",
		},
	})
	if mappingErr.Message != "missing_client_id" {
		t.Errorf("expected message %q, got %q", "missing_client_id", mappingErr.Message)
	}
}

func TestRedHatIdentityCEL_ServiceAccountClientIdFallback(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "service-account-myapp",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "service-account-myapp",
			"clientId":           "fallback-client",
			"sub":                "abc-123",
		},
	})

	identity := getIdentity(t, result)
	sa := getNestedMap(t, identity, "service_account")
	if sa["client_id"] != "fallback-client" {
		t.Errorf("expected client_id=fallback-client, got %v", sa["client_id"])
	}
}

func TestRedHatIdentityCEL_ServiceAccountDenyEmptyClientID(t *testing.T) {
	m := newIdentityMapper(t)
	mappingErr := mapIdentityExpectError(t, m, &trust.Result{
		Subject:     "service-account-myapp",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "service-account-myapp",
			"client_id":          "",
			"sub":                "abc-123",
		},
	})
	if mappingErr.Message != "missing_client_id" {
		t.Errorf("expected message %q, got %q", "missing_client_id", mappingErr.Message)
	}
}

func TestRedHatIdentityCEL_ServiceAccountEmptyClientIdFallsBackToClientId(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "service-account-myapp",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "service-account-myapp",
			"client_id":          "",
			"clientId":           "fallback-client",
			"sub":                "abc-123",
		},
	})

	identity := getIdentity(t, result)
	sa := getNestedMap(t, identity, "service_account")
	if sa["client_id"] != "fallback-client" {
		t.Errorf("expected client_id=fallback-client, got %v", sa["client_id"])
	}
}

func TestRedHatIdentityCEL_ServiceAccountDenyBothClientIDsEmpty(t *testing.T) {
	m := newIdentityMapper(t)
	mappingErr := mapIdentityExpectError(t, m, &trust.Result{
		Subject:     "service-account-myapp",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "service-account-myapp",
			"client_id":          "",
			"clientId":           "",
			"sub":                "abc-123",
		},
	})
	if mappingErr.Message != "missing_client_id" {
		t.Errorf("expected message %q, got %q", "missing_client_id", mappingErr.Message)
	}
}

func TestRedHatIdentityCEL_ConsoleAPIUser(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "user-123",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "jdoe",
			"email":              "jdoe@example.com",
			"given_name":         "John",
			"family_name":        "Doe",
			"locale":             "en_US",
			"user_id":            42,
			"scope":              "api.console openid",
			"iat":                float64(1718442000),
			"idp":                "https://sso.redhat.com/auth/realms/internal",
			"organization": map[string]any{
				"id":             "org-1",
				"account_number": "12345",
			},
			"realm_access": map[string]any{
				"roles": []any{"admin:org:all"},
			},
		},
	})

	identity := getIdentity(t, result)
	if identity["type"] != "User" {
		t.Errorf("expected type=User, got %v", identity["type"])
	}
	if identity["org_id"] != "org-1" {
		t.Errorf("expected org_id=org-1, got %v", identity["org_id"])
	}

	user := getNestedMap(t, identity, "user")
	if user["username"] != "jdoe" {
		t.Errorf("expected username=jdoe, got %v", user["username"])
	}
	if user["first_name"] != "John" {
		t.Errorf("expected first_name=John, got %v", user["first_name"])
	}
	if user["is_org_admin"] != true {
		t.Errorf("expected is_org_admin=true, got %v", user["is_org_admin"])
	}
	if user["is_internal"] != true {
		t.Errorf("expected is_internal=true (idp matches internal), got %v", user["is_internal"])
	}
}

func TestRedHatIdentityCEL_RHSMAPIUser(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "user-456",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		Audience:    []string{"rhsm-api"},
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "rhsm-user",
			"email":              "rhsm@example.com",
			"sub":                "rhsm-sub-789",
			"account_id":         "acct-001",
			"iat":                float64(1718442000),
		},
	})

	identity := getIdentity(t, result)
	if identity["type"] != "User" {
		t.Errorf("expected type=User, got %v", identity["type"])
	}
	if identity["auth_type"] != "jwt-auth" {
		t.Errorf("expected auth_type=jwt-auth, got %v", identity["auth_type"])
	}
	if identity["org_id"] != "acct-001" {
		t.Errorf("expected org_id=acct-001, got %v", identity["org_id"])
	}
	if identity["account_number"] != "acct-001" {
		t.Errorf("expected account_number=acct-001, got %v", identity["account_number"])
	}

	user := getNestedMap(t, identity, "user")
	if user["username"] != "rhsm-user" {
		t.Errorf("expected username=rhsm-user, got %v", user["username"])
	}
	if user["user_id"] != "rhsm-sub-789" {
		t.Errorf("expected user_id=rhsm-sub-789, got %v", user["user_id"])
	}
	if user["is_internal"] != false {
		t.Errorf("expected is_internal=false (no idp claim), got %v", user["is_internal"])
	}
}

func TestRedHatIdentityCEL_RHSMAPIInternalUser(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "user-internal-rhsm",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		Audience:    []string{"rhsm-api"},
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "internal-rhsm-user",
			"email":              "internal@redhat.com",
			"sub":                "internal-rhsm-sub",
			"account_id":         "acct-internal",
			"idp":                "https://sso.redhat.com/auth/realms/internal",
			"iat":                float64(1718442000),
		},
	})

	identity := getIdentity(t, result)
	if identity["type"] != "User" {
		t.Errorf("expected type=User, got %v", identity["type"])
	}

	user := getNestedMap(t, identity, "user")
	if user["is_internal"] != true {
		t.Errorf("expected is_internal=true (idp matches internal target), got %v", user["is_internal"])
	}
}

func TestRedHatIdentityCEL_CustomerPortalUser(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "portal-user-1",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		Audience:    []string{"customer-portal"},
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"username":  "portal-jane",
			"email":     "jane@acme.com",
			"firstName": "Jane",
			"lastName":  "Smith",
			"lang":      "fr_FR",
			"user_id":   101,
			"sub":       "portal-sub-101",
			"iat":       float64(1718442000),
			"organization": map[string]any{
				"id": "org-portal",
			},
		},
	})

	identity := getIdentity(t, result)
	if identity["type"] != "User" {
		t.Errorf("expected type=User, got %v", identity["type"])
	}
	if identity["org_id"] != "org-portal" {
		t.Errorf("expected org_id=org-portal, got %v", identity["org_id"])
	}

	user := getNestedMap(t, identity, "user")
	if user["username"] != "portal-jane" {
		t.Errorf("expected username=portal-jane, got %v", user["username"])
	}
	if user["first_name"] != "Jane" {
		t.Errorf("expected first_name=Jane (from firstName), got %v", user["first_name"])
	}
	if user["last_name"] != "Smith" {
		t.Errorf("expected last_name=Smith (from lastName), got %v", user["last_name"])
	}
	if user["locale"] != "fr_FR" {
		t.Errorf("expected locale=fr_FR (from lang), got %v", user["locale"])
	}
	if user["is_internal"] != false {
		t.Errorf("expected is_internal=false (no idp claim), got %v", user["is_internal"])
	}
}

func TestRedHatIdentityCEL_CustomerPortalInternalUser(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "portal-internal-1",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		Audience:    []string{"customer-portal"},
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"username":  "portal-internal",
			"email":     "internal@redhat.com",
			"firstName": "Internal",
			"lastName":  "User",
			"lang":      "en_US",
			"user_id":   201,
			"sub":       "portal-internal-sub",
			"idp":       "https://sso.redhat.com/auth/realms/internal",
			"iat":       float64(1718442000),
			"organization": map[string]any{
				"id": "org-internal-portal",
			},
		},
	})

	identity := getIdentity(t, result)
	if identity["type"] != "User" {
		t.Errorf("expected type=User, got %v", identity["type"])
	}
	if identity["org_id"] != "org-internal-portal" {
		t.Errorf("expected org_id=org-internal-portal, got %v", identity["org_id"])
	}

	user := getNestedMap(t, identity, "user")
	if user["username"] != "portal-internal" {
		t.Errorf("expected username=portal-internal, got %v", user["username"])
	}
	if user["is_internal"] != true {
		t.Errorf("expected is_internal=true (idp matches internal target), got %v", user["is_internal"])
	}
}

func TestRedHatIdentityCEL_UnsupportedTokenDenied(t *testing.T) {
	m := newIdentityMapper(t)
	mappingErr := mapIdentityExpectError(t, m, &trust.Result{
		Subject:     "unknown-user",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "unknown-user",
			"email":              "unknown@example.com",
			"sub":                "unknown-sub",
		},
	})
	if mappingErr.Message != "unsupported_token_type" {
		t.Errorf("expected message %q, got %q", "unsupported_token_type", mappingErr.Message)
	}
}

func TestRedHatIdentityCEL_UnsupportedTokenWithUnknownAudienceDenied(t *testing.T) {
	m := newIdentityMapper(t)
	mappingErr := mapIdentityExpectError(t, m, &trust.Result{
		Subject:     "unknown-aud-user",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		Audience:    []string{"unknown-audience"},
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "unknown-aud-user",
			"sub":                "unknown-aud-sub",
		},
	})
	if mappingErr.Message != "unsupported_token_type" {
		t.Errorf("expected message %q, got %q", "unsupported_token_type", mappingErr.Message)
	}
}

func TestRedHatIdentityCEL_PrecedenceScopeOverAudience(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "dual-user",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		Audience:    []string{"rhsm-api"},
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "dual-user",
			"scope":              "api.console openid",
			"given_name":         "Dual",
			"family_name":        "User",
			"locale":             "en_US",
			"iat":                float64(1718442000),
			"organization": map[string]any{
				"id":             "org-dual",
				"account_number": "11111",
			},
		},
	})

	identity := getIdentity(t, result)
	if identity["type"] != "User" {
		t.Errorf("expected type=User, got %v", identity["type"])
	}
	if identity["org_id"] != "org-dual" {
		t.Errorf("expected org_id from Console API branch (organization.id), got %v", identity["org_id"])
	}

	user := getNestedMap(t, identity, "user")
	if user["locale"] != "en_US" {
		t.Errorf("expected locale=en_US from Console API branch, got %v", user["locale"])
	}
}

func TestRedHatIdentityCEL_PrecedenceServiceAccountOverAudience(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "service-account-sa-with-aud",
		Issuer:      "https://sso.redhat.com/auth/realms/redhat-external",
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		Audience:    []string{"rhsm-api"},
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"preferred_username": "service-account-sa-with-aud",
			"client_id":          "my-sa-client",
			"sub":                "sa-sub-1",
		},
	})

	identity := getIdentity(t, result)
	if identity["type"] != "ServiceAccount" {
		t.Errorf("expected type=ServiceAccount (SA branch wins over aud), got %v", identity["type"])
	}
}

func TestRedHatIdentityCEL_RegistryAuthStage(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "registry-user",
		Issuer:      "https://container-registry-authorizer.stage.api.redhat.com",
		TrustDomain: "registry.redhat.com",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"org_id": "reg-org-1",
		},
	})

	identity := getIdentity(t, result)
	if identity["auth_type"] != "registry-auth" {
		t.Errorf("expected auth_type=registry-auth, got %v", identity["auth_type"])
	}
	if identity["type"] != "User" {
		t.Errorf("expected type=User, got %v", identity["type"])
	}
	if identity["org_id"] != "reg-org-1" {
		t.Errorf("expected org_id=reg-org-1, got %v", identity["org_id"])
	}

	user := getNestedMap(t, identity, "user")
	if user["username"] != "registry-user" {
		t.Errorf("expected username=registry-user, got %v", user["username"])
	}
}

func TestRedHatIdentityCEL_RegistryAuthProduction(t *testing.T) {
	m := newIdentityMapper(t)
	result := mapIdentity(t, m, &trust.Result{
		Subject:     "prod-registry-user",
		Issuer:      "https://container-registry-authorizer.api.redhat.com",
		TrustDomain: "registry.redhat.com",
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Claims: map[string]any{
			"org_id": "reg-org-prod",
		},
	})

	identity := getIdentity(t, result)
	if identity["auth_type"] != "registry-auth" {
		t.Errorf("expected auth_type=registry-auth, got %v", identity["auth_type"])
	}
	if identity["type"] != "User" {
		t.Errorf("expected type=User, got %v", identity["type"])
	}
	if identity["org_id"] != "reg-org-prod" {
		t.Errorf("expected org_id=reg-org-prod, got %v", identity["org_id"])
	}

	user := getNestedMap(t, identity, "user")
	if user["username"] != "prod-registry-user" {
		t.Errorf("expected username=prod-registry-user, got %v", user["username"])
	}
}
