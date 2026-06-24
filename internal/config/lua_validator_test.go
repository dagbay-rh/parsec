package config

import (
	"context"
	"testing"

	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestNewTrustStore_LuaValidatorWithCaching(t *testing.T) {
	const luaScript = `
function validate(input)
  if input.credential.token ~= config.get("expected_token") then
    return nil
  end
  return {
    subject = "lua-user",
    issuer = "https://issuer.example.com",
    trust_domain = "lua.example.com",
    claims = {source = "lua"},
    expires_at = 4102444800
  }
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      token = input.credential.token
    }
  }
end
`

	store, err := NewTrustStore(TrustStoreConfig{
		Type: "filtered_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "lua-validator",
				ValidatorConfig: ValidatorConfig{
					Type:            "lua_validator",
					Script:          luaScript,
					CredentialTypes: []string{"bearer"},
					Config: map[string]any{
						"expected_token": "valid",
					},
					Caching: &CachingConfig{
						Type: "in_memory",
						TTL:  "10m",
					},
				},
			},
		},
	}, nil, observer.NoOp())
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	result, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "valid"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "lua-user" {
		t.Fatalf("Subject=%q", result.Subject)
	}
	if result.Claims.GetString("source") != "lua" {
		t.Fatalf("source=%v", result.Claims["source"])
	}
}
