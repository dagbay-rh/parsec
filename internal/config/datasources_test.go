package config

import (
	"testing"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/observer"
)

func TestNewDataSourceRegistry_Static(t *testing.T) {
	t.Parallel()

	reg, err := NewDataSourceRegistry([]DataSourceConfig{
		{
			Name: "identity-policy",
			Type: "static",
			Data: map[string]any{
				"internal_idp_target":   "https://idp.example.com/internal",
				"role_fallback_enabled": true,
			},
		},
	}, nil, observer.NoOp())
	if err != nil {
		t.Fatalf("NewDataSourceRegistry: %v", err)
	}

	ds := reg.Get("identity-policy")
	if ds == nil {
		t.Fatal("expected registered data source")
	}
	if _, ok := ds.(*datasource.StaticDataSource); !ok {
		t.Fatalf("got %T, want *datasource.StaticDataSource", ds)
	}
}

func TestNewDataSourceRegistry_CacheableLuaUsesObserver(t *testing.T) {
	const luaScript = `
function fetch(input)
  return {data = "{}", content_type = "application/json"}
end
function fetch_cache_key(input)
  return input
end
`
	obs := observer.NoOp()
	reg, err := NewDataSourceRegistry([]DataSourceConfig{
		{
			Name:   "with_cache_key",
			Type:   "lua",
			Script: luaScript,
			Caching: &CachingConfig{
				Type: "in_memory",
				TTL:  "10m",
			},
		},
	}, nil, obs)
	if err != nil {
		t.Fatalf("NewDataSourceRegistry: %v", err)
	}
	ds := reg.Get("with_cache_key")
	if ds == nil {
		t.Fatal("expected registered data source")
	}
	if _, ok := ds.(*datasource.InMemoryCachingDataSource); !ok {
		t.Fatalf("got %T, want *datasource.InMemoryCachingDataSource", ds)
	}
}
