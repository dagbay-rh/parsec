package config

import (
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/observer"
)

func testHTTPRegistry(t *testing.T) *httpclient.Registry {
	t.Helper()
	r, err := NewHTTPClientRegistry(nil, nil)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry: %v", err)
	}
	return r
}

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
	}, testHTTPRegistry(t), observer.NoOp())
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
	}, testHTTPRegistry(t), obs)
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

func TestNewDataSourceRegistry_InvalidCachingType(t *testing.T) {
	t.Parallel()

	const luaScript = `
function fetch(input)
  return {data = "{}", content_type = "application/json"}
end
`
	_, err := NewDataSourceRegistry([]DataSourceConfig{
		{
			Name:   "ds",
			Type:   "lua",
			Script: luaScript,
			Caching: &CachingConfig{
				Type: "redis",
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())

	if err == nil {
		t.Fatal("expected error for invalid caching type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown caching type") {
		t.Fatalf("expected 'unknown caching type' error, got: %v", err)
	}
}
