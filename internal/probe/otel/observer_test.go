package otel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/service"
)

type ctxKey struct{}

func testProvider(t *testing.T) *Provider {
	t.Helper()
	reg := prometheus.NewRegistry()
	p, err := New(WithRegistry(reg))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return p
}

func scrape(t *testing.T, p *Provider) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	p.Handler().ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func TestNewObserver_SatisfiesObserverInterface(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)
	require.NotNil(t, obs)
}

func TestTokenIssuanceMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.TokenIssuanceStarted(ctx, nil, nil, "test", []service.TokenType{"jwt"})
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_token_issuance_total")
	assert.Contains(t, body, `status="success"`)
	assert.Contains(t, body, "parsec_token_issuance_duration_seconds")
}

func TestTokenIssuanceMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.TokenIssuanceStarted(ctx, nil, nil, "test", []service.TokenType{"jwt"})
	probe.TokenTypeIssuanceFailed("jwt", errors.New("sign error"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, `status="error"`)
}

func TestTokenExchangeMetrics(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.TokenExchangeStarted(ctx, "urn:ietf:params:oauth:grant-type:token-exchange", "jwt", "aud", "scope")
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_token_exchange_total")
	assert.Contains(t, body, "parsec_token_exchange_duration_seconds")
}

func TestAuthzCheckMetrics(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.AuthzCheckStarted(ctx)
	probe.ActorValidationFailed(errors.New("bad actor"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_authz_check_total")
	assert.Contains(t, body, `status="error"`)
}

func TestCacheFetchStarted(t *testing.T) {
	tests := []struct {
		name           string
		dataSourceName string
		action         func(probe datasource.CacheFetchProbe)
		wantResult     string
		wantStatus     string
	}{
		{
			name:           "hit",
			dataSourceName: "inventory",
			action:         func(p datasource.CacheFetchProbe) { p.CacheHit() },
			wantResult:     `result="hit"`,
			wantStatus:     `status="success"`,
		},
		{
			name:           "miss",
			dataSourceName: "inventory",
			action:         func(p datasource.CacheFetchProbe) { p.CacheMiss() },
			wantResult:     `result="miss"`,
			wantStatus:     `status="success"`,
		},
		{
			name:           "expired",
			dataSourceName: "inventory",
			action:         func(p datasource.CacheFetchProbe) { p.CacheExpired() },
			wantResult:     `result="expired"`,
			wantStatus:     `status="success"`,
		},
		{
			name:           "error",
			dataSourceName: "inventory",
			action:         func(p datasource.CacheFetchProbe) { p.FetchFailed(errors.New("timeout")) },
			wantResult:     `result="error"`,
			wantStatus:     `status="error"`,
		},
		{
			name:           "unknown when no outcome is signaled",
			dataSourceName: "inventory",
			action:         func(datasource.CacheFetchProbe) {},
			wantResult:     `result="unknown"`,
			wantStatus:     `status="success"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(t)
			obs, err := NewObserver(p, "/metrics")
			require.NoError(t, err)

			_, probe := obs.CacheFetchStarted(context.Background(), tt.dataSourceName)
			tt.action(probe)
			probe.End()

			body := scrape(t, p)
			assert.Contains(t, body, "parsec_datasource_cache_fetch_total")
			assert.Contains(t, body, "parsec_datasource_cache_fetch_duration_seconds")
			assert.Contains(t, body, fmt.Sprintf(`datasource="%s"`, tt.dataSourceName))
			assert.Contains(t, body, tt.wantResult)
			assert.Contains(t, body, tt.wantStatus)
		})
	}
}

func TestTrustValidationMetrics(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.ValidationStarted(ctx)
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_trust_validation_total")
	assert.Contains(t, body, `status="success"`)
}

func TestKeyRotationMetrics(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.RotationCheckStarted(ctx)
	probe.RotationCheckFailed(errors.New("timeout"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_rotation_total")
	assert.Contains(t, body, `status="error"`)
}

func TestKeyCacheUpdateMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.KeyCacheUpdateStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_cache_update_total")
	assert.Contains(t, body, `status="success"`)
}

func TestKeyCacheUpdateMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.KeyCacheUpdateStarted(ctx)
	probe.KeyCacheUpdateFailed(errors.New("stale"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_cache_update_total")
	assert.Contains(t, body, "parsec_keys_cache_update_duration_seconds")
	assert.Contains(t, body, `status="error"`)
}

func TestJWTValidateMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.JWTValidateStarted(context.Background(), "test-issuer")
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_trust_jwt_validate_total")
	assert.Contains(t, body, `issuer="test-issuer"`)
	assert.Contains(t, body, `status="success"`)
}

func TestJWTValidateMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.JWTValidateStarted(ctx, "test-issuer")
	probe.TokenInvalid(errors.New("bad signature"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_trust_jwt_validate_total")
	assert.Contains(t, body, "parsec_trust_jwt_validate_duration_seconds")
	assert.Contains(t, body, `issuer="test-issuer"`)
	assert.Contains(t, body, `status="error"`)
}

func TestForActorFilterMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.ForActorStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_trust_actor_filter_total")
	assert.Contains(t, body, `status="success"`)
}

func TestForActorFilterMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.ForActorStarted(ctx)
	probe.FilterEvaluationFailed("validator-1", errors.New("eval error"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_trust_actor_filter_total")
	assert.Contains(t, body, "parsec_trust_actor_filter_duration_seconds")
	assert.Contains(t, body, `status="error"`)
}

func TestKMSRotateMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.KMSRotateStarted(context.Background(), "td", "ns", "my-key")
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_kms_rotate_total")
	assert.Contains(t, body, "parsec_keys_kms_rotate_duration_seconds")
	assert.Contains(t, body, `key_name="my-key"`)
	assert.Contains(t, body, `status="success"`)
}

func TestKMSRotateMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.KMSRotateStarted(context.Background(), "td", "ns", "my-key")
	probe.CreateKeyFailed(errors.New("kms error"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, `key_name="my-key"`)
	assert.Contains(t, body, `status="error"`)
}

func TestDiskRotateMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.DiskRotateStarted(context.Background(), "td", "ns", "disk-key")
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_disk_rotate_total")
	assert.Contains(t, body, "parsec_keys_disk_rotate_duration_seconds")
	assert.Contains(t, body, `key_name="disk-key"`)
	assert.Contains(t, body, `status="success"`)
}

func TestDiskRotateMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.DiskRotateStarted(context.Background(), "td", "ns", "disk-key")
	probe.KeyWriteFailed(errors.New("disk full"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, `key_name="disk-key"`)
	assert.Contains(t, body, `status="error"`)
}

func TestMemoryRotateMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.MemoryRotateStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_memory_rotate_total")
	assert.Contains(t, body, "parsec_keys_memory_rotate_duration_seconds")
	assert.Contains(t, body, `status="success"`)
}

func TestMemoryRotateMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.MemoryRotateStarted(context.Background())
	probe.KeyGenerationFailed(errors.New("entropy"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_keys_memory_rotate_total")
	assert.Contains(t, body, `status="error"`)
}

func TestInitPopulationMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.InitPopulationStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_jwks_init_total")
	assert.Contains(t, body, "parsec_server_jwks_init_duration_seconds")
	assert.Contains(t, body, `status="success"`)
}

func TestInitPopulationMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.InitPopulationStarted(context.Background())
	probe.InitialCachePopulationFailed(errors.New("fetch failed"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_jwks_init_total")
	assert.Contains(t, body, `status="error"`)
}

func TestCacheRefreshMetrics_Success(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.CacheRefreshStarted(context.Background())
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_jwks_refresh_total")
	assert.Contains(t, body, "parsec_server_jwks_refresh_duration_seconds")
	assert.Contains(t, body, `status="success"`)
}

func TestCacheRefreshMetrics_Error(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	_, probe := obs.CacheRefreshStarted(context.Background())
	probe.CacheRefreshFailed(errors.New("timeout"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_jwks_refresh_total")
	assert.Contains(t, body, `status="error"`)
}

func TestServeFailedMetrics_GRPC(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	obs.GRPCServeFailed(errors.New("bind error"))

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_serve_failed_total")
	assert.Contains(t, body, `transport="grpc"`)
}

func TestServeFailedMetrics_HTTP(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	obs.HTTPServeFailed(errors.New("bind error"))

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_server_serve_failed_total")
	assert.Contains(t, body, `transport="http"`)
}

func TestLuaFetchMetrics(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.Background()
	_, probe := obs.LuaFetchStarted(ctx, "enrichment")
	probe.ScriptExecutionFailed(errors.New("lua panic"))
	probe.End()

	body := scrape(t, p)
	assert.Contains(t, body, "parsec_datasource_lua_fetch_total")
	assert.Contains(t, body, "parsec_datasource_lua_fetch_duration_seconds")
	assert.Contains(t, body, `datasource="enrichment"`)
	assert.Contains(t, body, `status="error"`)
}

func TestProbeContext_CarriesRequestContext(t *testing.T) {
	p := testProvider(t)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), ctxKey{}, "request-123")

	_, ip := obs.TokenIssuanceStarted(ctx, nil, nil, "", nil)
	assert.Equal(t, "request-123", ip.(*tokenIssuanceProbe).ctx.Value(ctxKey{}))

	_, ep := obs.TokenExchangeStarted(ctx, "", "", "", "")
	assert.Equal(t, "request-123", ep.(*tokenExchangeProbe).ctx.Value(ctxKey{}))

	_, ap := obs.AuthzCheckStarted(ctx)
	assert.Equal(t, "request-123", ap.(*authzCheckProbe).ctx.Value(ctxKey{}))

	_, cp := obs.CacheFetchStarted(ctx, "ds")
	assert.Equal(t, "request-123", cp.(*cacheFetchProbe).ctx.Value(ctxKey{}))

	_, lp := obs.LuaFetchStarted(ctx, "ds")
	assert.Equal(t, "request-123", lp.(*luaFetchProbe).ctx.Value(ctxKey{}))

	_, vp := obs.ValidationStarted(ctx)
	assert.Equal(t, "request-123", vp.(*validationProbe).ctx.Value(ctxKey{}))

	_, rp := obs.RotationCheckStarted(ctx)
	assert.Equal(t, "request-123", rp.(*rotationCheckProbe).ctx.Value(ctxKey{}))

	_, kcp := obs.KeyCacheUpdateStarted(ctx)
	assert.Equal(t, "request-123", kcp.(*keyCacheUpdateProbe).ctx.Value(ctxKey{}))

	_, jp := obs.JWTValidateStarted(ctx, "iss")
	assert.Equal(t, "request-123", jp.(*jwtValidateProbe).ctx.Value(ctxKey{}))

	_, fp := obs.ForActorStarted(ctx)
	assert.Equal(t, "request-123", fp.(*forActorProbe).ctx.Value(ctxKey{}))

	_, kmsp := obs.KMSRotateStarted(ctx, "td", "ns", "k")
	assert.Equal(t, "request-123", kmsp.(*kmsRotateProbe).ctx.Value(ctxKey{}))

	_, dkp := obs.DiskRotateStarted(ctx, "td", "ns", "k")
	assert.Equal(t, "request-123", dkp.(*diskRotateProbe).ctx.Value(ctxKey{}))

	_, mrp := obs.MemoryRotateStarted(ctx)
	assert.Equal(t, "request-123", mrp.(*memoryRotateProbe).ctx.Value(ctxKey{}))

	_, ipp := obs.InitPopulationStarted(ctx)
	assert.Equal(t, "request-123", ipp.(*initPopulationProbe).ctx.Value(ctxKey{}))

	_, crp := obs.CacheRefreshStarted(ctx)
	assert.Equal(t, "request-123", crp.(*cacheRefreshProbe).ctx.Value(ctxKey{}))
}
