package otel

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/project-kessel/parsec/internal/service"
)

func benchProvider(b *testing.B) *Provider {
	b.Helper()
	reg := prometheus.NewRegistry()
	p, err := New(WithRegistry(reg))
	require.NoError(b, err)
	b.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return p
}

func BenchmarkProbeRecord_StatusOnly(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.TokenIssuanceStarted(ctx, nil, nil, "test", []service.TokenType{"jwt"})
		probe.End()
	}
}

func BenchmarkProbeRecord_StatusOnly_Error(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.TokenIssuanceStarted(ctx, nil, nil, "test", []service.TokenType{"jwt"})
		probe.TokenTypeIssuanceFailed("jwt", errBench)
		probe.End()
	}
}

func BenchmarkProbeRecord_KnownAtStartAttrs(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.JWTValidateStarted(ctx, "https://issuer.example.com")
		probe.End()
	}
}

func BenchmarkProbeRecord_KnownAtStartAttrs_Error(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.JWTValidateStarted(ctx, "https://issuer.example.com")
		probe.TokenInvalid(errBench)
		probe.End()
	}
}

func BenchmarkProbeRecord_MidFlightAttrs(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, probe := obs.CacheFetchStarted(ctx, "inventory")
		probe.CacheHit()
		probe.End()
	}
}

func BenchmarkProbeRecord_ServeFailedStatic(b *testing.B) {
	p := benchProvider(b)
	obs, err := NewObserver(p, "/metrics")
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		obs.GRPCServeFailed(errBench)
	}
}

var errBench = context.DeadlineExceeded
