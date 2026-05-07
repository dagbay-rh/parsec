package otel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
)

func TestNew_CreatesProvider(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	require.NotNil(t, p)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	assert.NotNil(t, p.Handler())
	assert.NotNil(t, p.Meter("test"))
}

func TestNew_WithCustomRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	p, err := New(WithRegistry(reg))
	require.NoError(t, err)
	require.NotNil(t, p)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
}

func TestProvider_Handler_ServesMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	p, err := New(WithRegistry(reg))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	p.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestProvider_Shutdown(t *testing.T) {
	p, err := New()
	require.NoError(t, err)

	err = p.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestProvider_DurationHistogram_UsesCustomBuckets(t *testing.T) {
	reg := prometheus.NewRegistry()
	p, err := New(WithRegistry(reg))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	m := p.Meter("test")
	h, err := m.Float64Histogram("parsec.test.duration", metric.WithUnit("s"))
	require.NoError(t, err)
	h.Record(context.Background(), 0.042)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	p.Handler().ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	out := string(body)

	assert.Contains(t, out, `le="0.005"`, "expected sub-ms bucket from durationSeconds")
	assert.Contains(t, out, `le="0.1"`, "expected 100ms bucket from durationSeconds")
	assert.Contains(t, out, `le="1"`, "expected 1s bucket from durationSeconds")
	assert.NotContains(t, out, `le="250"`, "should not have default SDK buckets")
}

func TestProvider_DurationHistogram_WithCustomBoundaries(t *testing.T) {
	reg := prometheus.NewRegistry()
	custom := []float64{0.1, 0.5, 1.0}
	p, err := New(WithRegistry(reg), WithDurationBoundaries(custom))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	m := p.Meter("test")
	h, err := m.Float64Histogram("parsec.test.duration", metric.WithUnit("s"))
	require.NoError(t, err)
	h.Record(context.Background(), 0.3)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	p.Handler().ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	out := string(body)

	assert.Contains(t, out, `le="0.1"`, "expected custom 100ms bucket")
	assert.Contains(t, out, `le="0.5"`, "expected custom 500ms bucket")
	assert.Contains(t, out, `le="1"`, "expected custom 1s bucket")
	assert.NotContains(t, out, `le="0.005"`, "should not have default sub-ms bucket")
	assert.NotContains(t, out, `le="10"`, "should not have default 10s bucket")
}

func TestProvider_MetricsEndpoint_ContainsOTelMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	p, err := New(WithRegistry(reg))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	m := p.Meter("test")
	counter, err := m.Int64Counter("test_counter")
	require.NoError(t, err)
	counter.Add(context.Background(), 42)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	p.Handler().ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Body)
	assert.Contains(t, string(body), "test_counter")
}
