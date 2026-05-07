package otel

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Provider owns the OTel MeterProvider and Prometheus HTTP handler.
// Create one with New.
type Provider struct {
	meterProvider *sdkmetric.MeterProvider
	registry      *prometheus.Registry
	handler       http.Handler
}

type providerConfig struct {
	registry           *prometheus.Registry
	durationBoundaries []float64
}

// Option configures the metrics Provider.
type Option func(*providerConfig)

// WithRegistry sets a custom Prometheus registry.
// Useful in tests to isolate metric state.
func WithRegistry(r *prometheus.Registry) Option {
	return func(c *providerConfig) {
		c.registry = r
	}
}

// WithDurationBoundaries overrides the default histogram bucket boundaries
// applied to all parsec duration histograms (unit "s").
func WithDurationBoundaries(b []float64) Option {
	return func(c *providerConfig) {
		c.durationBoundaries = b
	}
}

var defaultDurationBoundaries = []float64{
	.005, .01, .025, .05, .075, .1, .25, .5, .75, 1, 2.5, 5, 7.5, 10,
}

// durationView matches parsec histogram instruments with unit "s" and overrides
// their bucket boundaries to sub-second through multi-second values typical of
// token issuance, exchange, and trust validation latencies.
func durationView(boundaries []float64) sdkmetric.View {
	return sdkmetric.NewView(
		sdkmetric.Instrument{Kind: sdkmetric.InstrumentKindHistogram, Unit: "s", Name: "parsec.*"},
		sdkmetric.Stream{
			Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: boundaries,
			},
		},
	)
}

// New creates a Provider backed by a Prometheus exporter.
func New(opts ...Option) (*Provider, error) {
	cfg := &providerConfig{}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.registry == nil {
		cfg.registry = prometheus.NewRegistry()
	}
	if cfg.durationBoundaries == nil {
		cfg.durationBoundaries = defaultDurationBoundaries
	}

	exporter, err := promexporter.New(
		promexporter.WithRegisterer(cfg.registry),
	)
	if err != nil {
		return nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithView(durationView(cfg.durationBoundaries)),
	)

	return &Provider{
		meterProvider: mp,
		registry:      cfg.registry,
		handler:       promhttp.HandlerFor(cfg.registry, promhttp.HandlerOpts{}),
	}, nil
}

// Meter returns a named Meter from the underlying MeterProvider.
func (p *Provider) Meter(name string) metric.Meter {
	return p.meterProvider.Meter(name)
}

// Handler returns the HTTP handler that serves /metrics for Prometheus scraping.
func (p *Provider) Handler() http.Handler {
	return p.handler
}

// Shutdown flushes pending metrics and releases resources.
func (p *Provider) Shutdown(ctx context.Context) error {
	return p.meterProvider.Shutdown(ctx)
}
