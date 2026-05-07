package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/server"
)

var (
	grpcServeFailedAttrs = metric.WithAttributeSet(attribute.NewSet(attribute.String("transport", "grpc")))
	httpServeFailedAttrs = metric.WithAttributeSet(attribute.NewSet(attribute.String("transport", "http")))
)

type serverObserver struct {
	server.NoOpServerObserver

	initPopTotal    metric.Int64Counter
	initPopDuration metric.Float64Histogram

	cacheRefreshTotal    metric.Int64Counter
	cacheRefreshDuration metric.Float64Histogram

	serveFailedTotal metric.Int64Counter
}

func newServerObserver(m metric.Meter) (*serverObserver, error) {
	ipt, err := m.Int64Counter("parsec.server.jwks.init.total",
		metric.WithDescription("Total JWKS initial population operations"),
	)
	if err != nil {
		return nil, err
	}
	ipd, err := m.Float64Histogram("parsec.server.jwks.init.duration",
		metric.WithDescription("JWKS initial population duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	crt, err := m.Int64Counter("parsec.server.jwks.refresh.total",
		metric.WithDescription("Total JWKS cache refresh operations"),
	)
	if err != nil {
		return nil, err
	}
	crd, err := m.Float64Histogram("parsec.server.jwks.refresh.duration",
		metric.WithDescription("JWKS cache refresh duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	sft, err := m.Int64Counter("parsec.server.serve.failed.total",
		metric.WithDescription("Total server serve failures"),
	)
	if err != nil {
		return nil, err
	}

	return &serverObserver{
		initPopTotal:         ipt,
		initPopDuration:      ipd,
		cacheRefreshTotal:    crt,
		cacheRefreshDuration: crd,
		serveFailedTotal:     sft,
	}, nil
}

// --- init population probe ---

func (o *serverObserver) InitPopulationStarted(ctx context.Context) (context.Context, server.InitPopulationProbe) {
	return ctx, &initPopulationProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.initPopTotal,
		histogram: o.initPopDuration,
		startTime: time.Now(),
	}}
}

type initPopulationProbe struct {
	server.NoOpInitPopulationProbe
	metricProbe
}

func (p *initPopulationProbe) InitialCachePopulationFailed(error) { p.markFailed() }
func (p *initPopulationProbe) End()                               { p.finish() }

// --- cache refresh probe ---

func (o *serverObserver) CacheRefreshStarted(ctx context.Context) (context.Context, server.CacheRefreshProbe) {
	return ctx, &cacheRefreshProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.cacheRefreshTotal,
		histogram: o.cacheRefreshDuration,
		startTime: time.Now(),
	}}
}

type cacheRefreshProbe struct {
	server.NoOpCacheRefreshProbe
	metricProbe
}

func (p *cacheRefreshProbe) CacheRefreshFailed(error)          { p.markFailed() }
func (p *cacheRefreshProbe) KeyConversionFailed(string, error) { p.markFailed() }
func (p *cacheRefreshProbe) End()                              { p.finish() }

// --- serve failed (fire-and-forget, counter only) ---
// context.Background() is intentional: the upstream LifecycleObserver interface
// provides no context for these methods because they are async lifecycle events
// fired from server-serve goroutines, not request-scoped operations.

func (o *serverObserver) GRPCServeFailed(_ error) {
	o.serveFailedTotal.Add(context.Background(), 1, grpcServeFailedAttrs)
}

func (o *serverObserver) HTTPServeFailed(_ error) {
	o.serveFailedTotal.Add(context.Background(), 1, httpServeFailedAttrs)
}

var (
	_ server.ServerObserver      = (*serverObserver)(nil)
	_ server.InitPopulationProbe = (*initPopulationProbe)(nil)
	_ server.CacheRefreshProbe   = (*cacheRefreshProbe)(nil)
)
