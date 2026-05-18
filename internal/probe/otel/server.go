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

	initPopDuration      metric.Float64Histogram
	cacheRefreshDuration metric.Float64Histogram
	serveFailedTotal     metric.Int64Counter
}

func newServerObserver(m metric.Meter) (*serverObserver, error) {
	ipd, err := m.Float64Histogram("parsec.server.jwks.init.duration",
		metric.WithDescription("JWKS initial population duration in seconds"),
		metric.WithUnit("s"),
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
		initPopDuration:      ipd,
		cacheRefreshDuration: crd,
		serveFailedTotal:     sft,
	}, nil
}

// --- init population probe ---

func (o *serverObserver) InitPopulationStarted(ctx context.Context) (context.Context, server.InitPopulationProbe) {
	return ctx, &initPopulationProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
	}
}

type initPopulationProbe struct {
	server.NoOpInitPopulationProbe
	obs       *serverObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
}

func (p *initPopulationProbe) InitialCachePopulationFailed(_ error) { p.status = errorStatusAttr }
func (p *initPopulationProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.status))
	p.obs.initPopDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- cache refresh probe ---

func (o *serverObserver) CacheRefreshStarted(ctx context.Context) (context.Context, server.CacheRefreshProbe) {
	return ctx, &cacheRefreshProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
	}
}

type cacheRefreshProbe struct {
	server.NoOpCacheRefreshProbe
	obs       *serverObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
}

func (p *cacheRefreshProbe) CacheRefreshFailed(_ error)            { p.status = errorStatusAttr }
func (p *cacheRefreshProbe) KeyConversionFailed(_ string, _ error) { p.status = errorStatusAttr }
func (p *cacheRefreshProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.status))
	p.obs.cacheRefreshDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

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
