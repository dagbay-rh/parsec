package observer

import (
	"context"
	"net/http"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// Observer is the central observability interface for the entire application.
// It embeds per-package aggregate observer interfaces so that adding a new
// observer to a domain package only requires updating that package's Observer
// — not this central type.
//
// An Observer value is assignable to any narrower per-package or per-operation
// observer interface (e.g. service.ServiceObserver, datasource.CacheObserver,
// keys.DualSlotRotatingSignerObserver) via Go structural typing.
//
// Observer also owns the lifecycle of any resources held by its
// implementations (e.g. an OTel MeterProvider). Call Shutdown during
// graceful shutdown to flush and release those resources.
//
// Config reload logging is intentionally excluded from the Observer interface.
type Observer interface {
	service.ServiceObserver
	datasource.DataSourceObserver
	keys.KeysObserver
	trust.TrustObserver
	server.ServerObserver

	// Shutdown flushes pending data and releases resources held by the
	// observer tree. Composite observers cascade Shutdown to all children.
	Shutdown(ctx context.Context) error

	// ConfigureHTTPMux registers any HTTP handlers the observer
	// implementation requires (e.g. a /metrics endpoint for Prometheus
	// scraping). Composite observers cascade to all children.
	// Implementations with no HTTP needs should no-op.
	ConfigureHTTPMux(mux *http.ServeMux)
}

// ComposeOption configures a [composed] observer built by [Compose].
type ComposeOption func(*composed)

// WithShutdown attaches a shutdown function that is called when the
// composed observer's Shutdown method is invoked.
func WithShutdown(fn func(context.Context) error) ComposeOption {
	return func(c *composed) { c.shutdownFn = fn }
}

// WithHTTPMux attaches an HTTP mux configuration function that is called
// when the composed observer's ConfigureHTTPMux method is invoked.
func WithHTTPMux(fn func(*http.ServeMux)) ComposeOption {
	return func(c *composed) { c.configureMux = fn }
}

// composed holds per-package aggregate observers and satisfies Observer
// by promoting all embedded interface methods.
type composed struct {
	service.ServiceObserver
	datasource.DataSourceObserver
	keys.KeysObserver
	trust.TrustObserver
	server.ServerObserver

	shutdownFn   func(context.Context) error
	configureMux func(*http.ServeMux)
}

func (c *composed) Shutdown(ctx context.Context) error {
	if c.shutdownFn != nil {
		return c.shutdownFn(ctx)
	}
	return nil
}

func (c *composed) ConfigureHTTPMux(mux *http.ServeMux) {
	if c.configureMux != nil {
		c.configureMux(mux)
	}
}

// Compose builds an Observer from per-package aggregate observers.
func Compose(
	app service.ServiceObserver,
	ds datasource.DataSourceObserver,
	ks keys.KeysObserver,
	ts trust.TrustObserver,
	srv server.ServerObserver,
	opts ...ComposeOption,
) Observer {
	c := &composed{
		ServiceObserver:    app,
		DataSourceObserver: ds,
		KeysObserver:       ks,
		TrustObserver:      ts,
		ServerObserver:     srv,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// NoOp returns an Observer where every method is a no-op.
func NoOp() Observer {
	return &noopObserver{}
}

type noopObserver struct {
	service.NoOpServiceObserver
	datasource.NoOpDataSourceObserver
	keys.NoOpKeysObserver
	trust.NoOpTrustObserver
	server.NoOpServerObserver
}

func (*noopObserver) Shutdown(context.Context) error  { return nil }
func (*noopObserver) ConfigureHTTPMux(*http.ServeMux) {}

// Compile-time check: both implementations satisfy Observer.
var (
	_ Observer = (*composed)(nil)
	_ Observer = (*noopObserver)(nil)
)
