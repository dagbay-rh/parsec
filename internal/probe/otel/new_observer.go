package otel

import (
	"net/http"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/observer"
)

// NewObserver builds a full observer.Observer backed by OTel metrics.
// The returned observer satisfies all per-package aggregate interfaces
// and records counters/histograms via the given [Provider].
//
// The returned observer's Shutdown delegates to p.Shutdown, and its
// ConfigureHTTPMux registers the Prometheus scrape handler at the given endpoint.
func NewObserver(p *Provider, endpoint string, clk clock.Clock) (observer.Observer, error) {
	m := p.Meter(meterName)

	svc, err := newServiceObserver(m, clk)
	if err != nil {
		return nil, err
	}
	ds, err := newDataSourceObserver(m, clk)
	if err != nil {
		return nil, err
	}
	ks, err := newKeysObserver(m, clk)
	if err != nil {
		return nil, err
	}
	ts, err := newTrustObserver(m, clk)
	if err != nil {
		return nil, err
	}
	srv, err := newServerObserver(m, clk)
	if err != nil {
		return nil, err
	}

	handler := p.Handler()
	return observer.Compose(svc, ds, ks, ts, srv,
		observer.WithShutdown(p.Shutdown),
		observer.WithHTTPMux(func(mux *http.ServeMux) {
			mux.Handle("GET "+endpoint, handler)
		}),
	), nil
}
