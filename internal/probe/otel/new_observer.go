package otel

import (
	"net/http"

	"github.com/project-kessel/parsec/internal/observer"
)

// NewObserver builds a full observer.Observer backed by OTel metrics.
// The returned observer satisfies all per-package aggregate interfaces
// and records counters/histograms via the given [Provider].
//
// The returned observer's Shutdown delegates to p.Shutdown, and its
// ConfigureHTTPMux registers the Prometheus scrape handler at the given endpoint.
func NewObserver(p *Provider, endpoint string) (observer.Observer, error) {
	m := p.Meter(meterName)

	svc, err := newServiceObserver(m)
	if err != nil {
		return nil, err
	}
	ds, err := newDataSourceObserver(m)
	if err != nil {
		return nil, err
	}
	ks, err := newKeysObserver(m)
	if err != nil {
		return nil, err
	}
	ts, err := newTrustObserver(m)
	if err != nil {
		return nil, err
	}
	srv, err := newServerObserver(m)
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
