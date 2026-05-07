package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const meterName = "github.com/project-kessel/parsec"

var (
	successStatusAttr    = attribute.String("status", "success")
	errorStatusAttr      = attribute.String("status", "error")
	successStatusAttrSet = metric.WithAttributeSet(attribute.NewSet(successStatusAttr))
	errorStatusAttrSet   = metric.WithAttributeSet(attribute.NewSet(errorStatusAttr))
)

// metricProbe is the shared base for probes that record a counter+histogram
// pair with a success/error status attribute.
type metricProbe struct {
	ctx       context.Context
	counter   metric.Int64Counter
	histogram metric.Float64Histogram
	startTime time.Time
	failed    bool
}

func (p *metricProbe) markFailed() { p.failed = true }

func (p *metricProbe) statusAttr() attribute.KeyValue {
	if p.failed {
		return errorStatusAttr
	}
	return successStatusAttr
}

func (p *metricProbe) record(attrs metric.MeasurementOption) {
	p.counter.Add(p.ctx, 1, attrs)
	p.histogram.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

func (p *metricProbe) recordWithStatusOnly() {
	if p.failed {
		p.record(errorStatusAttrSet)
	} else {
		p.record(successStatusAttrSet)
	}
}

// serviceObserver implements service.ServiceObserver using OTel counters and histograms.
type serviceObserver struct {
	service.NoOpServiceObserver

	issuanceTotal    metric.Int64Counter
	issuanceDuration metric.Float64Histogram
	exchangeTotal    metric.Int64Counter
	exchangeDuration metric.Float64Histogram
	authzTotal       metric.Int64Counter
	authzDuration    metric.Float64Histogram
}

func newServiceObserver(m metric.Meter) (*serviceObserver, error) {
	it, err := m.Int64Counter("parsec.token.issuance.total",
		metric.WithDescription("Total token issuance operations"),
	)
	if err != nil {
		return nil, err
	}
	id, err := m.Float64Histogram("parsec.token.issuance.duration",
		metric.WithDescription("Token issuance duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	et, err := m.Int64Counter("parsec.token.exchange.total",
		metric.WithDescription("Total token exchange operations"),
	)
	if err != nil {
		return nil, err
	}
	ed, err := m.Float64Histogram("parsec.token.exchange.duration",
		metric.WithDescription("Token exchange duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	at, err := m.Int64Counter("parsec.authz.check.total",
		metric.WithDescription("Total authorization check operations"),
	)
	if err != nil {
		return nil, err
	}
	ad, err := m.Float64Histogram("parsec.authz.check.duration",
		metric.WithDescription("Authorization check duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &serviceObserver{
		issuanceTotal:    it,
		issuanceDuration: id,
		exchangeTotal:    et,
		exchangeDuration: ed,
		authzTotal:       at,
		authzDuration:    ad,
	}, nil
}

func (o *serviceObserver) TokenIssuanceStarted(
	ctx context.Context,
	_ *trust.Result,
	_ *trust.Result,
	_ string,
	_ []service.TokenType,
) (context.Context, service.TokenIssuanceProbe) {
	return ctx, &tokenIssuanceProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.issuanceTotal,
		histogram: o.issuanceDuration,
		startTime: time.Now(),
	}}
}

func (o *serviceObserver) TokenExchangeStarted(
	ctx context.Context,
	_ string,
	_ string,
	_ string,
	_ string,
) (context.Context, service.TokenExchangeProbe) {
	return ctx, &tokenExchangeProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.exchangeTotal,
		histogram: o.exchangeDuration,
		startTime: time.Now(),
	}}
}

func (o *serviceObserver) AuthzCheckStarted(
	ctx context.Context,
) (context.Context, service.AuthzCheckProbe) {
	return ctx, &authzCheckProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.authzTotal,
		histogram: o.authzDuration,
		startTime: time.Now(),
	}}
}

// --- token issuance probe ---

type tokenIssuanceProbe struct {
	service.NoOpTokenIssuanceProbe
	metricProbe
}

func (p *tokenIssuanceProbe) TokenTypeIssuanceFailed(_ service.TokenType, _ error) { p.markFailed() }
func (p *tokenIssuanceProbe) IssuerNotFound(_ service.TokenType, _ error)          { p.markFailed() }
func (p *tokenIssuanceProbe) End()                                                 { p.recordWithStatusOnly() }

// --- token exchange probe ---

type tokenExchangeProbe struct {
	service.NoOpTokenExchangeProbe
	metricProbe
}

func (p *tokenExchangeProbe) ActorValidationFailed(_ error)        { p.markFailed() }
func (p *tokenExchangeProbe) RequestContextParseFailed(_ error)    { p.markFailed() }
func (p *tokenExchangeProbe) SubjectTokenValidationFailed(_ error) { p.markFailed() }
func (p *tokenExchangeProbe) End()                                 { p.recordWithStatusOnly() }

// --- authz check probe ---

type authzCheckProbe struct {
	service.NoOpAuthzCheckProbe
	metricProbe
}

func (p *authzCheckProbe) ActorValidationFailed(_ error)             { p.markFailed() }
func (p *authzCheckProbe) SubjectCredentialExtractionFailed(_ error) { p.markFailed() }
func (p *authzCheckProbe) SubjectValidationFailed(_ error)           { p.markFailed() }
func (p *authzCheckProbe) End()                                      { p.recordWithStatusOnly() }

var (
	_ service.ServiceObserver    = (*serviceObserver)(nil)
	_ service.TokenIssuanceProbe = (*tokenIssuanceProbe)(nil)
	_ service.TokenExchangeProbe = (*tokenExchangeProbe)(nil)
	_ service.AuthzCheckProbe    = (*authzCheckProbe)(nil)
)
