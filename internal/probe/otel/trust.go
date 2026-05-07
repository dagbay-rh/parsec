package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/trust"
)

type trustObserver struct {
	trust.NoOpTrustObserver

	validationTotal     metric.Int64Counter
	validationDuration  metric.Float64Histogram
	jwtValidateTotal    metric.Int64Counter
	jwtValidateDuration metric.Float64Histogram
	actorFilterTotal    metric.Int64Counter
	actorFilterDuration metric.Float64Histogram
}

func newTrustObserver(m metric.Meter) (*trustObserver, error) {
	vt, err := m.Int64Counter("parsec.trust.validation.total",
		metric.WithDescription("Total trust validation operations"),
	)
	if err != nil {
		return nil, err
	}
	vd, err := m.Float64Histogram("parsec.trust.validation.duration",
		metric.WithDescription("Trust validation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	jvt, err := m.Int64Counter("parsec.trust.jwt.validate.total",
		metric.WithDescription("Total JWT validation operations"),
	)
	if err != nil {
		return nil, err
	}
	jvd, err := m.Float64Histogram("parsec.trust.jwt.validate.duration",
		metric.WithDescription("JWT validation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	aft, err := m.Int64Counter("parsec.trust.actor.filter.total",
		metric.WithDescription("Total actor filter operations"),
	)
	if err != nil {
		return nil, err
	}
	afd, err := m.Float64Histogram("parsec.trust.actor.filter.duration",
		metric.WithDescription("Actor filter duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &trustObserver{
		validationTotal:     vt,
		validationDuration:  vd,
		jwtValidateTotal:    jvt,
		jwtValidateDuration: jvd,
		actorFilterTotal:    aft,
		actorFilterDuration: afd,
	}, nil
}

func (o *trustObserver) ValidationStarted(ctx context.Context) (context.Context, trust.ValidationProbe) {
	return ctx, &validationProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.validationTotal,
		histogram: o.validationDuration,
		startTime: time.Now(),
	}}
}

type validationProbe struct {
	trust.NoOpValidationProbe
	metricProbe
}

func (p *validationProbe) AllValidatorsFailed(_ trust.CredentialType, _ int, _ error) { p.markFailed() }
func (p *validationProbe) End()                                                       { p.record() }

// --- JWT validate probe ---

func (o *trustObserver) JWTValidateStarted(ctx context.Context, issuer string) (context.Context, trust.JWTValidateProbe) {
	return ctx, &jwtValidateProbe{
		metricProbe: metricProbe{
			ctx:       ctx,
			counter:   o.jwtValidateTotal,
			histogram: o.jwtValidateDuration,
			startTime: time.Now(),
		},
		issuer: issuer,
	}
}

// jwtValidateProbe records metrics for a single JWT validation.
// The issuer attribute is the configured issuer URL of the validator,
// bounded by the number of trust_store.validators — not a per-request value.
type jwtValidateProbe struct {
	trust.NoOpJWTValidateProbe
	metricProbe
	issuer string
}

func (p *jwtValidateProbe) JWKSLookupFailed(error)       { p.markFailed() }
func (p *jwtValidateProbe) TokenExpired()                { p.markFailed() }
func (p *jwtValidateProbe) TokenInvalid(error)           { p.markFailed() }
func (p *jwtValidateProbe) ClaimsExtractionFailed(error) { p.markFailed() }
func (p *jwtValidateProbe) End() {
	p.record(attribute.String("issuer", p.issuer))
}

// --- actor filter probe ---

func (o *trustObserver) ForActorStarted(ctx context.Context) (context.Context, trust.ForActorProbe) {
	return ctx, &forActorProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.actorFilterTotal,
		histogram: o.actorFilterDuration,
		startTime: time.Now(),
	}}
}

type forActorProbe struct {
	trust.NoOpForActorProbe
	metricProbe
}

func (p *forActorProbe) FilterEvaluationFailed(string, error) { p.markFailed() }
func (p *forActorProbe) End()                                 { p.record() }

var (
	_ trust.TrustObserver    = (*trustObserver)(nil)
	_ trust.ValidationProbe  = (*validationProbe)(nil)
	_ trust.JWTValidateProbe = (*jwtValidateProbe)(nil)
	_ trust.ForActorProbe    = (*forActorProbe)(nil)
)
