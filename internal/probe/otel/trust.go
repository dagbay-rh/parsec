package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/trust"
)

var (
	jwtResultJWKSLookupFailed       = attribute.String("result", "jwks_lookup_failed")
	jwtResultTokenExpired           = attribute.String("result", "token_expired")
	jwtResultTokenInvalid           = attribute.String("result", "token_invalid")
	jwtResultClaimsExtractionFailed = attribute.String("result", "claims_extraction_failed")

	registryResultPatternRejected   = attribute.String("result", "username_pattern_rejected")
	registryResultCallFailed        = attribute.String("result", "registry_call_failed")
	registryResultAccessDenied      = attribute.String("result", "access_denied")
	registryResultUsernameParseFail = attribute.String("result", "username_parse_failed")
	registryResultCacheHit          = attribute.String("result", "cache_hit")
)

type trustObserver struct {
	trust.NoOpTrustObserver

	validationDuration       metric.Float64Histogram
	jwtValidateDuration      metric.Float64Histogram
	actorFilterDuration      metric.Float64Histogram
	registryValidateDuration metric.Float64Histogram
}

func newTrustObserver(m metric.Meter) (*trustObserver, error) {
	vd, err := m.Float64Histogram("parsec.trust.validation.duration",
		metric.WithDescription("Trust validation duration in seconds"),
		metric.WithUnit("s"),
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
	afd, err := m.Float64Histogram("parsec.trust.actor.filter.duration",
		metric.WithDescription("Actor filter duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	rvd, err := m.Float64Histogram("parsec.trust.registry.validate.duration",
		metric.WithDescription("Registry validation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &trustObserver{
		validationDuration:       vd,
		jwtValidateDuration:      jvd,
		actorFilterDuration:      afd,
		registryValidateDuration: rvd,
	}, nil
}

// --- validation probe ---

func (o *trustObserver) ValidationStarted(ctx context.Context) (context.Context, trust.ValidationProbe) {
	return ctx, &validationProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
	}
}

type validationProbe struct {
	trust.NoOpValidationProbe
	obs       *trustObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
}

func (p *validationProbe) AllValidatorsFailed(_ trust.CredentialType, _ int, _ error) {
	p.status = errorStatusAttr
}
func (p *validationProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.status))
	p.obs.validationDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- JWT validate probe ---

func (o *trustObserver) JWTValidateStarted(ctx context.Context, issuer string) (context.Context, trust.JWTValidateProbe) {
	return ctx, &jwtValidateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
		result: resultSuccess,
		issuer: attribute.String("issuer", issuer),
	}
}

// jwtValidateProbe records metrics for a single JWT validation.
// The issuer attribute is the configured issuer URL of the validator,
// bounded by the number of trust_store.validators — not a per-request value.
type jwtValidateProbe struct {
	trust.NoOpJWTValidateProbe
	obs       *trustObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	result    attribute.KeyValue
	issuer    attribute.KeyValue
}

func (p *jwtValidateProbe) JWKSLookupFailed(_ error) {
	p.status = errorStatusAttr
	p.result = jwtResultJWKSLookupFailed
}
func (p *jwtValidateProbe) TokenExpired() {
	p.status = errorStatusAttr
	p.result = jwtResultTokenExpired
}
func (p *jwtValidateProbe) TokenInvalid(_ error) {
	p.status = errorStatusAttr
	p.result = jwtResultTokenInvalid
}
func (p *jwtValidateProbe) ClaimsExtractionFailed(_ error) {
	p.status = errorStatusAttr
	p.result = jwtResultClaimsExtractionFailed
}
func (p *jwtValidateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.issuer, p.result, p.status))
	p.obs.jwtValidateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- actor filter probe ---

func (o *trustObserver) ForActorStarted(ctx context.Context) (context.Context, trust.ForActorProbe) {
	return ctx, &forActorProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
	}
}

type forActorProbe struct {
	trust.NoOpForActorProbe
	obs       *trustObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
}

func (p *forActorProbe) FilterEvaluationFailed(_ string, _ error) { p.status = errorStatusAttr }
func (p *forActorProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.status))
	p.obs.actorFilterDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- registry validate probe ---

func (o *trustObserver) RegistryValidateStarted(ctx context.Context, url string) (context.Context, trust.RegistryValidateProbe) {
	return ctx, &registryValidateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status:      successStatusAttr,
		result:      resultSuccess,
		registryURL: attribute.String("registry_url", url),
	}
}

type registryValidateProbe struct {
	trust.NoOpRegistryValidateProbe
	obs         *trustObserver
	ctx         context.Context
	startTime   time.Time
	status      attribute.KeyValue
	result      attribute.KeyValue
	registryURL attribute.KeyValue
}

func (p *registryValidateProbe) UsernamePatternRejected() {
	p.status = errorStatusAttr
	p.result = registryResultPatternRejected
}
func (p *registryValidateProbe) CacheHit() {
	p.result = registryResultCacheHit
}
func (p *registryValidateProbe) RegistryCallFailed(_ error) {
	p.status = errorStatusAttr
	p.result = registryResultCallFailed
}
func (p *registryValidateProbe) AccessDenied() {
	p.status = errorStatusAttr
	p.result = registryResultAccessDenied
}
func (p *registryValidateProbe) UsernameParseFailed(_ error) {
	p.status = errorStatusAttr
	p.result = registryResultUsernameParseFail
}
func (p *registryValidateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.registryURL, p.result, p.status))
	p.obs.registryValidateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

var (
	_ trust.TrustObserver         = (*trustObserver)(nil)
	_ trust.ValidationProbe       = (*validationProbe)(nil)
	_ trust.JWTValidateProbe      = (*jwtValidateProbe)(nil)
	_ trust.ForActorProbe         = (*forActorProbe)(nil)
	_ trust.RegistryValidateProbe = (*registryValidateProbe)(nil)
)
