package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const meterName = "github.com/project-kessel/parsec"

var (
	successStatusAttr = attribute.String("status", "success")
	errorStatusAttr   = attribute.String("status", "error")

	resultSuccess = attribute.String("result", "success")

	resultIssuanceFailed = attribute.String("result", "issuance_failed")
	resultIssuanceDenied = attribute.String("result", "issuance_denied")
	resultIssuerNotFound = attribute.String("result", "issuer_not_found")

	resultActorValidationFailed             = attribute.String("result", "actor_validation_failed")
	resultRequestContextParseFailed         = attribute.String("result", "request_context_parse_failed")
	resultSubjectTokenValidationFailed      = attribute.String("result", "subject_token_validation_failed")
	resultSubjectCredentialExtractionFailed = attribute.String("result", "subject_credential_extraction_failed")
	resultSubjectValidationFailed           = attribute.String("result", "subject_validation_failed")
	resultPolicyIssue                       = attribute.String("result", "policy_issue")
	resultPolicyAllowWithoutIssue           = attribute.String("result", "policy_allow_without_issue")
	resultPolicyDenied                      = attribute.String("result", "policy_denied")
	resultPolicyEvaluationFailed            = attribute.String("result", "policy_evaluation_failed")

	// Predefined OAuth / abort-reason metric attributes (11 well-known values).
	// Avoids per-call attribute.String allocations on the denial path.
	oauthErrInvalidRequest       = attribute.String("mapping.oauth_error", string(service.OAuthInvalidRequest))
	oauthErrInvalidTarget        = attribute.String("mapping.oauth_error", string(service.OAuthInvalidTarget))
	oauthErrInvalidGrant         = attribute.String("mapping.oauth_error", string(service.OAuthInvalidGrant))
	oauthErrUnauthorizedClient   = attribute.String("mapping.oauth_error", string(service.OAuthUnauthorizedClient))
	oauthErrInvalidClient        = attribute.String("mapping.oauth_error", string(service.OAuthInvalidClient))
	oauthErrUnsupportedGrantType = attribute.String("mapping.oauth_error", string(service.OAuthUnsupportedGrantType))
	oauthErrInvalidScope         = attribute.String("mapping.oauth_error", string(service.OAuthInvalidScope))

	abortReasonInvalidSubject       = attribute.String("mapping.abort_reason", string(service.AbortReasonInvalidSubject))
	abortReasonInvalidActor         = attribute.String("mapping.abort_reason", string(service.AbortReasonInvalidActor))
	abortReasonInvalidAudience      = attribute.String("mapping.abort_reason", string(service.AbortReasonInvalidAudience))
	abortReasonUnsupportedTokenType = attribute.String("mapping.abort_reason", string(service.AbortReasonUnsupportedTokenType))
)

func oauthErrorAttr(code service.OAuthErrorCode) (attribute.KeyValue, bool) {
	switch code {
	case service.OAuthInvalidRequest:
		return oauthErrInvalidRequest, true
	case service.OAuthInvalidTarget:
		return oauthErrInvalidTarget, true
	case service.OAuthInvalidGrant:
		return oauthErrInvalidGrant, true
	case service.OAuthUnauthorizedClient:
		return oauthErrUnauthorizedClient, true
	case service.OAuthInvalidClient:
		return oauthErrInvalidClient, true
	case service.OAuthUnsupportedGrantType:
		return oauthErrUnsupportedGrantType, true
	case service.OAuthInvalidScope:
		return oauthErrInvalidScope, true
	default:
		return attribute.KeyValue{}, false
	}
}

func abortReasonAttr(reason service.AbortReason) (attribute.KeyValue, bool) {
	switch reason {
	case service.AbortReasonInvalidSubject:
		return abortReasonInvalidSubject, true
	case service.AbortReasonInvalidActor:
		return abortReasonInvalidActor, true
	case service.AbortReasonInvalidAudience:
		return abortReasonInvalidAudience, true
	case service.AbortReasonUnsupportedTokenType:
		return abortReasonUnsupportedTokenType, true
	default:
		return attribute.KeyValue{}, false
	}
}

// serviceObserver implements [service.ServiceObserver] using OTel histograms.
// Histogram instruments provide count, sum, and distribution via _count, _sum,
// and _bucket suffixes, making separate counters redundant.
type serviceObserver struct {
	service.NoOpServiceObserver

	issuanceDuration metric.Float64Histogram
	exchangeDuration metric.Float64Histogram
	authzDuration    metric.Float64Histogram
	clock            clock.Clock
}

func newServiceObserver(m metric.Meter, clk clock.Clock) (*serviceObserver, error) {
	id, err := m.Float64Histogram("parsec.token.issuance.duration",
		metric.WithDescription("Token issuance duration in seconds"),
		metric.WithUnit("s"),
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
	ad, err := m.Float64Histogram("parsec.authz.check.duration",
		metric.WithDescription("Authorization check duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &serviceObserver{
		issuanceDuration: id,
		exchangeDuration: ed,
		authzDuration:    ad,
		clock:            clk,
	}, nil
}

func (o *serviceObserver) TokenIssuanceStarted(
	ctx context.Context,
	_ *trust.Result,
	_ *trust.Result,
	_ string,
	_ []service.TokenType,
) (context.Context, service.TokenIssuanceProbe) {
	return ctx, &tokenIssuanceProbe{
		obs: o, ctx: ctx, startTime: o.clock.Now(),
		status: successStatusAttr, result: resultSuccess,
	}
}

func (o *serviceObserver) TokenExchangeStarted(
	ctx context.Context,
	grantType string,
	requestedTokenType string,
	_ string,
	_ string,
) (context.Context, service.TokenExchangeProbe) {
	return ctx, &tokenExchangeProbe{
		obs: o, ctx: ctx, startTime: o.clock.Now(),
		status:             successStatusAttr,
		result:             resultSuccess,
		grantType:          attribute.String("grant_type", grantType),
		requestedTokenType: attribute.String("requested_token_type", requestedTokenType),
	}
}

func (o *serviceObserver) AuthzCheckStarted(
	ctx context.Context,
) (context.Context, service.AuthzCheckProbe) {
	return ctx, &authzCheckProbe{
		obs: o, ctx: ctx, startTime: o.clock.Now(),
		status: successStatusAttr, result: resultSuccess,
	}
}

// --- token issuance probe ---

type tokenIssuanceProbe struct {
	service.NoOpTokenIssuanceProbe
	obs         *serviceObserver
	ctx         context.Context
	startTime   time.Time
	status      attribute.KeyValue
	result      attribute.KeyValue
	oauthError  attribute.KeyValue
	abortReason attribute.KeyValue
}

func (p *tokenIssuanceProbe) TokenTypeIssuanceFailed(_ service.TokenType, _ error) {
	p.status = errorStatusAttr
	p.result = resultIssuanceFailed
}
func (p *tokenIssuanceProbe) TokenTypeIssuanceDenied(_ service.TokenType, exchErr *service.ExchangeError) {
	p.status = errorStatusAttr
	p.result = resultIssuanceDenied
	if attr, ok := oauthErrorAttr(exchErr.OAuthError); ok {
		p.oauthError = attr
	}
	if attr, ok := abortReasonAttr(exchErr.Reason); ok {
		p.abortReason = attr
	}
}
func (p *tokenIssuanceProbe) IssuerNotFound(_ service.TokenType, _ error) {
	p.status = errorStatusAttr
	p.result = resultIssuerNotFound
}
func (p *tokenIssuanceProbe) End() {
	keys := []attribute.KeyValue{p.result, p.status}
	if p.oauthError.Key != "" {
		keys = append(keys, p.oauthError)
	}
	if p.abortReason.Key != "" {
		keys = append(keys, p.abortReason)
	}
	attrs := metric.WithAttributeSet(attribute.NewSet(keys...))
	p.obs.issuanceDuration.Record(p.ctx, p.obs.clock.Since(p.startTime).Seconds(), attrs)
}

// --- token exchange probe ---
// grant_type and requested_token_type are bounded by the OAuth 2.0 spec.

type tokenExchangeProbe struct {
	service.NoOpTokenExchangeProbe
	obs                *serviceObserver
	ctx                context.Context
	startTime          time.Time
	status             attribute.KeyValue
	result             attribute.KeyValue
	grantType          attribute.KeyValue
	requestedTokenType attribute.KeyValue
}

func (p *tokenExchangeProbe) ActorValidationFailed(_ error) {
	p.status = errorStatusAttr
	p.result = resultActorValidationFailed
}
func (p *tokenExchangeProbe) RequestContextParseFailed(_ error) {
	p.status = errorStatusAttr
	p.result = resultRequestContextParseFailed
}
func (p *tokenExchangeProbe) SubjectTokenValidationFailed(_ error) {
	p.status = errorStatusAttr
	p.result = resultSubjectTokenValidationFailed
}
func (p *tokenExchangeProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(
		p.grantType, p.requestedTokenType, p.result, p.status))
	p.obs.exchangeDuration.Record(p.ctx, p.obs.clock.Since(p.startTime).Seconds(), attrs)
}

// --- authz check probe ---

type authzCheckProbe struct {
	service.NoOpAuthzCheckProbe
	obs       *serviceObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	result    attribute.KeyValue
}

func (p *authzCheckProbe) ActorValidationFailed(_ error) {
	p.status = errorStatusAttr
	p.result = resultActorValidationFailed
}
func (p *authzCheckProbe) SubjectCredentialExtractionFailed(_ error) {
	p.status = errorStatusAttr
	p.result = resultSubjectCredentialExtractionFailed
}
func (p *authzCheckProbe) SubjectValidationFailed(_ error) {
	p.status = errorStatusAttr
	p.result = resultSubjectValidationFailed
}
func (p *authzCheckProbe) PolicyDecisionIssue(_ int, _ string, _ string) {
	p.result = resultPolicyIssue
}
func (p *authzCheckProbe) PolicyDecisionAllowWithoutIssue(_ string) {
	p.result = resultPolicyAllowWithoutIssue
}
func (p *authzCheckProbe) PolicyDecisionDeny(_ string) {
	p.status = errorStatusAttr
	p.result = resultPolicyDenied
}
func (p *authzCheckProbe) PolicyEvaluationFailed(_ error) {
	p.status = errorStatusAttr
	p.result = resultPolicyEvaluationFailed
}
func (p *authzCheckProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.result, p.status))
	p.obs.authzDuration.Record(p.ctx, p.obs.clock.Since(p.startTime).Seconds(), attrs)
}

var (
	_ service.ServiceObserver    = (*serviceObserver)(nil)
	_ service.TokenIssuanceProbe = (*tokenIssuanceProbe)(nil)
	_ service.TokenExchangeProbe = (*tokenExchangeProbe)(nil)
	_ service.AuthzCheckProbe    = (*authzCheckProbe)(nil)
)
