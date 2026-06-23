package config

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// NewTrustStore creates a trust store from configuration
func NewTrustStore(cfg TrustStoreConfig, transport http.RoundTripper, trustObs trust.TrustObserver) (trust.Store, error) {
	switch cfg.Type {
	case "stub_store":
		return newStubStore(cfg, transport, trustObs)
	case "filtered_store":
		return newFilteredStore(cfg, transport, trustObs)
	default:
		return nil, fmt.Errorf("unknown trust store type: %s (supported: stub_store, filtered_store)", cfg.Type)
	}
}

// newStubStore creates a stub trust store (no filtering)
func newStubStore(cfg TrustStoreConfig, transport http.RoundTripper, trustObs trust.TrustObserver) (trust.Store, error) {
	store := trust.NewStubStore()

	// Add validators
	for _, validatorCfg := range cfg.Validators {
		validator, err := newValidator(validatorCfg.ValidatorConfig, transport, trustObs)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator: %w", err)
		}
		store.AddValidator(validator)
	}

	return store, nil
}

// newFilteredStore creates a filtered trust store with validator filtering
func newFilteredStore(cfg TrustStoreConfig, transport http.RoundTripper, trustObs trust.TrustObserver) (trust.Store, error) {
	var opts []trust.FilteredStoreOption

	// Add validator filter if configured
	if cfg.Filter != nil {
		filter, err := newValidatorFilter(*cfg.Filter)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator filter: %w", err)
		}
		opts = append(opts, trust.WithValidatorFilter(filter))
	}

	opts = append(opts, trust.WithObserver(trustObs))

	store, err := trust.NewFilteredStore(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create filtered store: %w", err)
	}

	// Add named validators
	for _, validatorCfg := range cfg.Validators {
		if validatorCfg.Name == "" {
			return nil, fmt.Errorf("validator name is required for filtered store")
		}

		validator, err := newValidator(validatorCfg.ValidatorConfig, transport, trustObs)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator %s: %w", validatorCfg.Name, err)
		}

		store.AddValidator(validatorCfg.Name, validator)
	}

	return store, nil
}

// newValidator creates a validator from configuration
func newValidator(cfg ValidatorConfig, transport http.RoundTripper, trustObs trust.TrustObserver) (trust.Validator, error) {
	switch cfg.Type {
	case "jwt_validator":
		return newJWTValidator(cfg, transport, trustObs)
	case "json_validator":
		return newJSONValidator(cfg)
	case "stub_validator":
		return newStubValidator(cfg)
	case "registry_validator":
		return newRegistryValidator(cfg, transport, trustObs)
	default:
		return nil, fmt.Errorf("unknown validator type: %s (supported: jwt_validator, json_validator, stub_validator, registry_validator)", cfg.Type)
	}
}

// newJWTValidator creates a JWT validator
func newJWTValidator(cfg ValidatorConfig, transport http.RoundTripper, trustObs trust.TrustObserver) (trust.Validator, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("jwt_validator requires issuer")
	}
	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("jwt_validator requires trust_domain")
	}

	validatorCfg := trust.JWTValidatorConfig{
		Issuer:           cfg.Issuer,
		JWKSURL:          cfg.JWKSURL,
		TrustDomain:      cfg.TrustDomain,
		AllowedAudiences: cfg.Audiences,
	}

	// Parse refresh interval if provided
	if cfg.RefreshInterval != "" {
		duration, err := time.ParseDuration(cfg.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh_interval: %w", err)
		}
		validatorCfg.RefreshInterval = duration
	}

	// Use provided transport if available
	if transport != nil {
		validatorCfg.HTTPClient = &http.Client{
			Transport: transport,
		}
	}

	validatorCfg.Observer = trustObs

	return trust.NewJWTValidator(validatorCfg)
}

// newJSONValidator creates a JSON validator
func newJSONValidator(cfg ValidatorConfig) (trust.Validator, error) {
	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("json_validator requires trust_domain")
	}

	return trust.NewJSONValidator(
		trust.WithTrustDomain(cfg.TrustDomain),
	), nil
}

// newStubValidator creates a stub validator
func newStubValidator(cfg ValidatorConfig) (trust.Validator, error) {
	// Convert credential type strings to CredentialType
	var credTypes []trust.CredentialType
	for _, typeStr := range cfg.CredentialTypes {
		credType, err := parseCredentialType(typeStr)
		if err != nil {
			return nil, err
		}
		credTypes = append(credTypes, credType)
	}

	// If no types specified, default to bearer
	if len(credTypes) == 0 {
		credTypes = []trust.CredentialType{trust.CredentialTypeBearer}
	}

	validator := trust.NewStubValidator(credTypes...)
	if len(cfg.Claims) == 0 {
		return validator, nil
	}

	trustDomain := cfg.TrustDomain
	if trustDomain == "" {
		trustDomain = "test-domain"
	}

	stubClaims := claims.Claims(maps.Clone(cfg.Claims))
	result := &trust.Result{
		Subject:     "test-subject",
		Issuer:      "https://test-issuer.example.com",
		TrustDomain: trustDomain,
		Claims:      stubClaims,
		ExpiresAt:   time.Now().Add(time.Hour),
		IssuedAt:    time.Now(),
		Audience:    []string{"https://parsec.example.com"},
	}
	if scope, ok := stubClaims["scope"].(string); ok {
		result.Scope = scope
	}

	return validator.WithResult(result), nil
}

// newRegistryValidator creates a registry-auth validator
func newRegistryValidator(cfg ValidatorConfig, transport http.RoundTripper, trustObs trust.TrustObserver) (trust.Validator, error) {
	if cfg.RegistryURL == "" {
		return nil, fmt.Errorf("registry_validator requires registry_url")
	}
	u, err := url.Parse(cfg.RegistryURL)
	if err != nil {
		return nil, fmt.Errorf("registry_validator: invalid registry_url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("registry_validator: registry_url must use https scheme, got %q", u.Scheme)
	}
	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("registry_validator requires trust_domain")
	}

	validatorCfg := trust.RegistryValidatorConfig{
		URL:             cfg.RegistryURL,
		TrustDomain:     cfg.TrustDomain,
		UsernamePattern: cfg.UsernamePattern,
		Observer:        trustObs,
	}

	if cfg.CacheTTL != "" {
		duration, err := time.ParseDuration(cfg.CacheTTL)
		if err != nil {
			return nil, fmt.Errorf("invalid cache_ttl: %w", err)
		}
		validatorCfg.CacheTTL = &duration
	}

	if cfg.RegistryTLS != nil {
		validatorCfg.TLSConfig = &trust.RegistryTLSConfig{
			InsecureSkipVerify: cfg.RegistryTLS.InsecureSkipVerify,
			ClientCertPath:     cfg.RegistryTLS.ClientCertPath,
			ClientKeyPath:      cfg.RegistryTLS.ClientKeyPath,
			SNI:                cfg.RegistryTLS.SNI,
		}
	}

	if transport != nil {
		validatorCfg.HTTPClient = &http.Client{Transport: transport}
	}

	return trust.NewRegistryValidator(validatorCfg)
}

// newValidatorFilter creates a validator filter from configuration
func newValidatorFilter(cfg ValidatorFilterConfig) (trust.ValidatorFilter, error) {
	switch cfg.Type {
	case "cel":
		if cfg.Script == "" {
			return nil, fmt.Errorf("cel filter requires script")
		}
		return trust.NewCelValidatorFilter(cfg.Script)
	case "any":
		// Composite filter - allows if any sub-filter allows
		if len(cfg.Filters) == 0 {
			return nil, fmt.Errorf("any filter requires at least one sub-filter")
		}

		// Recursively create sub-filters
		var subFilters []trust.ValidatorFilter
		for i, subCfg := range cfg.Filters {
			subFilter, err := newValidatorFilter(subCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create sub-filter %d: %w", i, err)
			}
			subFilters = append(subFilters, subFilter)
		}

		return trust.NewAnyValidatorFilter(subFilters...), nil
	case "passthrough":
		// Passthrough filter - allows all validators
		return &passthroughValidatorFilter{}, nil
	default:
		return nil, fmt.Errorf("unknown validator filter type: %s (supported: cel, any, passthrough)", cfg.Type)
	}
}

// passthroughValidatorFilter allows all validators (no filtering)
type passthroughValidatorFilter struct{}

func (f *passthroughValidatorFilter) IsAllowed(_ context.Context, _ *trust.Result, _ string, _ *request.RequestAttributes) (bool, error) {
	return true, nil
}

// parseCredentialType converts a string to a CredentialType
func parseCredentialType(s string) (trust.CredentialType, error) {
	switch s {
	case "bearer":
		return trust.CredentialTypeBearer, nil
	case "jwt":
		return trust.CredentialTypeJWT, nil
	case "json":
		return trust.CredentialTypeJSON, nil
	case "mtls":
		return trust.CredentialTypeMTLS, nil
	case "basic_auth":
		return trust.CredentialTypeBasicAuth, nil
	default:
		return "", fmt.Errorf("unknown credential type: %s (supported: bearer, jwt, json, mtls, basic_auth)", s)
	}
}
