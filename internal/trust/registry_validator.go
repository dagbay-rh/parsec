package trust

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
)

const maxRegistryResponseBytes = 1 << 20 // 1 MB

// RegistryValidator validates credentials against an external registry authorization service.
// It accepts BasicAuth credentials, POSTs them to the configured registry service,
// and checks for access.pull == "granted" in the response.
type RegistryValidator struct {
	url             string
	trustDomain     string
	usernamePattern *regexp.Regexp
	httpClient      *http.Client
	cacheTTL        time.Duration
	cacheHMACKey    []byte
	mu              sync.RWMutex
	entries         map[string]*cacheEntry
	clock           clock.Clock
	observer        RegistryValidatorObserver
}

// registryValidatorConfig contains configuration for registry-auth validation.
type registryValidatorConfig struct {
	// CacheTTL is the TTL for caching successful auth results. Zero or negative value disables caching.
	// If nil, defaults to 5 min.
	CacheTTL *time.Duration

	// HTTPClient is the HTTP client for calling the registry service.
	// If nil, a default client is created (with TLSConfig applied if provided).
	HTTPClient *http.Client

	// Clock for time operations (testability). If nil, uses system clock.
	Clock clock.Clock

	// Observer for validation events. If nil, a no-op observer is used.
	Observer RegistryValidatorObserver
}

type cacheEntry struct {
	result    *Result
	expiresAt time.Time
}

type registryAuthRequest struct {
	Credentials registryCredentials `json:"credentials"`
}

type registryCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type registryAuthResponse struct {
	Access registryAccess `json:"access"`
}

type registryAccess struct {
	Pull string `json:"pull"`
}

type RegistryValidatorOption func(*registryValidatorConfig)

func WithCacheTTL(ttl time.Duration) RegistryValidatorOption {
	return func(cfg *registryValidatorConfig) {
		cfg.CacheTTL = &ttl
	}
}

func WithHTTPClient(client *http.Client) RegistryValidatorOption {
	return func(cfg *registryValidatorConfig) {
		cfg.HTTPClient = client
	}
}

func WithClock(clock clock.Clock) RegistryValidatorOption {
	return func(cfg *registryValidatorConfig) {
		cfg.Clock = clock
	}
}
func WithRegistryObserver(observer RegistryValidatorObserver) RegistryValidatorOption {
	return func(cfg *registryValidatorConfig) {
		cfg.Observer = observer
	}
}

// NewRegistryValidator creates a new registry-auth validator.
func NewRegistryValidator(registryURL, trustDomain, usernamePattern string, opts ...RegistryValidatorOption) (*RegistryValidator, error) {
	// validation
	if registryURL == "" {
		return nil, fmt.Errorf("registry URL is required")
	}
	parsedURL, err := url.Parse(registryURL)
	if err != nil {
		return nil, fmt.Errorf("invalid registry URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("registry URL must use https scheme, got %q", parsedURL.Scheme)
	}

	if trustDomain == "" {
		return nil, fmt.Errorf("trust domain is required")
	}
	
	if usernamePattern == "" {
		return nil, fmt.Errorf("usernamePattern is required")
	}
	var compiledPattern *regexp.Regexp
	compiledPattern, err = regexp.Compile(usernamePattern)
	if err != nil {
		return nil, fmt.Errorf("invalid username pattern: %w", err)
	}

	// options
	cfg := registryValidatorConfig{}
    for _, option := range opts {
        option(&cfg)
    }

	// defaults
	var cacheTTL time.Duration
	if cfg.CacheTTL == nil {
		cacheTTL = 5 * time.Minute
	} else if *cfg.CacheTTL < 0 {
		cacheTTL = 0
	} else {
		cacheTTL = *cfg.CacheTTL
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	obs := cfg.Observer
	if obs == nil {
		obs = NoOpRegistryValidatorObserver{}
	}
	
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("failed to generate cache HMAC key: %w", err)
	}

	return &RegistryValidator{
		url:             registryURL,
		trustDomain:     trustDomain,
		usernamePattern: compiledPattern,
		httpClient:      httpClient,
		cacheTTL:        cacheTTL,
		cacheHMACKey:    hmacKey,
		entries:         make(map[string]*cacheEntry),
		clock:           clk,
		observer:        obs,
	}, nil
}


// CredentialTypes returns the credential types this validator can handle.
func (v *RegistryValidator) CredentialTypes() []CredentialType {
	return []CredentialType{CredentialTypeBasicAuth}
}

// Validate validates a BasicAuth credential against the registry authorization service.
func (v *RegistryValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	ctx, p := v.observer.RegistryValidateStarted(ctx, v.url)
	defer p.End()

	cred, ok := credential.(*BasicAuthCredential)
	if !ok {
		return nil, fmt.Errorf("expected BasicAuthCredential, got %T", credential)
	}

	if cred.Username == "" || cred.Password == "" {
		return nil, fmt.Errorf("%w: empty username or password", ErrInvalidToken)
	}

	if v.usernamePattern != nil && !v.usernamePattern.MatchString(cred.Username) {
		p.UsernamePatternRejected()
		return nil, fmt.Errorf("%w: username does not match required pattern", ErrInvalidToken)
	}

	cacheKey := v.cacheKey(cred.Username, cred.Password)
	if v.cacheTTL > 0 {
		v.mu.RLock()
		entry, found := v.entries[cacheKey]
		v.mu.RUnlock()

		if found {
			if v.clock.Now().Before(entry.expiresAt) {
				p.CacheHit()
				return entry.result, nil
			}
			v.mu.Lock()
			delete(v.entries, cacheKey)
			v.mu.Unlock()
		}
	}

	if err := v.callRegistryService(ctx, cred.Username, cred.Password, p); err != nil {
		return nil, err
	}

	orgID, username, err := parseRegistryUsername(cred.Username)
	if err != nil {
		p.UsernameParseFailed(err)
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	now := v.clock.Now()
	result := &Result{
		Subject:     username,
		Issuer:      v.url,
		TrustDomain: v.trustDomain,
		Claims: claims.Claims{
			"org_id":    orgID,
			"auth_type": "registry-auth",
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(v.cacheTTL),
	}

	if v.cacheTTL > 0 {
		v.mu.Lock()
		v.entries[cacheKey] = &cacheEntry{
			result:    result,
			expiresAt: now.Add(v.cacheTTL),
		}
		v.mu.Unlock()
	}

	return result, nil
}

func (v *RegistryValidator) callRegistryService(ctx context.Context, username, password string, p RegistryValidateProbe) error {
	reqBody := registryAuthRequest{
		Credentials: registryCredentials{
			Username: username,
			Password: password,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal registry request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create registry request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(httpReq)
	if err != nil {
		p.RegistryCallFailed(err)
		return fmt.Errorf("%w: registry service call failed: %v", ErrInvalidToken, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponseBytes))
	if err != nil {
		p.RegistryCallFailed(err)
		return fmt.Errorf("%w: failed to read registry response: %v", ErrInvalidToken, err)
	}

	if resp.StatusCode != http.StatusOK {
		p.AccessDenied()
		return fmt.Errorf("%w: registry service returned status %d", ErrInvalidToken, resp.StatusCode)
	}

	var authResp registryAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		p.RegistryCallFailed(err)
		return fmt.Errorf("%w: invalid registry response: %v", ErrInvalidToken, err)
	}

	if authResp.Access.Pull != "granted" {
		p.AccessDenied()
		return fmt.Errorf("%w: registry access not granted", ErrInvalidToken)
	}

	return nil
}

// Cleanup removes expired entries from the cache.
// This should be called periodically to prevent memory leaks.
func (v *RegistryValidator) Cleanup() {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.clock.Now()
	for key, entry := range v.entries {
		if now.After(entry.expiresAt) {
			delete(v.entries, key)
		}
	}
}

func (v *RegistryValidator) cacheKey(username, password string) string {
	mac := hmac.New(sha256.New, v.cacheHMACKey)
	mac.Write([]byte(username + ":" + password))
	return hex.EncodeToString(mac.Sum(nil))
}

// parseRegistryUsername splits "org_id|username" into its components.
func parseRegistryUsername(raw string) (orgID string, username string, err error) {
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid username format: expected 'org_id|username', got %q", raw)
	}
	if parts[0] == "" {
		return "", "", fmt.Errorf("empty org_id in username %q", raw)
	}
	if parts[1] == "" {
		return "", "", fmt.Errorf("empty username in %q", raw)
	}
	return parts[0], parts[1], nil
}
