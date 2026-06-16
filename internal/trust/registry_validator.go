package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
)

// RegistryValidator validates credentials against an external registry authorization service.
// It accepts BasicAuth credentials, POSTs them to the configured registry service,
// and checks for access.pull == "granted" in the response.
type RegistryValidator struct {
	url             string
	trustDomain     string
	usernamePattern *regexp.Regexp
	httpClient      *http.Client
	cacheTTL        time.Duration
	mu              sync.RWMutex
	entries         map[string]*cacheEntry
	clock           clock.Clock
	observer        RegistryValidatorObserver
}

// RegistryValidatorConfig contains configuration for registry-auth validation.
type RegistryValidatorConfig struct {
	// URL is the registry authorization service endpoint
	URL string

	// TrustDomain for validated identities
	TrustDomain string

	// UsernamePattern is a regex the username must match.
	// Empty means accept all usernames.
	UsernamePattern string

	// CacheTTL is the TTL for caching successful auth results. Zero disables caching.
	CacheTTL time.Duration

	// HTTPClient is the HTTP client for calling the registry service.
	// If nil, a default client is created (with TLSConfig applied if provided).
	HTTPClient *http.Client

	// TLSConfig configures TLS for the registry service connection.
	TLSConfig *RegistryTLSConfig

	// Clock for time operations (testability). If nil, uses system clock.
	Clock clock.Clock

	// Observer for validation events. If nil, a no-op observer is used.
	Observer RegistryValidatorObserver
}

// RegistryTLSConfig configures TLS for the registry service connection.
type RegistryTLSConfig struct {
	InsecureSkipVerify bool
	ClientCertPath     string
	ClientKeyPath      string
	// SNI overrides the TLS ServerName sent during the handshake. Needed when the
	// registry URL points to an internal address but the server's certificate is
	// issued for a different hostname (e.g. behind a load balancer or proxy).
	SNI string
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

// NewRegistryValidator creates a new registry-auth validator.
func NewRegistryValidator(cfg RegistryValidatorConfig) (*RegistryValidator, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("registry URL is required")
	}
	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("trust domain is required")
	}

	var compiledPattern *regexp.Regexp
	if cfg.UsernamePattern != "" {
		var err error
		compiledPattern, err = regexp.Compile(cfg.UsernamePattern)
		if err != nil {
			return nil, fmt.Errorf("invalid username pattern: %w", err)
		}
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		var err error
		httpClient, err = buildHTTPClient(cfg.TLSConfig)
		if err != nil {
			return nil, err
		}
	}

	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	obs := cfg.Observer
	if obs == nil {
		obs = NoOpRegistryValidatorObserver{}
	}

	return &RegistryValidator{
		url:             cfg.URL,
		trustDomain:     cfg.TrustDomain,
		usernamePattern: compiledPattern,
		httpClient:      httpClient,
		cacheTTL:        cfg.CacheTTL,
		entries:         make(map[string]*cacheEntry),
		clock:           clk,
		observer:        obs,
	}, nil
}

func buildHTTPClient(tlsCfg *RegistryTLSConfig) (*http.Client, error) {
	if tlsCfg == nil {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
			ServerName:         tlsCfg.SNI,
		},
	}

	if tlsCfg.ClientCertPath != "" && tlsCfg.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfg.ClientCertPath, tlsCfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate/key: %w", err)
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
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
		ExpiresAt: now.Add(v.effectiveTTL()),
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

	respBody, err := io.ReadAll(resp.Body)
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
	h := sha256.Sum256([]byte(username + ":" + password))
	return hex.EncodeToString(h[:])
}

func (v *RegistryValidator) effectiveTTL() time.Duration {
	if v.cacheTTL > 0 {
		return v.cacheTTL
	}
	return 5 * time.Minute
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
