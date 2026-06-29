package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/trust"
)

// CookieCredentialSource extracts a bearer token from a named cookie.
type CookieCredentialSource struct {
	SourceName string
	CookieName string
}

// NewCookieCredentialSource returns a CookieCredentialSource with the given
// source name and cookie name. Both are required.
func NewCookieCredentialSource(name, cookieName string) (*CookieCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("cookie credential source: name is required")
	}
	if cookieName == "" {
		return nil, fmt.Errorf("cookie credential source: cookie_name is required")
	}
	return &CookieCredentialSource{SourceName: name, CookieName: cookieName}, nil
}

func (s *CookieCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	cookieHeader := cc.Headers["cookie"]
	if cookieHeader == "" {
		return nil, nil
	}

	token, ok := cookieValue(cookieHeader, s.CookieName)
	if !ok {
		return nil, nil
	}
	if token == "" {
		return nil, fmt.Errorf("cookie %q present but token is empty", s.CookieName)
	}

	return &CredentialExtraction{
		Credential:  &trust.BearerCredential{Token: token},
		CookiesUsed: []string{s.CookieName},
		SourceName:  s.SourceName,
	}, nil
}

func cookieValue(cookieHeader, name string) (string, bool) {
	for part := range strings.SplitSeq(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		key, value, ok := strings.Cut(part, "=")
		if ok && key == name {
			return strings.Trim(value, `"`), true
		}
	}
	return "", false
}

// sanitizeCookieHeader rebuilds a Cookie header value without the named
// cookies. Returns an empty string when all cookies are omitted.
func sanitizeCookieHeader(cookieHeader string, omitNames ...string) string {
	omit := make(map[string]struct{}, len(omitNames))
	for _, name := range omitNames {
		omit[name] = struct{}{}
	}
	var remaining []string
	for part := range strings.SplitSeq(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, _, ok := strings.Cut(part, "=")
		if ok {
			if _, skip := omit[key]; skip {
				continue
			}
		}
		remaining = append(remaining, part)
	}
	return strings.Join(remaining, "; ")
}
