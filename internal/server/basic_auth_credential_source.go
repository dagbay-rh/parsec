package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/trust"
)

// BasicAuthCredentialSource extracts HTTP Basic Auth credentials from the
// Authorization header. It decodes the base64 value and splits it into
// username:password, returning a [trust.BasicAuthCredential].
//
// When the Authorization header is absent or uses a non-Basic scheme,
// Extract returns (nil, nil), allowing coexistence with other credential
// sources in the same chain.
type BasicAuthCredentialSource struct {
	SourceName string
}

// NewBasicAuthCredentialSource returns a BasicAuthCredentialSource with the given name.
func NewBasicAuthCredentialSource(name string) *BasicAuthCredentialSource {
	return &BasicAuthCredentialSource{SourceName: name}
}

func (s *BasicAuthCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	authHeader := cc.Headers["authorization"]
	if authHeader == "" {
		return nil, nil
	}

	scheme, value, ok := strings.Cut(authHeader, " ")
	if !ok || !strings.EqualFold(scheme, "basic") {
		return nil, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty Basic auth value")
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid Basic auth encoding: %w", err)
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return nil, fmt.Errorf("invalid Basic auth format: missing colon separator")
	}

	return &CredentialExtraction{
		Credential:      &trust.BasicAuthCredential{Username: username, Password: password},
		HeadersToRemove: []string{"authorization"},
		SourceName:      s.sourceName(),
	}, nil
}

func (s *BasicAuthCredentialSource) sourceName() string {
	if s.SourceName != "" {
		return s.SourceName
	}
	return CredentialSourceTypeBasicAuth
}
