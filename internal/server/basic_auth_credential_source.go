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

// NewBasicAuthCredentialSource returns a BasicAuthCredentialSource with the
// given name. The name is required.
func NewBasicAuthCredentialSource(name string) (*BasicAuthCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("basic auth credential source: name is required")
	}
	return &BasicAuthCredentialSource{SourceName: name}, nil
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
		Credential:  &trust.BasicAuthCredential{Username: username, Password: password},
		HeadersUsed: []string{"authorization"},
		SourceName:  s.SourceName,
	}, nil
}
