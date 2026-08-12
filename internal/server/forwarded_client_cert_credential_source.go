package server

import (
	"context"
	"fmt"

	"github.com/project-kessel/parsec/internal/trust"
)

// ForwardedClientCertCredentialSource extracts certificate authentication
// credentials from proxy-forwarded headers. A TLS-terminating proxy (e.g.,
// Akamai CDN) validates the client certificate and forwards relevant fields
// as headers. The set of headers to extract is configurable.
//
// When none of the configured headers are present, Extract returns (nil, nil),
// allowing coexistence with other credential sources in the same chain.
type ForwardedClientCertCredentialSource struct {
	SourceName string
	Headers    []string
}

// NewForwardedClientCertCredentialSource returns a ForwardedClientCertCredentialSource
// with the given name and list of headers to extract.
func NewForwardedClientCertCredentialSource(name string, headers []string) (*ForwardedClientCertCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("forwarded client cert credential source: name is required")
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("forwarded client cert credential source: at least one header is required")
	}
	return &ForwardedClientCertCredentialSource{SourceName: name, Headers: headers}, nil
}

func (s *ForwardedClientCertCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	extracted := make(map[string]string)
	for _, h := range s.Headers {
		if v := cc.Headers[h]; v != "" {
			extracted[h] = v
		}
	}

	if len(extracted) == 0 {
		return nil, nil
	}

	if len(extracted) != len(s.Headers) {
		var missing []string
		for _, h := range s.Headers {
			if _, ok := extracted[h]; !ok {
				missing = append(missing, h)
			}
		}
		return nil, fmt.Errorf("missing required headers: %v (all configured headers must be present when any are)", missing)
	}

	return &CredentialExtraction{
		Credential:  &trust.ForwardedClientCertCredential{Headers: extracted},
		HeadersUsed: s.Headers,
		SourceName:  s.SourceName,
	}, nil
}
