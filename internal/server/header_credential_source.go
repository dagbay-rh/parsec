package server

import (
	"context"
	"fmt"

	"github.com/project-kessel/parsec/internal/trust"
)

// HeaderCredentialSource extracts a configurable set of headers from a request
// and passes them to validators as a generic HeaderCredential.
//
// When none of the configured headers are present, Extract returns (nil, nil),
// allowing coexistence with other credential sources in the same chain.
type HeaderCredentialSource struct {
	SourceName string
	Headers    []string
}

func NewHeaderCredentialSource(name string, headers []string) (*HeaderCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("header credential source: name is required")
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("header credential source: at least one header is required")
	}
	return &HeaderCredentialSource{SourceName: name, Headers: headers}, nil
}

func (s *HeaderCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
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
		Credential:  &trust.HeaderCredential{Headers: extracted},
		HeadersUsed: s.Headers,
		SourceName:  s.SourceName,
	}, nil
}
