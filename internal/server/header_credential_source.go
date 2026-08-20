package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/trust"
)

// HeaderSpec configures a single header for extraction.
type HeaderSpec struct {
	Name string
}

// HeaderCredentialSource extracts a configurable set of headers from a request
// and passes them to validators as a generic HeaderCredential.
//
// When none of the configured headers are present, Extract returns (nil, nil),
// allowing coexistence with other credential sources in the same chain.
type HeaderCredentialSource struct {
	SourceName string
	Headers    []HeaderSpec
}

func NewHeaderCredentialSource(name string, headers []HeaderSpec) (*HeaderCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("header credential source: name is required")
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("header credential source: at least one header is required")
	}
	normalized := make([]HeaderSpec, len(headers))
	for i, h := range headers {
		normalized[i] = HeaderSpec{Name: strings.ToLower(h.Name)}
	}
	return &HeaderCredentialSource{SourceName: name, Headers: normalized}, nil
}

func (s *HeaderCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	extracted := make(map[string]string)
	headerNames := make([]string, len(s.Headers))
	for i, h := range s.Headers {
		headerNames[i] = h.Name
		if v := cc.Headers[h.Name]; v != "" {
			extracted[h.Name] = v
		}
	}

	if len(extracted) == 0 {
		return nil, nil
	}

	if len(extracted) != len(s.Headers) {
		var missing []string
		for _, h := range s.Headers {
			if _, ok := extracted[h.Name]; !ok {
				missing = append(missing, h.Name)
			}
		}
		return nil, fmt.Errorf("missing required headers: %v (all configured headers must be present when any are)", missing)
	}

	return &CredentialExtraction{
		Credential:  &trust.HeaderCredential{Headers: extracted},
		HeadersUsed: headerNames,
		SourceName:  s.SourceName,
	}, nil
}
