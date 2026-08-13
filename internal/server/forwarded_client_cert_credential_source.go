package server

import (
	"context"
	"fmt"

	"github.com/project-kessel/parsec/internal/trust"
)

// ForwardedClientCertCredentialSource extracts certificate authentication
// credentials from proxy-forwarded headers. A TLS-terminating proxy (e.g.,
// Akamai CDN) validates the client certificate and forwards the subject and
// issuer as headers. The header names are configurable.
//
// When neither header is present, Extract returns (nil, nil), allowing
// coexistence with other credential sources in the same chain.
type ForwardedClientCertCredentialSource struct {
	SourceName    string
	SubjectHeader string
	IssuerHeader  string
}

func NewForwardedClientCertCredentialSource(name, subjectHeader, issuerHeader string) (*ForwardedClientCertCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("forwarded client cert credential source: name is required")
	}
	if subjectHeader == "" {
		return nil, fmt.Errorf("forwarded client cert credential source: subject_header is required")
	}
	if issuerHeader == "" {
		return nil, fmt.Errorf("forwarded client cert credential source: issuer_header is required")
	}
	return &ForwardedClientCertCredentialSource{
		SourceName:    name,
		SubjectHeader: subjectHeader,
		IssuerHeader:  issuerHeader,
	}, nil
}

func (s *ForwardedClientCertCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	subject := cc.Headers[s.SubjectHeader]
	issuer := cc.Headers[s.IssuerHeader]

	if subject == "" && issuer == "" {
		return nil, nil
	}

	if subject == "" {
		return nil, fmt.Errorf("missing required header: %s (both subject and issuer headers must be present)", s.SubjectHeader)
	}
	if issuer == "" {
		return nil, fmt.Errorf("missing required header: %s (both subject and issuer headers must be present)", s.IssuerHeader)
	}

	return &CredentialExtraction{
		Credential: &trust.ForwardedClientCertCredential{
			Subject: subject,
			Issuer:  issuer,
		},
		HeadersUsed: []string{s.SubjectHeader, s.IssuerHeader},
		SourceName:  s.SourceName,
	}, nil
}
