package server

import (
	"context"
	"fmt"

	"github.com/project-kessel/parsec/internal/trust"
)

const (
	HeaderCertAuthCN     = "x-rh-certauth-cn"
	HeaderCertAuthIssuer = "x-rh-certauth-issuer"
)

// ForwardedClientCertCredentialSource extracts certificate authentication
// credentials from proxy-forwarded headers. A TLS-terminating proxy (e.g.,
// Akamai CDN) validates the client certificate and forwards the subject and
// issuer as x-rh-certauth-cn and x-rh-certauth-issuer headers.
//
// When both headers are absent, Extract returns (nil, nil), allowing
// coexistence with other credential sources in the same chain.
type ForwardedClientCertCredentialSource struct {
	SourceName string
}

// NewForwardedClientCertCredentialSource returns a ForwardedClientCertCredentialSource
// with the given name. The name is required.
func NewForwardedClientCertCredentialSource(name string) (*ForwardedClientCertCredentialSource, error) {
	if name == "" {
		return nil, fmt.Errorf("forwarded client cert credential source: name is required")
	}
	return &ForwardedClientCertCredentialSource{SourceName: name}, nil
}

func (s *ForwardedClientCertCredentialSource) Extract(_ context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	cn := cc.Headers[HeaderCertAuthCN]
	issuer := cc.Headers[HeaderCertAuthIssuer]

	if cn == "" && issuer == "" {
		return nil, nil
	}

	if cn == "" {
		return nil, fmt.Errorf("%s header is required when %s is present", HeaderCertAuthCN, HeaderCertAuthIssuer)
	}
	if issuer == "" {
		return nil, fmt.Errorf("%s header is required when %s is present", HeaderCertAuthIssuer, HeaderCertAuthCN)
	}

	return &CredentialExtraction{
		Credential:  &trust.ForwardedClientCertCredential{CN: cn, Issuer: issuer},
		HeadersUsed: []string{HeaderCertAuthCN, HeaderCertAuthIssuer},
		SourceName:  s.SourceName,
	}, nil
}
