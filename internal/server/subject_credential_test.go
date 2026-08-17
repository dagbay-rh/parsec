package server

import (
	"testing"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestSubjectCredential(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		tokenType string
		wantType  trust.CredentialType
	}{
		{
			name:      "JWT token type",
			token:     "fake-jwt-token-for-test",
			tokenType: "urn:ietf:params:oauth:token-type:jwt",
			wantType:  trust.CredentialTypeJWT,
		},
		{
			name:      "OIDC id_token type",
			token:     "fake-oidc-token-for-test",
			tokenType: "urn:ietf:params:oauth:token-type:id_token",
			wantType:  trust.CredentialTypeOIDC,
		},
		{
			name:      "username token type",
			token:     "alice",
			tokenType: "urn:redhat:params:oauth:token-type:username",
			wantType:  trust.CredentialTypeUsername,
		},
		{
			name:      "access_token type",
			token:     "opaque-token-xyz",
			tokenType: "urn:ietf:params:oauth:token-type:access_token",
			wantType:  trust.CredentialTypeBearer,
		},
		{
			name:      "empty token type defaults to bearer",
			token:     "some-token",
			tokenType: "",
			wantType:  trust.CredentialTypeBearer,
		},
		{
			name:      "unknown token type defaults to bearer",
			token:     "some-token",
			tokenType: "urn:example:custom:token-type",
			wantType:  trust.CredentialTypeBearer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := subjectCredential(tt.token, tt.tokenType)

			if cred.Type() != tt.wantType {
				t.Errorf("subjectCredential(%q, %q).Type() = %q, want %q",
					tt.token, tt.tokenType, cred.Type(), tt.wantType)
			}

			switch c := cred.(type) {
			case *trust.JWTCredential:
				if c.Token != tt.token {
					t.Errorf("JWTCredential.Token = %q, want %q", c.Token, tt.token)
				}
			case *trust.OIDCCredential:
				if c.Token != tt.token {
					t.Errorf("OIDCCredential.Token = %q, want %q", c.Token, tt.token)
				}
			case *trust.UsernameCredential:
				if c.Username != tt.token {
					t.Errorf("UsernameCredential.Username = %q, want %q", c.Username, tt.token)
				}
			case *trust.BearerCredential:
				if c.Token != tt.token {
					t.Errorf("BearerCredential.Token = %q, want %q", c.Token, tt.token)
				}
			default:
				t.Errorf("unexpected credential type: %T", cred)
			}
		})
	}
}
