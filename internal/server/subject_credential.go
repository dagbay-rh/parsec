package server

import "github.com/project-kessel/parsec/internal/trust"

// subjectCredential maps an RFC 8693 subject_token_type URN and the raw token
// value to the appropriate strongly-typed trust.Credential.
//
// Unknown or empty token types fall back to BearerCredential for backward
// compatibility. Validators registered for the resulting credential type in
// the trust store handle actual validation.
func subjectCredential(token, tokenType string) trust.Credential {
	switch tokenType {
	case "urn:ietf:params:oauth:token-type:jwt":
		return &trust.JWTCredential{
			BearerCredential: trust.BearerCredential{Token: token},
		}
	case "urn:ietf:params:oauth:token-type:id_token":
		return &trust.OIDCCredential{Token: token}
	case trust.UnsignedJSONTokenTypeURN:
		return &trust.JSONCredential{RawJSON: []byte(token)}
	case "urn:ietf:params:oauth:token-type:access_token", "":
		return &trust.BearerCredential{Token: token}
	default:
		return &trust.BearerCredential{Token: token}
	}
}
