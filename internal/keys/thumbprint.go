package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// ecdsaCoordinates extracts the X and Y coordinates from an ECDSA public key
// using the uncompressed point encoding (0x04 || X || Y) returned by Bytes().
func ecdsaCoordinates(key *ecdsa.PublicKey) (x, y []byte, err error) {
	raw, err := key.Bytes()
	if err != nil {
		return nil, nil, err
	}
	// Uncompressed point: 0x04 prefix + X + Y (equal length)
	coordLen := (len(raw) - 1) / 2
	return raw[1 : 1+coordLen], raw[1+coordLen:], nil
}

// ComputeThumbprint computes the RFC 7638 JWK Thumbprint for a public key.
// Returns a base64url-encoded SHA-256 hash of the canonical JWK representation.
func ComputeThumbprint(publicKey crypto.PublicKey) (string, error) {
	jwk, err := publicKeyToJWK(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to convert public key to JWK: %w", err)
	}

	// Create canonical JSON representation (sorted keys, no whitespace)
	canonicalJSON, err := canonicalizeJWK(jwk)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize JWK: %w", err)
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256([]byte(canonicalJSON))

	// Return base64url-encoded (no padding)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// publicKeyToJWK converts a crypto.PublicKey to a JWK map
func publicKeyToJWK(publicKey crypto.PublicKey) (map[string]interface{}, error) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsaToJWK(key)
	case *rsa.PublicKey:
		return rsaToJWK(key)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", publicKey)
	}
}

// ecdsaToJWK converts an ECDSA public key to JWK format
func ecdsaToJWK(key *ecdsa.PublicKey) (map[string]interface{}, error) {
	curve := key.Params().Name
	var crv string
	switch curve {
	case "P-256":
		crv = "P-256"
	case "P-384":
		crv = "P-384"
	case "P-521":
		crv = "P-521"
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %s", curve)
	}

	// Extract coordinates from the uncompressed point encoding
	x, y, err := ecdsaCoordinates(key)
	if err != nil {
		return nil, fmt.Errorf("failed to encode EC public key: %w", err)
	}

	return map[string]interface{}{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}, nil
}

// rsaToJWK converts an RSA public key to JWK format
func rsaToJWK(key *rsa.PublicKey) (map[string]interface{}, error) {
	return map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}, nil
}

// canonicalizeJWK creates the canonical JSON representation for RFC 7638
func canonicalizeJWK(jwk map[string]interface{}) (string, error) {
	// Get required members based on key type
	kty, ok := jwk["kty"].(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid 'kty' field")
	}

	var requiredMembers []string
	switch kty {
	case "EC":
		requiredMembers = []string{"crv", "kty", "x", "y"}
	case "RSA":
		requiredMembers = []string{"e", "kty", "n"}
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}

	// Build canonical map with only required members
	canonical := make(map[string]interface{})
	for _, member := range requiredMembers {
		value, ok := jwk[member]
		if !ok {
			return "", fmt.Errorf("missing required member: %s", member)
		}
		canonical[member] = value
	}

	// Marshal to JSON (Go's json.Marshal produces sorted keys for maps)
	jsonBytes, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
