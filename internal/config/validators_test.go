package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/trust"
)

func TestNewRegistryValidator(t *testing.T) {
	tests := []struct {
		name      string
		cfg       ValidatorConfig
		transport http.RoundTripper
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid minimal config",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "https://registry.example.com/v1/auth",
				TrustDomain:     "example.com",
				UsernamePattern: `^\d+\|.+$`,
			},
		},
		{
			name: "valid with cache TTL",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "https://registry.example.com/v1/auth",
				TrustDomain:     "example.com",
				UsernamePattern: `^\d+\|.+$`,
				CacheTTL:        "5m",
			},
		},
		{
			name: "valid with HTTP timeout",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "https://registry.example.com/v1/auth",
				TrustDomain:     "example.com",
				UsernamePattern: `^\d+\|.+$`,
				HTTPTimeout:     "10s",
			},
		},
		{
			name: "invalid cache TTL",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "https://registry.example.com/v1/auth",
				TrustDomain:     "example.com",
				UsernamePattern: `^\d+\|.+$`,
				CacheTTL:        "not-a-duration",
			},
			wantErr: true,
			errMsg:  "invalid cache_ttl",
		},
		{
			name: "invalid HTTP timeout",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "https://registry.example.com/v1/auth",
				TrustDomain:     "example.com",
				UsernamePattern: `^\d+\|.+$`,
				HTTPTimeout:     "bad",
			},
			wantErr: true,
			errMsg:  "invalid http_timeout",
		},
		{
			name: "missing registry URL",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				TrustDomain:     "example.com",
				UsernamePattern: `^\d+\|.+$`,
			},
			wantErr: true,
			errMsg:  "registry URL is required",
		},
		{
			name: "missing trust domain",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "https://registry.example.com/v1/auth",
				UsernamePattern: `^\d+\|.+$`,
			},
			wantErr: true,
			errMsg:  "trust domain is required",
		},
		{
			name: "missing username pattern",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "https://registry.example.com/v1/auth",
				TrustDomain:     "example.com",
				UsernamePattern: "",
			},
			wantErr: true,
			errMsg:  "usernamePattern is required",
		},
		{
			name: "non-https URL",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "http://registry.example.com/v1/auth",
				TrustDomain:     "example.com",
				UsernamePattern: `^\d+\|.+$`,
			},
			wantErr: true,
			errMsg:  "registry URL must use https",
		},
		{
			name: "with transport",
			cfg: ValidatorConfig{
				Type:            "registry_validator",
				RegistryURL:     "https://registry.example.com/v1/auth",
				TrustDomain:     "example.com",
				UsernamePattern: `^\d+\|.+$`,
			},
			transport: http.DefaultTransport,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := newRegistryValidator(tt.cfg, tt.transport, trust.NoOpTrustObserver{})
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v == nil {
				t.Fatal("expected non-nil validator")
			}
		})
	}
}

func TestBuildRegistryHTTPClient(t *testing.T) {
	t.Run("nil TLS nil transport defaults", func(t *testing.T) {
		client, err := buildRegistryHTTPClient(nil, nil, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client.Timeout != 30*time.Second {
			t.Fatalf("expected 30s timeout, got %v", client.Timeout)
		}
		if client.Transport != nil {
			t.Fatal("expected nil transport")
		}
	})

	t.Run("nil TLS with transport", func(t *testing.T) {
		transport := http.DefaultTransport
		client, err := buildRegistryHTTPClient(nil, transport, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client.Transport != transport {
			t.Fatal("expected provided transport")
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		client, err := buildRegistryHTTPClient(nil, nil, 10*time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client.Timeout != 10*time.Second {
			t.Fatalf("expected 10s timeout, got %v", client.Timeout)
		}
	})

	t.Run("zero timeout defaults to 30s", func(t *testing.T) {
		client, err := buildRegistryHTTPClient(nil, nil, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client.Timeout != 30*time.Second {
			t.Fatalf("expected 30s default timeout, got %v", client.Timeout)
		}
	})

	t.Run("TLS with SNI", func(t *testing.T) {
		tlsCfg := &RegistryTLSConfig{SNI: "registry.internal"}
		client, err := buildRegistryHTTPClient(tlsCfg, nil, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected *http.Transport")
		}
		if transport.TLSClientConfig.ServerName != "registry.internal" {
			t.Fatalf("expected SNI 'registry.internal', got %q", transport.TLSClientConfig.ServerName)
		}
	})

	t.Run("TLS with InsecureSkipVerify", func(t *testing.T) {
		tlsCfg := &RegistryTLSConfig{InsecureSkipVerify: true}
		client, err := buildRegistryHTTPClient(tlsCfg, nil, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected *http.Transport")
		}
		if !transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("expected InsecureSkipVerify to be true")
		}
	})

	t.Run("only cert no key", func(t *testing.T) {
		tlsCfg := &RegistryTLSConfig{ClientCertPath: "/some/cert.pem"}
		_, err := buildRegistryHTTPClient(tlsCfg, nil, 0)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "only certificate provided") {
			t.Fatalf("expected cert-only error, got %q", err.Error())
		}
	})

	t.Run("only key no cert", func(t *testing.T) {
		tlsCfg := &RegistryTLSConfig{ClientKeyPath: "/some/key.pem"}
		_, err := buildRegistryHTTPClient(tlsCfg, nil, 0)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "only key provided") {
			t.Fatalf("expected key-only error, got %q", err.Error())
		}
	})

	t.Run("invalid cert key paths", func(t *testing.T) {
		tlsCfg := &RegistryTLSConfig{
			ClientCertPath: "/nonexistent/cert.pem",
			ClientKeyPath:  "/nonexistent/key.pem",
		}
		_, err := buildRegistryHTTPClient(tlsCfg, nil, 0)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "failed to load client certificate/key") {
			t.Fatalf("expected load error, got %q", err.Error())
		}
	})

	t.Run("valid cert and key", func(t *testing.T) {
		certPath, keyPath := generateTestCert(t)
		tlsCfg := &RegistryTLSConfig{
			ClientCertPath: certPath,
			ClientKeyPath:  keyPath,
		}
		client, err := buildRegistryHTTPClient(tlsCfg, nil, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected *http.Transport")
		}
		if len(transport.TLSClientConfig.Certificates) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(transport.TLSClientConfig.Certificates))
		}
	})
}

func generateTestCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	return certPath, keyPath
}
