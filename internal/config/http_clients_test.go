package config

import (
	"net/http"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/httpclient"
)

func TestNewHTTPClientRegistry_DefaultClientAutoCreated(t *testing.T) {
	registry, err := NewHTTPClientRegistry(nil, nil)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry() error: %v", err)
	}

	client, err := registry.Get("default")
	if err != nil {
		t.Fatalf("Get(default) error: %v", err)
	}

	if client.Timeout != defaultHTTPClientTimeout {
		t.Errorf("default client timeout = %v, want %v", client.Timeout, defaultHTTPClientTimeout)
	}
}

func TestNewHTTPClientRegistry_ExplicitDefault(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{
			Name:           "default",
			HTTPClientSpec: HTTPClientSpec{Timeout: "15s"},
		},
	}

	registry, err := NewHTTPClientRegistry(cfgs, nil)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry() error: %v", err)
	}

	client, err := registry.Get("default")
	if err != nil {
		t.Fatalf("Get(default) error: %v", err)
	}

	if client.Timeout != 15*time.Second {
		t.Errorf("default client timeout = %v, want %v", client.Timeout, 15*time.Second)
	}
}

func TestNewHTTPClientRegistry_NamedClient(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{
			Name: "api",
			HTTPClientSpec: HTTPClientSpec{
				Timeout: "10s",
				HTTPAuth: &HTTPAuthConfig{
					Type:  "bearer",
					Token: "my-token",
				},
			},
		},
	}

	registry, err := NewHTTPClientRegistry(cfgs, nil)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry() error: %v", err)
	}

	client, err := registry.Get("api")
	if err != nil {
		t.Fatalf("Get(api) error: %v", err)
	}

	if client.Timeout != 10*time.Second {
		t.Errorf("client timeout = %v, want %v", client.Timeout, 10*time.Second)
	}

	// The transport should be a BearerTransport wrapping DefaultTransport
	bt, ok := client.Transport.(*httpclient.BearerTransport)
	if !ok {
		t.Fatalf("transport type = %T, want *httpclient.BearerTransport", client.Transport)
	}
	if bt.Token != "my-token" {
		t.Errorf("token = %q, want %q", bt.Token, "my-token")
	}
}

func TestNewHTTPClientRegistry_MissingNameErrors(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{HTTPClientSpec: HTTPClientSpec{Timeout: "5s"}},
	}

	_, err := NewHTTPClientRegistry(cfgs, nil)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestNewHTTPClientRegistry_InvalidTimeoutErrors(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{Name: "bad", HTTPClientSpec: HTTPClientSpec{Timeout: "not-a-duration"}},
	}

	_, err := NewHTTPClientRegistry(cfgs, nil)
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestNewHTTPClientRegistry_InvalidAuthTypeErrors(t *testing.T) {
	cfgs := []HTTPClientConfig{
		{
			Name: "bad-auth",
			HTTPClientSpec: HTTPClientSpec{
				HTTPAuth: &HTTPAuthConfig{Type: "unknown"},
			},
		},
	}

	_, err := NewHTTPClientRegistry(cfgs, nil)
	if err == nil {
		t.Fatal("expected error for unknown auth type")
	}
}

func TestNewHTTPClientRegistry_FixtureTransportApplied(t *testing.T) {
	var called bool
	fixture := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	registry, err := NewHTTPClientRegistry(nil, fixture)
	if err != nil {
		t.Fatalf("NewHTTPClientRegistry() error: %v", err)
	}

	client, _ := registry.Get("default")
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if !called {
		t.Error("fixture transport was not used for default client")
	}
}

func TestResolveHTTPClient_ByName(t *testing.T) {
	registry, _ := NewHTTPClientRegistry([]HTTPClientConfig{
		{Name: "named", HTTPClientSpec: HTTPClientSpec{Timeout: "3s"}},
	}, nil)

	client, err := resolveHTTPClient("named", nil, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}
	if client.Timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", client.Timeout)
	}
}

func TestResolveHTTPClient_Inline(t *testing.T) {
	registry, _ := NewHTTPClientRegistry(nil, nil)

	spec := &HTTPClientSpec{Timeout: "7s"}
	client, err := resolveHTTPClient("", spec, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}
	if client.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want 7s", client.Timeout)
	}
}

func TestResolveHTTPClient_DefaultFallback(t *testing.T) {
	registry, _ := NewHTTPClientRegistry(nil, nil)

	client, err := resolveHTTPClient("", nil, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}
	if client.Timeout != defaultHTTPClientTimeout {
		t.Errorf("timeout = %v, want %v", client.Timeout, defaultHTTPClientTimeout)
	}
}

func TestResolveHTTPClient_InlinePrioritizedOverName(t *testing.T) {
	registry, _ := NewHTTPClientRegistry([]HTTPClientConfig{
		{Name: "named", HTTPClientSpec: HTTPClientSpec{Timeout: "99s"}},
	}, nil)

	spec := &HTTPClientSpec{Timeout: "1s"}
	client, err := resolveHTTPClient("named", spec, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}
	// Inline spec takes priority
	if client.Timeout != 1*time.Second {
		t.Errorf("timeout = %v, want 1s (inline spec should win)", client.Timeout)
	}
}

func TestResolveHTTPClient_InlineGetsFixtureTransport(t *testing.T) {
	var called bool
	fixture := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	registry, _ := NewHTTPClientRegistry(nil, fixture)

	spec := &HTTPClientSpec{Timeout: "5s"}
	client, err := resolveHTTPClient("", spec, registry)
	if err != nil {
		t.Fatalf("resolveHTTPClient error: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	if !called {
		t.Error("fixture transport should be applied to inline clients")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
