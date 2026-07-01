package server

import (
	"context"
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// Representative optional-auth patterns (subset of configs/examples/parsec-optional-auth.yaml).
var testOptionalPathPatterns = []string{
	`^/r/insights/platform/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json$`,
	`^/api/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json$`,
	`^/api/pulp/api/v3/status/$`,
	`^/api/pulp-content/public-.*$`,
	`^/api/distributors/.*/v[0-9]/openapi.json$`,
	`^/api/content-sources/v[0-9]+(\.[0-9]+)?/repository_gpg_key/[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}$`,
	`^/api/distributors/docs$`,
}

func newTestOptionalPathPolicy(t *testing.T, tokenTypes []TokenTypeSpec) *OptionalPathAuthzPolicy {
	t.Helper()
	policy, err := NewOptionalPathAuthzPolicy(testOptionalPathPatterns, tokenTypes)
	if err != nil {
		t.Fatalf("NewOptionalPathAuthzPolicy: %v", err)
	}
	return policy
}

func TestNormalizeRequestPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{"/api/foo", "/api/foo"},
		{"/api/foo?bar=baz", "/api/foo"},
		{"/api/foo?", "/api/foo"},
		{"", ""},
	}

	for _, tt := range tests {
		if got := normalizeRequestPath(tt.in); got != tt.want {
			t.Errorf("normalizeRequestPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestOptionalPathAuthzPolicy(t *testing.T) {
	t.Parallel()

	customTypes := []TokenTypeSpec{
		{Type: service.TokenTypeRHIdentity, HeaderName: "x-rh-identity"},
	}
	policy := newTestOptionalPathPolicy(t, customTypes)

	tests := []struct {
		name       string
		subject    Principal
		path       string
		wantAction AuthzCheckAction
		wantReason string
	}{
		{
			name:       "anonymous optional path",
			subject:    anonymousPrincipal(),
			path:       "/api/foo/v1/openapi.json",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "anonymous optional path with query",
			subject:    anonymousPrincipal(),
			path:       "/api/foo/v1/openapi.json?format=yaml",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "authenticated optional path",
			subject:    Principal{Result: &trust.Result{Subject: "user@example.com"}},
			path:       "/api/foo/v1/openapi.json",
			wantAction: AuthzCheckIssue,
		},
		{
			name:       "anonymous protected path",
			subject:    anonymousPrincipal(),
			path:       "/api/private/resource",
			wantAction: AuthzCheckDeny,
			wantReason: anonymousSubjectDenyReason,
		},
		{
			name:       "insights openapi",
			subject:    anonymousPrincipal(),
			path:       "/r/insights/platform/cost-management/v1/openapi.json",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "pulp status",
			subject:    anonymousPrincipal(),
			path:       "/api/pulp/api/v3/status/",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "pulp content public",
			subject:    anonymousPrincipal(),
			path:       "/api/pulp-content/public-foo/bar",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "distributors openapi",
			subject:    anonymousPrincipal(),
			path:       "/api/distributors/acme/v1/openapi.json",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "content sources gpg key",
			subject:    anonymousPrincipal(),
			path:       "/api/content-sources/v1/repository_gpg_key/12345678-1234-1234-1234-123456789012",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "distributors docs",
			subject:    anonymousPrincipal(),
			path:       "/api/distributors/docs",
			wantAction: AuthzCheckAllowWithoutIssue,
		},
		{
			name:       "unanchored pattern does not substring match",
			subject:    anonymousPrincipal(),
			path:       "/private/api/distributors/docs/secret",
			wantAction: AuthzCheckDeny,
			wantReason: anonymousSubjectDenyReason,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
				Subject: tt.subject,
				Request: &request.RequestAttributes{Path: tt.path},
			})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Action != tt.wantAction {
				t.Errorf("expected action %s, got %s", tt.wantAction, decision.Action)
			}
			if tt.wantReason != "" && decision.Reason != tt.wantReason {
				t.Errorf("expected reason %q, got %q", tt.wantReason, decision.Reason)
			}
			if tt.wantAction == AuthzCheckIssue {
				if len(decision.TokenTypes) != 1 || decision.TokenTypes[0].HeaderName != "x-rh-identity" {
					t.Errorf("unexpected token types: %+v", decision.TokenTypes)
				}
			}
		})
	}
}

func TestOptionalPathAuthzPolicy_ImplicitAnchoring(t *testing.T) {
	t.Parallel()

	// Pattern without explicit ^ or $ anchors — the constructor wraps it
	// in ^(?:...)$ so it only matches the full path, not a substring.
	policy, err := NewOptionalPathAuthzPolicy([]string{`/public/health`}, nil)
	if err != nil {
		t.Fatalf("NewOptionalPathAuthzPolicy: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		wantAction AuthzCheckAction
	}{
		{"exact match", "/public/health", AuthzCheckAllowWithoutIssue},
		{"prefix should not match", "/public/health/extra", AuthzCheckDeny},
		{"suffix should not match", "/x/public/health", AuthzCheckDeny},
		{"substring should not match", "/prefix/public/health/suffix", AuthzCheckDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, err := policy.Decide(context.Background(), AuthzCheckPolicyInput{
				Subject: anonymousPrincipal(),
				Request: &request.RequestAttributes{Path: tt.path},
			})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Action != tt.wantAction {
				t.Errorf("path %q: expected action %s, got %s", tt.path, tt.wantAction, decision.Action)
			}
		})
	}
}

func TestNewOptionalPathAuthzPolicy_EmptyPatterns(t *testing.T) {
	t.Parallel()

	_, err := NewOptionalPathAuthzPolicy(nil, nil)
	if err == nil {
		t.Fatal("expected error for empty patterns")
	}
}

func TestNewOptionalPathAuthzPolicy_InvalidPattern(t *testing.T) {
	t.Parallel()

	_, err := NewOptionalPathAuthzPolicy([]string{`[invalid`}, nil)
	if err == nil {
		t.Fatal("expected error for invalid pattern")
	}
	if !strings.Contains(err.Error(), "optional_path_patterns[0]") {
		t.Fatalf("expected indexed pattern error, got: %v", err)
	}
}

func TestNewOptionalPathAuthzPolicy_InvalidPatternAfterValid(t *testing.T) {
	t.Parallel()

	_, err := NewOptionalPathAuthzPolicy([]string{
		`^/public$`,
		`[invalid`,
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid pattern")
	}
	if !strings.Contains(err.Error(), "optional_path_patterns[1]") {
		t.Fatalf("expected indexed pattern error, got: %v", err)
	}
}
