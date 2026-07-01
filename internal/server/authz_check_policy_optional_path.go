package server

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/project-kessel/parsec/internal/request"
)

const anonymousSubjectDenyReason = "anonymous subjects not allowed"

// normalizeRequestPath strips the query string from an HTTP path so RE2
// anchors match the path component only (Envoy :path may include ?query).
func normalizeRequestPath(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

var _ AuthzCheckPolicy = (*OptionalPathAuthzPolicy)(nil)

// OptionalPathAuthzPolicy allows anonymous access on configured URL path patterns
// and issues tokens for authenticated subjects. Selected via type: optional_path
// with optional_path_patterns in the authz_server.policy config.
type OptionalPathAuthzPolicy struct {
	patterns   []*regexp.Regexp
	tokenTypes []TokenTypeSpec
}

// NewOptionalPathAuthzPolicy creates a policy that matches request paths against
// RE2 regex patterns. Each pattern is implicitly anchored to a full match
// (wrapped in ^(?:...)$) so partial/substring matches cannot bypass controls.
// Patterns are validated at construction time.
func NewOptionalPathAuthzPolicy(patterns []string, tokenTypes []TokenTypeSpec) (*OptionalPathAuthzPolicy, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("optional path authz policy requires at least one path pattern")
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for i, pattern := range patterns {
		re, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			return nil, fmt.Errorf("optional_path_patterns[%d]: invalid RE2 regex %q: %w", i, pattern, err)
		}
		compiled = append(compiled, re)
	}

	if len(tokenTypes) == 0 {
		tokenTypes = DefaultTokenTypeSpecs()
	}

	return &OptionalPathAuthzPolicy{
		patterns:   compiled,
		tokenTypes: tokenTypes,
	}, nil
}

// Decide allows anonymous requests on optional paths, denies other anonymous
// requests, and issues configured token types for authenticated subjects.
func (p *OptionalPathAuthzPolicy) Decide(_ context.Context, in AuthzCheckPolicyInput) (AuthzCheckDecision, error) {
	path := requestPath(in.Request)

	if in.Subject.Anonymous {
		if matchesAnyPattern(p.patterns, path) {
			return AuthzCheckDecision{Action: AuthzCheckAllowWithoutIssue}, nil
		}
		return AuthzCheckDecision{
			Action: AuthzCheckDeny,
			Reason: anonymousSubjectDenyReason,
		}, nil
	}

	return AuthzCheckDecision{
		Action:     AuthzCheckIssue,
		TokenTypes: p.tokenTypes,
	}, nil
}

func requestPath(attrs *request.RequestAttributes) string {
	if attrs == nil {
		return ""
	}
	return normalizeRequestPath(attrs.Path)
}

func matchesAnyPattern(patterns []*regexp.Regexp, path string) bool {
	for _, re := range patterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
