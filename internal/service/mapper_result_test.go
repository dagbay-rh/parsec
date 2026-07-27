package service

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/project-kessel/parsec/internal/claims"
)

func TestMappingResult_Merge(t *testing.T) {
	t.Parallel()

	t.Run("allow_allow_merges_claims", func(t *testing.T) {
		t.Parallel()
		a := AllowResult(claims.Claims{"a": 1, "shared": "from-a"})
		b := AllowResult(claims.Claims{"b": 2, "shared": "from-b"})
		got := a.Merge(b)
		if !got.Decision.IsAllow() {
			t.Fatalf("expected Allow, got %+v", got.Decision)
		}
		if got.Claims["a"] != 1 || got.Claims["b"] != 2 {
			t.Fatalf("claims not merged: %+v", got.Claims)
		}
		if got.Claims["shared"] != "from-b" {
			t.Fatalf("expected other to overwrite shared, got %v", got.Claims["shared"])
		}
		// Receiver's underlying map must not be mutated.
		if a.Claims["b"] != nil {
			t.Fatalf("Merge mutated receiver claims: %+v", a.Claims)
		}
	})

	t.Run("first_deny_wins", func(t *testing.T) {
		t.Parallel()
		deny := DenyReason(AbortReasonInvalidSubject, "nope")
		allow := AllowResult(claims.Claims{"x": 1})
		got := deny.Merge(allow)
		if got.Decision.Action != MappingDeny {
			t.Fatalf("expected Deny, got %+v", got.Decision)
		}
		if got.Decision.Reason != AbortReasonInvalidSubject {
			t.Fatalf("reason: got %q", got.Decision.Reason)
		}
		if got.Claims["x"] != nil {
			t.Fatalf("should not merge later allow claims into prior deny: %+v", got.Claims)
		}
	})

	t.Run("allow_then_deny_clears_claims", func(t *testing.T) {
		t.Parallel()
		allow := AllowResult(claims.Claims{"kept": true})
		deny := DenyReason(AbortReasonInvalidAudience, "bad aud")
		got := allow.Merge(deny)
		if got.Decision.Action != MappingDeny {
			t.Fatalf("expected Deny, got %+v", got.Decision)
		}
		if got.Decision.OAuthError != OAuthInvalidTarget {
			t.Fatalf("OAuthError: got %q", got.Decision.OAuthError)
		}
		if len(got.Claims) != 0 {
			t.Fatalf("expected no claims on deny merge, got %+v", got.Claims)
		}
	})
}

func TestMappingDecision_AsExchangeError(t *testing.T) {
	t.Parallel()

	if AllowResult(nil).Decision.AsExchangeError() != nil {
		t.Fatal("Allow should not produce ExchangeError")
	}

	exchErr := DenyReason(AbortReasonInvalidSubject, "msg").Decision.AsExchangeError()
	if exchErr == nil {
		t.Fatal("Deny should produce ExchangeError")
	}
	if exchErr.OAuthError != OAuthInvalidRequest || exchErr.Reason != AbortReasonInvalidSubject || exchErr.Message != "msg" {
		t.Fatalf("unexpected ExchangeError: %+v", exchErr)
	}
}

type countingMapper struct {
	result MappingResult
	err    error
	calls  *atomic.Int32
}

func (m *countingMapper) Map(ctx context.Context, input *MapperInput) (MappingResult, error) {
	m.calls.Add(1)
	return m.result, m.err
}

func TestToClaims_EarlyStopOnDeny(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	first := &countingMapper{
		result: AllowResult(claims.Claims{"from": "first"}),
		calls:  &calls,
	}
	second := &countingMapper{
		result: DenyReason(AbortReasonInvalidSubject, "stop"),
		calls:  &calls,
	}
	third := &countingMapper{
		result: AllowResult(claims.Claims{"from": "third"}),
		calls:  &calls,
	}

	ic := &IssueContext{}
	_, exchErr, err := ic.ToClaims(context.Background(), []ClaimMapper{first, second, third})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exchErr == nil {
		t.Fatal("expected ExchangeError from Deny")
	}
	if exchErr.OAuthError != OAuthInvalidRequest {
		t.Fatalf("OAuthErrorCode: got %q", exchErr.OAuthError)
	}
	if exchErr.Reason != AbortReasonInvalidSubject {
		t.Fatalf("AbortReason: got %q", exchErr.Reason)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 mapper calls (early stop), got %d", got)
	}
}

func TestToClaims_MergesAllowMappers(t *testing.T) {
	t.Parallel()

	ic := &IssueContext{}
	got, exchErr, err := ic.ToClaims(context.Background(), []ClaimMapper{
		NewStubClaimMapper(claims.Claims{"a": 1}),
		NewStubClaimMapper(claims.Claims{"b": 2}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exchErr != nil {
		t.Fatalf("unexpected ExchangeError: %v", exchErr)
	}
	if got["a"] != 1 || got["b"] != 2 {
		t.Fatalf("claims: %+v", got)
	}
}

func TestMappingFailure(t *testing.T) {
	t.Parallel()

	fail := &MappingFailure{Message: "mapping exploded"}
	wrapped := fmt.Errorf("failed to evaluate: %w", fail)

	if ExtractOAuthErrorCode(wrapped) != "" {
		t.Fatal("MappingFailure must not look like an OAuth ExchangeError")
	}
	if ExtractAbortReason(wrapped) != "" {
		t.Fatal("MappingFailure must not carry an abort reason")
	}
	if got := MappingMessage(wrapped); got != "mapping exploded" {
		t.Fatalf("MappingMessage: got %q", got)
	}

	var mf *MappingFailure
	if !errors.As(wrapped, &mf) {
		t.Fatal("expected errors.As MappingFailure")
	}
	var ee *ExchangeError
	if errors.As(wrapped, &ee) {
		t.Fatal("MappingFailure must not unwrap as ExchangeError")
	}
}

func TestDenyConstructors(t *testing.T) {
	t.Parallel()

	t.Run("DenyOAuth", func(t *testing.T) {
		got := DenyOAuth(OAuthInvalidTarget, "bad aud")
		if got.Decision.Action != MappingDeny {
			t.Fatalf("action: %+v", got.Decision)
		}
		if got.Decision.OAuthError != OAuthInvalidTarget || got.Decision.Reason != "" || got.Decision.Message != "bad aud" {
			t.Fatalf("decision: %+v", got.Decision)
		}
		if len(got.Claims) != 0 {
			t.Fatalf("DenyOAuth should have no claims, got %+v", got.Claims)
		}
	})

	t.Run("DenyReason_maps_audience", func(t *testing.T) {
		got := DenyReason(AbortReasonInvalidAudience, "bad aud")
		if got.Decision.OAuthError != OAuthInvalidTarget {
			t.Fatalf("OAuthError: got %q, want invalid_target", got.Decision.OAuthError)
		}
		if got.Decision.Reason != AbortReasonInvalidAudience {
			t.Fatalf("Reason: got %q", got.Decision.Reason)
		}
	})
}
