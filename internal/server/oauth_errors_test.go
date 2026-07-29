package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/project-kessel/parsec/internal/service"
)

func TestExchangeErrToGRPC(t *testing.T) {
	t.Run("invalid_request", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "impersonated tokens are not accepted",
			OAuthError: service.OAuthInvalidRequest,
			Reason:     service.AbortReasonInvalidSubject,
		})
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("code: got %v, want InvalidArgument", st.Code())
		}
		if st.Message() != "impersonated tokens are not accepted" {
			t.Errorf("message: got %q", st.Message())
		}
		info := oauthErrorInfo(t, st)
		if info.Reason != string(service.OAuthInvalidRequest) {
			t.Errorf("ErrorInfo.Reason: got %q", info.Reason)
		}
		if info.Metadata["abort_reason"] != string(service.AbortReasonInvalidSubject) {
			t.Errorf("abort_reason: got %q", info.Metadata["abort_reason"])
		}
	})

	t.Run("invalid_target", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "bad audience",
			OAuthError: service.OAuthInvalidTarget,
			Reason:     service.AbortReasonInvalidAudience,
		})
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("code: got %v, want InvalidArgument", st.Code())
		}
		info := oauthErrorInfo(t, st)
		if info.Reason != string(service.OAuthInvalidTarget) {
			t.Errorf("ErrorInfo.Reason: got %q", info.Reason)
		}
	})

	t.Run("no_abort_reason_when_empty", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "bad request",
			OAuthError: service.OAuthInvalidRequest,
		})
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		info := oauthErrorInfo(t, st)
		if _, hasReason := info.Metadata["abort_reason"]; hasReason {
			t.Error("Layer A (no reason) should not set abort_reason metadata")
		}
	})
}

func TestInternalGRPCError(t *testing.T) {
	t.Run("wraps_error_as_internal", func(t *testing.T) {
		err := internalGRPCError(errors.New("signing failed"))
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		if st.Code() != codes.Internal {
			t.Errorf("code: got %v, want Internal", st.Code())
		}
		if st.Message() != "failed to issue token: signing failed" {
			t.Errorf("message: got %q", st.Message())
		}
	})

	t.Run("no_oauth_error_info", func(t *testing.T) {
		err := internalGRPCError(errors.New("boom"))
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status, got %T", err)
		}
		for _, d := range st.Details() {
			if _, ok := d.(*errdetails.ErrorInfo); ok {
				t.Fatal("internal errors should not attach OAuth ErrorInfo")
			}
		}
	})
}

func TestOAuthHTTPErrorHandler(t *testing.T) {
	mux := runtime.NewServeMux()
	marshaler := &runtime.JSONPb{}

	t.Run("writes_oauth_json", func(t *testing.T) {
		err := exchangeErrToGRPC(&service.ExchangeError{
			Message:    "impersonated tokens are not accepted",
			OAuthError: service.OAuthInvalidRequest,
			Reason:     service.AbortReasonInvalidSubject,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/token", nil)
		oauthHTTPErrorHandler(context.Background(), mux, marshaler, rec, req, err)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status: got %d, want 400", rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if body["error"] != string(service.OAuthInvalidRequest) {
			t.Errorf("error: got %q", body["error"])
		}
		if body["error_description"] != "impersonated tokens are not accepted" {
			t.Errorf("error_description: got %q", body["error_description"])
		}
	})

	t.Run("non_oauth_uses_default", func(t *testing.T) {
		err := status.Error(codes.Internal, "failed to issue token: boom")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/token", nil)
		oauthHTTPErrorHandler(context.Background(), mux, marshaler, rec, req, err)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status: got %d, want 500", rec.Code)
		}
		body, _ := io.ReadAll(rec.Body)
		if len(body) == 0 {
			t.Fatal("expected default error body")
		}
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("default body should be JSON: %v", err)
		}
		if _, ok := parsed["error"]; ok {
			t.Error("non-OAuth errors should not use OAuth error field")
		}
	})
}

func oauthErrorInfo(t *testing.T, st *status.Status) *errdetails.ErrorInfo {
	t.Helper()
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info
		}
	}
	t.Fatal("expected ErrorInfo detail")
	return nil
}
