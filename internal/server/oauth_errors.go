package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/project-kessel/parsec/internal/service"
)

const oauthErrorDomain = "oauth"

// exchangeErrToGRPC maps an ExchangeError (known OAuth denial) to a gRPC
// status with ErrorInfo carrying the OAuth wire code. Used by the exchange
// endpoint when ExchangeResult.ExchangeErr is non-nil.
func exchangeErrToGRPC(exchErr *service.ExchangeError) error {
	msg := exchErr.Message
	if msg == "" {
		msg = string(exchErr.OAuthError)
	}

	st := status.New(codes.InvalidArgument, msg)
	info := &errdetails.ErrorInfo{
		Reason: string(exchErr.OAuthError),
		Domain: oauthErrorDomain,
		Metadata: map[string]string{
			"error_description": msg,
		},
	}
	if exchErr.Reason != "" {
		info.Metadata["abort_reason"] = string(exchErr.Reason)
	}
	detailed, detailErr := st.WithDetails(info)
	if detailErr != nil {
		return st.Err()
	}
	return detailed.Err()
}

// internalGRPCError maps an unexpected error to a gRPC Internal status.
// Used by the exchange endpoint when IssueTokens returns a top-level error.
func internalGRPCError(err error) error {
	return status.Errorf(codes.Internal, "failed to issue token: %v", err)
}

// oauthHTTPErrorHandler writes RFC 6749 §5.2 / RFC 8693 error JSON for OAuth
// errors encoded in gRPC ErrorInfo. All other errors use the default handler.
func oauthHTTPErrorHandler(
	ctx context.Context,
	mux *runtime.ServeMux,
	marshaler runtime.Marshaler,
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	st := status.Convert(err)
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok || info.Domain != oauthErrorDomain {
			continue
		}
		desc := info.Metadata["error_description"]
		if desc == "" {
			desc = st.Message()
		}
		body, marshalErr := json.Marshal(map[string]string{
			"error":             info.Reason,
			"error_description": desc,
		})
		if marshalErr != nil {
			runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(runtime.HTTPStatusFromCode(st.Code()))
		_, _ = w.Write(body)
		return
	}
	runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
}
