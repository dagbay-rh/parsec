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

// issueTokensGRPCError maps a TokenService.IssueTokens error to a gRPC status.
// ClaimMappingError with an OAuthError becomes InvalidArgument plus ErrorInfo
// details carrying the OAuth wire code (and optional abort reason). Empty
// OAuthError (fail()) and all other errors become Internal.
func issueTokensGRPCError(err error) error {
	oauthCode := service.OAuthErrorCode(err)
	if oauthCode == "" {
		if msg := service.MappingMessage(err); msg != "" {
			return status.Errorf(codes.Internal, "failed to issue token: %s", msg)
		}
		return status.Errorf(codes.Internal, "failed to issue token: %v", err)
	}

	msg := service.MappingMessage(err)
	if msg == "" {
		msg = oauthCode
	}

	st := status.New(codes.InvalidArgument, msg)
	info := &errdetails.ErrorInfo{
		Reason: oauthCode,
		Domain: oauthErrorDomain,
		Metadata: map[string]string{
			"error_description": msg,
		},
	}
	if reason := service.AbortReason(err); reason != "" {
		info.Metadata["abort_reason"] = reason
	}
	detailed, detailErr := st.WithDetails(info)
	if detailErr != nil {
		return st.Err()
	}
	return detailed.Err()
}

// authzIssueDenialCode returns the ext_authz gRPC code and denial message for
// an IssueTokens error. OAuth client errors map to InvalidArgument; others
// remain Internal.
func authzIssueDenialCode(err error) (codes.Code, string) {
	oauthCode := service.OAuthErrorCode(err)
	if oauthCode == "" {
		if msg := service.MappingMessage(err); msg != "" {
			return codes.Internal, "failed to issue tokens: " + msg
		}
		return codes.Internal, "failed to issue tokens"
	}
	msg := service.MappingMessage(err)
	if msg == "" {
		msg = oauthCode
	}
	return codes.InvalidArgument, msg
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
