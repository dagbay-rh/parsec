package server

import (
	"context"
	"errors"
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TokenTypeSpec specifies a token type to issue and how to deliver it
type TokenTypeSpec struct {
	// Type is the token type to issue
	Type service.TokenType

	// HeaderName is the HTTP header to use for this token
	// e.g., "Transaction-Token", "Authorization", "X-Custom-Token"
	HeaderName string
}

// AuthzServer implements Envoy's ext_authz Authorization service
type AuthzServer struct {
	authv3.UnimplementedAuthorizationServer

	trustStore        trust.Store
	tokenService      *service.TokenService
	observer          service.AuthzCheckObserver
	credentialSources CredentialSources
	policy            AuthzCheckPolicy
}

// NewAuthzServer creates a new ext_authz server.
// policy decides, for each request, whether to issue tokens, pass through,
// or deny. If nil, a [StaticAuthenticatedPolicy] with default token types
// is used (preserving pre-policy behavior).
// credentialSources defines where credentials are extracted from for both
// subject and actor authentication.
func NewAuthzServer(trustStore trust.Store, tokenService *service.TokenService, policy AuthzCheckPolicy, credentialSources CredentialSources, observer service.AuthzCheckObserver) *AuthzServer {
	if policy == nil {
		policy = NewStaticAuthenticatedPolicy(nil)
	}

	if observer == nil {
		observer = service.NoOpAuthzCheckObserver{}
	}

	return &AuthzServer{
		trustStore:        trustStore,
		tokenService:      tokenService,
		policy:            policy,
		observer:          observer,
		credentialSources: credentialSources,
	}
}

// Check implements the ext_authz check endpoint
func (s *AuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	// Create request-scoped probe
	ctx, p := s.observer.AuthzCheckStarted(ctx)
	defer p.End()

	// 1. Build request attributes
	reqAttrs := s.buildRequestAttributes(req)
	p.RequestAttributesParsed(reqAttrs)

	// 2. Authenticate actor from gRPC context
	actorResult, actorExt, err := authenticateActorWithExtraction(ctx, s.credentialSources, s.trustStore, p)
	if err != nil {
		return s.denyResponse(codes.Unauthenticated,
			fmt.Sprintf("%v", err)), nil
	}

	var actorPrin Principal
	if actorExt != nil {
		actorPrin = newPrincipal(actorResult, actorExt)
	} else {
		actorPrin = anonymousPrincipal()
	}

	// 3. Extract subject credential and build subject Principal.
	// Only "no credential found" enters the anonymous path; malformed or
	// invalid credentials are hard failures.
	var subjectPrin Principal
	var subjectExt *CredentialExtraction

	cc, err := CredentialContextFromCheckRequest(req)
	if err != nil {
		p.SubjectCredentialExtractionFailed(err)
		return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
	}

	subjectExt, err = s.credentialSources.Extract(ctx, cc)
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			subjectPrin = anonymousPrincipal()
			p.SubjectAnonymous()
		} else {
			p.SubjectCredentialExtractionFailed(err)
			return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("failed to extract credentials: %v", err)), nil
		}
	}

	// If we got a credential, filter trust store and validate it
	if subjectExt != nil {
		p.SubjectCredentialExtracted(subjectExt.Credential, subjectExt.HeadersToRemove)

		filteredStore, filterErr := s.trustStore.ForActor(ctx, actorResult, reqAttrs)
		if filterErr != nil {
			return s.denyResponse(codes.PermissionDenied,
				fmt.Sprintf("failed to filter trust store: %v", filterErr)), nil
		}

		result, validationErr := filteredStore.Validate(ctx, subjectExt.Credential)
		if validationErr != nil {
			p.SubjectValidationFailed(validationErr)
			return s.denyResponse(codes.Unauthenticated, fmt.Sprintf("validation failed: %v", validationErr)), nil
		}
		p.SubjectValidationSucceeded(result)
		subjectPrin = newPrincipal(result, subjectExt)
	}

	// 4. Evaluate authz check policy
	decision, err := s.policy.Decide(ctx, AuthzCheckPolicyInput{
		Subject: subjectPrin,
		Actor:   actorPrin,
		Request: reqAttrs,
	})
	if err != nil {
		p.PolicyEvaluationFailed(err)
		return s.denyResponse(codes.Internal,
			fmt.Sprintf("policy evaluation failed: %v", err)), nil
	}

	// 5. Handle policy decision
	switch decision.Action {
	case AuthzCheckDeny:
		p.PolicyDecisionDeny(decision.Reason)
		return s.denyResponse(codes.PermissionDenied, decision.Reason), nil

	case AuthzCheckAllowWithoutIssue:
		p.PolicyDecisionAllowWithoutIssue(decision.Reason)
		return s.allowWithoutIssueResponse(subjectExt), nil

	case AuthzCheckIssue:
		p.PolicyDecisionIssue(len(decision.TokenTypes), decision.Scope)
		return s.issueResponse(ctx, decision, subjectPrin, actorPrin, reqAttrs, subjectExt)

	default:
		return s.denyResponse(codes.Internal,
			fmt.Sprintf("unknown policy action: %s", decision.Action)), nil
	}
}

// issueResponse builds an OK response with issued tokens in headers.
func (s *AuthzServer) issueResponse(
	ctx context.Context,
	decision AuthzCheckDecision,
	subject, actor Principal,
	reqAttrs *request.RequestAttributes,
	ext *CredentialExtraction,
) (*authv3.CheckResponse, error) {
	tokenTypes := make([]service.TokenType, len(decision.TokenTypes))
	for i, spec := range decision.TokenTypes {
		tokenTypes[i] = spec.Type
	}

	issuedTokens, err := s.tokenService.IssueTokens(ctx, &service.IssueRequest{
		Subject:           subject.Result,
		Actor:             actor.Result,
		RequestAttributes: reqAttrs,
		TokenTypes:        tokenTypes,
		Scope:             decision.Scope,
	})
	if err != nil {
		return s.denyResponse(codes.Internal, fmt.Sprintf("failed to issue tokens: %v", err)), nil
	}

	responseHeaders := make([]*corev3.HeaderValueOption, 0, len(issuedTokens))
	for _, spec := range decision.TokenTypes {
		if token, ok := issuedTokens[spec.Type]; ok {
			responseHeaders = append(responseHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   spec.HeaderName,
					Value: token.Value,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
	}

	// Append credential rewrite headers if any
	if ext != nil {
		for name, value := range ext.HeadersToSet {
			responseHeaders = append(responseHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   name,
					Value: value,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
	}

	// Remove external credential headers - security boundary
	var headersToRemove []string
	if ext != nil {
		headersToRemove = ext.HeadersToRemove
	}

	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers:         responseHeaders,
				HeadersToRemove: headersToRemove,
			},
		},
	}, nil
}

// allowWithoutIssueResponse builds an OK response without issuing tokens.
// Credential headers are still sanitized when a credential was present.
func (s *AuthzServer) allowWithoutIssueResponse(ext *CredentialExtraction) *authv3.CheckResponse {
	var headersToRemove []string
	var responseHeaders []*corev3.HeaderValueOption

	if ext != nil {
		headersToRemove = ext.HeadersToRemove
		for name, value := range ext.HeadersToSet {
			responseHeaders = append(responseHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   name,
					Value: value,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
	}

	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers:         responseHeaders,
				HeadersToRemove: headersToRemove,
			},
		},
	}
}

// buildRequestAttributes extracts request attributes from the Envoy request
func (s *AuthzServer) buildRequestAttributes(req *authv3.CheckRequest) *request.RequestAttributes {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return &request.RequestAttributes{}
	}

	additional := map[string]any{
		"host": httpReq.GetHost(),
	}

	// Add Envoy context extensions
	// These are custom key-value pairs set by Envoy configuration
	// and provide additional context about the request
	if contextExtensions := req.GetAttributes().GetContextExtensions(); len(contextExtensions) > 0 {
		additional["context_extensions"] = contextExtensions
	}

	return &request.RequestAttributes{
		Method:     httpReq.GetMethod(),
		Path:       httpReq.GetPath(),
		IPAddress:  req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress(),
		UserAgent:  httpReq.GetHeaders()["user-agent"],
		Headers:    httpReq.GetHeaders(),
		Additional: additional,
	}
}

// denyResponse creates a denial response
func (s *AuthzServer) denyResponse(code codes.Code, message string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code:    int32(code),
			Message: message,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Body: message,
			},
		},
	}
}
