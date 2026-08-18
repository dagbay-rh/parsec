-- Cert auth validator: authenticates certificate credentials against an
-- external back office proxy (BOP) service.
--
-- The HTTP client injecting x-rh-clientid and x-rh-apitoken headers is
-- configured at the http_clients level via http_auth.type: headers.
--
-- Config values:
--   bop_url                 (required) HTTPS endpoint for BOP auth (e.g., https://bop.api.redhat.com/v1/auth)
--   trust_domain            (required) trust domain for validated results
--   bop_certauth_secret_env (required) env var name containing the proxy proof secret for x-rh-insights-certauth-secret header
--   bop_env                 (required) environment value for x-rh-insights-env header (e.g., "stage", "prod")

function validate(input)
  local bop_url = config.get("bop_url")
  local trust_domain = config.get("trust_domain")
  local bop_certauth_secret = os.getenv(config.get("bop_certauth_secret_env"))
  local bop_env = config.has("bop_env") and config.get("bop_env") or "stage"

  local cn = input.credential.subject
  local cert_issuer = input.credential.issuer

  if cn == nil or cn == "" then
    return nil
  end

  if cert_issuer == nil or cert_issuer == "" then
    return nil
  end

  -- Extract the CN value from the subject string.
  -- Handles formats like "/CN=abc123" or "/O=foo/CN=abc123/I=bar".
  local cn_value = string.match(cn, "/CN=([^/]+)")
  if cn_value == nil then
    cn_value = cn
  end

  local response, err = http.get(bop_url, {
    ["x-rh-insights-certauth-secret"] = bop_certauth_secret,
    ["x-rh-insights-env"] = bop_env,
    ["x-rh-certauth-cn"] = cn,
    ["x-rh-certauth-issuer"] = cert_issuer,
  })

  if response == nil then
    error("BOP service call failed: " .. (err or "unknown error"))
  end

  if response.status ~= 200 then
    return nil
  end

  local auth_resp = json.decode(response.body)
  if auth_resp == nil then
    return nil
  end

  local claims = {}
  if auth_resp.account_number ~= nil then
    claims.account_number = auth_resp.account_number
  end
  if auth_resp.org_id ~= nil then
    claims.org_id = auth_resp.org_id
  end
  if auth_resp.type ~= nil then
    claims.cert_type = auth_resp.type
  end
  claims.cn = cn_value

  return {
    subject = cn_value,
    issuer = bop_url,
    trust_domain = trust_domain,
    claims = claims
  }
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      subject = input.credential.subject,
      issuer = input.credential.issuer
    }
  }
end
