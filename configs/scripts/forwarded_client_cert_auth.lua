-- Cert auth validator: authenticates certificate credentials against an
-- external back office proxy (BOP) service.
--
-- Config values:
--   bop_url           (required) HTTPS endpoint for BOP auth (e.g., https://bop.api.redhat.com/v1/auth)
--   trust_domain      (required) trust domain for validated results
--   bop_certauth_secret_env (required) env var name containing the proxy proof secret for x-rh-insights-certauth-secret header
--   bop_client_id_env   (required) env var name containing the BOP client ID for x-rh-clientid header
--   bop_token_env       (required) env var name containing the BOP API token for x-rh-apitoken header

function validate(input)
  local bop_url = config.get("bop_url")
  local trust_domain = config.get("trust_domain")
  local bop_certauth_secret = os.getenv(config.get("bop_certauth_secret_env"))
  local bop_client_id = os.getenv(config.get("bop_client_id_env"))
  local bop_token = os.getenv(config.get("bop_token_env"))

  local cn = input.credential.cn
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
    -- client id and token required for any bop request
    ["x-rh-clientid"] = bop_client_id,
    ["x-rh-apitoken"] = bop_token,
    -- cert auth secret is specifically required for cert auth in bop
    ["x-rh-insights-certauth-secret"] = bop_certauth_secret,
    -- cn and issuer for specific request
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
      cn = input.credential.cn,
      issuer = input.credential.issuer
    }
  }
end
