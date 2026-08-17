-- BOP (Back Office Proxy) user enrichment data source.
--
-- Fetches user details from BOP /v1/users for a given username,
-- returning org_id, account_number, email, and other profile fields
-- needed by the CEL claim mapper to build x-rh-identity.
--
-- Fail-closed: returns nil on any error so identity is not issued
-- for unenrichable users.
--
-- Config values:
--   bop_url      (required) BOP base URL, e.g. "https://backoffice-proxy.example.com"
--   users_path   (optional) path for user lookup, defaults to "/v1/users"
--   api_token    (required) x-rh-apitoken value
--   client_id    (required) x-rh-clientid value
--   environment  (required) x-rh-insights-env value, e.g. "stage" or "prod"

function fetch(input)
  local username = input.subject.subject
  if username == nil or username == "" then
    return nil
  end

  local bop_url = config.get("bop_url")
  local users_path = config.get("users_path", "/v1/users")
  local api_token = config.get("api_token")
  local client_id = config.get("client_id")
  local environment = config.get("environment")

  local url = bop_url .. users_path .. "?queryBy=userId"

  local body = json.encode({ users = { username } })

  local headers = {
    ["x-rh-apitoken"]     = api_token,
    ["x-rh-clientid"]     = client_id,
    ["x-rh-insights-env"] = environment,
    ["Content-Type"]      = "application/json",
    ["Accept"]            = "application/json"
  }

  local response, err = http.post(url, body, headers)

  if response == nil then
    return nil
  end

  if response.status ~= 200 then
    return nil
  end

  local users, decode_err = json.decode(response.body)
  if users == nil then
    return nil
  end

  -- BOP returns a JSON array; we require exactly one match.
  if type(users) ~= "table" or #users ~= 1 then
    return nil
  end

  local user = users[1]

  if user.org_id == nil or user.id == nil then
    return nil
  end

  local result = {
    org_id         = tostring(user.org_id),
    account_number = user.account_number,
    email          = user.email,
    first_name     = user.first_name,
    last_name      = user.last_name,
    is_org_admin   = user.is_org_admin,
    is_internal    = user.is_internal,
    is_active      = user.is_active,
    locale         = user.locale,
    user_id        = tostring(user.id),
    username       = user.username
  }

  return {
    data = json.encode(result),
    content_type = "application/json"
  }
end

function fetch_cache_key(input)
  return {
    subject = {
      subject = input.subject.subject
    }
  }
end
