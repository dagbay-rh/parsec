-- Trivial pass-through validator for opaque username subject tokens.
--
-- The username is already trusted by the caller (e.g. extracted from
-- x-rh-user-id by an upstream proxy). This validator simply returns
-- the username as the subject with a namespaced issuer — no HTTP calls,
-- no BOP interaction. Enrichment happens later via the BOP data source.
--
-- Config values:
--   trust_domain  (required) trust domain for validated results
--   issuer        (required) stable issuer namespace, e.g. "urn:redhat:names:identity:username"

function validate(input)
  local username = input.credential.username

  if username == nil or username == "" then
    return nil
  end

  -- Reject values that look like JWTs (three base64 segments separated by dots)
  -- so this validator never "wins" over real JWT validators if ordering slips.
  if string.match(username, "^[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+$") then
    return nil
  end

  return {
    subject = username,
    issuer = config.get("issuer"),
    trust_domain = config.get("trust_domain"),
    claims = {}
  }
end
