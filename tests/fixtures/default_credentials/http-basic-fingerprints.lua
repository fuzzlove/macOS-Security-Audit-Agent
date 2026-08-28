-- Benign MSAA test-only fingerprint for http-default-accounts.nse.
-- It recognizes only scripts/run_default_credential_test_server.py.
local http = require "http"

table.insert(fingerprints, {
  name = "MSAA Test HTTP Basic Fixture",
  cpe = "cpe:/a:msaa:test_fixture",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    local challenge = response.header["www-authenticate"] or ""
    return response.status == 401 and challenge:find("MSAA Fixture", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local credentials = {username = user, password = pass}
    local response = http.get(host, port, path, {
      auth = credentials,
      bypass_cache = true,
      no_cache = true,
      redirect_ok = false
    })
    return response.status == 200
           and (response.body or ""):find("MSAA DEFAULT CREDENTIAL FIXTURE", 1, true)
  end
})
