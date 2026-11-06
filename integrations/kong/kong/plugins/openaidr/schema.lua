local typedefs = require "kong.db.schema.typedefs"
local url = require "socket.url"

return {
  name = "openaidr",
  fields = {
    { protocols = typedefs.protocols_http },
    { consumer = typedefs.no_consumer },
    { config = {
      type = "record",
      fields = {
        { backend_url = {
          type = "string", required = true,
          custom_validator = function(value)
            local parsed = url.parse(value)
            if not parsed or parsed.scheme ~= "https" or not parsed.host
              or parsed.userinfo or parsed.query or parsed.fragment
              or (parsed.path and parsed.path ~= "" and parsed.path ~= "/") then
              return false, "must be an HTTPS origin without credentials, path, query or fragment"
            end
            return true
          end,
        } },
        { credential = { type = "string", required = true, len_min = 1,
                         encrypted = true, referenceable = true } },
        { capture_content = { type = "boolean", default = false } },
        { timeout_ms = { type = "integer", default = 1000, between = { 50, 2000 } } },
        { provider = { type = "string", len_min = 1, len_max = 128 } },
        { application_name = { type = "string", len_min = 1, len_max = 256 } },
      },
    } },
  },
}
