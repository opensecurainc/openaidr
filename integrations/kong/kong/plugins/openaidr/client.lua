local cjson = require "cjson.safe"
local http = require "resty.http"
local url = require "socket.url"

local M = {}
local MAX_RESPONSE_BYTES = 32768

local function transport_failure(err)
  return err == "timeout" and "timeout" or "backend_unavailable"
end

function M.key(conf)
  return "openaidr:" .. ngx.md5(conf.backend_url .. "\0" .. conf.credential)
end

-- The timeout covers DNS, TLS, headers and body, including a slow response stream.
-- This function is called only from access or a timer, where cosockets are legal.
function M.post(conf, path, payload, timeout_ms)
  local encoded = cjson.encode(payload)
  if not encoded or #encoded > 65536 then
    return nil, "invalid_response"
  end
  local parsed = url.parse(conf.backend_url)
  local client = http.new()
  client:set_timeouts(timeout_ms, timeout_ms, timeout_ms)
  local worker = ngx.thread.spawn(function()
    local ok, err = client:connect({
      scheme = "https", host = parsed.host, port = tonumber(parsed.port) or 443,
      ssl_verify = true, ssl_server_name = parsed.host,
    })
    if not ok then
      return nil, transport_failure(err)
    end
    local response, request_err = client:request({
      method = "POST", path = path, body = encoded,
      headers = { ["Content-Type"] = "application/json",
                  ["Authorization"] = "Bearer " .. conf.credential },
    })
    if not response then
      return nil, transport_failure(request_err)
    end
    local chunks, size = {}, 0
    while true do
      local chunk, err = response.body_reader(4096)
      if err then
        return nil, transport_failure(err)
      end
      if not chunk then break end
      size = size + #chunk
      if size > MAX_RESPONSE_BYTES then
        return nil, "invalid_response"
      end
      chunks[#chunks + 1] = chunk
    end
    local body = cjson.decode(table.concat(chunks))
    if response.status ~= 200 then
      return nil, "backend_unavailable", body
    end
    if type(body) ~= "table" then
      return nil, "invalid_response"
    end
    client:set_keepalive(30000, 16)
    return body
  end)
  local timer = ngx.thread.spawn(function()
    ngx.sleep(timeout_ms / 1000)
    return nil, "timeout"
  end)
  local ok, body, reason, rejected_body = ngx.thread.wait(worker, timer)
  ngx.thread.kill(worker)
  ngx.thread.kill(timer)
  if not body then pcall(client.close, client) end
  if not ok then
    return nil, "backend_unavailable"
  end
  return body, reason, rejected_body
end

function M.uuid(value)
  return type(value) == "string" and #value == 36
    and value:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil
end

function M.positive_integer(value)
  return type(value) == "number" and value >= 1 and value <= 2147483647 and value == math.floor(value)
end

function M.decision(body, request_id)
  if type(body) ~= "table" or body.request_id ~= request_id or not M.uuid(body.id)
    or body.status ~= "evaluated"
    or (body.mode ~= "shadow" and body.mode ~= "enforce")
    or (body.evaluated_decision ~= "allow" and body.evaluated_decision ~= "deny")
    or (body.returned_decision ~= "allow" and body.returned_decision ~= "deny")
    or not M.positive_integer(body.settings_version)
    or (body.policy_version ~= 0 and not M.positive_integer(body.policy_version))
    or type(body.reason) ~= "string"
    or (body.mode == "shadow" and body.returned_decision ~= "allow")
    or (body.mode == "enforce" and body.returned_decision ~= body.evaluated_decision) then
    return nil
  end
  return body
end

return M
