local cjson = require "cjson.safe"
local uuid = require("kong.tools.uuid").uuid
local client = require "kong.plugins.openaidr.client"
local redact = require "kong.plugins.openaidr.redact"
local version = require "kong.plugins.openaidr.version"

local Handler = { PRIORITY = 771, VERSION = version }
local configured = {}
local heartbeat_running = false
local pending_events = 0
local last_drop_log = 0
local roles = { system = true, developer = true, user = true, assistant = true, tool = true }
local MAX_REQUEST_BYTES = 65536
local CAPTURE_LEASE_SECONDS = 60

local function dropped(conf)
  ngx.shared.kong:incr(client.key(conf) .. ":dropped", 1, 0)
  if ngx.now() - last_drop_log >= 30 then
    last_drop_log = ngx.now()
    kong.log.warn("OpenAIDR telemetry delivery is unavailable; evidence may be missing")
  end
end

local function deliver(conf, path, event)
  if pending_events >= 256 then dropped(conf); return end
  pending_events = pending_events + 1
  local ok = ngx.timer.at(0, function(premature)
    if premature then
      pending_events = pending_events - 1
      dropped(conf)
      return
    end
    local success, response = pcall(client.post, conf, path, event, 500)
    pending_events = pending_events - 1
    if not success or not response or response.accepted ~= true
      or response.request_id ~= event.request_id then
      dropped(conf)
    end
  end)
  if not ok then
    pending_events = pending_events - 1
    dropped(conf)
  end
end

local function heartbeat(conf, routes)
  local key = client.key(conf)
  local response = client.post(conf, "/ingest/v1/gateway-heartbeats", {
    node_id = kong.node.get_id(), plugin_version = version, kong_version = kong.version,
    routes = #routes > 0 and routes or cjson.empty_array,
    coverage = "observed_only", dropped_events = ngx.shared.kong:get(key .. ":dropped") or 0,
  }, 500)
  if response and client.uuid(response.gateway_id) and client.positive_integer(response.version)
    and (response.mode == "shadow" or response.mode == "enforce")
    and type(response.enabled) == "boolean" and type(response.capture_content) == "boolean" then
    ngx.shared.kong:set(key .. ":capture", response.enabled and response.capture_content,
                        CAPTURE_LEASE_SECONDS)
    ngx.shared.kong:set(key .. ":metrics", response.guardrail_metrics == true, CAPTURE_LEASE_SECONDS)
  else
    -- A failed heartbeat removes permission immediately, including before lease expiry.
    ngx.shared.kong:delete(key .. ":capture")
    ngx.shared.kong:delete(key .. ":metrics")
  end
end

local function heartbeat_all(premature)
  if premature or heartbeat_running then return end
  heartbeat_running = true
  for _, item in pairs(configured) do
    local ok = pcall(heartbeat, item.conf, item.routes)
    if not ok then
      ngx.shared.kong:delete(client.key(item.conf) .. ":capture")
      ngx.shared.kong:delete(client.key(item.conf) .. ":metrics")
    end
  end
  heartbeat_running = false
end

function Handler:init_worker()
  if ngx.worker.id() == 0 then
    local ok = ngx.timer.every(30, heartbeat_all)
    if not ok then kong.log.warn("OpenAIDR heartbeat timer unavailable; content capture remains disabled") end
  end
end

function Handler:configure(configs)
  if ngx.worker.id() ~= 0 then return end
  local next_configs = {}
  for _, conf in ipairs(configs or {}) do
    local key = client.key(conf)
    local item = next_configs[key]
    if not item then
      item = { conf = conf, routes = {}, seen = {} }
      next_configs[key] = item
    end
    if conf.route_id and not item.seen[conf.route_id] and #item.routes < 256 then
      item.seen[conf.route_id] = true
      item.routes[#item.routes + 1] = {
        route_id = conf.route_id, service_id = conf.service_id, protocol = "openai.chat",
      }
    end
  end
  for key in pairs(configured) do
    if not next_configs[key] then
      ngx.shared.kong:delete(key .. ":capture")
      ngx.shared.kong:delete(key .. ":metrics")
    end
  end
  configured = next_configs
  ngx.timer.at(0, heartbeat_all)
end

local function identity_label(value)
  if type(value) ~= "string" or #value > 256 or not value:find("%S") or value:find("%c") then return nil end
  local safe, changed = redact.text(value)
  if not changed then return safe end
end

local function prepare(conf, state)
  local route, service, consumer = kong.router.get_route(), kong.router.get_service(), kong.client.get_consumer()
  state.event = {
    request_id = uuid(), node_id = kong.node.get_id(),
    route_id = route and route.id, service_id = service and service.id,
    consumer_id = consumer and consumer.id, protocol = "openai.chat", stream = false,
    consumer_name = consumer and identity_label(consumer.username),
    application_name = identity_label(conf.application_name),
  }
  local event = state.event
  if conf.provider then event.provider = redact.text(conf.provider) end
  local availability, messages = "available", cjson.empty_array
  local body
  local content_type = (kong.request.get_header("content-type") or ""):lower()
  if kong.request.get_method() ~= "POST"
    or not (content_type:match("^application/json%s*$") or content_type:match("^application/json%s*;")) then
    availability = "unsupported_content"
  elseif (tonumber(kong.request.get_header("content-length")) or 0) > MAX_REQUEST_BYTES then
    availability = "oversized"
  else
    local raw = kong.request.get_raw_body()
    if not raw or #raw > MAX_REQUEST_BYTES then
      availability = "oversized"
    else
      body = cjson.decode(raw)
      if type(body) ~= "table" then availability = "unsupported_content" end
    end
  end
  if type(body) == "table" then
    if type(body.model) == "string" and #body.model > 0 and #body.model <= 256 then
      event.model = redact.text(body.model)
    else
      availability = "unsupported_content"
    end
    event.stream = body.stream == true
    if body.stream ~= nil and type(body.stream) ~= "boolean" then availability = "unsupported_content" end
  end
  local allowed_capture = conf.capture_content
    and ngx.shared.kong:get(client.key(conf) .. ":capture") == true
  if availability == "available" and not allowed_capture then
    availability = "capture_disabled"
  elseif availability == "available" then
    if type(body.messages) ~= "table" or #body.messages < 1 or #body.messages > 128
      or body.tools or body.functions or body.function_call then
      availability = "unsupported_content"
    else
      messages = {}
      local bytes, changed = 0, false
      for _, message in ipairs(body.messages) do
        if type(message) ~= "table" or not roles[message.role] or type(message.content) ~= "string"
          or message.tool_calls or message.function_call then
          availability = "unsupported_content"
          break
        end
        local text, redacted = redact.text(message.content)
        if not text then availability = "unsupported_content"; break end
        bytes, changed = bytes + #text, changed or redacted
        if bytes > 48000 then availability = "oversized"; break end
        messages[#messages + 1] = { role = message.role, content = text }
      end
      if changed and availability == "available" then availability = "content_redacted" end
    end
  end
  if availability ~= "available" then
    messages = cjson.empty_array
    state.failure_reason = availability
  end
  local payload = {}
  for key, value in pairs(event) do payload[key] = value end
  payload.messages, payload.availability, payload.timeout_ms = messages, availability, conf.timeout_ms
  local started = ngx.now()
  local response, failure, rejected = client.post(conf, "/ingest/v1/gateway-checks", payload, conf.timeout_ms)
  ngx.update_time()
  if (ngx.now() - started) * 1000 >= conf.timeout_ms then
    response, failure = nil, "timeout"
  end
  if not response then
    state.failure_reason = state.failure_reason or failure or "backend_unavailable"
    if type(rejected) == "table" and rejected.request_id == event.request_id and client.uuid(rejected.id) then
      state.check_id = rejected.id
    end
    return false
  end
  local decision = client.decision(response, event.request_id)
  if not decision or availability ~= "available" then
    state.failure_reason = state.failure_reason or "invalid_response"
    return false
  end
  state.check_id = decision.id
  return decision.mode == "enforce" and decision.returned_decision == "deny"
end

function Handler:access(conf)
  ngx.update_time()
  local state = { started = ngx.now() }
  kong.ctx.plugin.openaidr = state
  local ok, deny = pcall(prepare, conf, state)
  ngx.update_time()
  if ngx.shared.kong:get(client.key(conf) .. ":metrics") == true then
    state.guardrail_e2e_ms = math.max(0, (ngx.now() - state.started) * 1000)
  end
  if not ok then
    state.failure_reason = "backend_unavailable"
    return
  end
  if deny then
    state.blocked = true
    return kong.response.exit(403, { error = {
      message = "Request blocked by OpenAIDR policy.", type = "openaidr_policy_denied",
      code = "policy_denied", request_id = state.event.request_id,
    } })
  end
end

function Handler:log(conf)
  -- No network or response body reads in the log/body-filter phases.
  local state = kong.ctx.plugin.openaidr
  if not state or not state.event then return end
  local status, source = kong.response.get_status(), kong.response.get_source()
  if type(status) ~= "number" or status < 100 or status > 599 then dropped(conf); return end
  local event = state.event
  event.check_id, event.status_code = state.check_id, status
  event.latency_ms = math.max(0, (ngx.now() - state.started) * 1000)
  if ngx.shared.kong:get(client.key(conf) .. ":metrics") == true then
    event.guardrail_e2e_ms = state.guardrail_e2e_ms
  end
  if state.blocked and status == 403 and source == "exit" then
    event.outcome = "blocked"
  elseif state.failure_reason then
    event.outcome, event.failure_reason = "fail_open", state.failure_reason
  elseif source == "service" then
    event.outcome = "forwarded"
  else
    event.outcome = "unconfirmed"
  end
  local ok = pcall(deliver, conf, "/ingest/v1/gateway-outcomes", event)
  if not ok then dropped(conf) end
end

return Handler
