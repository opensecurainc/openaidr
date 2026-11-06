local rules = require "kong.plugins.openaidr.rules"
local json = require("cjson.safe").new()
json.decode_max_depth(32)

local M = {}
local JSON_STRING = [["(?:[^"\\]|\\.)*"]]

-- Use the shared secret rules against the original text, then merge overlapping
-- capture spans. Replacements cannot hide a longer credential from another rule.
local function redact_text(text)
  local spans, lower = {}, text:lower()
  for order, rule in ipairs(rules.patterns) do
    local relevant = not rule.keywords or #rule.keywords == 0
    for _, keyword in ipairs(rule.keywords or {}) do
      if lower:find(keyword:lower(), 1, true) then relevant = true; break end
    end
    if relevant then
      local ctx = { pos = 1 }
      while ctx.pos <= #text do
        local start, finish, err = ngx.re.find(text, rule.pattern, "jo", ctx, rule.group or 0)
        if err then return nil end
        if not start then break end
        if finish < start or #spans >= 1024 then return nil end
        spans[#spans + 1] = { start, finish, order, rule.name }
        if ctx.pos <= start then ctx.pos = finish + 1 end
      end
    end
  end
  if #spans == 0 then return text, false end
  table.sort(spans, function(a, b)
    if a[1] ~= b[1] then return a[1] < b[1] end
    if a[2] ~= b[2] then return a[2] < b[2] end
    return a[3] < b[3]
  end)
  local merged = {}
  for _, span in ipairs(spans) do
    local previous = merged[#merged]
    if previous and span[1] <= previous[2] then
      previous[2] = math.max(previous[2], span[2])
      if span[3] < previous[3] then previous[3], previous[4] = span[3], span[4] end
    else
      merged[#merged + 1] = span
    end
  end
  local parts, cursor = {}, 1
  for _, span in ipairs(merged) do
    parts[#parts + 1] = text:sub(cursor, span[1] - 1)
    parts[#parts + 1] = "[REDACTED:" .. span[4] .. "]"
    cursor = span[2] + 1
  end
  parts[#parts + 1] = text:sub(cursor)
  return table.concat(parts), true
end

local function inspect_json(text, depth, budget)
  budget.bytes = budget.bytes + #text
  if depth > 8 or budget.bytes > 262144 then return nil end
  -- The root was already checked. Decoding can expose new credential patterns.
  if depth > 0 then
    local redacted, changed = redact_text(text)
    if not redacted then return nil end
    if changed then return true end
  end
  local first = text:match("^%s*(.)")
  if first ~= "{" and first ~= "[" and first ~= '"' then return false end
  local decoded, decode_err = json.decode(text)
  if decode_err then return nil end
  if type(decoded) == "string" then
    return inspect_json(decoded, depth + 1, budget)
  end

  -- Decode only for validation above; an object map loses duplicate-key values.
  -- Inspect every original JSON string token, including keys and overwritten values.
  local ctx = { pos = 1 }
  while ctx.pos <= #text do
    local start, finish, err = ngx.re.find(text, JSON_STRING, "jo", ctx)
    if err then return nil end
    if not start then break end
    budget.strings = budget.strings + 1
    if budget.strings > 1024 then return nil end
    local value, value_err = json.decode(text:sub(start, finish))
    if value_err or type(value) ~= "string" then return nil end
    local following = finish + 1
    while text:sub(following, following):match("%s") do following = following + 1 end
    if text:sub(following, following) == ":" then
      local match, _, key_err = ngx.re.find(value, rules.secret_key_pattern, "ijo")
      if key_err then return nil end
      if match then return true end
    end
    local found = inspect_json(value, depth + 1, budget)
    if found ~= false then return found end
    ctx.pos = finish + 1
  end
  return false
end

function M.text(text)
  local redacted, changed = redact_text(text)
  if not redacted or changed then return redacted, changed end
  local found = inspect_json(text, 0, { bytes = 0, strings = 0 })
  if found == nil then return nil end
  if found then return "[REDACTED:json]", true end
  -- Inspection must not normalize benign JSON or alter classifier evidence.
  return text, false
end

return M
