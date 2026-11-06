import { execFile } from "node:child_process";
import { userInfo } from "node:os";

// OpenCode 1.x loads the same server plugin for its desktop app and CLI.
export const OpenAIDR = async ({ directory }) => {
  // Only messages observed before inference are live requests. Fork/import
  // events also replay completed steps with new IDs and must not add usage.
  const messages = new Map();
  const key = value => JSON.stringify([value.sessionID, value.messageID ?? value.id]);
  const count = value => Number.isSafeInteger(value) && value >= 0;
  const identifier = value => typeof value === "string" && value.length > 0 && value.length <= 256;
  const zero = tokens => tokens && [tokens.input, tokens.output, tokens.reasoning,
    tokens.cache?.read, tokens.cache?.write].every(value => value === 0);
  async function usage(event) {
    if (!openaidr.telemetry) return;
    if (event?.type === "message.updated") {
      const info = event.properties?.info;
      if (info?.role !== "assistant" || !identifier(info.id) || !identifier(info.sessionID)) return;
      if (info.time?.completed !== undefined) messages.delete(key(info));
      else if (!info.finish && info.cost === 0 && zero(info.tokens)) {
        messages.set(key(info), {model: info.modelID, provider: info.providerID});
        if (messages.size > 4096) messages.delete(messages.keys().next().value);
      }
      return;
    }
    if (event?.type !== "message.part.updated") return;
    const part = event.properties?.part;
    if (part?.type !== "step-finish" || !identifier(part.id) || !identifier(part.messageID)
        || !identifier(part.sessionID)) return;
    const message = messages.get(key(part));
    const tokens = part.tokens;
    if (!message || !tokens || ![tokens.input, tokens.output, tokens.reasoning,
      tokens.cache?.read, tokens.cache?.write].every(count)) return;
    const output = tokens.output + tokens.reasoning;
    if (!count(output)) return;
    const values = {
      "session.id": part.sessionID, "request_id": part.id, "turn.id": part.messageID,
      "model": message.model, "gen_ai.provider.name": message.provider,
      "input_token_count": tokens.input, "output_token_count": output,
      "cached_token_count": tokens.cache.read, "cache_write_token_count": tokens.cache.write,
      "reasoning_token_count": tokens.reasoning, "cost.kind": "agent_estimate",
    };
    // OpenCode also produces zero when model prices are missing. It cannot
    // establish a free request, so retain the usage with an unknown cost.
    if (Number.isFinite(part.cost) && part.cost > 0) values.cost_usd = part.cost;
    const attributes = data => Object.entries(data).filter(([,value]) =>
      typeof value === "number" || typeof value === "string" && value.length <= 4096)
      .map(([key,value]) => ({key,value:typeof value === "number" ? {doubleValue:value} : {stringValue:value}}));
    const resource = {"service.name":"opencode", "process.cwd":directory};
    try { resource["os.user"] = userInfo().username; } catch {}
    try {
      const response = await fetch(openaidr.telemetry.endpoint, {
        method:"POST", headers:{"Content-Type":"application/json"},
        signal:AbortSignal.timeout(1000), redirect:"error",
        body:JSON.stringify({resourceLogs:[{resource:{attributes:attributes(resource)},scopeLogs:[{
          scope:{name:"openaidr.opencode"},logRecords:[{eventName:"opencode.api_request",
            timeUnixNano:(BigInt(Date.now()) * 1000000n).toString(),attributes:attributes(values)}],
        }]}]}),
      });
      await response.body?.cancel();
    } catch {}
  }
  async function check(event, payload) {
    try {
      const started = performance.now();
      const input = JSON.stringify({ ...payload, hook_event_name: event, cwd: directory });
      if (Buffer.byteLength(input) > 4 * 1024 * 1024) return {};
      const [file, ...args] = openaidr.invocations[event];
      const result = await new Promise((resolve) => {
        const child = execFile(file, args, {
          // This plugin is the agent's hook host. It owns the native cap;
          // the shared launcher and client retain their existing deadlines.
          timeout: openaidr.timeout * 1000,
          maxBuffer: 4 * 1024 * 1024,
          windowsHide: true,
        }, (error, stdout) => {
          if (error || !stdout.trim()) return resolve({});
          try {
            const value = JSON.parse(stdout);
            resolve(value && typeof value === "object" && !Array.isArray(value) ? value : {});
          } catch {
            resolve({});
          }
        });
        child.stdin.on("error", () => {});
        child.stdin.end(input);
      });
      return performance.now() - started < openaidr.timeout * 1000 ? result : {};
    } catch {
      return {};
    }
  }
  return {
    "tool.execute.before": async (input, output) => {
      const reply = await check("PreToolUse", {
        session_id: input?.sessionID, tool_use_id: input?.callID,
        tool_name: input?.tool, tool_input: output?.args,
      });
      if (reply.decision === "deny" && typeof reply.reason === "string") {
        throw new Error(reply.reason || "Blocked by OpenAIDR policy");
      }
    },
    "tool.execute.after": async (input, output) => {
      await check("PostToolUse", {
        session_id: input?.sessionID, tool_use_id: input?.callID,
        tool_name: input?.tool, tool_input: input?.args, tool_response: output?.output,
      });
    },
    "chat.message": async (input, output) => {
      if (!Array.isArray(output?.parts)) return;
      const text = output.parts.filter(part => part?.type === "text" && !part.synthetic && typeof part.text === "string")
        .map(part => part.text).join("\n");
      if (text) await check("UserPromptSubmit", { session_id: input?.sessionID, prompt: text });
    },
    event: async ({ event }) => {
      await usage(event);
      if (event?.type === "session.created") {
        await check("SessionStart", { session_id: event.properties?.info?.id });
      }
    },
  };
};
