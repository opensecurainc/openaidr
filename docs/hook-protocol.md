# Hook protocol

[Back to the overview](../README.md)

This page describes how OpenAIDR receives coding-agent hook events, what it
sends to the guardrail backend, and what it returns to the agent. It is for
agent and tool integrators and for contributors to the sensor. The format of
the personal rules file is in the
[guide](guide.md#personal-local-rules-and-enforce). The implementation lives in
`src/openaidr/core/hook_protocol.py`, `src/openaidr/sensor/hook_client.py`,
`src/openaidr/sensor/hooks.py`, and `src/openaidr/guardrail/hooks.py`.

## Flow

1. Setup installs a hook command into each supported agent's native
   configuration. The command is a launcher script that runs
   `openaidr hook [--agent <agent>] [--config <sensor.yaml>] <Event>`.
2. The agent runs the launcher with its native JSON payload on standard input.
   The client reads at most 4 MiB and posts it unchanged to the sensor's
   loopback listener.
3. The sensor normalizes the payload to canonical fields, maps the tool call to
   actions, and asks its backend for a decision before the deadline. Workspace
   connections ask the workspace server. Personal connections evaluate local
   rules and the cloud assessment on the device.
4. The sensor returns a native response, which the launcher prints to standard
   output. Outside a managed launch, any failure returns allow with no output,
   and the check is recorded with its failure reason. Under a managed launch
   (`OPENAIDR_MANAGED_BRIDGE` is set), the Claude Code and Codex launchers
   forward the event to the managed session's hold instead of the sensor and
   print a denial when that hold is unreachable.

## Canonical events

The sensor names events as Claude Code and Codex do. Other agents' native
names are translated on arrival.

| Canonical | Decision | GitHub Copilot | Cursor | Antigravity | OpenCode | Hermes Agent |
| --- | --- | --- | --- | --- | --- | --- |
| `PreToolUse` | yes | `preToolUse` | `preToolUse` | `PreToolUse` | `tool.execute.before` | `pre_tool_call` |
| `PostToolUse` | yes | `postToolUse` | `postToolUse` | `PostToolUse` | `tool.execute.after` | `post_tool_call` |
| `PostToolUseFailure` | yes | `postToolUseFailure` | `postToolUseFailure` | `PostToolUse` with `error` | none | `post_tool_call` with error status |
| `UserPromptSubmit` | yes | `userPromptSubmitted` | `beforeSubmitPrompt` | none | `chat.message` | `pre_llm_call` |
| `SessionStart` | no | `sessionStart` | `sessionStart` | `SessionStart` | `session.created` | `on_session_start` |
| `SessionEnd` | no | `sessionEnd` | `sessionEnd` | none | none | `on_session_finalize` |
| `Stop` | no | `agentStop` | `afterAgentResponse` | `Stop` | none | `post_llm_call` |

WorkBuddy uses the canonical names. Decision events can change what the agent
does; the others only record activity. Setup registers either the generic or
the tool-specific native hook for an event, never both, so one call is not
evaluated twice.

## Canonical payload fields

| Field | Events | Meaning |
| --- | --- | --- |
| `hook_event_name` | all | Canonical event name after translation |
| `session_id` | all | Agent session; required for decision events |
| `cwd` | all | Working directory of the agent |
| `transcript_path` | all | Native transcript file, when the agent reports one |
| `model` | all | Model name, when reported |
| `tool_name`, `tool_input` | `PreToolUse`, `PostToolUse` | Tool call; required for tool events |
| `tool_use_id` | tool events | Native call identifier |
| `tool_response` | `PostToolUse` | Native result |
| `error` | `PostToolUseFailure` | Native error text |
| `prompt` | `UserPromptSubmit` | Prompt text; required |
| `last_assistant_message` | `Stop` | Final assistant text |
| `reason`, `source` | `SessionEnd`, `SessionStart` | Native end reason and start source |

Native aliases that are translated: Copilot `sessionId`, `toolName`,
`toolArgs` (JSON text is parsed), `toolResult.textResultForLlm`, and
`transcriptPath`; Cursor `conversation_id`, a single `workspace_roots` entry as
`cwd`, `tool_output`, `error_message`, and `text` on stop; Antigravity
`conversationId`, `modelName`, `transcriptPath`, a single `workspacePaths`
entry, `toolCall.name` and `toolCall.args`, `stepIdx` as the call identifier,
and `error` on a tool result; Hermes `extra.tool_call_id`, `extra.model`,
`extra.result`, `extra.user_message`, `extra.assistant_response`,
`extra.error_message`, and `extra.status`.

## Local listener request

The client posts to `http://<listen>/v1/hooks/<route>` on the loopback
listener from `sensor.yaml`, port 8377 by default. Routes are `claude-code`,
`codex`, `github-copilot`, `cursor`, `antigravity`, `opencode`,
`hermes-agent`, and `workbuddy`.

Query parameters:

| Parameter | Meaning |
| --- | --- |
| `event` | Canonical event name |
| `started`, `deadline` | Launcher start and deadline in wall-clock nanoseconds |
| `execution` | Launcher execution identifier for delivery accounting |
| `timeout_owner` | `agent` when the agent's own timeout governs the wait; `sensor` when the launcher waits on the sensor |
| `client_pid` | Launcher process ID, used to check result-replacement capability |
| `path_home` | The user's home directory, sent on `PreToolUse` so `~` globs resolve |
| `result_capable` | `1` when the launcher can deliver a replaced tool result |

A per-user sensor requires `Authorization: Bearer <local_token>` from the
private sensor configuration, because every local account can reach loopback
TCP. A sensor running as root or SYSTEM serves all accounts without it.

The reply is JSON:

```json
{"decision": "deny", "reason": "Blocked by OpenAIDR policy rule SSH keys",
 "rule_id": "ssh", "output": {"hookSpecificOutput": {"...": "..."}}}
```

`decision` is `allow`, `warn`, `ask`, or `deny`. `output` is the native
response the launcher prints when it is not empty; `claude_code` is a legacy
alias of `output`. A reply with `failed: true` is treated as unavailable.
Native launchers on per-user macOS installs post over the sensor's Unix socket
and receive the native output directly: 200 with a body, 204 when there is
nothing to print, and 503 when the hook is unavailable.

Deadlines: agent launchers allow two or three seconds end to end, five on
Windows. Decision work is bounded at two seconds and the delivery reserve
covers formatting the response. Work that finishes after the agent stopped
waiting is still recorded, within a ten-second limit, so the decision history
stays complete.

## Actions

Decision events are reduced to actions before any rule or assessment sees
them. Each action carries `kind`, `agent` (`product` and `model`), `session`
(`id` and `cwd`), and `tool` (`name`, `call_id`, `input`), plus the fields of
its kind:

| Kind | Fields | Source |
| --- | --- | --- |
| `command` | `command.text`, `command.cwd` | Shell tools such as Bash and Codex `exec` |
| `file.read`, `file.write` | `file.path`, `file.operation` | File tools and patches |
| `network` | `network.url`, `network.method`, `network.host` | Fetch and web tools |
| `tool.call` | none | Any other tool call |
| `prompt` | `text` | `UserPromptSubmit` |
| `tool.result` | `tool.output`, `tool.is_error`, `command.exit_code` | `PostToolUse` and `PostToolUseFailure` |

One tool call can produce several actions, for example a script with several
commands. Rules match `kinds`, `products`, and `tool_name`, `command_regex`
against `command.text`, `path_glob` against `file.path`, and `host_glob`
against `network.host` or hosts found in command text. When several actions of
one call match, the strictest decision wins: deny, then ask, then warn.

Content capture settings and secret redaction run before actions leave the
device. When capture is off or content was truncated, the check carries an
`availability` other than `available` and no action content.

## Backend check

Workspace sensors post each decision event to
`<server>/ingest/v1/hook-checks` with their enrollment credentials.

Request fields: `request_id` (UUID), `product`, `hook_event`, `session_id`,
`tool_call_id`, `actions` (at most 128, body at most 64 KiB), `availability`
(`available`, `capture_disabled`, `unsupported_boundary`, `content_redacted`,
`content_truncated`, or `unsupported_content`), `path_home`,
`control_supported`, and `timeout_ms` (1 to 1800). Action kinds per event are
`prompt` for `UserPromptSubmit`; `tool.call`, `command`, `file.read`,
`file.write`, and `network` for `PreToolUse`; and `tool.result` for the
post-tool events.

Reply fields: `id`, `request_id`, `status` (`evaluated`), `mode` (`shadow` or
`enforce`), `settings_version`, `policy_version`, `evaluated_decision`,
`returned_decision`, `reason`, `rule_id`, and `rule_name`. The sensor enforces
two invariants: in Shadow mode `returned_decision` is `allow`, and in Enforce
mode it equals `evaluated_decision` unless the boundary is unsupported, when it
is `allow`. Personal connections produce the same reply shape on the device.

## Native responses

| Agent | Event | deny | ask | warn |
| --- | --- | --- | --- | --- |
| Claude Code, Codex | `PreToolUse` | `hookSpecificOutput.permissionDecision: deny` | `ask` (Codex: `deny`) | `systemMessage` warning |
| Claude Code, Codex | `UserPromptSubmit` | `decision: block` | `decision: block` | `systemMessage` warning |
| Claude Code | `PostToolUse` (Bash) | `updatedToolOutput` replaces stdout with the reason | same as deny | `systemMessage` warning |
| Codex | `PostToolUse` | `decision: block` | `decision: block` | `systemMessage` warning |
| GitHub Copilot | `PreToolUse` | `permissionDecision: deny` | `permissionDecision: ask` | recorded only |
| Cursor | `PreToolUse` | `permission: deny` | `permission: deny` | recorded only |
| Cursor | `UserPromptSubmit` | `continue: false` | `continue: false` | recorded only |
| Antigravity | `PreToolUse` | `decision: deny` | `decision: force_ask` | recorded only |
| OpenCode | `PreToolUse` | plugin throws the denial | denied | recorded only |
| Hermes Agent | `PreToolUse` | `action: block` | `action: approve` (native approval) | recorded only |
| WorkBuddy | `PreToolUse` | `hookSpecificOutput.permissionDecision: deny` | `ask` | recorded only |

Agents other than Claude Code and Codex control only `PreToolUse`, and Cursor
also `UserPromptSubmit`. At other boundaries the decision is recorded and the
action continues. A warn decision has no portable native form outside Claude
Code and Codex, so it is recorded without claiming delivery.

## Failure behavior

Invalid payloads, expired deadlines, and unavailable backends return allow with
no output. The launcher exits 0 unless a wrapper sets
`OPENAIDR_HOOK_WRAPPED=1`, in which case a failure exits 1 for diagnostics.
Native agent permissions and sandboxes still apply. The one fail-closed path
is the managed launch: with `OPENAIDR_MANAGED_BRIDGE` set, a Claude Code or
Codex launcher that cannot reach the managed hold prints a denial
(`permissionDecision: deny` on `PreToolUse`, otherwise `decision: block` with
`continue: false`). Each decision event is recorded as a `hook.decision`
event whose `hook` object holds `hook_event`, `decision`, `request_id`,
`latency_ms`, and, when a backend replied, `evaluated_decision`,
`returned_decision`, `mode`, `settings_version`, `policy_version`, `reason`,
`rule_id`, `rule_name`, and `check_id`. Failures add `failure_reason`
(`deadline_expired` or `backend_unavailable`). Native launchers add
`execution_id` and delivery status so a decision the agent never received is
not counted as enforced.
