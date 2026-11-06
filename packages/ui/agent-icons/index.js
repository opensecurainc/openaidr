const icons = new Map([
  ["codex-cli", "codex.png"],
  ["codex", "codex.png"],
  ["claude-code", "claude-code.png"],
  ["claude_code", "claude-code.png"],
  ["cowork", "claude-code.png"],
  ["claude-ai", "claude-code.png"],
  ["gemini-cli", "gemini-cli.png"],
  ["copilot-cli", "github-copilot.png"],
  ["github-copilot", "github-copilot.png"],
  ["copilot", "github-copilot.png"],
  ["cursor", "cursor.png"],
  ["antigravity", "antigravity.svg"],
  ["opencode", "opencode.png"],
  ["hermes-agent", "hermes.png"],
  ["hermes", "hermes.png"],
  ["aider", "aider.png"],
  ["windsurf", "windsurf.svg"],
  ["workbuddy", "workbuddy.svg"],
]);

export function agentIcon(product) {
  const file = icons.get(product);
  return file ? `/agent-icons/${file}` : undefined;
}
