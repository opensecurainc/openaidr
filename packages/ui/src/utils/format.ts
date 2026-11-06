export function compact(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "0";
  if (Math.abs(n) < 10_000) return n.toLocaleString();
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
}

export function relative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const diff = now - t;
  const abs = Math.abs(diff);
  const future = diff < 0;
  const units: [number, string][] = [[60_000, "s"], [3_600_000, "m"], [86_400_000, "h"], [604_800_000, "d"], [2_592_000_000, "w"], [31_536_000_000, "mo"], [Infinity, "y"]];
  let prev = 1000;
  for (const [limit, unit] of units) {
    if (abs < limit) {
      const v = Math.max(1, Math.floor(abs / prev));
      if (unit === "s" && v < 10) return future ? "in a moment" : "just now";
      return future ? `in ${v}${unit}` : `${v}${unit} ago`;
    }
    prev = limit;
  }
  return "";
}

export function duration(startIso: string, endIso: string | null): string {
  const s = new Date(startIso).getTime();
  const e = endIso ? new Date(endIso).getTime() : Date.now();
  const ms = Math.max(0, e - s);
  const m = Math.floor(ms / 60_000);
  if (m < 1) return `${Math.floor(ms / 1000)}s`;
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

/** snake_case or kebab-case to Sentence case. */
export function humanize(s: string | null | undefined): string {
  if (!s) return "";
  const t = s.replace(/[_-]+/g, " ").replace(/\./g, " ").trim();
  return t.charAt(0).toUpperCase() + t.slice(1);
}

export const PRODUCT_LABEL: Record<string, string> = {
  "claude-code": "Claude Code", "codex-cli": "Codex CLI", "gemini-cli": "Gemini CLI", "copilot-cli": "Copilot CLI",
  cowork: "Cowork", "claude-ai": "Claude",
  cursor: "Cursor", aider: "Aider", unknown: "Unknown",
};
export const OS_LABEL: Record<string, string> = { darwin: "macOS", linux: "Linux", windows: "Windows" };
export const CATEGORY_LABEL: Record<string, string> = {
  secret_exfiltration: "Secret exfiltration", data_exfiltration: "Data exfiltration", supply_chain: "Supply chain",
  destructive_command: "Destructive command", excessive_agency: "Excessive agency", hallucination: "Hallucination",
};
export const STATUS_LABEL: Record<string, string> = { open: "Open", triaged: "Triaged", resolved: "Resolved", false_positive: "False positive" };
export const ACTION_LABEL: Record<string, string> = {
  block_command: "Block command", block_path: "Block path", block_host: "Block host", disable_sensor: "Disable sensor",
  enable_sensor: "Enable sensor", note: "Note",
};

export function productLabel(p: string): string { return PRODUCT_LABEL[p] ?? humanize(p); }
export function osLabel(o: string): string { return OS_LABEL[o] ?? o; }
export function categoryLabel(c: string): string { return CATEGORY_LABEL[c] ?? humanize(c); }
export function statusLabel(s: string): string { return STATUS_LABEL[s] ?? humanize(s); }
export function actionLabel(a: string): string { return ACTION_LABEL[a] ?? humanize(a); }

export function escapeRegex(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

export function initials(name: string): string {
  return name.split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0]!.toUpperCase()).join("") || "?";
}

export function slugify(s: string): string {
  return s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
}

export function shortId(id: string): string { return id.slice(0, 8); }

/** Summarize an event in one line for lists and tables. */
export function eventSummary(e: { kind: string; command?: { text: string } | undefined; file?: { path: string; op: string } | undefined; network?: { host: string; url: string } | undefined; tool?: { name: string; is_error?: boolean; output?: string } | undefined; text?: string | undefined; hook?: { decision: string; reason?: string } | undefined }): string {
  switch (e.kind) {
    case "command": return e.command?.text ?? "";
    case "file.read": return e.file?.path ?? "";
    case "file.write": return `${e.file?.op ?? "write"} ${e.file?.path ?? ""}`;
    case "network": return e.network?.url ?? e.network?.host ?? "";
    case "tool.call": return e.tool?.name ?? "";
    case "tool.result": return `${e.tool?.name ?? ""}${e.tool?.is_error ? " (error)" : ""}${e.tool?.output ? `: ${e.tool.output.split("\n")[0]}` : ""}`;
    case "hook.decision": return `${e.hook?.decision ?? ""} ${e.command?.text ?? e.file?.path ?? ""}${e.hook?.reason ? ` (${e.hook.reason})` : ""}`;
    case "prompt":
    case "response": return e.text ?? "";
    case "session.start": return "Session started";
    case "session.end": return "Session ended";
    default: return e.text ?? "";
  }
}
