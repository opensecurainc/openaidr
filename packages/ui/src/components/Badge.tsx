import type { ReactNode } from "react";
import type { Category, EventKind, FindingStatus, Product, Severity } from "../api/types";
import { categoryLabel, humanize, osLabel, productLabel, statusLabel } from "../utils/format";
import { agentIcon } from "../../agent-icons/index.js";

export type Tone = "critical" | "high" | "medium" | "low" | "info" | "ok" | "warn" | "bad" | "muted" | "accent" | "none";

export function Badge({ tone = "none", children, mono, plain, title }: { tone?: Tone; children: ReactNode; mono?: boolean; plain?: boolean; title?: string }) {
  const cls = ["badge", tone !== "none" ? `badge--${tone}` : "", mono ? "badge--mono" : "", plain ? "badge--plain" : ""].filter(Boolean).join(" ");
  return <span className={cls} title={title}>{tone !== "none" && <span className="badge__dot" aria-hidden="true" />}{children}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={severity}>{humanize(severity)}</Badge>;
}

const STATUS_TONE: Record<FindingStatus, Tone> = { open: "bad", triaged: "warn", resolved: "ok", false_positive: "muted" };
export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return <Badge tone={STATUS_TONE[status] ?? "muted"}>{statusLabel(status)}</Badge>;
}

export function CategoryBadge({ category }: { category: Category }) {
  return <Badge plain>{categoryLabel(category)}</Badge>;
}

export function ProductBadge({ product }: { product: Product | string }) {
  const icon = agentIcon(product);
  return <Badge plain>{icon && <img src={icon} alt="" width={16} height={16} className="agent-icon" />}{productLabel(product)}</Badge>;
}

export function OSBadge({ os }: { os: string }) {
  return <Badge plain>{osLabel(os)}</Badge>;
}

export function KindBadge({ kind }: { kind: EventKind | string }) {
  return <Badge mono plain>{kind}</Badge>;
}

export function OnlineBadge({ status }: { status: "online" | "offline" | "disabled" | "active" | "idle" | "ok" | "stale" | "active_user" | "suspended" | "deleted" | string }) {
  const tone: Tone = status === "online" || status === "active" || status === "ok" ? "ok"
    : status === "offline" || status === "stale" || status === "suspended" ? "warn"
    : status === "disabled" || status === "deleted" ? "bad" : "muted";
  return <Badge tone={tone}>{humanize(status)}</Badge>;
}

export function ActionStatusBadge({ status }: { status: "pending" | "applied" | "failed" }) {
  const tone: Tone = status === "applied" ? "ok" : status === "failed" ? "bad" : "warn";
  return <Badge tone={tone}>{humanize(status)}</Badge>;
}

export function RoleBadge({ role }: { role: string }) {
  return <Badge plain>{humanize(role)}</Badge>;
}

export function DecisionBadge({ decision }: { decision: string }) {
  // An approval requirement needs attention; it is not an allow.
  const tone: Tone = decision === "deny" ? "bad" : decision === "warn" || decision === "ask" ? "warn" : "ok";
  return <Badge tone={tone}>{humanize(decision)}</Badge>;
}
