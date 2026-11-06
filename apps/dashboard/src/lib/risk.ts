import { SEVERITY_ORDER, type Severity } from "@/components/ui/severity-mark";
import { isUuid } from "@/lib/session";

export type UserRiskKind = "account" | "os_user";

export type UserRisk = {
  /** Grouping identity: the reported agent account, or the exact OS username; empty when neither was reported. */
  user: string;
  /** How the row was keyed. Absent from older backends, which group by OS username alone. */
  kind?: UserRiskKind;
  /** Reporting sensor for OS-user rows; null for account rows. */
  sensor_id?: string | null;
  /** Distinct OS usernames seen in the group. */
  users?: string[];
  hosts: string[];
  accounts: string[];
  /** Open and triaged findings across all retained records. */
  open: Record<Severity, number>;
  openTotal: number;
  total: number;
};

export type UserRiskSummary = { items: UserRisk[]; total_findings: number };

/** Reject incomplete aggregates instead of presenting unmeasured counts as zero. */
export function validUserRisk(value: unknown): value is UserRiskSummary {
  const count = (n: unknown) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
  const texts = (v: unknown) => Array.isArray(v) && v.every((s) => typeof s === "string");
  if (!value || typeof value !== "object") return false;
  const data = value as UserRiskSummary;
  if (!count(data.total_findings) || !Array.isArray(data.items)) return false;
  return data.items.every((row) => row && typeof row === "object"
    && typeof row.user === "string" && texts(row.hosts) && texts(row.accounts)
    && (row.kind === undefined || row.kind === "account" || row.kind === "os_user")
    && (row.sensor_id === undefined || row.sensor_id === null || isUuid(row.sensor_id))
    && (row.users === undefined || texts(row.users))
    && count(row.total) && count(row.openTotal) && row.total >= row.openTotal
    && row.open && SEVERITY_ORDER.every((severity) => count(row.open[severity]))
    && SEVERITY_ORDER.reduce((sum, severity) => sum + row.open[severity], 0) === row.openTotal)
    && data.items.reduce((sum, row) => sum + row.total, 0) === data.total_findings;
}

/** Finding filters that select exactly the findings counted in a User Risk row. */
export function userRiskFilters(row: Pick<UserRisk, "user" | "kind" | "sensor_id">): Record<string, string> {
  if (row.kind === "account") return { account: row.user };
  if (row.kind === "os_user") return { account: "", username: row.user, ...(row.sensor_id ? { sensor_id: row.sensor_id } : {}) };
  return { username: row.user };
}
