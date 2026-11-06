export const creditServices = {
  guardrail: "Live Guardrail",
  investigations: "Investigations",
  application_research: "Application research",
  skill_assessment: "Skill analysis",
  assistant: "Assistant",
  overview_summaries: "Overview summaries",
  session_summaries: "Session summaries",
  rule_generation: "Rule generation",
  url_reputation: "URL reputation",
  package_vulnerabilities: "Package vulnerabilities",
} as const;

export type CreditService = keyof typeof creditServices;
export type CreditTotals = {
  credits_charged: string | null;
  operations: number;
  pending_operations: number;
  unrated_operations: number;
};
export type ServiceCredits = CreditTotals & { service: CreditService };
export type CreditSnapshot = {
  schema_version: 1;
  tenant_id: string;
  status: "disabled" | "unconfigured" | "active" | "exhausted" | "unavailable";
  rate_version: string | null;
  credits_per_usd: "100";
  since: string;
  until: string;
  bucket_seconds: number;
  balance: { available: string | null; reserved: string | null };
  summary: CreditTotals;
  by_service: ServiceCredits[];
  series: (CreditTotals & { time: string; by_service: ServiceCredits[] })[];
};

const decimal = (value: unknown): value is string => typeof value === "string"
  && /^(0|[1-9]\d*)(\.\d{1,6})?$/.test(value) && Number(value) <= Number.MAX_SAFE_INTEGER;

export function creditLimit(value: unknown): bigint | null {
  if (!decimal(value)) return null;
  const [whole, fraction = ""] = value.split(".");
  const microcredits = BigInt(whole) * BigInt(1_000_000) + BigInt(fraction.padEnd(6, "0"));
  return microcredits <= BigInt("9007199254740991") ? microcredits : null;
}

const amount = (value: unknown) => value === null || decimal(value);
const count = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const totals = (value: CreditTotals) => value && amount(value.credits_charged)
  && count(value.operations) && count(value.pending_operations) && count(value.unrated_operations);
const services = (rows: ServiceCredits[]) => Array.isArray(rows) && rows.every(row => row
  && Object.hasOwn(creditServices, row.service) && totals(row))
  && new Set(rows.map(row => row.service)).size === rows.length;

export function validCreditSnapshot(value: CreditSnapshot): boolean {
  return Boolean(value && value.schema_version === 1 && typeof value.tenant_id === "string"
    && ["disabled", "unconfigured", "active", "exhausted", "unavailable"].includes(value.status)
    && (value.rate_version === null || typeof value.rate_version === "string")
    && value.credits_per_usd === "100" && Number.isFinite(Date.parse(value.since))
    && Number.isFinite(Date.parse(value.until)) && Date.parse(value.since) < Date.parse(value.until)
    && [3600, 86400].includes(value.bucket_seconds)
    && value.balance && amount(value.balance.available) && amount(value.balance.reserved)
    && totals(value.summary) && services(value.by_service) && Array.isArray(value.series)
    && value.series.every(row => row && Number.isFinite(Date.parse(row.time)) && totals(row) && services(row.by_service))
    && (["active", "exhausted"].includes(value.status) || (value.balance.available === null && value.balance.reserved === null))
    && (value.status !== "unavailable" || (value.summary.credits_charged === null
      && value.by_service.every(row => row.credits_charged === null)
      && value.series.every(row => row.credits_charged === null && row.by_service.every(item => item.credits_charged === null)))));
}

export function creditAmount(value: string | null | undefined): string {
  if (!decimal(value)) return "Unavailable";
  const [whole, fraction = ""] = value.split(".");
  const tail = fraction.replace(/0+$/, "");
  const separator = new Intl.NumberFormat().formatToParts(1.1).find(part => part.type === "decimal")?.value ?? ".";
  return new Intl.NumberFormat().format(BigInt(whole)) + (tail ? separator + tail : "");
}
