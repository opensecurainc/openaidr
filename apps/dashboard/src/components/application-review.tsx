"use client";

import { useContext, useEffect, useId, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowDown,
  TriangleAlert,
  CircleCheck,
  CircleX,
  ExternalLink,
  Eye,
  MoreHorizontal,
  RefreshCw,
} from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { EndpointAlerts } from "@/components/endpoint-alerts";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageNotice,
  PageSection,
  TableLayout,
} from "@/components/page-layout";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { ReviewCard, reviewTable, reviewTableHeader, type ReviewTone } from "@/components/review-card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverClose,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Status } from "@/components/ui/status";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, APIError, relative } from "@/lib/api";
import { displayText } from "@/lib/display";
import { ResourceCacheContext } from "@/lib/resource-cache";
import { hasRole } from "@/lib/roles";
import { useResource } from "@/lib/use-resource";
import { cn } from "@/lib/utils";

const endpoint = "inventory/application-review";
const statuses = {
  approved: "Approved",
  unapproved: "Unapproved",
  monitoring: "Monitoring",
} as const;
const approvalActions = {
  approved: "Approve",
  unapproved: "Mark unapproved",
  monitoring: "Move to monitoring",
} as const;
const tones = {
  approved: "ok",
  unapproved: "critical",
  monitoring: "info",
} as const;
// Each approval group is a ReviewCard in its status tone (DESIGN.md, Review
// boards). The icon shape and label carry the state without color.
const columnHeaders: Record<ApprovalStatus, { icon: typeof CircleCheck; tone: ReviewTone }> = {
  approved: { icon: CircleCheck, tone: "ok" },
  unapproved: { icon: CircleX, tone: "critical" },
  monitoring: { icon: Eye, tone: "info" },
};
// Product risk estimates use the existing severity palette (COLORS.md).
const riskBands = [
  [75, "bg-severity-critical"],
  [50, "bg-severity-high"],
  [25, "bg-severity-medium"],
  [0, "bg-severity-low"],
] as const;
const riskBand = (score: number) =>
  riskBands.find(([floor]) => score >= floor)![1];
const categories = {
  coding_agent: "Coding agent",
  chat_assistant: "Chat assistant",
  local_model_runtime: "Local model runtime",
  other_ai: "Other AI tool",
  ordinary: "Not AI-focused",
} as const;
const classificationLabels = {
  pending: "Awaiting classification",
  unknown: "Classification inconclusive",
  unavailable: "Classification unavailable",
  stale: "Classification refresh delayed",
  complete: "Classified",
} as const;
const softwareTypes = {
  application: "Application",
  command_line_tool: "Command-line tool",
  library: "Library",
  helper: "Supporting helper",
  system_component: "System component",
  package: "Package · role unconfirmed",
} as const;
type ApprovalStatus = keyof typeof statuses;
type ApplicationView = "report" | "devices" | "users";
type UserCount = { user: string; device_count: number };
const capabilityLabels = {
  code_execution: "Code execution",
  file_access: "File access",
  external_transmission: "External data transmission",
  autonomy: "Autonomy",
} as const;
type CapabilityEvidence = {
  level: number | null;
  reason: string;
  sources: string[];
};
type Assessment = Record<keyof typeof capabilityLabels, CapabilityEvidence> & {
  capability_score: number | null;
  confidence: "high" | "medium" | "low";
  summary: string;
  controls: { reason: string; sources: string[] };
  report?: {
    purpose: { reason: string; sources: string[] };
    harms: { damage: string; likelihood: string; sources: string[] }[];
  };
  reputation?: { reason: string; sources: string[] };
  risk?: { score: number | null; provisional_score?: number | null; reason: string; sources: string[] };
};
const researchLabels = {
  queued: "Research queued",
  researching: "Researching",
  retry_pending: "Retry pending",
  complete: "Research complete",
} as const;
type Application = {
  id: string;
  name: string;
  display_name?: string;
  reported_names?: string[];
  approval_scope?: string;
  approval_conflict?: boolean;
  software_type?: keyof typeof softwareTypes;
  is_builtin?: boolean;
  review_required?: boolean;
  review_reason?: string;
  device_count: number;
  users: UserCount[];
  needs_attention: boolean;
  category: keyof typeof categories | null;
  classification_status: keyof typeof classificationLabels;
  reason: string;
  sources: string[];
  checked_at: string | null;
  assessment?: Assessment | null;
  research_status?: keyof typeof researchLabels;
  assessment_status?:
    | "pending"
    | "unavailable"
    | "needs_identification"
    | "complete"
    | "stale";
  approval_status: ApprovalStatus;
  approval_updated_at: string | null;
};
type Inventory = {
  items: Application[];
  device_count: number;
  users: UserCount[];
  classifier_configured: boolean;
  generated_at: string;
};
type Device = {
  id: string;
  name: string;
  os: string;
  user: string;
  versions: string[];
  last_seen_at: string;
  installations?: Installation[];
};
type Installation = Record<
  | "name"
  | "identifier"
  | "publisher"
  | "version"
  | "source"
  | "ecosystem"
  | "kind"
  | "path"
  | "scope"
  | "root"
  | "environment",
  string
>;
type Devices = { id: string; name: string; items: Device[] };
type Approval = { id: string; approved: boolean | null; approval_updated_at: string };
const count = (value: number) => value.toLocaleString();
const timestamp = (value: unknown) =>
  typeof value === "string" && Number.isFinite(Date.parse(value));
const natural = (value: unknown) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
function sourceUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return (
      ["https:", "http:"].includes(url.protocol) &&
      !url.username &&
      !url.password
    );
  } catch {
    return false;
  }
}
function validUsers(users: UserCount[], devices: number): boolean {
  return (
    Array.isArray(users) &&
    users.every(
      (entry) =>
        entry &&
        typeof entry.user === "string" &&
        natural(entry.device_count) &&
        entry.device_count > 0,
    ) &&
    new Set(users.map((entry) => entry.user)).size === users.length &&
    users.reduce((total, entry) => total + entry.device_count, 0) === devices
  );
}
const userCount = (app: Application) =>
  app.users.filter((entry) => entry.user !== "").length;
const appName = (app: Application) => app.display_name || app.name;
const requiresReview = (app: Application) =>
  app.needs_attention &&
  (app.approval_status !== "monitoring" || (app.review_required ?? true));
const softwareType = (app: Application) =>
  app.approval_conflict
    ? "Review previous approvals"
    : app.approval_scope
      ? "Product"
      : app.is_builtin
        ? "Built-in app"
        : app.software_type
          ? softwareTypes[app.software_type]
          : "";
function isRiskCandidate(app: Application) {
  return (
    app.needs_attention &&
    app.category !== "ordinary" &&
    (!app.software_type ||
      ["application", "command_line_tool"].includes(app.software_type))
  );
}
function isAiApplication(app: Application) {
  return app.category !== null && isRiskCandidate(app);
}
function applicationRisk(app: Application): number | null {
  return isRiskCandidate(app)
    ? (app.assessment?.risk?.score ?? app.assessment?.risk?.provisional_score ?? null)
    : null;
}
type SimilarApplication = {
  app: Application;
  dimensions: (keyof typeof capabilityLabels)[];
  basis: "elevated_capabilities" | "close_profile";
};
function similarUnapproved(
  app: Application,
  unapproved: Application[],
): SimilarApplication[] {
  if (
    !requiresReview(app) ||
    !isAiApplication(app) ||
    app.approval_status === "unapproved" ||
    !app.category ||
    app.category === "ordinary" ||
    !app.assessment ||
    app.assessment.confidence === "low"
  )
    return [];
  return unapproved
    .flatMap<SimilarApplication>((other) => {
      if (
        other.id === app.id ||
        !isAiApplication(other) ||
        !other.category ||
        other.category === "ordinary" ||
        !other.assessment ||
        other.assessment.confidence === "low"
      )
        return [];
      const dimensions = (
        Object.keys(capabilityLabels) as (keyof typeof capabilityLabels)[]
      ).filter(
        (key) =>
          (app.assessment![key].level ?? -1) >= 2 &&
          (other.assessment![key].level ?? -1) >= 2,
      );
      if (
        dimensions.length >= 2 &&
        dimensions.some((key) => key === "code_execution" || key === "autonomy")
      )
        return [{ app: other, dimensions, basis: "elevated_capabilities" }];
      const supported = (
        Object.keys(capabilityLabels) as (keyof typeof capabilityLabels)[]
      ).filter(
        (key) =>
          app.assessment![key].level !== null &&
          other.assessment![key].level !== null,
      );
      const distance = supported.reduce(
        (sum, key) =>
          sum +
          Math.abs(app.assessment![key].level! - other.assessment![key].level!),
        0,
      );
      // Closely matched runtime profiles can matter even without host execution.
      return app.category === other.category &&
        supported.length >= 3 &&
        distance <= 1
        ? [{ app: other, dimensions: supported, basis: "close_profile" }]
        : [];
    })
    .sort(
      (a, b) =>
        b.dimensions.length - a.dimensions.length ||
        appName(a.app).localeCompare(appName(b.app)) ||
        a.app.id.localeCompare(b.app.id),
    );
}
const riskLabel = (score: number) =>
  score >= 75
    ? "Critical"
    : score >= 50
      ? "High"
      : score >= 25
        ? "Moderate"
        : "Low";

function validAssessment(value: Assessment | null | undefined): boolean {
  if (value == null) return true;
  const evidence = (fact: Assessment["controls"]) =>
    fact &&
    typeof fact.reason === "string" &&
    fact.reason.trim().length > 0 &&
    Array.isArray(fact.sources) &&
    fact.sources.every(sourceUrl);
  if (!(
    typeof value.summary === "string" &&
    ["high", "medium", "low"].includes(value.confidence) &&
    evidence(value.controls) &&
    (value.report === undefined ||
      (value.report !== null &&
        evidence(value.report.purpose) &&
        value.report.purpose.reason.length <= 240 &&
        value.report.purpose.sources.length <= 5 &&
        Array.isArray(value.report.harms) &&
        value.report.harms.length <= 3 &&
        value.report.harms.every((harm) =>
          harm &&
          typeof harm.damage === "string" &&
          harm.damage.trim().length > 0 && harm.damage.length <= 180 &&
          typeof harm.likelihood === "string" &&
          harm.likelihood.trim().length > 0 && harm.likelihood.length <= 240 &&
          Array.isArray(harm.sources) &&
          harm.sources.length > 0 && harm.sources.length <= 5 &&
          harm.sources.every(sourceUrl)))) &&
    (value.reputation === undefined || evidence(value.reputation)) &&
    (value.risk === undefined ||
      (evidence(value.risk) &&
        (value.risk.score === null ||
          (natural(value.risk.score) &&
            value.risk.score <= 100 &&
            value.risk.sources.length > 0 &&
            value.confidence !== "low")) &&
        (value.risk.provisional_score == null ||
          (natural(value.risk.provisional_score) &&
            value.risk.provisional_score <= 100 &&
            value.risk.score === null))))
  ))
    return false;
  const dimensions = Object.keys(
    capabilityLabels,
  ) as (keyof typeof capabilityLabels)[];
  if (
    !dimensions.every(
      (key) =>
        evidence(value[key]) &&
        (value[key].level === null ||
          (natural(value[key].level) &&
            value[key].level! <= 3 &&
            value[key].sources.length > 0)),
    )
  )
    return false;
  if (
    (value.risk?.score != null ||
      (value.risk?.provisional_score != null && value.confidence !== "low")) &&
    !dimensions.some((key) => value[key].level !== null)
  )
    return false;
  return (
    value.capability_score === null ||
    (natural(value.capability_score) &&
      value.capability_score <= 100 &&
      value.confidence !== "low" &&
      dimensions.every((key) => value[key].level !== null) &&
      value.capability_score ===
        Math.round(
          (dimensions.reduce((sum, key) => sum + value[key].level!, 0) * 100) /
            12,
        ))
  );
}

function validInventory(data: Inventory | null): data is Inventory {
  return Boolean(
    data &&
      natural(data.device_count) &&
      validUsers(data.users, data.device_count) &&
      timestamp(data.generated_at) &&
      typeof data.classifier_configured === "boolean" &&
      Array.isArray(data.items) &&
      data.items.every(
        (app) =>
          app &&
          typeof app.id === "string" &&
          app.id &&
          typeof app.name === "string" &&
          (app.display_name === undefined ||
            typeof app.display_name === "string") &&
          (app.reported_names === undefined ||
            (Array.isArray(app.reported_names) &&
              app.reported_names.every((name) => typeof name === "string"))) &&
          (app.approval_scope === undefined ||
            typeof app.approval_scope === "string") &&
          (app.approval_conflict === undefined ||
            typeof app.approval_conflict === "boolean") &&
          (app.software_type === undefined ||
            Object.hasOwn(softwareTypes, app.software_type)) &&
          (app.is_builtin === undefined ||
            typeof app.is_builtin === "boolean") &&
          (app.review_required === undefined ||
            typeof app.review_required === "boolean") &&
          (app.review_reason === undefined ||
            typeof app.review_reason === "string") &&
          natural(app.device_count) &&
          validUsers(app.users, app.device_count) &&
          app.device_count <= data.device_count &&
          typeof app.needs_attention === "boolean" &&
          (app.category === null || Object.hasOwn(categories, app.category)) &&
          Object.hasOwn(classificationLabels, app.classification_status) &&
          Object.hasOwn(statuses, app.approval_status) &&
          typeof app.reason === "string" &&
          validAssessment(app.assessment) &&
          (app.research_status === undefined ||
            (typeof app.research_status === "string" &&
              Object.hasOwn(researchLabels, app.research_status))) &&
          (app.assessment_status === undefined ||
            [
              "pending",
              "unavailable",
              "needs_identification",
              "complete",
              "stale",
            ].includes(app.assessment_status)) &&
          (app.assessment?.risk?.score == null ||
            (app.needs_attention && app.category !== null && app.category !== "ordinary"
              && app.checked_at !== null && (app.software_type === undefined
                || ["application", "command_line_tool"].includes(app.software_type)))) &&
          (app.assessment?.risk?.provisional_score == null ||
            (isRiskCandidate(app) && app.checked_at !== null &&
              (app.assessment.confidence === "low" || app.category !== null))) &&
          (app.assessment?.capability_score == null ||
            (app.category !== null &&
              app.checked_at !== null &&
              ["complete", "stale"].includes(app.assessment_status ?? ""))) &&
          Array.isArray(app.sources) &&
          app.sources.every(sourceUrl) &&
          (app.checked_at === null || timestamp(app.checked_at)) &&
          (app.approval_updated_at === null ||
            timestamp(app.approval_updated_at)),
      ) &&
      new Set(data.items.map((app) => app.id)).size === data.items.length,
  );
}
function validDevices(data: Devices): boolean {
  return Boolean(
    data &&
      typeof data.id === "string" &&
      typeof data.name === "string" &&
      Array.isArray(data.items) &&
      data.items.every(
        (device) =>
          device &&
          typeof device.id === "string" &&
          typeof device.name === "string" &&
          typeof device.os === "string" &&
          typeof device.user === "string" &&
          Array.isArray(device.versions) &&
          device.versions.every((version) => typeof version === "string") &&
          (device.installations === undefined ||
            (Array.isArray(device.installations) &&
              device.installations.every(
                (entry) =>
                  entry &&
                  [
                    "name",
                    "identifier",
                    "publisher",
                    "version",
                    "source",
                    "ecosystem",
                    "kind",
                    "path",
                    "scope",
                    "root",
                    "environment",
                  ].every(
                    (key) =>
                      typeof entry[key as keyof Installation] === "string",
                  ),
              ))) &&
          timestamp(device.last_seen_at),
      ) &&
      new Set(data.items.map((device) => device.id)).size === data.items.length,
  );
}
function category(app: Application) {
  return app.category
    ? categories[app.category]
    : classificationLabels[app.classification_status];
}
function unscoredLabel(app: Application) {
  if (!app.needs_attention || app.category === "ordinary")
    return "Outside AI review";
  if (["library", "helper", "system_component", "package"].includes(app.software_type ?? ""))
    return "Supporting software";
  if (app.research_status && app.research_status !== "complete")
    return researchLabels[app.research_status];
  if (app.category === null) return "Needs identification";
  return app.assessment?.risk
    ? "Insufficient evidence"
    : "Awaiting risk assessment";
}
function ResearchProgress({
  apps,
  configured,
}: {
  apps: Application[];
  configured: boolean;
}) {
  if (!apps.length || apps.some((app) => app.research_status === undefined))
    return null;
  const totals = { queued: 0, researching: 0, retry_pending: 0, complete: 0 };
  for (const app of apps) totals[app.research_status!]++;
  const review = apps.filter(requiresReview);
  const scored = review.filter((app) => applicationRisk(app) !== null).length;
  const ordinary = apps.filter((app) => app.category === "ordinary").length;
  const unidentified = apps.filter((app) => app.category === null).length;
  return (
    <div
      role="status"
      aria-label="Application research progress"
      className="text-sm text-muted-foreground"
    >
      <p>
        <span className="font-medium text-foreground">
          {configured ? "Application research" : "Application research paused"}
        </span>
        {" · "}
        {count(apps.length - totals.complete)} remaining ·{" "}
        {count(totals.complete)} of {count(apps.length)} apps and packages
        processed
      </p>
      <p className="text-xs">
        {count(totals.queued)} queued · {count(totals.researching)} researching
        · {count(totals.retry_pending)} retry pending ·{" "}
        {count(ordinary)} ordinary software · {count(unidentified)} unidentified
        · {count(scored)} of {count(review.length)} review apps risk-scored
      </p>
    </div>
  );
}

function ApprovalControl({
  app,
  disabled,
  onSave,
}: {
  app: Application;
  disabled: boolean;
  onSave: (app: Application, approved: boolean | null) => void;
}) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon-xs"
          aria-label={`Approval for ${appName(app)}`}
          data-approval={app.id}
          disabled={disabled}
        >
          <MoreHorizontal aria-hidden="true" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="w-56 space-y-2"
        aria-label={`Approval for ${appName(app)}`}
      >
        <p className="text-xs text-muted-foreground">
          {app.approval_scope || "Applies across the organization"}
        </p>
        {(["approved", "unapproved", "monitoring"] as const).map((status) => (
          <PopoverClose asChild key={status}>
            <Button
              variant="ghost"
              className="w-full justify-start"
              disabled={
                disabled ||
                (app.approval_status === status && !app.approval_conflict)
              }
              onClick={() => onSave(app, status === "monitoring" ? null : status === "approved")}
            >
              {approvalActions[status]}
            </Button>
          </PopoverClose>
        ))}
      </PopoverContent>
    </Popover>
  );
}

type RankedApplication = Application & { riskScore: number | null; similar: SimilarApplication[] };

function ApprovalGroup({
  status,
  apps,
  limit,
  onShowMore,
  detailed = false,
  stacked,
  className,
  canEdit,
  disabled,
  onOpen,
  onSave,
}: {
  status: ApprovalStatus;
  apps: RankedApplication[];
  limit: number;
  onShowMore: () => void;
  /** Monitoring is the work queue: it adds the classification column. */
  detailed?: boolean;
  /** Stacked cards share one column beside Monitoring: the top card keeps a
   *  short list and the bottom card fills the remaining column height. */
  stacked?: "top" | "bottom";
  className?: string;
  canEdit: boolean;
  disabled: boolean;
  onOpen: (app: Application, trigger: HTMLElement, view?: ApplicationView) => void;
  onSave: (app: Application, approved: boolean | null) => void;
}) {
  const { icon, tone } = columnHeaders[status];
  const label = statuses[status];
  return (
    <ReviewCard
      tone={tone}
      icon={icon}
      title={label}
      label={`${label} applications`}
      count={`${count(apps.length)} ${apps.length === 1 ? "app" : "apps"}`}
      stacked={stacked}
      className={className}
    >
          {apps.length ? (
            <Table
              aria-label={`${label} applications`}
              className={cn(reviewTable, "[&_th]:px-2 [&_td]:px-2")}
            >
              <TableHeader className={reviewTableHeader}>
                <TableRow>
                  <TableHead>Application</TableHead>
                  {detailed && (
                    <TableHead className="hidden lg:table-cell">
                      Classification
                    </TableHead>
                  )}
                  <TableHead className="text-right">Devices</TableHead>
                  <TableHead className="text-right">Users</TableHead>
                  {status !== "approved" && <TableHead
                    className="text-right"
                    aria-sort="descending"
                    title="Estimated product risk out of 100"
                  >
                    <span className="inline-flex items-center gap-1">
                      Risk score
                      <ArrowDown className="size-3.5" aria-hidden="true" />
                    </span>
                  </TableHead>}
                  <TableHead>Report</TableHead>
                  {status === "unapproved" && <TableHead className="text-right">Notify users</TableHead>}
                  {canEdit && (
                    <TableHead>
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  )}
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.slice(0, limit).map((app) => (
                  <TableRow key={app.id} data-application={app.id}>
                    {/* The name column takes the slack so counts stay
                        compact and names rarely wrap. */}
                    <TableCell className={cn("w-full whitespace-normal", detailed && "min-w-40 lg:min-w-0", status === "unapproved" && "min-w-24")}>
                      <button
                        className="text-left font-medium wrap-anywhere text-foreground hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                        data-open-app={app.id}
                        onClick={(event) => onOpen(app, event.currentTarget)}
                      >
                        {appName(app)}
                      </button>
                      {/* Keep approval conflicts visible in the narrow cards too. */}
                      {(detailed || app.approval_conflict) && (
                        <span className="block text-xs text-muted-foreground lg:ml-1.5 lg:inline">
                          {softwareType(app)}
                          <span className={detailed ? "lg:hidden" : "hidden"}>
                            {softwareType(app) ? " · " : ""}
                            {category(app)}
                          </span>
                        </span>
                      )}
                      {app.similar.length > 0 && (
                        <button className="mt-1 flex items-center gap-1 text-left text-xs text-muted-foreground hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                          title="Similar to unapproved apps"
                          aria-label={`Why ${appName(app)} is similar to unapproved apps`}
                          onClick={(event) => onOpen(app, event.currentTarget)}>
                          <TriangleAlert className="size-3 shrink-0" aria-hidden="true" />
                          {detailed ? "Similar to unapproved" : "Similar"}
                        </button>
                      )}
                    </TableCell>
                    {detailed && (
                      <TableCell className="hidden lg:table-cell">
                        {category(app)}
                        {app.classification_status === "stale"
                          ? " · Refresh delayed"
                          : ""}
                      </TableCell>
                    )}
                    <TableCell className="number text-right">
                      <button
                        data-open-devices={app.id}
                        onClick={(event) => onOpen(app, event.currentTarget, "devices")}
                        aria-label={`Show ${count(app.device_count)} devices for ${appName(app)}`}
                        className="font-medium text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >
                        {count(app.device_count)}
                      </button>
                    </TableCell>
                    <TableCell className="number text-right">
                      <button
                        onClick={(event) => onOpen(app, event.currentTarget, "users")}
                        aria-label={`Show ${count(userCount(app))} users for ${appName(app)}`}
                        className="font-medium text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >
                        {count(userCount(app))}
                      </button>
                    </TableCell>
                    {status !== "approved" && <TableCell className="text-right">
                      {app.riskScore === null ? (
                        <span className="block whitespace-normal text-xs text-muted-foreground">
                          {unscoredLabel(app)}
                        </span>
                      ) : (
                        <>
                          <div className={detailed ? "flex items-center justify-end gap-2" : undefined}>
                            <span
                              className="number"
                              aria-label={`Risk score ${app.riskScore} out of 100`}
                            >
                              {app.riskScore}
                            </span>
                            {detailed && (
                              <span
                                aria-hidden="true"
                                className="inline-block h-1.5 w-10 shrink-0 overflow-hidden rounded-xs bg-muted"
                              >
                                <span
                                  className={`block h-full rounded-xs ${riskBand(app.riskScore)}`}
                                  style={{ width: `${app.riskScore}%` }}
                                />
                              </span>
                            )}
                            <span className={cn("text-xs text-muted-foreground", detailed ? "w-14 shrink-0 text-left" : "block")}>{riskLabel(app.riskScore)}</span>
                          </div>
                          {app.assessment?.risk?.provisional_score != null && (
                            <span className={cn("block text-xs text-muted-foreground", detailed ? "whitespace-nowrap" : "whitespace-normal")}>Low confidence</span>
                          )}
                          {(app.classification_status === "stale" || app.research_status === "retry_pending") && (
                            <span className="block text-xs text-muted-foreground">
                              Refresh delayed
                            </span>
                          )}
                        </>
                      )}
                    </TableCell>}
                    <TableCell>
                      <button
                        onClick={(event) => onOpen(app, event.currentTarget)}
                        aria-label={`View report for ${appName(app)}`}
                        className="font-medium text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >
                        View
                      </button>
                    </TableCell>
                    {status === "unapproved" && (
                      <TableCell className="text-right">
                        <EndpointAlerts applicationId={app.id} name={appName(app)}
                          recipients={async (signal) => {
                            const result = await api<Devices>(`${endpoint}/${encodeURIComponent(app.id)}/devices`, { signal });
                            if (!validDevices(result) || result.id !== app.id)
                              throw new Error("The device response is incompatible. Refresh to try again.");
                            return result.items;
                          }}
                          scopeNote="Devices with a reported installation across the organization are included."
                          notification={{ title: `Unapproved application: ${appName(app)}`.slice(0, 160),
                            message: `${appName(app)} was found on your device and is not approved by your organization.\n\nContact IT for guidance on removing this application or choosing an approved alternative.`.slice(0, 2000) }} />
                      </TableCell>
                    )}
                    {canEdit && (
                      <TableCell className="w-px">
                        <ApprovalControl
                          app={app}
                          disabled={disabled}
                          onSave={onSave}
                        />
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState
              title={`No ${label.toLowerCase()} applications`}
              description={
                status === "monitoring"
                  ? "New AI tools appear here until you make an approval decision."
                  : "Change an application's approval to move it here."
              }
            />
          )}
          {apps.length > limit && (
            <div className="border-t px-4 py-3">
              <Button variant="ghost" size="xs" onClick={onShowMore}>
                Show more {label.toLowerCase()} applications
              </Button>
              <p className="mt-1 text-xs text-muted-foreground">
                Showing {count(limit)} of {count(apps.length)}
              </p>
            </div>
          )}
    </ReviewCard>
  );
}

export function ApplicationReview() {
  const inventory = useResource<Inventory>(endpoint, 30_000, false, {
    validate: validInventory,
  });
  const cache = useContext(ResourceCacheContext);
  const router = useRouter();
  const { user } = useDashboard();
  const canEdit =
    hasRole(user, "it_admin") || hasRole(user, "security_analyst");
  const { chartTimestamp } = useTimeZone();
  const [previous, setPrevious] = useState<{
    data: Inventory;
    generation: number;
  } | null>(null);
  const compatible = validInventory(inventory.data);
  useEffect(() => {
    if (validInventory(inventory.data))
      setPrevious({ data: inventory.data, generation: cache?.generation ?? 0 });
  }, [inventory.data, cache]);
  const data = compatible
    ? inventory.data
    : inventory.data === null && !inventory.error
      ? null
      : previous?.generation === (cache?.generation ?? 0)
        ? previous.data
        : null;
  const loadError =
    inventory.error ||
    (inventory.data && !compatible
      ? "The application inventory response is incompatible. Refresh after the server is updated."
      : "");
  const [query, setQuery] = useState("");
  const [userFilter, setUserFilter] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [softwareFilter, setSoftwareFilter] = useState("all");
  const [page, setPage] = useState(0);
  const pageSize = 10;
  const [limits, setLimits] = useState({
    approved: 50,
    unapproved: 50,
    monitoring: 50,
  });
  function resetLists() {
    setLimits({ approved: 50, unapproved: 50, monitoring: 50 });
    setPage(0);
  }
  const [selected, setSelected] = useState<string | null>(null);
  const [detailView, setDetailView] = useState<ApplicationView>("report");
  const [saving, setSaving] = useState("");
  const pending = useRef(false);
  const [saveError, setSaveError] = useState("");
  const [announcement, setAnnouncement] = useState("");
  const root = useRef<HTMLDivElement>(null);
  const reviewId = useId();
  const detailTrigger = useRef<HTMLElement | null>(null);
  const detailId = useRef("");
  // The review cards are organization-wide; only the software table and the
  // drawer it opens follow the user filter.
  const detailScoped = useRef(false);
  function openDetails(
    app: Application,
    trigger: HTMLElement,
    view: ApplicationView = "report",
    scoped = false,
  ) {
    detailTrigger.current = trigger;
    detailId.current = app.id;
    detailScoped.current = scoped;
    setDetailView(view);
    setSelected(app.id);
  }
  const focusAfterSave = useRef("");
  useEffect(() => {
    if (focusAfterSave.current && !saving) {
      const id = focusAfterSave.current;
      focusAfterSave.current = "";
      root.current
        ?.querySelectorAll<HTMLButtonElement>("[data-approval]")
        .forEach((control) => {
          if (control.dataset.approval === id && !selected) control.focus();
        });
    }
  }, [saving, selected]);
  const unapprovedApps = (data?.items ?? []).filter((app) => app.approval_status === "unapproved" && requiresReview(app));
  const allApps: RankedApplication[] = (data?.items ?? [])
    .map((app) => ({ ...app, riskScore: applicationRisk(app), similar: similarUnapproved(app, unapprovedApps) }))
    .sort(
      (a, b) =>
        appName(a).localeCompare(appName(b)) || a.id.localeCompare(b.id),
    );
  const apps = allApps
    .map((app) => {
      if (userFilter === null) return app;
      const users = app.users.filter((entry) => entry.user === userFilter);
      return { ...app, users, device_count: users[0]?.device_count ?? 0 };
    })
    .filter((app) => app.device_count > 0);
  const matches = (app: Application) =>
    [app.name, appName(app), ...(app.reported_names ?? [])].some((name) =>
      name.toLowerCase().includes(query.trim().toLowerCase()),
    ) &&
    (categoryFilter === "all" ||
      (app.category ?? "unclassified") === categoryFilter);
  const needs = allApps
    .filter(requiresReview)
    .sort(
      (a, b) =>
        (b.riskScore ?? -1) - (a.riskScore ?? -1) ||
        appName(a).localeCompare(appName(b)) ||
        a.id.localeCompare(b.id),
    );
  const groups = {
    approved: needs.filter((app) => app.approval_status === "approved"),
    unapproved: needs.filter((app) => app.approval_status === "unapproved"),
    monitoring: needs.filter((app) => app.approval_status === "monitoring"),
  };
  const ranked = apps
    .filter(matches)
    .filter(
      (app) =>
        softwareFilter === "all" ||
        softwareFilter ===
          (app.category === null
            ? "unclassified"
            : app.category === "ordinary"
              ? "ordinary"
              : "ai"),
    )
    .sort(
      (a, b) =>
        userCount(b) - userCount(a) ||
        appName(a).localeCompare(appName(b)) ||
        a.id.localeCompare(b.id),
    );
  const selectedApp = (detailScoped.current ? apps : allApps).find(
    (app) => app.id === selected,
  );
  const currentPage = Math.min(
    page,
    Math.max(0, Math.ceil(ranked.length / pageSize) - 1),
  );
  const pageStart = currentPage * pageSize;

  async function save(app: Application, approved: boolean | null) {
    if (pending.current || loadError || !canEdit) return;
    pending.current = true;
    setSaving(app.id);
    setSaveError("");
    setAnnouncement(`Saving approval for ${appName(app)}.`);
    const generation = cache?.generation;
    try {
      const result = await api<Approval>(
        `${endpoint}/${encodeURIComponent(app.id)}/approval`,
        { method: "PUT", body: JSON.stringify({ approved }) },
      );
      if (cache?.generation !== generation) return;
      if (
        !result ||
        result.id !== app.id ||
        result.approved !== approved ||
        !timestamp(result.approval_updated_at)
      )
        throw new Error(
          "The approval response is incompatible. Refresh to confirm the saved choice.",
        );
      const fraction = (value: string) =>
        (value.match(/\.(\d+)/)?.[1] ?? "").padEnd(9, "0").slice(0, 9);
      inventory.setData((previous) =>
        validInventory(previous)
          ? {
              ...previous,
              items: previous.items.map((row) => {
                if (row.id !== result.id) return row;
                if (row.approval_updated_at) {
                  const difference =
                    Date.parse(row.approval_updated_at) -
                    Date.parse(result.approval_updated_at);
                  if (
                    difference > 0 ||
                    (difference === 0 &&
                      fraction(row.approval_updated_at) >
                        fraction(result.approval_updated_at))
                  )
                    return row;
                }
                return {
                  ...row,
                  approval_status: result.approved === null ? "monitoring" : result.approved ? "approved" : "unapproved",
                  approval_updated_at: result.approval_updated_at,
                  approval_conflict: false,
                  review_required: row.needs_attention,
                  review_reason: !row.needs_attention
                    ? "The available evidence identifies ordinary software."
                    : result.approved === null
                      ? "This software is monitored by the organization."
                      : "An organization approval decision is recorded for this software.",
                };
              }),
            }
          : previous,
      );
      focusAfterSave.current = app.id;
      setAnnouncement(
        `${appName(app)} ${approved === null ? "moved to monitoring" : approved ? "approved" : "marked unapproved"}.`,
      );
    } catch (cause) {
      if (cache?.generation !== generation) return;
      if (cause instanceof APIError && [401, 403].includes(cause.status)) {
        cache?.clear();
        setPrevious(null);
        setSelected(null);
        router.replace("/login");
        return;
      }
      setSaveError(
        `Could not confirm approval for ${appName(app)}. ${displayText(cause instanceof Error ? cause.message : "Please try again.")}`,
      );
      setAnnouncement("");
    } finally {
      pending.current = false;
      setSaving("");
    }
  }
  const topMonitoring = groups.monitoring.find((app) => app.riskScore !== null);
  const unscored = groups.monitoring.filter(
    (app) => app.riskScore === null,
  ).length;
  const reportedUsers = data
    ? data.users.filter((entry) => entry.user !== "").length
    : 0;
  const groupProps = {
    canEdit,
    disabled: Boolean(saving || loadError),
    onOpen: openDetails,
    onSave: save,
  };
  const showMore = (status: ApprovalStatus) => () =>
    setLimits((current) => ({ ...current, [status]: current[status] + 50 }));
  return (
    <div ref={root} className="space-y-4">
      {loadError && (
        <ErrorState
          title={
            data
              ? "Application inventory may be out of date"
              : "Unable to load applications"
          }
          message={displayText(loadError)}
          onRetry={() => void inventory.reload()}
        />
      )}
      {saveError && (
        <ErrorState title="Approval was not confirmed" message={saveError} />
      )}
      <span className="sr-only" role="status" aria-label="Approval updates">
        {announcement}
      </span>
      {data && !data.classifier_configured && (
        <PageNotice title="Automatic classification is unavailable">
          <p>
            Configure the Intelligence API connection in Settings and enable
            application classification on the server. All reported software
            remains visible in the inventory.
          </p>
        </PageNotice>
      )}
      {data?.items.some((app) => app.review_required === undefined) && (
        <PageNotice title="Software context is unavailable">
          <p>
            This inventory does not yet distinguish apps from built-in software
            and supporting packages. Review the reported details before taking
            action.
          </p>
        </PageNotice>
      )}
      {/* The review is three peer cards under one unframed heading, so the
          group headers are the only colored chrome on the page. */}
      <section aria-labelledby={reviewId} className="space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-60 flex-1">
            <h2 id={reviewId} className="text-base font-semibold">
              Application review
            </h2>
            <p
              data-slot="review-summary"
              className="mt-0.5 text-sm text-muted-foreground"
            >
              {data && allApps.length ? (
                <>
                  {count(groups.monitoring.length)} of {count(needs.length)}{" "}
                  applications awaiting a decision across{" "}
                  {count(data.device_count)}{" "}
                  {data.device_count === 1 ? "device" : "devices"} and{" "}
                  {count(reportedUsers)}{" "}
                  {reportedUsers === 1 ? "user" : "users"}
                  {topMonitoring && (
                    <>
                      {" "}
                      · Highest risk{" "}
                      <span className="font-medium text-foreground">
                        {appName(topMonitoring)}
                      </span>{" "}
                      on {count(topMonitoring.device_count)}{" "}
                      {topMonitoring.device_count === 1 ? "device" : "devices"}
                    </>
                  )}
                  {unscored > 0 && <> · {count(unscored)} unscored</>}
                  {groups.unapproved.length === 1 ? (
                    <>
                      {" "}
                      ·{" "}
                      <span className="font-medium text-status-critical">
                        {appName(groups.unapproved[0])}
                      </span>{" "}
                      is unapproved on{" "}
                      {count(groups.unapproved[0].device_count)}{" "}
                      {groups.unapproved[0].device_count === 1
                        ? "device"
                        : "devices"}
                    </>
                  ) : groups.unapproved.length > 1 ? (
                    <>
                      {" "}
                      ·{" "}
                      <span className="font-medium text-status-critical">
                        {count(groups.unapproved.length)} unapproved
                      </span>
                    </>
                  ) : null}
                </>
              ) : (
                "AI apps and command-line tools that need an approval decision."
              )}
            </p>
          </div>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            {inventory.updated && (
              <p className="text-xs text-muted-foreground">
                Updated{" "}
                <time title={chartTimestamp(inventory.updated.toISOString())}>
                  {relative(inventory.updated.toISOString())}
                </time>
              </p>
            )}
            <Button
              variant="outline"
              size="responsive"
              onClick={() => void inventory.reload()}
              disabled={inventory.loading}
            >
              <RefreshCw aria-hidden="true" />
              {inventory.loading ? "Refreshing…" : "Refresh"}
            </Button>
          </div>
        </div>
        {data && (
          <ResearchProgress
            apps={data.items}
            configured={data.classifier_configured}
          />
        )}
        {!data ? (
          inventory.loading ? (
            <LoadingState label="Loading applications…" />
          ) : (
            <p className="text-sm text-muted-foreground">
              Application inventory is unavailable.
            </p>
          )
        ) : !allApps.length ? (
          <EmptyState
            title="No applications reported"
            description="Connect a device and wait for an application inventory scan."
          />
        ) : (
          <div className="grid min-w-0 grid-cols-1 gap-4 2xl:grid-cols-[minmax(0,2fr)_minmax(33rem,1fr)]">
            <ApprovalGroup
              status="monitoring"
              apps={groups.monitoring}
              limit={limits.monitoring}
              onShowMore={showMore("monitoring")}
              detailed
              {...groupProps}
            />
            {/* The stack is capped at the Monitoring card's maximum height
                (its 36px header plus the list cap) so Approved fills the
                remaining column instead of growing the row. */}
            <div className="flex min-w-0 flex-col gap-4 md:max-h-[calc(min(28rem,60dvh)+2.375rem)]">
              <ApprovalGroup
                status="unapproved"
                apps={groups.unapproved}
                limit={limits.unapproved}
                onShowMore={showMore("unapproved")}
                stacked="top"
                className="shrink-0"
                {...groupProps}
              />
              <ApprovalGroup
                status="approved"
                apps={groups.approved}
                limit={limits.approved}
                onShowMore={showMore("approved")}
                stacked="bottom"
                className="min-h-0 flex-1"
                {...groupProps}
              />
            </div>
          </div>
        )}
        <div className="flex flex-wrap gap-x-6">
          <PageNotice title="How risk scores work" collapsible>
            <p>
              Risk scores are AI estimates from public research into capabilities,
              autonomy, data exposure, safeguards, security history, and community
              reputation. Each assessment includes reasoning, sources, and confidence.
              Device counts, user counts, and approval decisions do not change the score.
            </p>
            <p>
              Scores range from 0 to 100: low below 25, moderate from 25 to 49,
              high from 50 to 74, and critical from 75. They are comparative product
              assessments, not measured incident probabilities. Local settings and
              enabled controls are not verified. All confidence levels can have a
              score. Uncertain identity or limited evidence produces a provisional
              estimate labeled Low confidence, with assumptions explained in details.
              Pending or failed research has no new score. Missing capability facts
              remain unverified and do not create similarity flags.
            </p>
            <p>
              Similar to unapproved flags apps sharing at least two documented
              capabilities at level 2 or 3 with an unapproved app, including code
              execution or autonomy. It compares capability profiles, not names or
              popularity. It also flags apps in the same category with at least
              three supported dimensions and a total difference of at most one
              level across them. Missing and low-confidence evidence cannot create
              a match. A match does not change approval or prove equivalent risk.
            </p>
          </PageNotice>
          <PageNotice title="How classification and approvals work" collapsible>
            <p>
              AI software provides or supports AI as its main purpose.
              Not AI-focused means the main purpose is something else, even if
              the software offers optional AI features. Unknown means its AI
              purpose has not been established. Each item belongs to one group;
              All software shows all three.
            </p>
            <p>
              AI capability alone is not evidence of a security problem.
              General-purpose apps with optional AI features, built-in apps,
              libraries, helpers, and unidentified software stay in inventory outside the default approval
              queue. Explicit decisions on AI or unclassified software remain in
              review.
            </p>
            <p>
              Classification uses public product information and web search.
              Approval labels do not block execution. Device counts use distinct
              endpoints with reported installations.
            </p>
            <p>
              Users are distinct latest signed-in endpoint usernames, not
              verified people or application usage. The user filter applies to
              the software table and the device details it opens. Unattributed
              devices remain visible and do not increase user counts. Approval
              choices apply to the application across the organization. The
              last known user is retained after logout or when the endpoint is
              offline. Endpoints need an updated sensor to report sign-in
              identities.
            </p>
          </PageNotice>
        </div>
      </section>
      {data && (
        <PageSection
          title="All installed software"
          titleAction={
            <span className="number text-xs text-muted-foreground">
              {count(apps.length)}
            </span>
          }
        >
          <div
            className="mb-4 flex min-w-0 flex-wrap items-center gap-2"
            role="group"
            aria-label="Software filters"
          >
            <Input
              type="search"
              size="responsive"
              aria-label="Find an application"
              placeholder="Find an app or package"
              className="w-full sm:w-60"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                resetLists();
              }}
            />
            <Select
              value={userFilter === null ? "all" : `user:${userFilter}`}
              onValueChange={(value) => {
                setUserFilter(value === "all" ? null : value.slice(5));
                setSelected(null);
                resetLists();
              }}
            >
              <SelectTrigger
                size="responsive"
                aria-label="Endpoint user"
                className="w-full sm:w-44"
                title={
                  userFilter === null
                    ? "All users"
                    : userFilter || "Unattributed"
                }
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All users</SelectItem>
                {data.users.map((entry) => (
                  <SelectItem key={entry.user} value={`user:${entry.user}`}>
                    {entry.user || "Unattributed"}
                  </SelectItem>
                ))}
                {userFilter !== null &&
                  !data.users.some((entry) => entry.user === userFilter) && (
                    <SelectItem value={`user:${userFilter}`}>
                      {userFilter || "Unattributed"}
                    </SelectItem>
                  )}
              </SelectContent>
            </Select>
            <Select
              value={categoryFilter}
              onValueChange={(value) => {
                setCategoryFilter(value);
                resetLists();
              }}
            >
              <SelectTrigger
                size="responsive"
                aria-label="Application category"
                className="w-full sm:w-44"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All categories</SelectItem>
                {Object.entries(categories).map(([value, label]) => (
                  <SelectItem key={value} value={value}>
                    {label}
                  </SelectItem>
                ))}
                <SelectItem value="unclassified">Unknown</SelectItem>
              </SelectContent>
            </Select>
            {(query || userFilter !== null || categoryFilter !== "all") && (
              <Button
                variant="ghost"
                size="responsive"
                onClick={() => {
                  setQuery("");
                  setUserFilter(null);
                  setCategoryFilter("all");
                  resetLists();
                }}
              >
                Clear filters
              </Button>
            )}
            <div
              role="group"
              aria-label="AI classification filter"
              className="flex flex-wrap gap-2 sm:ml-auto"
            >
              {[
                ["all", "All software"],
                ["ai", "AI software"],
                ["ordinary", "Not AI-focused"],
                ["unclassified", "Unknown"],
              ].map(([value, label]) => (
                <Button
                  key={value}
                  variant={softwareFilter === value ? "secondary" : "ghost"}
                  size="responsive"
                  aria-pressed={softwareFilter === value}
                  onClick={() => {
                    setSoftwareFilter(value);
                    setPage(0);
                  }}
                >
                  {label}
                </Button>
              ))}
            </div>
          </div>
          <TableLayout
            footer={`Ranked by distinct reported usernames. Installations do not establish usage.`}
          >
            <Table
              className="min-w-[680px]"
              aria-label="All installed software"
            >
              <TableHeader>
                <TableRow>
                  <TableHead>Software</TableHead>
                  <TableHead>AI classification</TableHead>
                  <TableHead>Approval status</TableHead>
                  <TableHead className="text-right" aria-sort="descending">
                    <span className="inline-flex items-center gap-1">
                      Users{" "}
                      <ArrowDown className="size-3.5" aria-hidden="true" />
                    </span>
                  </TableHead>
                  <TableHead className="text-right">Devices</TableHead>
                  <TableHead>Report</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ranked.slice(pageStart, pageStart + pageSize).map((app) => (
                  <TableRow key={app.id}>
                    <TableCell className="max-w-80 whitespace-normal">
                      <button
                        data-open-app={app.id}
                        onClick={(event) =>
                          openDetails(app, event.currentTarget, "report", true)
                        }
                        className="text-left font-medium wrap-anywhere text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >
                        {appName(app)}
                      </button>
                      {softwareType(app) && (
                        <span className="ml-1.5 text-xs text-muted-foreground">
                          {softwareType(app)}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {category(app)}
                      {(app.classification_status === "stale" || app.research_status === "retry_pending") && (
                        <p className="text-xs text-muted-foreground">
                          Refresh delayed
                        </p>
                      )}
                    </TableCell>
                    <TableCell>
                      {requiresReview(app) ? (
                        <Status tone={tones[app.approval_status]}>
                          {statuses[app.approval_status]}
                        </Status>
                      ) : (
                        <span className="text-muted-foreground">
                          Outside approval review
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="number text-right">
                      <button
                        onClick={(event) => openDetails(app, event.currentTarget, "users", true)}
                        aria-label={`Show ${count(userCount(app))} users for ${appName(app)}`}
                        className="font-medium text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >
                        {count(userCount(app))}
                      </button>
                    </TableCell>
                    <TableCell className="number text-right">
                      <button
                        data-open-devices={app.id}
                        onClick={(event) =>
                          openDetails(app, event.currentTarget, "devices", true)
                        }
                        aria-label={`Show ${count(app.device_count)} devices for ${appName(app)}`}
                        className="font-medium text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >
                        {count(app.device_count)}
                      </button>
                    </TableCell>
                    <TableCell>
                      <button
                        onClick={(event) => openDetails(app, event.currentTarget, "report", true)}
                        aria-label={`View report for ${appName(app)}`}
                        className="font-medium text-primary hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >
                        View
                      </button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableLayout>
          {!ranked.length && (
            <EmptyState
              title={
                userFilter !== null && !apps.length
                  ? "No applications for this user"
                  : "No matching installed apps"
              }
              description={
                userFilter !== null && !apps.length
                  ? "Select another user or refresh the inventory."
                  : "Try another application name, category, or user."
              }
            />
          )}
          <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs text-muted-foreground">
              {ranked.length
                ? `${count(pageStart + 1)}–${count(Math.min(pageStart + pageSize, ranked.length))}`
                : "0"}{" "}
              of {count(ranked.length)} applications
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="responsive"
                aria-label="Previous software page"
                disabled={currentPage === 0}
                onClick={() => setPage(currentPage - 1)}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="responsive"
                aria-label="Next software page"
                disabled={pageStart + pageSize >= ranked.length}
                onClick={() => setPage(currentPage + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        </PageSection>
      )}
      <Dialog
        open={Boolean(selectedApp)}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent
          variant="drawer"
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            if (detailTrigger.current?.isConnected)
              detailTrigger.current.focus();
            else {
              const controls =
                root.current?.querySelectorAll<HTMLButtonElement>(
                  "[data-open-app]",
                );
              const match = Array.from(controls ?? []).find(
                (control) => control.dataset.openApp === detailId.current,
              );
              (
                match ??
                root.current?.querySelector<HTMLInputElement>(
                  "input[type=search]",
                )
              )?.focus();
            }
          }}
        >
          {selectedApp && (
            <>
              <div className="border-b px-4 py-3 pr-12">
                <DialogTitle className="wrap-anywhere">
                  {appName(selectedApp)}
                </DialogTitle>
                <DialogDescription>
                  {[softwareType(selectedApp), category(selectedApp)]
                    .filter(Boolean)
                    .join(" · ")}
                </DialogDescription>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto">
                {detailView === "devices" ? (
                  <DeviceList
                    key={selectedApp.id}
                    app={selectedApp}
                    userFilter={detailScoped.current ? userFilter : null}
                  />
                ) : detailView === "users" ? (
                  <UserList app={selectedApp} />
                ) : (
                  <>
                    <div className="flex flex-wrap items-center justify-between gap-4 px-4 py-4">
                      {requiresReview(selectedApp) ? (
                        <Status tone={tones[selectedApp.approval_status]}>
                          {statuses[selectedApp.approval_status]}
                        </Status>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          Outside approval review
                        </span>
                      )}
                      {selectedApp.needs_attention && canEdit && (
                        <div className="flex flex-wrap gap-2">
                          <Button
                            size="responsive"
                            disabled={
                              Boolean(saving || loadError) ||
                              (selectedApp.approval_status === "approved" &&
                                !selectedApp.approval_conflict)
                            }
                            onClick={() => void save(selectedApp, true)}
                          >
                            Approve
                          </Button>
                          <Button
                            variant="outline"
                            size="responsive"
                            disabled={
                              Boolean(saving || loadError) ||
                              (selectedApp.approval_status === "unapproved" &&
                                !selectedApp.approval_conflict)
                            }
                            onClick={() => void save(selectedApp, false)}
                          >
                            Mark unapproved
                          </Button>
                          <Button
                            variant="outline"
                            size="responsive"
                            disabled={
                              Boolean(saving || loadError) ||
                              (selectedApp.approval_status === "monitoring" &&
                                !selectedApp.approval_conflict)
                            }
                            onClick={() => void save(selectedApp, null)}
                          >
                            Move to monitoring
                          </Button>
                        </div>
                      )}
                    </div>
                    <p className="px-4 pb-4 text-xs text-muted-foreground">
                      {selectedApp.approval_scope && (
                        <>{selectedApp.approval_scope} </>
                      )}
                      Approval is an organization label. It does not block
                      execution.
                    </p>
                    {selectedApp.approval_conflict && (
                      <p className="px-4 pb-4 text-sm">
                        Previous installations had different approval decisions.
                        This product stays Unapproved until you choose one decision
                        for all its installations.
                      </p>
                    )}
                    <RiskAssessment app={selectedApp} />
                    {selectedApp.similar.length > 0 && (
                      <section className="space-y-2 border-t p-4" aria-label="Similar to unapproved apps">
                        <h3 className="font-semibold">Similar to unapproved apps</h3>
                        <p className="text-sm text-muted-foreground">Shared documented capabilities. Your approval decision remains separate.</p>
                        <ul className="space-y-3">
                          {selectedApp.similar.map(({ app, dimensions, basis }) => (
                            <li key={app.id}>
                              <p className="font-medium">{appName(app)}</p>
                              <p className="text-sm">{dimensions.map((key) => capabilityLabels[key]).join(" · ")}</p>
                              <p className="text-xs text-muted-foreground">
                                {basis === "elevated_capabilities"
                                  ? "Both apps have supported levels of 2 or 3 in these areas."
                                  : `Same category: ${category(app)}. These ${dimensions.length} supported dimensions differ by at most one level in total.`}
                              </p>
                            </li>
                          ))}
                        </ul>
                      </section>
                    )}
                    {saveError && (
                      <div className="px-4 pb-4">
                        <ErrorState
                          title="Approval was not confirmed"
                          message={saveError}
                        />
                      </div>
                    )}
                    <SoftwareContext app={selectedApp} />
                    <DeviceList
                      key={selectedApp.id}
                      app={selectedApp}
                      userFilter={detailScoped.current ? userFilter : null}
                    />
                    <div className="border-t p-4">
                      <PageNotice title="Why this classification?" collapsible>
                        <p>
                          {selectedApp.reason ||
                            classificationLabels[selectedApp.classification_status]}
                        </p>
                        {selectedApp.checked_at && (
                          <p className="text-xs text-muted-foreground">
                            Checked {chartTimestamp(selectedApp.checked_at)}
                            {selectedApp.classification_status === "stale"
                              ? " · Refresh delayed"
                              : ""}
                          </p>
                        )}
                        {selectedApp.sources.length > 0 && (
                          <ul className="space-y-1">
                            {selectedApp.sources.map((source, index) => (
                              <li key={source}>
                                <a
                                  href={source}
                                  title={source}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 text-primary hover:underline"
                                >
                                  Source {index + 1}
                                  <ExternalLink
                                    aria-hidden="true"
                                    className="size-3.5"
                                  />
                                </a>
                              </li>
                            ))}
                          </ul>
                        )}
                      </PageNotice>
                    </div>
                  </>
                )}
              </div>
              <div className="flex justify-end border-t px-4 py-3">
                <Button
                  variant="outline"
                  size="responsive"
                  onClick={() => setSelected(null)}
                >
                  Done
                </Button>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function RiskAssessment({ app }: { app: RankedApplication }) {
  const { chartTimestamp } = useTimeZone();
  const assessment = app.assessment;
  const report = assessment?.report;
  const sources = (urls: string[], label = "Source") =>
    urls.length > 0 && (
      <ul className="flex flex-wrap gap-x-3 gap-y-1">
        {urls.map((url, index) => (
          <li key={url}>
            <a
              href={url}
              title={url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              {label} {index + 1}
              <span className="sr-only">: {url}</span>
            </a>
          </li>
        ))}
      </ul>
    );
  return (
    <section className="space-y-4 border-t p-4 wrap-anywhere" aria-label="Risk assessment">
      <div className="space-y-1">
        <h3 className="text-sm font-semibold">What it does</h3>
        <p className="text-sm">
          {report?.purpose.reason || app.reason || "The product's purpose has not been established yet."}
        </p>
      </div>
      <div className="space-y-2">
        <h3 className="text-sm font-semibold">Potential harm and likelihood</h3>
        <Table className="table-fixed" aria-label="Potential harm and likelihood">
          <TableHeader>
            <TableRow>
              <TableHead className="whitespace-normal">What could go wrong?</TableHead>
              <TableHead className="whitespace-normal">How likely?</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {report && report.harms.length > 0 ? report.harms.map((harm, index) => (
              <TableRow key={index}>
                <TableCell className="align-top whitespace-normal">{harm.damage}</TableCell>
                <TableCell className="align-top whitespace-normal">{harm.likelihood}</TableCell>
              </TableRow>
            )) : (
              <TableRow>
                <TableCell className="align-top whitespace-normal">
                  {report ? "Not established by the available evidence." : "Not assessed in this report yet."}
                </TableCell>
                <TableCell className="align-top whitespace-normal">
                  Unknown. Product capabilities and local settings need verification.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        <p className="text-xs text-muted-foreground">
          Potential scenarios, not observed incidents. Local settings and use are unverified.
        </p>
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium">
          {app.riskScore === null
            ? unscoredLabel(app)
            : `Risk score ${app.riskScore}/100 · ${riskLabel(app.riskScore)} risk`}
        </p>
        {app.riskScore === null && (
          <p className="mt-1 text-sm text-muted-foreground">
            No applicable risk estimate is available yet.
          </p>
        )}
        {assessment?.risk?.provisional_score != null && (
          <p className="mt-1 text-sm text-muted-foreground">
            Provisional estimate.
            {app.category === null && " Product identity is unresolved."}
            {assessment.risk.sources.length === 0 && " No public sources were cited for this estimate."}
          </p>
        )}
        {app.assessment_status === "unavailable" && (
          <p className="mt-1 text-sm text-muted-foreground">
            Research is temporarily unavailable.
          </p>
        )}
        {assessment ? (
          <>
            <p className="text-xs text-muted-foreground">
              {assessment.risk?.provisional_score != null
                ? `Risk confidence: low · Capability confidence: ${assessment.confidence}`
                : `Research confidence: ${assessment.confidence}`}
              {app.checked_at
                ? ` · Checked ${chartTimestamp(app.checked_at)}`
                : ""}
              {app.assessment_status === "stale" || app.research_status === "retry_pending" ? " · Refresh delayed" : ""}
            </p>
            <p className="text-xs text-muted-foreground">The score compares product risk; it is not a probability of harm.</p>
          </>
        ) : (
          <p className="text-xs text-muted-foreground">
            A sourced capability assessment is not available yet.
          </p>
        )}
      </div>
      {assessment && (
        <PageNotice title="Evidence and available controls" collapsible>
          {report && (
            <>
              <div className="space-y-1">
                <p className="font-medium">Product purpose sources</p>
                {report.purpose.sources.length ? sources(report.purpose.sources) : <p>No public sources were cited.</p>}
              </div>
              {report.harms.map((harm, index) => (
                <div key={index} className="space-y-1">
                  <p className="font-medium">{harm.damage}</p>
                  {sources(harm.sources)}
                </div>
              ))}
            </>
          )}
          {assessment.risk && (
            <div className="space-y-1">
              <p className="font-medium">Risk reasoning</p>
              <p>{assessment.risk.reason}</p>
              {sources(assessment.risk.sources, "Risk source")}
            </div>
          )}
          <p>{assessment.summary}</p>
          {(
            Object.keys(capabilityLabels) as (keyof typeof capabilityLabels)[]
          ).map((key) => (
            <div key={key} className="space-y-1">
              <p className="font-medium">
                {capabilityLabels[key]} ·{" "}
                {assessment[key].level === null
                  ? "Unverified"
                  : `${assessment[key].level}/3`}
              </p>
              <p>{assessment[key].reason}</p>
              {sources(assessment[key].sources)}
            </div>
          ))}
          <div className="space-y-1">
            <p className="font-medium">
              Available controls
              {assessment.controls.sources.length === 0
                ? " · Unverified"
                : ""}
            </p>
            <p>{assessment.controls.reason}</p>
            {sources(assessment.controls.sources)}
          </div>
          {assessment.reputation && (
            <div className="space-y-1">
              <p className="font-medium">
                Security history and community reputation
              </p>
              <p>{assessment.reputation.reason}</p>
              {sources(assessment.reputation.sources)}
            </div>
          )}
          <p>
            These are documented product capabilities. Enabled settings, use
            on these devices, and the effectiveness of controls are not
            verified. Confidence describes the research, not a probability of
            harm.
          </p>
        </PageNotice>
      )}
    </section>
  );
}

function SoftwareContext({ app }: { app: Application }) {
  const guidance = app.is_builtin
    ? "Reported in the operating system's built-in app location. Check the operating system's available controls before changing this software."
    : app.software_type === "library" ||
        app.software_type === "helper" ||
        app.software_type === "package" ||
        app.software_type === "system_component"
      ? "This component may not appear in Applications or the installed-app list. Use its reported name and location below. Confirm which app or project uses it before removal; the owning app is not confirmed."
      : app.software_type === "command_line_tool"
        ? "Command-line tools are usually managed through a terminal or package manager. Use the reported name, location, and package environment below to find the installation."
        : "Use the reported name and installation location on each device to find this software.";
  return (
    <section
      aria-label="Software context"
      className="space-y-2 border-t px-4 py-3"
    >
      <PageNotice title="Installation guidance" collapsible>
        {appName(app) !== app.name && (
          <div>
            <p className="text-xs text-muted-foreground">Reported name</p>
            <p className="font-mono text-sm font-normal wrap-anywhere">
              {app.name}
            </p>
          </div>
        )}
        {app.review_reason && (
          <p className="text-xs text-muted-foreground">
            {app.needs_attention && app.approval_status !== "monitoring"
              ? "An organization approval decision is recorded for this software."
              : app.review_reason}
          </p>
        )}
        <p className="text-sm">{guidance}</p>
      </PageNotice>
    </section>
  );
}

function UserList({ app }: { app: Application }) {
  const users = app.users.filter((entry) => entry.user !== "");
  const unattributed = app.users.find((entry) => entry.user === "")?.device_count ?? 0;
  return (
    <section aria-label="Application users">
      <div className="border-t px-4 py-3">
        <h3 className="text-sm font-semibold">Reported users ({count(users.length)})</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          Latest signed-in endpoint usernames on devices with {appName(app)} installed.
          These are reported identities, not verified people or application usage.
        </p>
        {unattributed > 0 && (
          <p className="mt-2 text-xs text-muted-foreground">
            {count(unattributed)} {unattributed === 1 ? "device has" : "devices have"} no reported username and {unattributed === 1 ? "is" : "are"} excluded from the user count.
          </p>
        )}
      </div>
      {users.length ? (
        <ul aria-label="Reported users" className="divide-y border-t">
          {users.map((entry) => (
            <li key={entry.user} className="flex min-w-0 items-start justify-between gap-4 px-4 py-3">
              <span className="min-w-0 text-sm font-medium wrap-anywhere">{entry.user}</span>
              <span className="number shrink-0 text-sm text-muted-foreground">
                {count(entry.device_count)} {entry.device_count === 1 ? "device" : "devices"}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState
          title="No reported users"
          description="Devices in this view have not reported a signed-in username."
        />
      )}
    </section>
  );
}

function DeviceList({
  app,
  userFilter,
}: {
  app: Application;
  userFilter: string | null;
}) {
  const result = useResource<Devices>(
    `${endpoint}/${encodeURIComponent(app.id)}/devices`,
    0,
    false,
    { validate: validDevices },
  );
  const { chartTimestamp } = useTimeZone();
  const compatible =
    result.data && validDevices(result.data) && result.data.id === app.id;
  const error =
    result.error ||
    (result.data && !compatible
      ? "The device response is incompatible. Refresh to try again."
      : "");
  const devices = compatible
    ? result.data!.items.filter(
        (device) => userFilter === null || device.user === userFilter,
      )
    : [];
  return (
    <section aria-label="Application devices">
      <div className="border-t px-4 py-3">
        <h3 className="text-sm font-semibold">
          Installed devices
          {compatible ? ` (${count(devices.length)})` : ""}
        </h3>
        <p className="mt-1 text-xs text-muted-foreground">
          Devices with a reported installation of {appName(app)}.
          {userFilter !== null && <> User: {userFilter || "Unattributed"}.</>}
        </p>
        <div className="mt-3"><EndpointAlerts applicationId={app.id} name={appName(app)} recipients={devices}
          scopeNote={userFilter !== null ? "Only devices in the selected user filter are available." : undefined} /></div>
      </div>
      {error && (
        <div className="px-4 pb-4">
          <ErrorState
            title="Unable to load devices"
            message={displayText(error)}
            onRetry={() => void result.reload()}
          />
        </div>
      )}
      {result.loading && !result.data && (
        <LoadingState label="Loading devices…" />
      )}
      {compatible &&
        (devices.length ? (
          <ul aria-label="Installed devices" className="divide-y border-t">
            {devices.map((device, deviceIndex) => (
              <li
                key={device.id}
                className="flex min-w-0 flex-wrap items-start justify-between gap-2 px-4 py-3"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium wrap-anywhere">
                    {device.name || (
                      <span className="font-mono text-sm font-normal">
                        {device.id}
                      </span>
                    )}
                  </p>
                  <p className="text-xs text-muted-foreground wrap-anywhere">
                    {device.user || "Unattributed"} ·{" "}
                    {device.os || "Platform not reported"}
                  </p>
                </div>
                <time
                  className="text-xs text-muted-foreground"
                  title={chartTimestamp(device.last_seen_at)}
                >
                  Reported {relative(device.last_seen_at)}
                </time>
                {device.installations?.length ? (
                  <details
                    className="min-w-0 basis-full"
                    open={deviceIndex === 0}
                  >
                    <summary className="cursor-pointer py-1 text-xs font-medium focus-visible:outline-2 focus-visible:outline-ring">
                      Installation details ({count(device.installations.length)}
                      )
                    </summary>
                    <div className="divide-y">
                      {device.installations.map((entry, index) => (
                        <dl key={index} className="space-y-2 py-2">
                          {[
                            ["Reported name", entry.name],
                            [
                              "Identifier",
                              entry.identifier !== entry.name
                                ? entry.identifier
                                : "",
                            ],
                            ["Version", entry.version],
                            ["Location", entry.path || "Not reported"],
                            ["Package root", entry.root],
                            [
                              "Environment",
                              entry.environment !== entry.root
                                ? entry.environment
                                : "",
                            ],
                            ["Package ecosystem", entry.ecosystem],
                            ["Source", entry.source],
                          ]
                            .filter(([, value]) => value)
                            .map(([label, value]) => (
                              <div key={label}>
                                <dt className="text-xs text-muted-foreground">
                                  {label}
                                </dt>
                                <dd className="font-mono text-sm font-normal wrap-anywhere">
                                  {value}
                                </dd>
                              </div>
                            ))}
                        </dl>
                      ))}
                    </div>
                  </details>
                ) : (
                  <p className="basis-full text-xs text-muted-foreground">
                    Installation location not reported.
                  </p>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState
            title="No current installations"
            description="No devices in this view currently report this application. Refresh the inventory."
          />
        ))}
    </section>
  );
}
