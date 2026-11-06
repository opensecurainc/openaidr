"use client";

import { useContext, useId, useRef, useState } from "react";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, CircleCheck, CircleDashed, CircleX, Eye, History, MoreHorizontal, RefreshCw } from "lucide-react";
import type { Root } from "@/components/component-inventory";
import { useDashboard } from "@/components/dashboard-context";
import { ResourceCacheContext } from "@/lib/resource-cache";
import { EndpointAlerts } from "@/components/endpoint-alerts";
import { SkillLlmControls } from "@/components/skill-llm-controls";
import { useInventoryPages } from "@/lib/use-inventory-pages";
import { useResource } from "@/lib/use-resource";
import { api, APIError, relative } from "@/lib/api";
import { hasRole } from "@/lib/roles";
import { cn } from "@/lib/utils";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Status } from "@/components/ui/status";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Popover, PopoverClose, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { ReviewCard, reviewTable, reviewTableHeader } from "@/components/review-card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

type ScanStatus = "pending" | "awaiting_upload" | "queued" | "running" | "complete" | "partial" | "failed" | "stale";
const approvalLabels = { approved: "Approved", unapproved: "Unapproved", monitoring: "Monitoring" };
const approvalActions = { approved: "Approve", unapproved: "Mark unapproved", monitoring: "Move to monitoring" };
type ApprovalStatus = keyof typeof approvalLabels;
type Skill = {
  id: string; name: string; installations: number; devices: number; last_seen_at: string;
  needs_attention: boolean; scan_status: ScanStatus; risk_score: number | null;
  retained_score?: number | null;
  scopes: string[]; collection_incomplete: boolean;
  sha256?: string | null; size_bytes?: number | null; bundle_complete?: boolean | null;
  approval_status: ApprovalStatus; approval_updated_at: string | null;
};
type Inventory = {
  enabled: boolean; items: Skill[]; next_cursor: string; total: number;
  summary: { installed: number; installations: number; attention: number; assessed: number; pending: number; incomplete: number };
};
type Finding = { rule: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"; title: string; description: string; file: string; line: number; remediation: string };
type Coverage = { reasons: { code: string; message: string; file: string; analyzer: string; line?: number; target?: string }[]; truncated: boolean };
type Details = {
  id: string; name: string; sha256: string | null; scan_status: ScanStatus; completed_at: string | null; error: string;
  approval_status: ApprovalStatus; approval_updated_at: string | null;
  size_bytes?: number | null;
  metadata: { repository_url?: string; source_url?: string; tools?: string[]; description?: string };
  manifest: { complete: boolean; files: { path: string; size?: number; sha256?: string; skip?: string }[] } | null;
  report: { complete: boolean; mode: "static" | "llm"; model?: string; llm_cache?: boolean; score: number; scanner_version: string; needs_attention: boolean; issues: Finding[]; coverage?: Coverage; finding_text_truncated?: boolean } | null;
  installations_truncated: boolean;
  installations: { id: string; hostname: string; sensor_id: string; path: string; scope: string; version: string; root_status: string; last_seen_at: string }[];
};
const labels: Record<ScanStatus, string> = {
  pending: "Not assessed", awaiting_upload: "Waiting for upload", queued: "Queued", running: "Scanning",
  complete: "Fully assessed", partial: "Coverage incomplete", failed: "Scan failed", stale: "Rescan due",
};
const filters = { all: "All assessments", attention: "Needs attention", assessed: "Fully assessed", pending: "Not fully assessed" };
const scopes = { all: "All scopes", user: "Personal", project: "Project", system: "System" };
const scopeLabel = (scope: string) => scopes[scope as keyof typeof scopes] || scope || "Unknown";
const severity = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "informational" } as const;
const validScore = (score: unknown): score is number => typeof score === "number" && Number.isInteger(score) && score >= 0 && score <= 100;
function bundleSize(size: number | null | undefined, sha256: string | null | undefined) {
  if (size == null) return sha256 ? "Not reported" : "Not collected";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
}
function validInventory(data: Inventory) {
  return Boolean(data?.summary && ["installed", "installations", "attention", "assessed", "pending", "incomplete"].every(key =>
    Number.isInteger(data.summary[key as keyof Inventory["summary"]]) && data.summary[key as keyof Inventory["summary"]] >= 0)
    && typeof data.enabled === "boolean" && Number.isInteger(data.total) && data.total >= 0
    && typeof data.next_cursor === "string" && Array.isArray(data.items)
    && data.items.every(item => item && typeof item.id === "string" && typeof item.name === "string"
      && item.scan_status in labels && Array.isArray(item.scopes)
      && Object.hasOwn(approvalLabels, item.approval_status)
      && (item.risk_score === null || validScore(item.risk_score))
      && (item.retained_score == null || validScore(item.retained_score))));
}
function validDetails(data: Details) {
  return Boolean(data && typeof data.id === "string" && typeof data.name === "string"
    && Object.hasOwn(approvalLabels, data.approval_status)
    && data.scan_status in labels && Array.isArray(data.installations)
    && (!data.manifest || Array.isArray(data.manifest.files))
    && (!data.report || (validScore(data.report.score) && Array.isArray(data.report.issues)
      && (data.report.finding_text_truncated === undefined || typeof data.report.finding_text_truncated === "boolean")
      && (!data.report.coverage || (Array.isArray(data.report.coverage.reasons)
        && typeof data.report.coverage.truncated === "boolean"
        && data.report.coverage.reasons.every(reason => reason && [reason.code, reason.message, reason.file, reason.analyzer].every(value => typeof value === "string")
          && (reason.line === undefined || (Number.isInteger(reason.line) && reason.line > 0 && reason.line <= 10_000_000))
          && (reason.target === undefined || typeof reason.target === "string")))))));
}

// Bands from the pinned SkillSpector release. Finding severity is independent.
// The bar reuses the severity marks so it reads like the Overview severity bar
// (COLORS.md, Magnitude); the band is a scanner aggregate, not a finding.
const band = (score: number) => score > 80 ? "critical" : score > 50 ? "high" : score > 20 ? "medium" : "low";
const bandFill = { critical: "bg-severity-critical", high: "bg-severity-high", medium: "bg-severity-medium", low: "bg-severity-low" } as const;

function RiskScore({ score, bar = false }: { score: number | null | undefined; bar?: boolean }) {
  if (!validScore(score)) return <span className="text-muted-foreground">Not available</span>;
  const level = band(score);
  return <span className="inline-flex items-center gap-2 whitespace-nowrap">
    <span className="number" aria-label={`Risk score ${score} out of 100`}>{score}</span>
    {bar && <span aria-hidden="true" className="inline-block h-1.5 w-10 overflow-hidden rounded-xs bg-muted">
      <span className={`block h-full rounded-xs ${bandFill[level]}`} style={{ width: `${score}%` }} />
    </span>}
    {level === "low" ? <span className="text-xs text-muted-foreground">Low</span> : <Badge variant={level}>{level[0].toUpperCase() + level.slice(1)}</Badge>}
  </span>;
}
const displayedScore = (skill: Skill) => skill.scan_status === "complete" ? skill.risk_score : skill.retained_score;
const scoreQualifier = (status: ScanStatus) => status === "partial" ? "Partial assessment" : status === "stale" ? "Stale assessment" : "Previous assessment";
function SkillScore({ skill, bar = false, onOpen }: { skill: Skill; bar?: boolean; onOpen: (skill: Skill, trigger: HTMLButtonElement) => void }) {
  const score = displayedScore(skill);
  const qualifier = scoreQualifier(skill.scan_status);
  const Icon = skill.scan_status === "partial" ? CircleDashed : History;
  return <div className="inline-flex items-center gap-1 whitespace-nowrap">
    <RiskScore score={score} bar={bar} />
    {validScore(score) && skill.scan_status !== "complete" && <Button variant="ghost" size="icon-xs"
      aria-label={`${qualifier} for ${skill.name}`} title={`${qualifier}. View assessment details.`}
      onClick={event => onOpen(skill, event.currentTarget)}>
      <Icon aria-hidden="true" /><span className="sr-only">{qualifier}</span>
    </Button>}
  </div>;
}
function Assessment({ skill }: { skill: Pick<Skill, "scan_status" | "needs_attention"> }) {
  return <div className="space-y-1">
    {skill.needs_attention ? <Status tone="warning">Needs attention</Status>
      : skill.scan_status === "complete" ? <span>No high-risk findings</span>
      : <Status tone={skill.scan_status === "failed" ? "critical" : ["partial", "stale"].includes(skill.scan_status) ? "warning" : "neutral"}>{labels[skill.scan_status]}</Status>}
    {skill.needs_attention && skill.scan_status !== "complete" && <p className="text-xs text-muted-foreground">{labels[skill.scan_status]}</p>}
  </div>;
}
function SkillName({ skill, scope = true, onOpen }: { skill: Skill; scope?: boolean; onOpen: (skill: Skill, trigger: HTMLButtonElement) => void }) {
  return <>
    <button className="text-left font-medium wrap-anywhere text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring"
      aria-label={`View details for ${skill.name}`} onClick={event => onOpen(skill, event.currentTarget)}>{skill.name}</button>
    {scope && <span className="ml-1.5 text-xs text-muted-foreground">{skill.scopes.map(scopeLabel).join(", ") || "Unknown"}</span>}
    {skill.collection_incomplete && <span className="ml-1.5 text-xs text-muted-foreground">· Collection incomplete</span>}
  </>;
}

/** One status-scoped first page for a review card; the table keeps its own query. */
function useSkillList(review: ApprovalStatus) {
  const params = new URLSearchParams({ q: "", status: "all", review, scope: "all", sort: "risk_desc", cursor: "" });
  const resource = useResource<Inventory>(`inventory/skills?${params}`, 30_000, false, { validate: validInventory });
  const data = resource.data && validInventory(resource.data) ? resource.data : null;
  return { ...resource, data, error: resource.error || (resource.data && !data ? "Inventory response is incompatible." : "") };
}

function CardState({ list, label, children }: { list: ReturnType<typeof useSkillList>; label: string; children: React.ReactNode }) {
  const title = label[0].toUpperCase() + label.slice(1);
  if (!list.data && list.loading) return <div className="px-4 py-3"><LoadingState label={`Loading ${label}…`} /></div>;
  if (!list.data) return <p className="px-4 py-3 text-sm text-muted-foreground">{title} unavailable. Use Refresh to reload.</p>;
  // useResource keeps the last response when a refresh fails, so a retained
  // list says so instead of passing as current; a successful Refresh clears it.
  return <>
    {list.error && <p role="alert" className="border-b border-l-4 border-l-status-warning bg-status-warning/10 px-4 py-2 text-xs text-foreground">
      {title} refresh failed: {list.error} Showing previously loaded results; use Refresh to retry.
    </p>}
    {children}
  </>;
}
const pill = (list: ReturnType<typeof useSkillList>, count: number) =>
  !list.data ? (list.loading ? "Loading" : "Unknown") : `${count.toLocaleString()} ${count === 1 ? "skill" : "skills"}`;

function ApprovalControl({ skill, disabled, onSave }: { skill: Skill; disabled: boolean; onSave: (skill: Skill, status: ApprovalStatus) => void }) {
  const canApprove = Boolean(skill.bundle_complete && skill.sha256 && skill.id === skill.sha256);
  return <Popover>
    <PopoverTrigger asChild><Button variant="ghost" size="icon-xs" aria-label={`Approval for ${skill.name}`} disabled={disabled}><MoreHorizontal aria-hidden="true" /></Button></PopoverTrigger>
    <PopoverContent className="w-64 space-y-2" aria-label={`Approval for ${skill.name}`}>
      <p className="text-xs text-muted-foreground">{canApprove ? "Applies to this exact skill content across the organization." : "Applies to this installation. Complete collection is required to approve."}</p>
      {skill.sha256 && <p className="font-mono text-sm font-normal" title={skill.sha256}>SHA-256: {skill.sha256.slice(0, 12)}…</p>}
      {(Object.keys(approvalLabels) as ApprovalStatus[]).map(status => <PopoverClose asChild key={status}>
        <Button variant="ghost" className="w-full justify-start" disabled={disabled || skill.approval_status === status || (status === "approved" && !canApprove)} onClick={() => onSave(skill, status)}>{approvalActions[status]}</Button>
      </PopoverClose>)}
    </PopoverContent>
  </Popover>;
}
async function recipients(skill: Skill, signal: AbortSignal) {
  const result = await api<{ id: string; items: { id: string; name: string; versions: string[] }[] }>(`inventory/skills/${encodeURIComponent(skill.id)}/devices`, { signal });
  if (result?.id !== skill.id || !Array.isArray(result.items) || !result.items.every(item => item && typeof item.id === "string" && typeof item.name === "string"
    && Array.isArray(item.versions) && item.versions.every(version => typeof version === "string"))) throw new Error("The skill devices response is incompatible. Refresh and try again.");
  return result.items;
}

export function SkillsInventory() {
  const reviewId = useId();
  const { user, refreshUser } = useDashboard();
  const cache = useContext(ResourceCacheContext);
  const canEdit = hasRole(user, "it_admin") || hasRole(user, "security_analyst");
  const [saving, setSaving] = useState(false);
  const pendingSave = useRef(false);
  const [saveError, setSaveError] = useState("");
  const [announcement, setAnnouncement] = useState("");
  const refreshButton = useRef<HTMLButtonElement | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [review, setReview] = useState("all");
  const [scope, setScope] = useState("all");
  const [sort, setSort] = useState("risk_desc");
  const [cursors, setCursors] = useState<string[]>([""]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState("findings");
  const trigger = useRef<HTMLButtonElement | null>(null);
  const { dateTime } = useTimeZone();
  const params = new URLSearchParams({ q: query, status: filter, review, scope, sort, cursor: cursors.at(-1) || "" });
  const inventory = useResource<Inventory>(`inventory/skills?${params}`, 30_000, false, { validate: validInventory });
  const unapproved = useSkillList("unapproved");
  const monitoring = useSkillList("monitoring");
  const approved = useSkillList("approved");
  const details = useResource<Details>(selected ? `inventory/skills/${encodeURIComponent(selected)}` : null, 0, false, { validate: validDetails });
  const roots = useInventoryPages<Root>("roots", "openaidr-skills", new URLSearchParams({ limit: "50" }));
  const data = inventory.data && validInventory(inventory.data) ? inventory.data : null;
  const error = inventory.error || (inventory.data && !data ? "Inventory response is incompatible. Update the backend to show scanner assessments." : "");
  // Every list response carries the organization summary; prefer the table's
  // and fall back to a card's so a failed table query keeps the headline.
  const summary = (data ?? unapproved.data ?? monitoring.data ?? approved.data)?.summary;
  const summaryUnknown = !summary && Boolean(error || unapproved.error);
  const count = (value: number | undefined) => value === undefined ? summaryUnknown ? "Unknown" : "…" : value.toLocaleString();
  const coverage = summary?.installed ? Math.round(summary.assessed / summary.installed * 100) : null;
  const chosen = details.data && validDetails(details.data) && details.data.id === selected ? details.data : null;
  const report = chosen?.report;
  const collectionWarnings = roots.items.filter(root => root.status !== "ok").length;
  function changeFilter(value: string) { setFilter(value); setCursors([""]); }
  function reset() { setQuery(""); setScope("all"); setReview("all"); changeFilter("all"); }
  async function refresh() { await Promise.all([inventory.reload(), unapproved.reload(), monitoring.reload(), approved.reload(), roots.reload(), ...(selected ? [details.reload()] : [])]); }
  function open(skill: Pick<Skill, "id">, control: HTMLButtonElement, tab = "findings") { trigger.current = control; setDetailTab(tab); setSelected(skill.id); }
  const enabled = (data ?? unapproved.data)?.enabled;
  async function save(skill: Skill, status: ApprovalStatus) {
    if (pendingSave.current || !canEdit) return;
    pendingSave.current = true; setSaving(true); setSaveError(""); setAnnouncement("");
    const generation = cache?.generation;
    const decision = status === "monitoring" ? null : status === "approved";
    try {
      const result = await api<{ id: string; approved: boolean | null; sha256: string | null; approval_updated_at: string }>(`inventory/skills/${encodeURIComponent(skill.id)}/approval`, {
        method: "PUT", body: JSON.stringify({ approved: decision, sha256: skill.sha256 ?? null }),
      });
      if (cache?.generation !== generation) return;
      if (result?.id !== skill.id || result.approved !== decision || result.sha256 !== (skill.sha256 ?? null) || !Number.isFinite(Date.parse(result.approval_updated_at))) throw new Error("The approval response is incompatible. Refresh to confirm the saved choice.");
      await refresh();
      if (cache?.generation !== generation) return;
      setAnnouncement(`${skill.name} moved to ${approvalLabels[status]}.`);
      setSaving(false);
      // Enable Refresh before moving focus away from the row that just moved.
      requestAnimationFrame(() => refreshButton.current?.focus());
    } catch (failure) {
      if (cache?.generation !== generation) return;
      if (failure instanceof APIError && [401, 403].includes(failure.status)) void refreshUser().catch(() => {});
      setSaveError(failure instanceof Error ? failure.message : "Could not save the approval decision.");
    } finally { pendingSave.current = false; setSaving(false); }
  }
  function reviewCard(status: ApprovalStatus) {
    const list = { unapproved, monitoring, approved }[status];
    const label = `${approvalLabels[status]} skills`;
    return <ReviewCard tone={status === "unapproved" ? "critical" : status === "approved" ? "ok" : "info"}
      icon={status === "unapproved" ? CircleX : status === "approved" ? CircleCheck : Eye}
      title={approvalLabels[status]} label={label} count={pill(list, list.data?.total ?? 0)}
      stacked={status === "unapproved" ? "top" : status === "approved" ? "bottom" : undefined}>
      <CardState list={list} label={`${status} list`}>
        {list.data?.items.length ? <>
          <Table aria-label={label} className={reviewTable}>
            <TableHeader className={reviewTableHeader}><TableRow>
              <TableHead>Skill</TableHead><TableHead className="text-right">Devices</TableHead>
              {status !== "approved" && <TableHead aria-sort="descending"><span className="inline-flex items-center gap-1">Risk score<ArrowDown className="size-3.5" aria-hidden="true" /></span></TableHead>}
              {status === "unapproved" && <TableHead className="text-right">Notify users</TableHead>}
              {canEdit && <TableHead><span className="sr-only">Approval</span></TableHead>}
            </TableRow></TableHeader>
            <TableBody>{list.data.items.map(skill => <TableRow key={skill.id} data-skill={skill.id}>
              <TableCell className="w-full min-w-28 whitespace-normal"><SkillName skill={skill} onOpen={open} /></TableCell>
              <TableCell className="number text-right">{skill.devices}</TableCell>
              {status !== "approved" && <TableCell><SkillScore skill={skill} bar={status === "unapproved"} onOpen={open} /></TableCell>}
              {status === "unapproved" && <TableCell className="text-right"><EndpointAlerts applicationId={`skill:${skill.id}`} name={skill.name}
                recipients={signal => recipients(skill, signal)} scopeNote="Devices with this skill across the organization."
                notification={{ title: `Unapproved skill: ${skill.name}`.slice(0, 160), message: `${skill.name} is not approved by your organization. Stop using this skill and contact your IT or security team for guidance.` }} /></TableCell>}
              {canEdit && <TableCell className="w-px"><ApprovalControl skill={skill} disabled={saving || Boolean(list.error)} onSave={save} /></TableCell>}
            </TableRow>)}</TableBody>
          </Table>
          {list.data.next_cursor && <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-xs text-muted-foreground">
            <span>Showing the first {list.data.items.length.toLocaleString()} of {list.data.total.toLocaleString()}</span>
            <Button variant="ghost" size="xs" onClick={() => { reset(); setReview(status); }}>Show all in All skills</Button>
          </div>}
        </> : <EmptyState title={`No ${status} skills`} description={status === "approved" ? "Approved skills appear here after an organization review." : status === "unapproved" ? "New or changed skill content starts here until reviewed." : "Skills moved to monitoring appear here."} />}
      </CardState>
    </ReviewCard>;
  }

  return <div className="min-w-0 space-y-4">
    {enabled === false && <PageNotice title="Skill scanning is disabled">Installed skills and retained results remain visible. New assessments require the tenant scanner to be enabled.</PageNotice>}
    {error && <ErrorState message={`${error}${data ? " Showing previously loaded records." : ""}`} onRetry={inventory.reload} />}
    {saveError && <p role="alert" className="text-sm text-destructive">{saveError}</p>}
    <p role="status" className="sr-only">{announcement}</p>
    <section aria-labelledby={reviewId} className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-60 flex-1">
          <h2 id={reviewId} className="text-base font-semibold">Skill review</h2>
          <p data-slot="review-summary" className="mt-0.5 max-w-3xl text-sm text-muted-foreground">
            {count(summary?.attention)} of {count(summary?.installed)} skills need attention · {count(summary?.assessed)} fully assessed
            {coverage !== null && ` (${coverage}%)`} · {count(summary?.incomplete)} incomplete or outdated
            {" · "}{count(summary ? summary.pending - summary.incomplete : undefined)} awaiting assessment · {count(summary?.installations)} installations
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <SkillLlmControls onChanged={refresh} />
          <Button ref={refreshButton} variant="outline" size="responsive" onClick={refresh} disabled={inventory.loading || saving}><RefreshCw className="size-3.5" />Refresh</Button>
        </div>
      </div>
      <div className="grid min-w-0 grid-cols-1 gap-3 xl:grid-cols-[minmax(0,2fr)_minmax(33rem,3fr)]">
        {reviewCard("monitoring")}
        <div className="flex min-w-0 flex-col gap-3 xl:max-h-[calc(min(28rem,60dvh)+2.375rem)]">
          {reviewCard("unapproved")}
          {reviewCard("approved")}
        </div>
      </div>
      <div className="flex flex-wrap gap-x-6">
        <PageNotice title="How assessments and scores work" collapsible>
          <p>New or changed content starts Unapproved. Approval applies to an exact, fully collected bundle across the organization. Monitoring is a saved review choice. These choices do not change scanner findings or enforce execution restrictions.</p>
          <p>Counts cover all reported skills in this tenant. Identical, fully collected bundles share one row. Names alone do not establish identity.</p>
          <p>NVIDIA SkillSpector scores run from 0 to 100, with higher scores indicating more risk: Low 0–20, Medium 21–50, High 51–80, Critical 81–100. The bar beside a queued score shows its band. Needs attention means a high or critical finding, regardless of aggregate score.</p>
          <p>Fully assessed requires complete collection and a successful scan. Static results expire after 24 hours. Dashboard model results are reused while the bundle SHA-256 and scanner profile remain unchanged. Retained scores stay visible with a partial, stale, or previous assessment label and are included in score sorting. Not available means no score was reported by the backend. No high-risk findings is not a safety guarantee or approval. Open a skill to see coverage reasons, analysis mode, and scan time.</p>
          <p>Incomplete or outdated includes partial coverage, failed scans, and results due for a rescan. Awaiting assessment includes skills waiting for collection or upload, queued scans, and scans in progress.</p>
        </PageNotice>
        <PageNotice title={`Collection details${collectionWarnings > 0 ? ` · ${collectionWarnings} loaded ${collectionWarnings === 1 ? "location needs" : "locations need"} attention` : ""}`} collapsible>
          <p className="text-xs text-muted-foreground">Known skill locations only. Partial or failed collection can retain earlier records. Installation does not establish agent use or granted permissions.</p>
          {roots.error && <ErrorState title="Collection details unavailable" message={roots.error} onRetry={roots.reload} />}
          {roots.loading && !roots.items.length ? <LoadingState label="Loading locations…" /> : roots.items.length ? <TableLayout><Table className="min-w-[720px]"><TableHeader><TableRow>{["Device", "Location", "Status", "Last success"].map(label => <TableHead key={label}>{label}</TableHead>)}</TableRow></TableHeader><TableBody>{roots.items.map(root => <TableRow key={root.id}><TableCell>{root.hostname || root.sensor_id}</TableCell><TableCell className="max-w-80 whitespace-normal break-all font-mono text-sm font-normal">{root.root}</TableCell><TableCell><Status tone={root.status === "ok" ? "neutral" : "warning"}>{root.status}</Status>{root.message && <p className="max-w-80 whitespace-normal text-xs text-muted-foreground">{root.message}</p>}</TableCell><TableCell>{root.last_success_at ? relative(root.last_success_at) : "Not reported"}</TableCell></TableRow>)}</TableBody></Table></TableLayout> : !roots.error && <p className="text-sm">No scan locations reported</p>}
          {roots.nextCursor && <Button variant="outline" size="xs" disabled={roots.loadingMore} onClick={roots.loadMore}>Load more locations</Button>}
        </PageNotice>
      </div>
    </section>
    <PageSection title="All skills" titleAction={<span className="number text-xs text-muted-foreground">{data ? data.total.toLocaleString() : count(undefined)}</span>}>
      <div role="group" aria-label="Skill filters" className="mb-3 flex min-w-0 flex-wrap items-center gap-2">
        <Input type="search" size="responsive" aria-label="Search skills" placeholder="Search skill, path, or device" value={query} onChange={event => { setQuery(event.target.value); setCursors([""]); }} className="w-full sm:w-64" />
        <Select value={scope} onValueChange={value => { setScope(value); setCursors([""]); }}><SelectTrigger size="responsive" aria-label="Scope filter" className="w-full sm:w-40"><SelectValue /></SelectTrigger><SelectContent>{Object.entries(scopes).map(([value, label]) => <SelectItem key={value} value={value}>{label}</SelectItem>)}</SelectContent></Select>
        {(query || filter !== "all" || review !== "all" || scope !== "all") && <Button variant="ghost" size="responsive" onClick={reset}>Clear filters</Button>}
        <Select value={review} onValueChange={value => { setReview(value); setCursors([""]); }}><SelectTrigger size="responsive" aria-label="Approval filter" className="w-full sm:w-44"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All review decisions</SelectItem>{Object.entries(approvalLabels).map(([value, label]) => <SelectItem key={value} value={value}>{label}</SelectItem>)}</SelectContent></Select>
        <div role="group" aria-label="Assessment filter" className="flex flex-wrap gap-1 sm:ml-auto">
          {Object.entries(filters).map(([value, label]) => <Button key={value} variant={filter === value ? "secondary" : "ghost"} size="responsive" aria-pressed={filter === value}
            aria-label={`Show ${label.toLowerCase()}`} onClick={() => changeFilter(value)}>{value === "all" ? "All" : label}</Button>)}
        </div>
      </div>
      {!data && !error ? <LoadingState label="Loading skills…" /> : data?.items.length ? <TableLayout footer={<div className="flex flex-wrap items-center justify-between gap-2">
        <span>{(cursors.length - 1) * 50 + 1}–{(cursors.length - 1) * 50 + data.items.length} of {data.total.toLocaleString()} skills{inventory.loading ? " · Updating…" : ""}</span>
        <div className="flex items-center gap-2"><Button size="icon-xs" variant="ghost" aria-label="Previous page" disabled={cursors.length === 1 || inventory.loading} onClick={() => setCursors(cursors.slice(0, -1))}><ChevronLeft /></Button><span>Page {cursors.length}</span><Button size="icon-xs" variant="ghost" aria-label="Next page" disabled={!data.next_cursor || inventory.loading} onClick={() => setCursors([...cursors, data.next_cursor])}><ChevronRight /></Button></div>
      </div>}><Table className="min-w-[1080px]" aria-label="All skills">
        <TableHeader><TableRow><TableHead>Skill</TableHead><TableHead className="text-right">Bundle size</TableHead><TableHead>Bundle SHA-256</TableHead><TableHead>Approval</TableHead><TableHead>Assessment</TableHead><TableHead aria-sort={sort === "risk_desc" ? "descending" : "ascending"}><button type="button" className="flex items-center gap-1 rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" onClick={() => { setSort(sort === "risk_desc" ? "risk_asc" : "risk_desc"); setCursors([""]); }} aria-label={`Sort risk score ${sort === "risk_desc" ? "ascending" : "descending"}`}>Risk score{sort === "risk_desc" ? <ArrowDown className="size-3" /> : <ArrowUp className="size-3" />}</button></TableHead><TableHead className="text-right">Devices</TableHead><TableHead className="text-right">Installations</TableHead><TableHead>Last seen</TableHead><TableHead><span className="sr-only">Details</span></TableHead>{canEdit && <TableHead><span className="sr-only">Approval actions</span></TableHead>}</TableRow></TableHeader>
        <TableBody>{data.items.map(skill => <TableRow key={skill.id}>
          <TableCell className={cn("w-full whitespace-normal", "max-w-80")}><SkillName skill={skill} onOpen={open} /></TableCell>
          <TableCell className="number text-right" title={skill.size_bytes == null ? undefined : `${skill.size_bytes.toLocaleString()} bytes collected`}>
            {bundleSize(skill.size_bytes, skill.sha256)}
            {skill.bundle_complete === false && <p className="text-xs text-muted-foreground">Partial collection</p>}
          </TableCell>
          <TableCell>{skill.sha256 ? <button type="button" className="font-mono text-sm font-normal underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring"
            title={skill.sha256} aria-label={`View bundle SHA-256 for ${skill.name}`} onClick={event => open(skill, event.currentTarget, "files")}>{skill.sha256.slice(0, 8)}…</button>
            : <span className="text-muted-foreground">Not collected</span>}</TableCell>
          <TableCell>{approvalLabels[skill.approval_status]}</TableCell><TableCell><Assessment skill={skill} /></TableCell><TableCell>{skill.approval_status === "approved" ? <span className="text-muted-foreground">See details</span> : <SkillScore skill={skill} onOpen={open} />}</TableCell>
          <TableCell className="number text-right">{skill.devices}</TableCell><TableCell className="number text-right">{skill.installations}</TableCell><TableCell title={dateTime(skill.last_seen_at)}><span className="text-xs text-muted-foreground">{relative(skill.last_seen_at)}</span></TableCell>
          <TableCell className="w-px"><Button size="icon-xs" variant="ghost" aria-label={`Open ${skill.name}`} onClick={event => open(skill, event.currentTarget)}><ChevronRight /></Button></TableCell>
          {canEdit && <TableCell className="w-px"><ApprovalControl skill={skill} disabled={saving || Boolean(error)} onSave={save} /></TableCell>}
        </TableRow>)}</TableBody>
      </Table></TableLayout> : data && <EmptyState title={query || filter !== "all" || review !== "all" || scope !== "all" ? "No matching skills" : "No skills reported"} description="Check collection details for reporting coverage." action={cursors.length > 1 ? <Button variant="outline" onClick={() => setCursors([""])}>First page</Button> : undefined} />}
    </PageSection>
    <Dialog open={Boolean(selected)} onOpenChange={open => { if (!open) setSelected(null); }}>
      <DialogContent className="left-auto right-0 top-0 h-dvh max-h-dvh w-full max-w-full translate-x-0 translate-y-0 content-start overflow-y-auto rounded-none sm:max-w-2xl" onCloseAutoFocus={event => { event.preventDefault(); trigger.current?.focus(); }}>
        <DialogHeader><DialogTitle>{chosen?.name || "Skill details"}</DialogTitle><DialogDescription>Scanner findings and reported installations.</DialogDescription></DialogHeader>
        {details.error && <ErrorState message={details.error} onRetry={details.reload} />}
        {!details.loading && !details.error && !chosen && <p className="text-sm">Assessment unavailable. Close this panel and refresh the inventory.</p>}
        {details.loading ? <LoadingState label="Loading assessment…" /> : chosen && <>
          <section className="space-y-3 text-sm">
            <p><span className="font-semibold">Approval:</span> {approvalLabels[chosen.approval_status]}</p>
            <h3 className="font-semibold">Assessment</h3>
            <div className="flex flex-wrap items-center justify-between gap-3"><Assessment skill={{ scan_status: chosen.scan_status, needs_attention: report?.needs_attention || false }} />{report && <span className="flex items-center gap-2"><span className="text-xs text-muted-foreground">{chosen.scan_status === "complete" ? "Risk score" : "Retained score"}</span><RiskScore score={report.score} /></span>}</div>
            {chosen.error && <p role="alert">{chosen.error}</p>}
            {report && <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1"><dt className="text-muted-foreground">Analysis</dt><dd>{report.mode === "static" ? "Static analysis only" : "Static and AI analysis"}</dd><dt className="text-muted-foreground">Last result</dt><dd>{dateTime(chosen.completed_at)}</dd></dl>}
            {report && chosen.scan_status !== "complete" && <p className="text-sm text-muted-foreground">This retained result does not establish a complete, current assessment. Coverage is incomplete or a new scan is needed.</p>}
            {report?.finding_text_truncated && <p className="text-sm text-muted-foreground">Some finding details were shortened to fit report limits. Scanner coverage is reported separately.</p>}
            {report && <div className="space-y-2">
              <h3 className="font-semibold">Coverage details</h3>
              {chosen.installations.some(record => record.root_status !== "ok") && <p>Inventory collection is incomplete for one or more installations. See Installations for their status.</p>}
              {chosen.manifest?.complete === false && <p>Skill file collection is incomplete. See Files for skipped entries.</p>}
              {!report.coverage ? <p className="text-muted-foreground">Coverage details were not recorded for this result. A new scan with the updated scanner is required.</p>
                : <>
                  {report.coverage.reasons.length > 0 ? <ul className="list-disc space-y-2 pl-5">
                    {report.coverage.reasons.map((reason, index) => <li key={index} className="wrap-anywhere">
                      <p>{reason.message}</p>
                      {reason.file && <p className="font-mono text-sm font-normal">{reason.file}{reason.line ? `:${reason.line}` : ""}</p>}
                      {reason.target && <p className="font-mono text-sm font-normal">Target: {reason.target}</p>}
                      {(reason.code || reason.analyzer) && <p className="text-xs text-muted-foreground">{[reason.code, reason.analyzer].filter(Boolean).join(" · ")}</p>}
                    </li>)}
                  </ul> : <p className="text-muted-foreground">{report.complete ? "The scanner reported no coverage limitations." : "The scanner did not provide a coverage reason."}</p>}
                  {report.coverage.truncated && <p className="text-muted-foreground">Coverage details were shortened to fit report limits.</p>}
                </>}
            </div>}
            {!report && <p className="text-muted-foreground">No assessment is available.</p>}
          </section>
          <Tabs value={detailTab} onValueChange={setDetailTab} key={selected} className="min-w-0 border-t pt-3">
            <TabsList variant="line"><TabsTrigger value="findings">Findings{report ? ` · ${report.issues.length}` : ""}</TabsTrigger><TabsTrigger value="installations">Installations</TabsTrigger><TabsTrigger value="files">Files</TabsTrigger></TabsList>
            <TabsContent value="findings" className="min-w-0">
              <div className="divide-y">{report?.issues.map((issue, index) => <article key={`${issue.rule}-${index}`} className="min-w-0 space-y-2 py-3 text-sm [overflow-wrap:anywhere]">
                <div className="flex flex-wrap items-center gap-2"><Badge variant={severity[issue.severity]}>{issue.severity[0] + issue.severity.slice(1).toLowerCase()}</Badge><span className="font-mono text-sm font-normal">{issue.rule}</span></div>
                <h3 className="font-semibold">{issue.title}</h3><p className="whitespace-pre-wrap">{issue.description}</p>
                {issue.file && <p className="font-mono text-sm font-normal">{issue.file}{issue.line ? `:${issue.line}` : ""}</p>}
                {issue.remediation && <p className="whitespace-pre-wrap">{issue.remediation}</p>}
              </article>)}</div>
              {!report?.issues.length && <p className="py-3 text-sm text-muted-foreground">{report ? "No findings in the analyzed content." : "No scanner findings available."}</p>}
            </TabsContent>
            <TabsContent value="installations" className="min-w-0 divide-y">
              {chosen.installations.map(record => <dl key={record.id} className="grid min-w-0 grid-cols-1 gap-1 py-3 text-sm sm:grid-cols-[6rem_minmax(0,1fr)]">{Object.entries({ Device: record.hostname || record.sensor_id, Path: record.path, Scope: scopeLabel(record.scope), Version: record.version, Collection: record.root_status, "Last seen": dateTime(record.last_seen_at) }).map(([key, value]) => <div key={key} className="contents"><dt className="text-muted-foreground">{key}</dt><dd className={`min-w-0 [overflow-wrap:anywhere] ${key === "Path" ? "font-mono text-sm font-normal" : ""}`}>{value || "Not reported"}</dd></div>)}</dl>)}
              {chosen.installations_truncated && <p className="py-3 text-xs text-muted-foreground">Showing the first 200 installations.</p>}
            </TabsContent>
            <TabsContent value="files" className="min-w-0 space-y-3 pt-3 text-sm">
              <p>{chosen.manifest ? chosen.manifest.complete ? "Collection complete" : "Collection incomplete" : "Bundle not collected"}</p>
              <div><h3 className="mb-1 font-semibold">Bundle size</h3><p>{bundleSize(chosen.size_bytes, chosen.sha256)}{chosen.size_bytes != null && ` (${chosen.size_bytes.toLocaleString()} bytes)`}</p></div>
              {chosen.sha256 && <div><h3 className="mb-1 font-semibold">Bundle SHA-256</h3><p className="break-all font-mono text-sm font-normal">{chosen.sha256}</p></div>}
              {chosen.manifest && <p className="text-muted-foreground">Size covers collected file contents. SHA-256 identifies the manifest of file paths, sizes, and hashes.{!chosen.manifest.complete && " Skipped or unreadable files are excluded from the size; this hash does not identify the full folder."}</p>}
              {chosen.metadata?.description && <p>{chosen.metadata.description}</p>}
              {(chosen.metadata?.repository_url || chosen.metadata?.source_url) && <p className="break-all font-mono text-sm font-normal">{chosen.metadata.repository_url || chosen.metadata.source_url}</p>}
              <p>Declared tools: {chosen.metadata?.tools?.join(", ") || "Not reported"}</p>
              <ul className="divide-y">{chosen.manifest?.files.map(file => <li key={file.path} className="py-2"><p className="break-all font-mono text-sm font-normal">{file.path}</p><p className="mt-1 text-xs text-muted-foreground">{file.skip ? `Skipped: ${file.skip.replaceAll("_", " ")}` : `${file.size} bytes`}</p></li>)}</ul>
            </TabsContent>
          </Tabs>
          <Button variant="outline" onClick={() => setSelected(null)}>Close details</Button>
        </>}
      </DialogContent>
    </Dialog>
  </div>;
}
