"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { ArrowDown, Download, FileText, RefreshCw, Search, X } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { EmptyState, ErrorState, LoadingState, PageNotice } from "@/components/page-layout";
import { ReportFinding, ReportNarrative } from "@/components/session-investigation";
import { UserRiskPage } from "@/components/security-pages";
import { useTimeZone } from "@/components/time-zone-context";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { api, apiResponse, number, productLabel } from "@/lib/api";
import { chartTicks } from "@/lib/chart";
import { investigationHref, sessionHref, type InvestigationReport } from "@/lib/session";
import { useResource } from "@/lib/use-resource";

type Outcome = "review" | "tp" | "fp";
type Kind = "sessions" | "users";
type RiskCase = {
  id: string; kind: Kind; identity_kind: "account" | "os_user" | "mixed" | "unknown";
  reported_user: string; hostname: string; product: string; accounts?: string[]; outcome: Outcome;
  opened_at: string; closed_at: string | null; version: number; peak: number | null;
  session_count: number; device_count: number; report_count: number; title: string; summary: string;
};
type Day = { day: string; review: number; tp: number; fp: number };
type Activity = Pick<RiskCase, "id" | "identity_kind" | "reported_user" | "hostname" | "product" | "accounts" | "peak" | "session_count" | "device_count"> & {
  session_id: string; external_id: string; last_activity_at: string;
  activity_summary?: { state: "pending" | "ready" | "unavailable"; text: string | null; through: string | null };
};
type CasePage<T = RiskCase> = { items: T[]; total: number; offset: number; limit: number };
type ActivitySnapshot = { state: "pending" | "unavailable" | "current" | "stale"; since: string | null; until: string | null; refresh_interval_seconds: number; refresh_failed: boolean };
type Cases = { view?: "cases" | "activity"; selection_policy?: string; detection_threshold?: number | null; since: string; until: string; time_zone: string; groups: Record<Kind, CasePage<RiskCase | Activity>> | null; charts: Record<Kind, Day[]>; activity_snapshot?: ActivitySnapshot };
type CaseReport = { job_id: string; snapshot_id: string; session_id: string | null; attempt_id: string | null; state: string; report: InvestigationReport | null };
type ReviewContext = { schema_version: 1; scope: "displayed_page"; case_id: string; case_version: number; offset: number; report_count: number;
  reports: (Pick<CaseReport, "job_id" | "snapshot_id" | "attempt_id" | "state"> & { report_sha256: string | null })[] };
type Detail = { case: RiskCase; reports: CaseReport[]; offset: number; has_more: boolean; review_context?: ReviewContext };
const kinds: Kind[] = ["sessions", "users"];
const outcomes: Outcome[] = ["review", "tp", "fp"];
const labels = { review: "Under review", tp: "TP", fp: "FP" };
const fullLabels = { review: "Under review", tp: "True positive", fp: "False positive" };
const fills = { review: "var(--chart-1)", tp: "var(--chart-2)", fp: "var(--chart-3)" };
const dots = { review: "bg-status-warning", tp: "bg-status-critical", fp: "bg-status-neutral" };
const groupLabel = { sessions: "Sessions", users: "Users" };
const dayLabel = (day: string) => new Date(`${day}T12:00:00Z`).toLocaleDateString("en-US", { timeZone: "UTC", month: "short", day: "numeric" });
const identityLabel = (row: Pick<RiskCase, "identity_kind">) => row.identity_kind === "account" ? "Historical account grouping" : row.identity_kind === "os_user" ? "OS user on one device" : row.identity_kind === "mixed" ? "Inconsistent OS user data" : "OS user not reported";
function ReportedAccounts({ accounts }: { accounts?: string[] }) {
  return accounts?.length ? <p className="mt-1 break-words text-xs text-muted-foreground">Reported agent {accounts.length === 1 ? "account" : "accounts"}: {accounts.join(", ")}</p> : null;
}
function validCases(value: Cases, view: "cases" | "activity") {
  if (!value) return false;
  const snapshot = view === "activity" ? value.activity_snapshot : undefined;
  const pending = snapshot && ["pending", "unavailable"].includes(snapshot.state);
  if (snapshot && (!["pending", "unavailable", "current", "stale"].includes(snapshot.state) ||
    snapshot.refresh_interval_seconds !== 900 || typeof snapshot.refresh_failed !== "boolean" ||
    (pending ? snapshot.since !== null || snapshot.until !== null : typeof snapshot.since !== "string" || typeof snapshot.until !== "string"))) return false;
  return Boolean((view === "activity" ? value.view === view : !value.view || value.view === view) && typeof value.since === "string" && typeof value.until === "string" &&
    (pending ? value.groups === null : kinds.every((kind) =>
    value.groups && Array.isArray(value.groups[kind]?.items) && Number.isInteger(value.groups[kind].total) &&
    value.groups[kind].items.every((row) => typeof row.id === "string" &&
      (view === "cases" ? "outcome" in row && outcomes.includes(row.outcome) && Number.isInteger(row.version)
        : "session_id" in row && typeof row.session_id === "string" && typeof row.last_activity_at === "string") &&
      (row.peak === null || (Number.isFinite(row.peak) && row.peak >= 0 && row.peak <= 100))))) && kinds.every((kind) =>
    Array.isArray(value.charts?.[kind]) && value.charts[kind].length === 30 && value.charts[kind].every((day) =>
      /^\d{4}-\d{2}-\d{2}$/.test(day.day) && outcomes.every((outcome) => Number.isInteger(day[outcome]) && day[outcome] >= 0))));
}

function ScoreValue({ value, threshold }: { value: number; threshold: number | null }) {
  return <>{number(value)}<span className="text-xs font-normal text-muted-foreground"
    title={threshold === null ? "Detection threshold unavailable" : "Current configured high-risk action threshold"}
    aria-label={`Detection threshold ${threshold === null ? "unavailable" : number(threshold)}`}> / {threshold === null ? "N/A" : number(threshold)}</span></>;
}

function ActivityList({ kind, data, threshold, loading, turn }: { kind: Kind; data: CasePage<Activity>; threshold: number | null; loading: boolean; turn: (offset: number) => void }) {
  const id = useId();
  const { dateTime } = useTimeZone();
  return <section aria-labelledby={id} className="min-w-0"><Card className="@container">
    <div className="flex flex-wrap justify-between gap-2 px-4 py-3">
      <div><h2 id={id} className="text-base font-semibold">{groupLabel[kind]}</h2><p className="text-xs text-muted-foreground">{number(data.total)} matching {kind} · Highest observed score first</p></div>
      <span className="flex items-center gap-1 text-xs text-muted-foreground">Risk score / Detection threshold <ArrowDown aria-hidden className="size-4" /></span>
    </div>
    <ol className="px-4" aria-label={`Top ${kind} by observed risk`}>
      {data.items.map((row) => {
        const reached = kind === "sessions" && row.peak != null && threshold !== null && row.peak >= threshold;
        return <li key={row.id} className={`relative grid min-w-0 grid-cols-1 gap-3 border-t py-3 @min-[440px]:grid-cols-[minmax(0,1fr)_144px] ${reached ? "before:absolute before:-left-4 before:inset-y-3 before:w-0.5 before:bg-status-warning" : ""}`}>
        <div className="min-w-0">
          <h3 className="break-words text-sm font-semibold">{kind === "users" ? row.reported_user : `${productLabel(row.product)} session`}</h3>
          {kind === "sessions" && <p aria-label="Session activity summary" className="mt-1 break-words text-sm"
            title={row.activity_summary?.state === "ready" && row.activity_summary.through ? `AI summary of captured activity through ${dateTime(row.activity_summary.through)}. Based on a bounded sample of retained prompts and actions.` : undefined}>
            {row.activity_summary?.state === "ready" && typeof row.activity_summary.text === "string" && row.activity_summary.text
              ? <><span className="text-xs text-muted-foreground">AI summary: </span>{row.activity_summary.text}</>
              : <span className="text-xs text-muted-foreground">{row.activity_summary?.state === "pending" ? "Summarizing captured activity…" : "Summary unavailable"}</span>}
          </p>}
          <p className="mt-1 truncate text-xs text-muted-foreground" title={kind === "sessions" ? row.external_id : row.hostname}>
            {kind === "sessions" ? row.external_id : `${number(row.session_count)} sessions · ${number(row.device_count)} devices`}
          </p>
          <p className="mt-1 truncate text-xs text-muted-foreground" title={`${row.reported_user || identityLabel(row)} · ${row.hostname || "Unnamed device"}`}>
            {kind === "sessions" ? `${row.reported_user || identityLabel(row)} · ${row.hostname || "Unnamed device"}` : `${identityLabel(row)} · ${row.hostname || "Unnamed device"}`}
          </p>
          <ReportedAccounts accounts={row.accounts} />
          <p className="mt-1 text-xs text-muted-foreground">Last activity {dateTime(row.last_activity_at)}</p>
        </div>
        <div className="flex items-center justify-between gap-2 @min-[440px]:flex-col @min-[440px]:items-end">
          <div className="flex flex-col gap-1 @min-[440px]:items-end">
            <span className={`number whitespace-nowrap text-sm font-semibold ${reached ? "text-status-warning" : ""}`}>{row.peak == null ? "Not scored" : <ScoreValue value={row.peak} threshold={threshold} />}</span>
            {reached && <Badge variant="warning" title="At least one captured action reached the configured high-risk threshold. Opening a case requires separate investigation criteria.">Threshold reached</Badge>}
          </div>
          <Button asChild variant="ghost" size="responsive"><Link href={sessionHref(row.session_id)}>{kind === "sessions" ? "View session" : "Top session"}</Link></Button>
        </div>
      </li>; })}
    </ol>
    {!data.items.length && <EmptyState title={`No matching ${kind}`} description="No retained activity matches this search and time window." />}
    <div className="flex items-center justify-between gap-2 border-t px-4 py-3 text-xs text-muted-foreground">
      <span>{data.items.length ? `${data.offset + 1}–${data.offset + data.items.length}` : "0"} of {number(data.total)} {kind}</span>
      <div className="flex gap-2"><Button variant="ghost" size="responsive" aria-label={`Previous ${kind}`} disabled={!data.offset || loading} onClick={() => turn(Math.max(0, data.offset - data.limit))}>Previous</Button>
        <Button variant="ghost" size="responsive" aria-label={`Next ${kind}`} disabled={data.offset + data.items.length >= data.total || loading} onClick={() => turn(data.offset + data.limit)}>Next</Button></div>
    </div>
  </Card></section>;
}

function OutcomeControl({ row, saving, save }: { row: RiskCase; saving: boolean; save: (row: RiskCase, outcome: Outcome) => void }) {
  return <label className="flex min-h-10 w-36 shrink-0 items-center gap-1 rounded-md border border-input bg-card pl-2 sm:min-h-8">
    <span aria-hidden className={`size-2 shrink-0 rounded-full ${dots[row.outcome]}`} />
    <span className="sr-only">Outcome for {row.kind === "users" ? row.reported_user : row.title}</span>
    <NativeSelect aria-label={`Outcome for case ${row.id}`} value={row.outcome} disabled={saving}
      onChange={(event) => save(row, event.target.value as Outcome)}
      variant="inline" className="flex-1">
      {outcomes.map((outcome) => <option key={outcome} value={outcome}>{labels[outcome]}</option>)}
    </NativeSelect>
  </label>;
}

function CaseChart({ kind, days, maximum, selected, select }: { kind: Kind; days: Day[]; maximum: number; selected: string; select: (day: string) => void }) {
  const title = `${kind === "sessions" ? "Session" : "User"} cases by outcome`;
  const id = useId();
  const host = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(480);
  useEffect(() => {
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(240, entry.contentRect.width)));
    if (host.current) observer.observe(host.current);
    return () => observer.disconnect();
  }, []);
  const ticks = chartTicks(maximum, true);
  const max = ticks.at(-1)!;
  const totals = outcomes.map((outcome) => days.reduce((sum, day) => sum + day[outcome], 0));
  const left = 28, right = 8, top = 12, plotHeight = 156, slot = (width - left - right) / 30;
  return <section aria-labelledby={id} className="min-w-0"><Card>
    <div className="flex flex-wrap items-start justify-between gap-2 px-4 py-3">
      <div><h2 id={id} className="text-base font-semibold">{title}</h2><p className="text-xs text-muted-foreground">Daily openings · Current outcome · Today partial</p></div>
      <p className="number text-base font-semibold">{number(totals.reduce((a, b) => a + b, 0))}<span className="ml-1 text-xs font-normal text-muted-foreground">cases</span></p>
    </div>
    <div ref={host} className="mx-4 h-48 min-w-0">
      <svg width="100%" height="192" viewBox={`0 0 ${width} 192`} role="group" aria-label={`${title}. Select an opening day to filter cases.`}>
        {ticks.map((tick) => <g key={tick}><line x1={left} x2={width - right} y1={top + plotHeight * (1 - tick / max)} y2={top + plotHeight * (1 - tick / max)} stroke="var(--border)" />
          <text x={left - 8} y={top + plotHeight * (1 - tick / max) + 4} textAnchor="end" fill="var(--muted-foreground)" className="text-xs">{tick}</text></g>)}
        {days.map((day, i) => {
          const x = left + i * slot;
          const text = `${dayLabel(day.day)}: Under review ${day.review}, TP ${day.tp}, FP ${day.fp}`;
          let used = 0;
          return <g key={day.day} role="button" tabIndex={0} aria-label={text} aria-pressed={selected === day.day}
            onClick={() => select(day.day)} onKeyDown={(event) => { if (["Enter", " "].includes(event.key)) { event.preventDefault(); select(day.day); } }}
            className="cursor-pointer outline-offset-2 focus-visible:outline-2 focus-visible:outline-ring">
            <title>{text}</title><rect x={x} y={top} width={slot} height={plotHeight} fill={selected === day.day ? "var(--accent)" : "transparent"} />
            {outcomes.map((outcome) => { const height = day[outcome] / max * plotHeight; used += height;
              return <rect key={outcome} x={x + 1} y={top + plotHeight - used} width={Math.max(1, slot - 4)} height={height} fill={fills[outcome]} />;
            })}
            {(width < 400 ? [0, 14, 29] : [0, 7, 14, 21, 29]).includes(i) && <text x={i === 0 ? left : i === 29 ? width - right : x + slot / 2} y={188}
              textAnchor={i === 0 ? "start" : i === 29 ? "end" : "middle"} fill="var(--muted-foreground)" className="text-xs">{dayLabel(day.day)}</text>}
          </g>;
        })}
      </svg>
    </div>
    <ul aria-label={`${title} totals`} className="flex flex-wrap gap-x-4 gap-y-1 px-4 pb-3 text-xs text-muted-foreground">
      {outcomes.map((outcome, i) => <li key={outcome} className="flex items-center gap-1" title={fullLabels[outcome]}><span aria-hidden className="size-2 rounded-xs" style={{ background: fills[outcome] }} />{labels[outcome]} <strong className="number font-medium text-foreground">{number(totals[i])}</strong></li>)}
    </ul>
  </Card></section>;
}

function CaseList({ kind, data, threshold, saving, save, open, turn }: { kind: Kind; data: CasePage; threshold: number | null; saving: boolean; save: (row: RiskCase, outcome: Outcome) => void; open: (row: RiskCase, button: HTMLButtonElement) => void; turn: (offset: number) => void }) {
  const id = useId();
  const { dateTime, timeZone } = useTimeZone();
  return <section aria-labelledby={id} className="min-w-0"><Card className="@container">
    <div className="flex flex-wrap justify-between gap-2 px-4 py-3">
      <div><h2 id={id} className="text-base font-semibold">{groupLabel[kind]}</h2><p className="text-xs text-muted-foreground">{number(data.total)} matching cases · Highest score first</p></div>
      <span className="flex items-center gap-1 text-xs text-muted-foreground">Risk score / Detection threshold <ArrowDown aria-hidden className="size-4" /></span>
    </div>
    <ol className="px-4" aria-label={`${groupLabel[kind]} cases`}>
      {data.items.map((row) => <li key={row.id} data-case-id={row.id} className="grid min-w-0 grid-cols-1 gap-3 border-t py-3 @min-[440px]:grid-cols-[minmax(0,1fr)_144px]">
        <div className="min-w-0">
          <h3 className="line-clamp-2 break-words text-sm font-semibold" title={kind === "sessions" ? row.title : row.reported_user}>{kind === "sessions" ? row.title : row.reported_user}</h3>
          <p className={`mt-1 truncate ${kind === "users" ? "text-sm" : "text-xs text-muted-foreground"}`} title={kind === "sessions" ? `${row.reported_user || identityLabel(row)} · ${productLabel(row.product)} · ${row.hostname || "Unnamed device"}` : `${row.hostname || "Unnamed device"} · ${row.summary}`}>
            {kind === "sessions" ? `${row.reported_user || identityLabel(row)} · ${productLabel(row.product)} · ${row.hostname || "Unnamed device"}` : `${row.hostname || "Unnamed device"} · ${row.summary}`}
          </p>
          <p className="mt-1 text-xs text-muted-foreground" title={`Opened ${dateTime(row.opened_at)}`}>{identityLabel(row)} · {kind === "users" ? `${number(row.session_count)} sessions · ${number(row.device_count)} devices` : `Opened ${new Date(row.opened_at).toLocaleDateString("en-US", { timeZone, month: "short", day: "numeric" })}`}</p>
          <ReportedAccounts accounts={row.accounts} />
        </div>
        <div className="flex min-w-0 items-center justify-between gap-2 @min-[440px]:flex-col @min-[440px]:items-stretch">
          <div className="flex flex-1 items-center justify-between gap-2 @min-[440px]:flex-none">
            <p className="number whitespace-nowrap text-sm font-semibold">{row.peak == null ? <span className="text-xs font-normal text-muted-foreground">Unavailable</span> : <ScoreValue value={row.peak} threshold={threshold} />}</p>
            <Button variant="ghost" size="responsive" className="px-1 text-primary @min-[440px]:h-6" aria-label={`Report for case ${row.id}`} onClick={(event) => open(row, event.currentTarget)}><FileText />Report</Button>
          </div>
          <OutcomeControl row={row} saving={saving} save={save} />
        </div>
      </li>)}
    </ol>
    {!data.items.length && <EmptyState title="No matching cases" description="Change the filters or wait for new investigations. No cases does not establish safety." />}
    <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-xs text-muted-foreground">
      <span>{data.items.length ? `${number(data.offset + 1)}–${number(data.offset + data.items.length)}` : "0"} of {number(data.total)} cases</span>
      <div className="flex gap-1"><Button variant="ghost" size="responsive" className="px-1" disabled={saving || data.offset === 0} onClick={() => turn(Math.max(0, data.offset - data.limit))} aria-label={`Previous ${kind}`}>Previous</Button>
        <Button variant="ghost" size="responsive" className="px-1" disabled={saving || data.offset + data.items.length >= data.total} onClick={() => turn(data.offset + data.limit)} aria-label={`Next ${kind}`}>Next</Button></div>
    </div>
  </Card></section>;
}

function CaseReportPreview({ id, saving, save, revision, saveError }: { id: string; saving: boolean; save: (row: RiskCase, outcome: Outcome, context?: ReviewContext) => void; revision: number; saveError: string }) {
  const [offset, setOffset] = useState(0);
  const resource = useResource<Detail>(`risk-cases/${id}?offset=${offset}`);
  const [downloadError, setDownloadError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const { dateTime } = useTimeZone();
  const previousRevision = useRef(revision);
  useEffect(() => { if (previousRevision.current !== revision) { previousRevision.current = revision; void resource.reload(); } }, [revision, resource.reload]);
  const data = resource.data?.case?.id === id && resource.data.offset === offset && Array.isArray(resource.data.reports) ? resource.data : null;
  const readError = resource.error || (resource.updated && !data ? "The server did not return the requested case report." : "");
  async function download() {
    setDownloading(true); setDownloadError("");
    try {
      const response = await apiResponse(`risk-cases/${id}/download`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href = url; link.download = `case-${id}.html`; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (cause) { setDownloadError(cause instanceof Error ? cause.message : "Unable to download report."); }
    finally { setDownloading(false); }
  }
  return <>
    <div className="border-b px-4 py-3 pr-12"><DialogTitle>Detection report</DialogTitle><DialogDescription>Retained reports and analyst outcome for this case.</DialogDescription></div>
    <div className="min-h-0 space-y-4 overflow-y-auto px-4 py-4" data-testid="case-report-scroll">
      {readError && <ErrorState message={readError} onRetry={resource.reload} />}
      {saveError && <ErrorState title="Outcome was not saved" message={saveError} onRetry={resource.reload} />}
      {!data && !readError && <LoadingState label="Loading case report…" />}
      {data && <>
        <div className="space-y-1 text-sm"><h3 className="break-words text-base font-semibold">{data.case.kind === "users" ? data.case.reported_user : data.case.title}</h3>
          <p>{identityLabel(data.case)} · Opened {dateTime(data.case.opened_at)}</p><p>Highest action risk: {data.case.peak == null ? "Unavailable" : `${number(data.case.peak)} / 100`}</p>
          <p>{data.case.reported_user || identityLabel(data.case)} · {data.case.hostname || "Unnamed device"}</p>
          <ReportedAccounts accounts={data.case.accounts} />
          <p className="text-muted-foreground">{data.case.kind === "users" ? "This report collects the contributing session reports. It is not an additional model assessment. " : ""}Analyst outcomes are independent of model conclusions.</p>
          {data.review_context && <p className="text-xs text-muted-foreground">Saving an outcome records the report versions on this page. Other pages are not recorded as reviewed.</p>}
        </div>
        {data.reports.map((item) => {
          const selection = { investigation: item.job_id, attempt: item.attempt_id ?? undefined, snapshot: item.snapshot_id };
          return <details key={item.job_id} open={data.reports.length === 1} className="border-t pt-3">
            <summary className="cursor-pointer break-words py-1 text-sm font-medium">{item.report?.title || "Session investigation"}</summary>
            <Link href={investigationHref(item.job_id, selection)} className="my-2 inline-flex min-h-10 items-center text-sm text-primary underline sm:min-h-8">Open retained investigation</Link>
            {item.report ? <><ReportNarrative report={item.report} sessionId={item.session_id} selection={selection} />
              {item.report.gaps.length > 0 && <PageNotice title="Report coverage gaps"><ul className="list-disc pl-4">{item.report.gaps.map((gap) => <li key={gap}>{gap}</li>)}</ul></PageNotice>}
              <ul className="divide-y">{item.report.findings.map((finding, index) => <ReportFinding key={index} finding={finding} index={index} sessionId={item.session_id} selection={selection} />)}</ul>
            </> : <p className="text-sm text-muted-foreground">No completed report is available. Investigation state: {item.state}.</p>}
          </details>;
        })}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground"><span>{offset + 1}–{offset + data.reports.length} of {data.case.report_count} investigations</span>
          <div className="flex gap-2"><Button variant="ghost" size="responsive" disabled={offset === 0 || resource.loading} onClick={() => setOffset(Math.max(0, offset - 20))}>Previous reports</Button>
            <Button variant="ghost" size="responsive" disabled={!data.has_more || resource.loading} onClick={() => setOffset(offset + 20)}>Next reports</Button></div>
        </div>
      </>}
      {downloadError && <ErrorState message={downloadError} onRetry={download} />}
    </div>
    <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3">
      {data && <OutcomeControl row={data.case} saving={saving || resource.loading} save={(row, value) => save(row, value, data.review_context)} />}
      <Button variant="outline" size="responsive" disabled={!data || downloading} onClick={() => void download()}><Download />{downloading ? "Downloading…" : "Download HTML"}</Button>
    </div>
  </>;
}

export function RiskCasesPage() {
  const { user } = useDashboard();
  const { timeZone, label, dateTime } = useTimeZone();
  const searchParams = useSearchParams();
  const router = useRouter();
  const view = searchParams.get("view") === "cases" ? "cases" : "activity";
  const [outcome, setOutcome] = useState<Outcome | "all">("all");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [day, setDay] = useState("");
  const [offsets, setOffsets] = useState({ sessions: 0, users: 0 });
  const [selected, setSelected] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revision, setRevision] = useState(0);
  const [findings, setFindings] = useState(searchParams.get("view") === "findings");
  const reportButton = useRef<HTMLButtonElement | null>(null);
  useEffect(() => { const timer = setTimeout(() => { setQuery(search); setOffsets({ sessions: 0, users: 0 }); }, 250); return () => clearTimeout(timer); }, [search]);
  const params = new URLSearchParams({ view, outcome: view === "cases" ? outcome : "all", q: query, day: view === "cases" ? day : "", time_zone: timeZone, sessions_offset: String(offsets.sessions), users_offset: String(offsets.users) });
  const validate = useCallback((value: Cases) => validCases(value, view), [view]);
  const resource = useResource<Cases>(user ? `risk-cases?${params}` : null, view === "activity" ? 15000 : 0, false, { validate });
  const data = resource.data && validCases(resource.data, view) ? resource.data : null;
  const groups = data?.groups;
  const snapshot = view === "activity" ? data?.activity_snapshot : undefined;
  const threshold = data?.selection_policy === "risk_budget" && typeof data.detection_threshold === "number"
    && Number.isInteger(data.detection_threshold) && data.detection_threshold >= 1 && data.detection_threshold <= 100
    ? data.detection_threshold : null;
  const readError = resource.error || (resource.updated && !data ? `The server did not return complete ${view === "activity" ? "activity rankings" : "risk case data"}.` : "");
  const maximum = data ? Math.max(1, ...kinds.flatMap((kind) => data.charts[kind].map((bin) => bin.review + bin.tp + bin.fp))) : 1;
  function filter(value: Outcome | "all", opening = day) { setOutcome(value); setDay(opening); setOffsets({ sessions: 0, users: 0 }); }
  function changeView(value: "cases" | "activity") {
    const next = new URLSearchParams(searchParams); next.set("view", value);
    router.replace(`/user-risk?${next}`, { scroll: false });
    setDay(""); setOffsets({ sessions: 0, users: 0 });
  }
  async function save(row: RiskCase, value: Outcome, context?: ReviewContext) {
    setSaving(true); setError(""); setNotice("");
    try {
      await api(`risk-cases/${row.id}`, { method: "PATCH", body: JSON.stringify({ outcome: value, version: row.version, ...(context ? { review_context: context } : {}) }) });
      setNotice(`Case marked ${fullLabels[value]}.`); setRevision((n) => n + 1);
      await resource.reload();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to save the analyst outcome."); }
    finally { setSaving(false); }
  }
  return <div className="min-w-0 space-y-4 text-sm">
    <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-muted-foreground">Past 30 days · {label}{data ? ` · Through ${dateTime(data.until)}` : ""}</p>
      <Button variant="ghost" size="responsive" disabled={resource.loading || saving} onClick={() => { setRevision((n) => n + 1); void resource.reload(); }}><RefreshCw />Refresh {view === "cases" ? "cases" : "activity"}</Button></div>
    <div role="group" aria-label="Risk view" className="flex gap-1">{(["activity", "cases"] as const).map((value) =>
      <Button key={value} variant={view === value ? "secondary" : "ghost"} size="responsive" aria-pressed={view === value} onClick={() => changeView(value)}>{value === "activity" ? "Top activity" : "Cases"}</Button>)}</div>
    {readError && <ErrorState message={`${readError}${data ? " Showing the last successful response." : ""}`} onRetry={resource.reload} />}
    {!data && !readError && <LoadingState label={`Loading session and user ${view}…`} />}
    {error && <ErrorState title="Outcome was not saved" message={error} onRetry={() => { setRevision((n) => n + 1); void resource.reload(); }} />}
    {notice && <p role="status" className="text-sm">{notice}</p>}
    {data && <>
      <div className="grid min-w-0 gap-4 md:grid-cols-2" aria-label="Daily case outcomes">{kinds.map((kind) => <CaseChart key={kind} kind={kind} days={data.charts[kind]} maximum={maximum} selected={view === "cases" ? day : ""} select={(value) => { if (view !== "cases") changeView("cases"); filter(outcome, value === day ? "" : value); }} />)}</div>
      {view === "activity" && <p className="text-xs text-muted-foreground">Top activity includes sessions and reported users below the investigation threshold. Scores come from retained activity in the past 30 days; unscored activity appears last. Charts count investigation cases only. Use Cases for reports and verdicts.</p>}
      {threshold === null && <p className="text-xs text-muted-foreground">Detection threshold unavailable (N/A). {data.selection_policy === "legacy" ? "Legacy selection uses accumulated session risk, which cannot be compared with a highest action score." : "Refresh after detection settings become available."}</p>}
      {snapshot && <p className="text-xs text-muted-foreground">{snapshot.until ? `Activity updated ${dateTime(snapshot.until)} · ` : ""}Activity rankings update every 15 minutes. Refresh loads the latest saved rankings. Case outcomes stay current.</p>}
      {snapshot?.state === "pending" && <LoadingState label="Preparing activity rankings…" />}
      {snapshot?.state === "unavailable" && <PageNotice title="Activity rankings are unavailable"><p>The first update failed. It will retry automatically.</p></PageNotice>}
      {snapshot?.state === "stale" && <PageNotice title="Activity rankings are out of date"><p>{snapshot.refresh_failed ? "The latest update failed. " : "The next update is pending. "}Showing the last successful rankings.</p></PageNotice>}
      {groups && <>
      <div className="flex flex-wrap items-center justify-between gap-2">
        {view === "cases" && <div className="flex flex-wrap items-center gap-2"><div role="group" aria-label="Filter cases by outcome" className="flex flex-wrap gap-1">
          {(["all", ...outcomes] as const).map((value) => <Button key={value} variant={outcome === value ? "secondary" : "ghost"} size="responsive" className="px-2" aria-pressed={outcome === value} onClick={() => filter(value)}>{value === "all" ? "All outcomes" : labels[value]}</Button>)}
        </div>{day && <Button variant="secondary" size="responsive" onClick={() => filter(outcome, "")} aria-label="Clear opening date filter">{dayLabel(day)}<X /></Button>}</div>}
        <label className="relative w-full sm:w-64"><span className="sr-only">Search {view}</span><Search aria-hidden className="absolute top-3 left-2 size-4 text-muted-foreground sm:top-2" /><Input type="search" maxLength={200} value={search} onChange={(event) => setSearch(event.target.value)} placeholder={view === "cases" ? "Search summaries or users" : "Search sessions or users"} className="h-10 pl-8 sm:h-8" /></label>
      </div>
      <div className="grid min-w-0 items-start gap-4 md:grid-cols-2">{kinds.map((kind) => view === "activity" ?
        <ActivityList key={kind} kind={kind} data={groups[kind] as CasePage<Activity>} threshold={threshold} loading={resource.loading} turn={(offset) => setOffsets((current) => ({ ...current, [kind]: offset }))} /> :
        <CaseList key={kind} kind={kind} data={groups[kind] as CasePage} threshold={threshold} saving={saving || resource.loading} save={(row, value) => void save(row, value)}
          open={(row, button) => { reportButton.current = button; setSelected(row.id); }} turn={(offset) => setOffsets((current) => ({ ...current, [kind]: offset }))} />)}</div>
      </>}
    </>}
    <PageNotice title="About scores, outcomes, and daily counts" collapsible>
      <p>Top activity uses the highest measured action risk in the displayed time window, from 0 to 100. Case scores use retained investigation snapshots. A score measures severity, not the probability of a true positive. A high score can be a false positive after review.</p>
      <p>The detection threshold is the current high-risk action threshold from investigation settings, for both sessions and users. It is a comparison value, not the maximum score or the threshold at the time a case opened. Investigations also depend on action counts, verified user patterns, urgent-risk criteria, and execution budgets.</p>
      <p>Threshold reached highlights sessions with at least one measured action at or above the current threshold. The highlight does not mean that an investigation case has opened.</p>
      <p>Under review means no analyst verdict. TP confirms the flagged risk; FP means it was not supported after review. Marking TP or FP closes the case. Later investigations open a new case. Changing a session outcome does not classify its user case.</p>
      <p>Users are grouped by OS username on one device. The same username on another device is a separate user. Reported agent accounts are supporting information; missing accounts do not create identity conflicts. Conflicting or missing OS users stay unattributed session records.</p>
      <p>Cases cover investigated activity. New user cases collect investigations for one OS user on one device. Historical account groups retain their reports and analyst outcomes. Reported identity does not establish a person's intent.</p>
      <p>Charts count each case once on its opening day, with its current outcome. Today is partial. Filters affect the lists only. Older open cases remain in the lists. Session and user totals are separate units and must not be added together.</p>
    </PageNotice>
    <details open={findings} onToggle={(event) => setFindings(event.currentTarget.open)}>
      <summary className="w-fit cursor-pointer py-2 font-medium text-primary">Policy findings and user totals</summary>
      {findings && <UserRiskPage />}
    </details>
    <Dialog open={selected !== null} onOpenChange={(open) => { if (!open) setSelected(null); }}>
      <DialogContent className="flex max-h-[calc(100dvh-2rem)] flex-col gap-0 overflow-hidden p-0 sm:max-w-4xl" onCloseAutoFocus={(event) => { event.preventDefault(); reportButton.current?.focus(); }}>
        {selected && <CaseReportPreview key={selected} id={selected} saving={saving} save={(row, value, context) => void save(row, value, context)} revision={revision} saveError={error} />}
      </DialogContent>
    </Dialog>
  </div>;
}
