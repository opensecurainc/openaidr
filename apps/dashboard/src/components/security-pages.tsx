"use client";

import { hasRole } from "@/lib/roles";

import { displayText } from "@/lib/display";
import { useTimeZone } from "@/components/time-zone-context";
import { useEffect, useId, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { FindingSessionLink } from "@/components/session-links";
import { DetectionPipeline } from "@/components/detection-pipeline";
import { DetectionRankings } from "@/components/detection-rankings";
import { DetectionEligibilityList } from "@/components/detection-eligibility";
import { InvestigationReports } from "@/components/investigation-reports";
import { DetectionSettings } from "@/components/detection-settings";
import { findingSessionHref, isUuid, type FindingSessionReference } from "@/lib/session";
import {
  ChevronRight,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Users,
  ScrollText,
  ArrowLeft,
  ArrowRight,
  Link2,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import {
  CollectionFooter,
  EmptyState,
  ErrorState,
  LoadingState,
  PageNotice,
  PageSection,
  PageToolbar,
  TableLayout,
} from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/ui/code-block";
import { Status, type StatusTone } from "@/components/ui/status";
import { SEVERITY_ORDER, severityLabel, type Severity } from "@/components/ui/severity-mark";
import { SEVERITY_FILL } from "@/components/risk-charts";
import { userRiskFilters, validUserRisk, type UserRisk, type UserRiskSummary } from "@/lib/risk";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { api, eventSummary, number, type AgentEvent } from "@/lib/api";
import { EventContent } from "@/components/event-content";
import { collectionNotes } from "@/lib/event-content";
import { useResource, usePagedResource } from "@/lib/use-resource";
import { cn } from "@/lib/utils";
import {
  EventSourceBadge,
  ExportDetailDialog,
  OpenTelemetryRecordButton,
} from "@/components/telemetry-panels";

type Finding = FindingSessionReference & {
  id: string;
  title: string;
  summary: string;
  severity: string;
  status: string;
  rule_name: string;
  category: string;
  product: string;
  created_at: string;
  host: { hostname: string; user: string };
  account?: string;
  sensor_id?: string;
  event_ids: string[];
  assignee: { id: string; name: string } | null;
  resolution: string;
};
type FindingDetail = {
  finding: Finding;
  events: AgentEvent[];
  notes: {
    id: string;
    body: string;
    author: { name: string };
    created_at: string;
  }[];
  actions: { id: string; type: string; status: string; created_at: string }[];
};
type DetectionRule = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: string;
  findings_30d: number;
};
type Policy = {
  version: number;
  updated_at?: string;
  rules: {
    id: string;
    name: string;
    action: string;
    enabled?: boolean;
    reason?: string;
  }[];
};
type Audit = {
  id: string;
  at: string;
  actor: { id: string; name: string };
  action: string;
  target_type: string;
  target_id: string;
  details: Record<string, unknown>;
};

function Refresh({
  onClick,
  disabled,
}: {
  onClick: () => void;
  disabled: boolean;
}) {
  return (
    <Button variant="outline" size="sm" onClick={onClick} disabled={disabled}>
      <RefreshCw />
      Refresh
    </Button>
  );
}
function Filter({
  label,
  value,
  setValue,
  options,
  swatch,
  labels,
}: {
  label: string;
  value: string;
  setValue: (value: string) => void;
  options: string[];
  /** A color mark shown before each option, such as a severity swatch. */
  swatch?: (option: string) => React.ReactNode;
  labels?: Record<string, string>;
}) {
  return (
    <Select value={value} onValueChange={setValue}>
      <SelectTrigger aria-label={label} className="w-44 bg-background">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">All {label.toLowerCase()}</SelectItem>
        {options.map((option) => (
          <SelectItem key={option} value={option}>
            {swatch?.(option)}
            {labels?.[option] ?? option.replaceAll("_", " ")}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
const SEVERITY_TONES: Record<
  string,
  "critical" | "high" | "medium" | "low" | "informational"
> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "informational",
};
// Open findings need attention; triaged ones are being handled.
const FINDING_STATUS_TONES: Record<string, StatusTone> = {
  open: "warning",
  triaged: "info",
  resolved: "ok",
  false_positive: "neutral",
};
function Severity({ value }: { value: string }) {
  return (
    <Badge variant={SEVERITY_TONES[value] ?? "outline"} className="capitalize">
      {value}
    </Badge>
  );
}

export function DetectionQueuePage() {
  const { user } = useDashboard();
  const [range, setRange] = useState("30d");
  if (!user) return <LoadingState label="Checking access…" />;
  return <div className="space-y-4">
    <InvestigationReports />
    <PageNotice title="Detection coverage" collapsible>
      <p>Investigation reports classify activity as True Positive, False Positive, or True Positive Non-malicious. Investigations with insufficient evidence remain incomplete. Individual policy, rule, and legacy Guardrail findings are available on <Link href="/user-risk?view=findings" className="text-primary underline underline-offset-4">Risky Sessions/Users</Link>. Reports cover retained evidence and its stated gaps. An empty queue does not establish that activity is safe.</p>
    </PageNotice>
    <DetectionPipeline range={range} setRange={setRange} />
    <DetectionRankings />
    <DetectionEligibilityList range={range} />
  </div>;
}

type FindingSource = "all" | "incident" | "policy";
type FindingInvestigation = {
  username: string | null;
  account: string | null;
  sensorId: string | null;
  status: string;
  severity: string;
  selected: string | null;
  update: (changes: Record<string, string | null>) => void;
};

function userFindingsHref(row: Pick<UserRisk, "user" | "kind" | "sensor_id">, severity?: string, active = true) {
  const query = new URLSearchParams(userRiskFilters(row));
  if (severity) query.set("severity", severity);
  if (active) query.set("status", "active");
  return `/user-risk/findings?${query}`;
}

export function UserFindingsPage() {
  const { user } = useDashboard();
  const router = useRouter();
  const params = useSearchParams();
  const [copyNotice, setCopyNotice] = useState("");
  const username = params.get("username");
  const account = params.get("account");
  const sensorId = params.get("sensor_id");
  const severity = params.get("severity") || "all";
  const status = params.get("status") || "all";
  const source = params.get("source") || "all";
  const selected = params.get("finding");
  const invalid = !["all", ...SEVERITY_ORDER].includes(severity)
    || !["all", "active", "open", "triaged", "resolved", "false_positive"].includes(status)
    || !["all", "incident", "policy"].includes(source)
    || (selected !== null && !isUuid(selected))
    || (sensorId !== null && !isUuid(sensorId));
  if (!user) return <LoadingState label="Checking access…" />;
  const update = (changes: Record<string, string | null>) => {
    const query = new URLSearchParams(params.toString());
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) query.delete(key);
      else query.set(key, value);
    }
    setCopyNotice("");
    router.push(`/user-risk/findings${query.size ? `?${query}` : ""}`, { scroll: false });
  };
  return <div className="min-w-0 space-y-4 break-words">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <Button asChild variant="outline" size="sm"><Link href="/user-risk?view=findings"><ArrowLeft />Back to Risky Sessions/Users</Link></Button>
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted-foreground" role="status">{copyNotice}</p>
        <Button variant="outline" size="sm" onClick={async () => {
          try {
            await navigator.clipboard.writeText(window.location.href);
            setCopyNotice("View link copied.");
          } catch {
            setCopyNotice("Copy the URL from your address bar to share this view.");
          }
        }}><Link2 />Copy view link</Button>
      </div>
    </div>
    <PageNotice title="About these findings" collapsible>
      <p>This view searches all retained findings matching the filters, across incident reports and policy findings. Finding counts cover all retained findings; case counts use their displayed window. Counts can change as new findings arrive or their status changes. An OS username is a reported identity; the same name on different devices may represent different people.</p>
    </PageNotice>
    {invalid ? <ErrorState message="This link contains an invalid finding filter or finding ID." onRetry={() => router.replace("/user-risk/findings")} /> :
      <FindingQueue
        source={source as FindingSource}
        investigation={{ username, account, sensorId, severity, status, selected, update }}
      />}
  </div>;
}

function FindingQueue({ source, investigation }: { source: FindingSource; investigation?: FindingInvestigation }) {
  const { dateTime } = useTimeZone();
  const { user } = useDashboard();
  const [localStatus, setLocalStatus] = useState("all");
  const [localSeverity, setLocalSeverity] = useState("all");
  const [localSelected, setLocalSelected] = useState<string | null>(null);
  const findingTrigger = useRef<HTMLButtonElement | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const investigating = Boolean(investigation);
  useEffect(() => {
    if (!investigating) return;
    const desktop = window.matchMedia("(min-width: 640px)");
    const resize = () => setFiltersOpen(desktop.matches);
    resize();
    desktop.addEventListener("change", resize);
    return () => desktop.removeEventListener("change", resize);
  }, [investigating]);
  const status = investigation?.status ?? localStatus;
  const severity = investigation?.severity ?? localSeverity;
  const selected = investigation ? investigation.selected : localSelected;
  const setStatus = (value: string) => investigation
    ? investigation.update({ status: value === "all" ? null : value, finding: null }) : setLocalStatus(value);
  const setSeverity = (value: string) => investigation
    ? investigation.update({ severity: value === "all" ? null : value, finding: null }) : setLocalSeverity(value);
  const setSelected = (value: string | null) => investigation
    ? investigation.update({ finding: value }) : setLocalSelected(value);
  const [exportTarget, setExportTarget] = useState<{
    exportId: string;
    record: number;
  } | null>(null);
  const incidents = source === "incident";
  const query = new URLSearchParams({ limit: "50" });
  if (source !== "all") query.set("source", source);
  if (investigation?.username !== undefined && investigation.username !== null) query.set("username", investigation.username);
  if (investigation?.account !== undefined && investigation.account !== null) query.set("account", investigation.account);
  if (investigation?.sensorId) query.set("sensor_id", investigation.sensorId);
  if (status !== "all") query.set("status", status);
  if (severity !== "all") query.set("severity", severity);
  const list = usePagedResource<Finding>(user ? `findings?${query}` : null);
  const detail = useResource<FindingDetail>(
    selected ? `findings/${selected}` : null,
  );
  // The device filter is a sensor id; name it from a matching finding and keep
  // that name when a narrower filter empties the list.
  const sensorId = investigation?.sensorId ?? null;
  const reportedHost = sensorId ? list.items.find((f) => f.sensor_id === sensorId)?.host.hostname ?? "" : "";
  const [knownHost, setKnownHost] = useState<{ id: string; name: string } | null>(null);
  useEffect(() => {
    if (sensorId && reportedHost) setKnownHost({ id: sensorId, name: reportedHost });
  }, [sensorId, reportedHost]);
  const device = sensorId ? reportedHost || (knownHost?.id === sensorId ? knownHost.name : "") || "unnamed device" : "";
  if (!user) return <LoadingState label="Checking access…" />;
  const filters = <>
    <Filter label="Statuses" value={status} setValue={setStatus}
      options={[...(investigation ? ["active"] : []), "open", "triaged", "resolved", "false_positive"]}
      labels={{ active: "Open + Triaged" }} />
    <Filter label="Severities" value={severity} setValue={setSeverity}
      options={[...SEVERITY_ORDER]}
      swatch={(option) => <span aria-hidden="true" className="size-2.5 shrink-0 rounded-sm" style={{ background: SEVERITY_FILL[option as Severity] }} />} />
    {investigation && <>
      <Filter label="Sources" value={source}
        setValue={(value) => investigation.update({ source: value === "all" ? null : value, finding: null })}
        options={["incident", "policy"]} labels={{ incident: "Incident reports", policy: "Policy findings" }} />
      <form key={JSON.stringify(investigation.username)} className="flex min-w-0 flex-wrap items-center gap-2" onSubmit={(event) => {
        event.preventDefault();
        investigation.update({ username: String(new FormData(event.currentTarget).get("username") ?? ""), account: null, sensor_id: null, finding: null });
      }}>
        <Input name="username" aria-label="OS username" placeholder="Exact OS username" defaultValue={investigation.username ?? ""} className="w-44" />
        <Button variant="outline" size="sm" type="submit">Apply user</Button>
      </form>
    </>}
  </>;
  const chips = investigation ? [
    ...(investigation.account !== null ? [{ key: "account", label: "Account", value: investigation.account || "Not reported" }] : []),
    ...(investigation.username !== null ? [{ key: "username", label: "OS user", value: investigation.username || "Not reported" }] : []),
    ...(investigation.sensorId ? [{ key: "sensor_id", label: "Device", value: device }] : []),
    ...(severity !== "all" ? [{ key: "severity", label: "Severity", value: severityLabel(severity) }] : []),
    ...(status !== "all" ? [{ key: "status", label: "Status", value: status === "active" ? "Open + Triaged" : status.replaceAll("_", " ") }] : []),
    ...(source !== "all" ? [{ key: "source", label: "Source", value: incidents ? "Incident reports" : "Policy findings" }] : []),
  ] : [];
  const subject = !investigation ? ""
    : investigation.account ? ` for ${investigation.account}`
    : investigation.username !== null ? ` for ${investigation.username || "unattributed users"}${device ? ` on ${device}` : ""}`
    : device ? ` on ${device}` : "";
  const title = investigation
    ? `${severity === "all" ? "Findings" : `${severityLabel(severity)} findings`}${subject}`
    : incidents ? "Incident reports" : "Policy findings";
  return (
    <div className="space-y-4">
      <PageSection
        title={title}
        description={investigation ? "Matching findings, newest first. Select a title to inspect evidence and session context." : incidents
          ? "Session investigations, newest first. Open a report for context, cited evidence, impact, and recommended response."
          : "Individual policy, rule, and legacy Guardrail findings. Select a title to inspect recorded evidence and response history."}
      >
        <PageToolbar
          action={<Refresh onClick={list.reload} disabled={list.loading} />}
        >
          {investigation ? <details className="group min-w-0 flex-1" open={filtersOpen} onToggle={(event) => setFiltersOpen(event.currentTarget.open)}>
            <summary className="flex min-h-10 w-fit cursor-pointer list-none items-center gap-2 rounded-md border border-input px-3 text-sm font-medium focus-visible:outline-2 focus-visible:outline-ring sm:hidden">
              <SlidersHorizontal className="size-4" />Edit filters<ChevronRight className="size-4 group-open:rotate-90" />
            </summary>
            <div className="mt-3 flex flex-wrap items-center gap-2 sm:mt-0">{filters}</div>
          </details> : filters}
        </PageToolbar>
        {investigation && <div className="mb-4 flex flex-wrap items-center gap-2" aria-label="Active finding filters">
          {chips.map((chip) => <Button key={chip.key} variant="outline" size="sm" className="h-auto min-h-10 max-w-full whitespace-normal break-words text-left sm:min-h-8"
            aria-label={`Remove ${chip.label.toLowerCase()} filter`}
            onClick={() => investigation.update({ [chip.key]: null, finding: null })}>
            <span>{chip.label}: {chip.value}</span><X className="shrink-0" />
          </Button>)}
          {chips.length ? <Button variant="ghost" size="sm" onClick={() => investigation.update({ username: null, account: null, sensor_id: null, severity: null, status: null, source: null, finding: null })}>Clear all filters</Button> :
            <p className="text-sm text-muted-foreground">All users, severities, statuses, and sources.</p>}
        </div>}
        {list.error && (
          <ErrorState
            message={`${list.error}${list.updated ? " Showing stale data from the last successful response." : ""}`}
            onRetry={list.reload}
          />
        )}
        {list.loading && !list.updated ? (
          <LoadingState label={investigation ? "Loading findings…" : incidents ? "Loading incident reports…" : "Loading policy findings…"} />
        ) : list.items.length ? (
          <TableLayout
            footer={
              <CollectionFooter
                count={list.items.length}
                label={!investigation && incidents ? (list.items.length === 1 ? "incident report" : "incident reports") : "findings"}
                hasMore={Boolean(list.nextCursor)}
                busy={list.loadingMore}
                onLoadMore={list.loadMore}
              />
            }
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{!investigation && incidents ? "Incident" : "Finding"}</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Device / user</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.items.map((f) => (
                  <TableRow key={f.id}>
                    <TableCell className={incidents ? "min-w-64 max-w-sm whitespace-normal" : "max-w-sm whitespace-normal"}>
                      {!investigation && incidents && findingSessionHref(f) ? <Link
                        href={findingSessionHref(f)!}
                        className="font-medium underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >{f.title}</Link> : <button
                        onClick={(event) => { findingTrigger.current = event.currentTarget; setSelected(f.id); }}
                        className="text-left font-medium underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      >
                        {f.title}
                      </button>}
                      <p className="mt-1 text-xs text-muted-foreground">
                        {investigation ? (f.investigation_job_id ? "Incident report" : "Policy finding") : incidents ? "Session investigation" : displayText(f.rule_name || f.category)}
                      </p>
                      {(incidents || investigation) && <>
                        <p className="mt-1 line-clamp-2 whitespace-pre-wrap break-words text-xs text-muted-foreground">{f.summary}</p>
                        {!investigation && <button onClick={() => setSelected(f.id)} className="mt-2 text-xs font-medium underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring">Finding details</button>}
                      </>}
                    </TableCell>
                    <TableCell>
                      <Severity value={f.severity} />
                    </TableCell>
                    <TableCell>
                      <Status
                        tone={FINDING_STATUS_TONES[f.status] ?? "neutral"}
                        className="capitalize"
                      >
                        {f.status.replaceAll("_", " ")}
                      </Status>
                    </TableCell>
                    <TableCell>
                      {f.host.hostname || "Unknown device"}
                      <p className="text-xs text-muted-foreground">
                        {f.host.user || "User not reported"}
                      </p>
                    </TableCell>
                    <TableCell>{dateTime(f.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableLayout>
        ) : (
          !list.error && (
            <EmptyState
              icon={ShieldAlert}
              title={investigation ? "No findings match these filters" : incidents ? "No incident reports match" : "No policy findings match"}
              description={investigation ? "Remove a filter or select another user, severity, status, or source." : incidents
                ? "No published session incident findings match these filters. Investigations without a published finding remain available in session history."
                : "No individual policy, rule, or legacy Guardrail findings match these filters."}
            />
          )
        )}
      </PageSection>
      <Dialog
        open={Boolean(selected)}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent
          onCloseAutoFocus={investigation ? (event) => { event.preventDefault(); findingTrigger.current?.focus(); } : undefined}
          className={investigation
            ? "top-0 right-0 left-auto flex h-dvh max-h-dvh w-full max-w-full translate-x-0 translate-y-0 flex-col gap-0 overflow-hidden rounded-none p-0 sm:max-w-2xl"
            : "max-h-[85vh] grid-cols-[minmax(0,1fr)] overflow-y-auto sm:max-w-2xl"}>
          <DialogHeader className={investigation ? "shrink-0 border-b p-6 pr-12 text-left" : undefined}>
            <DialogTitle>Finding details</DialogTitle>
            <DialogDescription>
              Recorded metadata, evidence references, notes, and response
              history.
            </DialogDescription>
          </DialogHeader>
          <div className={investigation ? "min-h-0 flex-1 overflow-y-auto p-6" : undefined}>
          {detail.loading ? (
            <LoadingState label="Loading finding…" />
          ) : detail.error ? (
            <ErrorState message={detail.error} onRetry={detail.reload} />
          ) : (
            detail.data && (
              <div className="space-y-5 text-sm">
                <div>
                  <h3 className="font-semibold">{detail.data.finding.title}</h3>
                  <p className="mt-2 whitespace-pre-wrap break-words text-muted-foreground">
                    {detail.data.finding.summary || "No summary recorded."}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Severity value={detail.data.finding.severity} />
                  <Status
                    tone={
                      FINDING_STATUS_TONES[detail.data.finding.status] ??
                      "neutral"
                    }
                    className="capitalize"
                  >
                    {detail.data.finding.status.replaceAll("_", " ")}
                  </Status>
                  <Badge variant="outline">
                    {displayText(detail.data.finding.product || "Unknown product")}
                  </Badge>
                </div>
                <p>
                  OS username: {detail.data.finding.host.user || "Not reported"}
                </p>
                <p>
                  Logged in account: {detail.data.finding.account || "Not reported"}
                </p>
                <p>
                  Assigned to:{" "}
                  {detail.data.finding.assignee?.name || "Unassigned"}
                </p>
                {detail.data.finding.resolution && (
                  <p className="whitespace-pre-wrap break-words">
                    Resolution: {detail.data.finding.resolution}
                  </p>
                )}
                <FindingSessionLink finding={detail.data.finding} />
                <div>
                  <h3 className="mb-2 font-semibold">
                    Evidence ({number(detail.data.events.length)})
                  </h3>
                  {detail.data.events.length ? (
                    <ul className="divide-y border-y">
                      {detail.data.events.map((e) => {
                        const summary = eventSummary(e);
                        return (
                          <li key={e.id} className="py-3">
                            <div className="flex flex-wrap items-start justify-between gap-2">
                              <div className="min-w-0 flex-1">
                                <p className="flex flex-wrap items-center gap-2">
                                  <span>
                                    {e.event_name || e.kind} · {dateTime(e.time)}
                                  </span>
                                  <EventSourceBadge event={e} />
                                </p>
                                {summary && (
                                  <EventContent
                                    className="mt-1"
                                    text={summary}
                                    label="evidence"
                                    truncated={e.truncated === true}
                                    notes={collectionNotes(e)}
                                  />
                                )}
                                <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
                                  {e.id}
                                </p>
                              </div>
                              <OpenTelemetryRecordButton
                                event={e}
                                onOpen={setExportTarget}
                              />
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  ) : (
                    <p className="text-muted-foreground">
                      No evidence records available.
                    </p>
                  )}
                </div>
                <div>
                  <h3 className="mb-2 font-semibold">Notes</h3>
                  {detail.data.notes.length ? (
                    detail.data.notes.map((n) => (
                      <div key={n.id} className="border-b py-3 first:border-t">
                        <p className="text-xs text-muted-foreground">
                          {n.author.name || "Unknown author"} ·{" "}
                          {dateTime(n.created_at)}
                        </p>
                        <p className="mt-1 whitespace-pre-wrap break-words">
                          {n.body}
                        </p>
                      </div>
                    ))
                  ) : (
                    <p className="text-muted-foreground">No notes recorded.</p>
                  )}
                </div>
                <div>
                  <h3 className="mb-2 font-semibold">Response actions</h3>
                  {detail.data.actions.length ? (
                    detail.data.actions.map((a) => (
                      <p key={a.id} className="py-1">
                        {a.type.replaceAll("_", " ")} · {a.status} ·{" "}
                        {dateTime(a.created_at)}
                      </p>
                    ))
                  ) : (
                    <p className="text-muted-foreground">
                      No response actions recorded.
                    </p>
                  )}
                </div>
              </div>
            )
          )}
          </div>
        </DialogContent>
      </Dialog>
      <ExportDetailDialog
        exportId={exportTarget?.exportId ?? null}
        highlightRecord={exportTarget?.record ?? null}
        onClose={() => setExportTarget(null)}
      />
    </div>
  );
}

/** Names a row in link labels; OS-user rows add the device so same-named users stay distinct. */
function userRiskSubject(g: UserRisk) {
  const name = g.user || "unattributed users";
  if (g.kind !== "os_user") return name;
  return `${name} on ${g.hosts.join(", ") || "unnamed device"}`;
}

export function UserRiskPage() {
  const { user } = useDashboard();
  // `group=identity` opts in to account and per-device rows; an older backend
  // ignores it and returns per-username rows, which link by username alone.
  const list = useResource<UserRiskSummary>(user ? "user-risk?group=identity" : null, 0, false, { validate: validUserRisk });
  const data = validUserRisk(list.data) ? list.data : null;
  const error = list.error || (list.updated && !data ? "The server response did not include complete user totals." : "");
  const groups = data?.items ?? [];
  if (!user) return <LoadingState label="Checking access…" />;
  return (
    <div className="space-y-4">
      <PageNotice title="Findings grouped by reported identity" collapsible>
        <p>
          Findings are grouped by the account the agent reported being logged in
          to, which follows a person across devices. Findings without a reported
          account are grouped by the operating-system username on one device, so
          the same local name on different devices stays separate. Rows are
          ordered by their most severe open findings, then by how many they
          have, across all retained findings in this tenant. Open counts include
          open and triaged findings; all counts also include resolved and false
          positive findings. A reported identity is evidence from the device,
          not a verified identity or a risk score.
        </p>
      </PageNotice>
      <PageSection
        title="Findings by reported user"
        description={data ? `${number(data.total_findings)} retained findings across ${number(groups.length)} reported users.` : "Counts across all retained findings."}
        action={<Refresh onClick={list.reload} disabled={list.loading} />}
      >
        {error && (
          <ErrorState
            message={`${error}${data && list.updated ? " Showing stale data from the last successful response." : ""}`}
            onRetry={list.reload}
          />
        )}
        {list.loading && !data ? (
          <LoadingState />
        ) : groups.length ? (
          <TableLayout>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Reported identity</TableHead>
                  <TableHead>Grouped by</TableHead>
                  <TableHead>Open by severity</TableHead>
                  <TableHead className="text-right">Open / triaged</TableHead>
                  <TableHead className="text-right">All findings</TableHead>
                  <TableHead>Reported hostnames</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {groups.map((g) => {
                  const subject = userRiskSubject(g);
                  return (
                  <TableRow key={`${g.kind ?? ""}:${g.sensor_id ?? ""}:${g.user}`}>
                    <TableCell className="font-medium">
                      <Link href={userFindingsHref(g)} className="inline-flex min-h-10 items-center gap-2 text-primary underline underline-offset-4 focus-visible:outline-2 focus-visible:outline-ring sm:min-h-8">
                        {g.user || (g.kind === "account" ? "Unattributed (account not reported)" : "Unattributed (OS username not reported)")}<ArrowRight className="size-4 shrink-0" aria-hidden="true" />
                      </Link>
                    </TableCell>
                    <TableCell className="max-w-64 whitespace-normal break-words">
                      {g.kind === "account" ? "Agent account" : g.kind === "os_user" ? "OS user on one device" : "OS username"}
                      <p className="text-xs text-muted-foreground">
                        {g.kind === "account"
                          ? `OS users: ${g.users?.join(", ") || "not reported"}`
                          : g.kind === "os_user" ? "No account reported"
                          : `Accounts: ${g.accounts.join(", ") || "not reported"}`}
                      </p>
                    </TableCell>
                    <TableCell>
                      {g.openTotal ? (
                        <div className="flex flex-wrap gap-2">
                          {SEVERITY_ORDER.filter((severity) => g.open[severity] > 0).map((severity) => <Link
                            key={severity} href={userFindingsHref(g, severity)}
                            aria-label={`View ${number(g.open[severity])} ${severityLabel(severity).toLowerCase()} findings for ${subject}`}
                            className="inline-flex min-h-10 items-center gap-1.5 whitespace-nowrap rounded-md border border-input px-2 py-1 text-primary underline-offset-4 hover:bg-accent hover:underline focus-visible:outline-2 focus-visible:outline-ring sm:min-h-8">
                            <span aria-hidden="true" className="size-2 shrink-0 rounded-xs" style={{ background: SEVERITY_FILL[severity] }} />
                            <span className="number font-medium">{number(g.open[severity])}</span>{severityLabel(severity)}<ChevronRight className="size-3" aria-hidden="true" />
                          </Link>)}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">None open</span>
                      )}
                    </TableCell>
                    <TableCell className="number text-right">
                      <Link href={userFindingsHref(g)} className="inline-flex min-h-10 min-w-10 items-center justify-end text-primary underline underline-offset-4 focus-visible:outline-2 focus-visible:outline-ring sm:min-h-8 sm:min-w-8"
                        aria-label={`View all open and triaged findings for ${subject}`}>{number(g.openTotal)}</Link>
                    </TableCell>
                    <TableCell className="number text-right">
                      <Link href={userFindingsHref(g, undefined, false)} className="inline-flex min-h-10 min-w-10 items-center justify-end text-primary underline underline-offset-4 focus-visible:outline-2 focus-visible:outline-ring sm:min-h-8 sm:min-w-8"
                        aria-label={`View all findings for ${subject}`}>{number(g.total)}</Link>
                    </TableCell>
                    <TableCell
                      className="max-w-64 truncate text-muted-foreground"
                      title={g.hosts.join(", ")}
                    >
                      {g.hosts.join(", ") || "Not reported"}
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableLayout>
        ) : (
          !error && (
            <EmptyState
              icon={Users}
              title="No user findings to summarize"
              description="Findings appear when collected activity matches a detection rule."
            />
          )
        )}
      </PageSection>
      <FindingQueue source="policy" />
    </div>
  );
}

export function SecurityPosturePage() {
  const { dateTime } = useTimeZone();
  const { user } = useDashboard();
  const policy = useResource<Policy>(user ? "response/policy" : null);
  if (!user) return <LoadingState label="Checking access…" />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageNotice title="Configuration does not prove coverage" collapsible>
          <p>
            Configured prevention rules do not confirm that actions are protected.
            Prevention requires compatible agents with sensor hooks installed.
            Check service health on Server Health. No posture score is calculated.
          </p>
        </PageNotice>
        {hasRole(user, "it_admin") && <Button asChild variant="outline" size="sm">
          <Link href="/administration/server">Check Server Health</Link>
        </Button>}
      </div>
      <PageSection
        title="Prevention policy"
        description={
          policy.data
            ? `Policy version ${number(policy.data.version)} · ${number(policy.data.rules.length)} rules`
            : "Tenant policy evaluated by the backend for installed hooks."
        }
        action={<Refresh onClick={policy.reload} disabled={policy.loading} />}
      >
        {policy.error && (
          <ErrorState
            message={`${policy.error}${policy.data ? " Showing stale data from the last successful response." : ""}`}
            onRetry={policy.reload}
          />
        )}
        {policy.loading && !policy.data ? (
          <LoadingState />
        ) : (
          policy.data &&
          (policy.data.rules.length ? (
            <div className="divide-y">
              {policy.data.rules.map((r) => (
                <div key={r.id} className="py-3 first:pt-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-semibold">{displayText(r.name)}</h3>
                    <Badge className="capitalize">{r.action}</Badge>
                    <Status
                      tone={r.enabled ? "ok" : "neutral"}
                      className="ml-auto"
                    >
                      {r.enabled ? "Enabled" : "Disabled"}
                    </Status>
                  </div>
                  <p className="mt-1 max-w-prose text-sm text-muted-foreground">
                    {r.reason || "No reason recorded."}
                  </p>
                </div>
              ))}
              <p className="pt-3 text-xs text-muted-foreground">
                Last changed: {dateTime(policy.data.updated_at || null)}
              </p>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              <span className="font-medium text-foreground">No prevention rules configured.</span>{" "}
              No tenant policy rules were returned. This does not establish protection on enrolled devices.
            </p>
          ))
        )}
      </PageSection>
    </div>
  );
}

export function DetectionRulesPage() {
  const { user } = useDashboard();
  const rules = useResource<{ items: DetectionRule[] }>(
    user ? "detections/rules" : null,
  );
  const editable = hasRole(user, "security_analyst");
  const [saving, setSaving] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<{ id: string; message: string } | null>(null);

  async function toggleRule(rule: DetectionRule) {
    if (!editable || saving || rules.loading || rules.error) return;
    setSaving(rule.id);
    setSaveError(null);
    try {
      const updated = await api<DetectionRule>(`detections/rules/${encodeURIComponent(rule.id)}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      if (updated?.id !== rule.id || typeof updated.enabled !== "boolean") {
        throw new Error("The server did not confirm the rule setting.");
      }
      rules.setData((previous) => previous ? {
        items: previous.items.map((item) => item.id === updated.id ? updated : item),
      } : previous);
    } catch (cause) {
      setSaveError({
        id: rule.id,
        message: cause instanceof Error ? cause.message : "Unable to change this rule.",
      });
      await rules.reload();
    } finally {
      setSaving(null);
    }
  }

  if (!user) return <LoadingState label="Checking access…" />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageNotice title="Configuration does not prove coverage" collapsible>
          <p>
            Enabled rules do not confirm that detection is running: check the
            detect service on Server Health. Rules evaluate collected agent
            events and native telemetry tool results; sensors with tool-detail
            capture disabled contribute no detectable content.
          </p>
          <p>
            Disabling a rule stops new findings for this organization. Existing
            findings and prevention policies stay unchanged.
          </p>
        </PageNotice>
        {hasRole(user, "it_admin") && <Button asChild variant="outline" size="sm">
          <Link href="/administration/server">Check Server Health</Link>
        </Button>}
      </div>
      <PageSection
        title="Detection rules"
        description={
          rules.data
            ? `${number(rules.data.items.filter((r) => r.enabled).length)} enabled of ${number(rules.data.items.length)} configured rules. Finding counts cover the last 30 days.`
            : "Detection rules for collected agent events and native telemetry."
        }
        action={<Refresh onClick={rules.reload} disabled={rules.loading || saving !== null} />}
      >
        {!editable && (
          <p className="mb-2 text-sm text-muted-foreground">
            A Security Analyst can change these rules.
          </p>
        )}
        {rules.error && (
          <ErrorState
            message={`${rules.error}${rules.data ? " Showing stale data from the last successful response." : ""}`}
            onRetry={rules.reload}
          />
        )}
        {rules.loading && !rules.data ? (
          <LoadingState />
        ) : (
          rules.data &&
          (rules.data.items.length ? (
            <div className="divide-y">
              {rules.data.items.map((r) => (
                <div key={r.id} className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 py-1">
                  <details className="group min-w-0">
                    <summary className="grid min-h-10 cursor-pointer list-none grid-cols-[auto_minmax(0,1fr)] items-center gap-x-2 gap-y-1 rounded-md py-1 outline-none hover:bg-muted/40 focus-visible:ring-[3px] focus-visible:ring-ring focus-visible:ring-offset-2 sm:min-h-8 md:grid-cols-[auto_minmax(0,1fr)_6rem_8rem] [&::-webkit-details-marker]:hidden">
                      <ChevronRight aria-hidden="true" className="size-3.5 shrink-0 text-muted-foreground group-open:rotate-90" />
                      <h3 className="min-w-0 break-words text-sm font-semibold">{displayText(r.name)}</h3>
                      <div className="col-start-2 flex flex-wrap items-center gap-x-3 gap-y-1 md:contents">
                        <span className="flex"><Severity value={r.severity} /></span>
                        <span className="number text-xs text-muted-foreground md:text-right">
                          {number(r.findings_30d)} findings<span className="sr-only"> in 30 days</span>
                        </span>
                      </div>
                    </summary>
                    <p className="max-w-prose pb-2 pl-6 pt-1 text-sm text-muted-foreground">
                      {displayText(r.description)}
                    </p>
                  </details>
                  <div className="flex min-h-10 w-16 items-center justify-end sm:min-h-8 sm:w-32">
                    {editable ? (
                      <Button
                        type="button"
                        role="switch"
                        aria-label={`Enable ${displayText(r.name)}`}
                        aria-checked={r.enabled}
                        variant="ghost"
                        size="responsive"
                        disabled={saving !== null || rules.loading || !!rules.error}
                        onClick={() => void toggleRule(r)}
                      >
                        <span aria-hidden="true" className={`flex h-5 w-9 items-center rounded-full p-0.5 ${r.enabled ? "bg-primary" : "bg-muted-foreground"}`}>
                          <span className={`size-4 rounded-full bg-primary-foreground ${r.enabled ? "translate-x-4" : ""}`} />
                        </span>
                        <span className="hidden sm:inline">{r.enabled ? "Enabled" : "Disabled"}</span>
                      </Button>
                    ) : (
                      <Status tone={r.enabled ? "ok" : "neutral"}>
                        {r.enabled ? "Enabled" : "Disabled"}
                      </Status>
                    )}
                  </div>
                  <p aria-live="polite" className="col-span-2 text-xs text-muted-foreground">
                    {saving === r.id ? "Saving…" : ""}
                  </p>
                  {saveError?.id === r.id && (
                    <p role="alert" className="col-span-2 mt-1 text-sm text-destructive">
                      {saveError.message}
                    </p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={ShieldCheck}
              title="No rules returned"
              description="The server returned no configured detection rules."
            />
          ))
        )}
      </PageSection>
      <DetectionSettings />
    </div>
  );
}

export function AuditLogsPage() {
  const { dateTime } = useTimeZone();
  const { user, authLoading } = useDashboard();
  const categoryName = useId();
  const [category, setCategory] = useState("actions");
  const categories = [
    ["actions", "Application actions"],
    ["page_views", "Page visits"],
    ["all", "All activity"],
  ];
  const allowed = hasRole(user, "it_admin");
  const list = usePagedResource<Audit>(allowed ? `audit?limit=50&category=${category}` : null);
  if (authLoading) return <LoadingState label="Checking access…" />;
  if (!allowed)
    return (
      <PageNotice title="Administrator access required">
        Audit logs are available to tenant admins and owners. Ask a tenant owner
        if you need access.
      </PageNotice>
    );
  return (
    <PageSection
      title="Tenant audit trail"
      description="Recorded application actions and page visits, newest first. Page visits are browser reports, not proof that content was read."
      action={<Refresh onClick={list.reload} disabled={list.loading} />}
    >
      <PageToolbar>
        <fieldset
          aria-label="Audit category"
          className="relative isolate grid h-10 w-full min-w-0 grid-cols-3 text-xs font-medium sm:h-8 sm:w-[28rem] sm:text-sm"
        >
          <legend className="sr-only">Audit category</legend>
          <span aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10 rounded-md border border-input bg-card">
            <span
              className="absolute inset-y-[3px] left-[3px] w-[calc((100%-6px)/3)] rounded-sm bg-primary transition-transform motion-reduce:transition-none"
              style={{ transform: `translateX(${categories.findIndex(([value]) => value === category) * 100}%)` }}
            />
          </span>
          {categories.map(([value, label]) => (
            <label
              key={value}
              className={cn(
                "relative flex cursor-pointer items-center justify-center rounded-md px-1 text-center select-none has-focus-visible:outline-3 has-focus-visible:outline-offset-2 has-focus-visible:outline-ring",
                category === value ? "text-primary-foreground" : "text-muted-foreground hover:text-foreground",
              )}
            >
              <input
                className="absolute inset-0 size-full cursor-pointer opacity-0"
                type="radio"
                name={categoryName}
                value={value}
                checked={category === value}
                onChange={() => setCategory(value)}
              />
              {label}
            </label>
          ))}
        </fieldset>
      </PageToolbar>
      {list.error && (
        <ErrorState
          message={`${list.error}${list.updated ? " Showing stale data from the last successful response." : ""}`}
          onRetry={list.reload}
        />
      )}
      {list.loading && !list.updated ? (
        <LoadingState label="Loading audit records…" />
      ) : list.items.length ? (
        <TableLayout
          footer={
            <CollectionFooter
              count={list.items.length}
              label="records"
              hasMore={Boolean(list.nextCursor)}
              busy={list.loadingMore}
              onLoadMore={list.loadMore}
            />
          }
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.items.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>{dateTime(a.at)}</TableCell>
                  <TableCell>
                    <p>{a.actor.name || a.actor.id || "Not recorded"}</p>
                    {a.actor.name && a.actor.id && (
                      <p
                        className="max-w-48 truncate text-xs text-muted-foreground"
                        title={a.actor.id}
                      >
                        {a.actor.id}
                      </p>
                    )}
                  </TableCell>
                  <TableCell>{a.action === "dashboard.page.view" ? "Page visit" : a.action}</TableCell>
                  <TableCell>
                    <p>{a.action === "dashboard.page.view" && typeof a.details?.page === "string"
                      ? displayText(a.details.page) : a.target_type || "Not recorded"}</p>
                    <p className="max-w-52 break-all whitespace-normal font-mono text-xs text-muted-foreground">
                      {a.target_id}
                    </p>
                  </TableCell>
                  <TableCell>
                    {Object.keys(a.details || {}).length ? (
                      <details>
                        <summary className="cursor-pointer text-xs font-medium">
                          View details
                        </summary>
                        <CodeBlock className="mt-2 max-h-64 max-w-sm">
                          {JSON.stringify(a.details, null, 2)}
                        </CodeBlock>
                      </details>
                    ) : (
                      <span className="text-muted-foreground">None</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableLayout>
      ) : (
        !list.error && (
          <EmptyState
            icon={ScrollText}
            title="No audit records yet"
            description="No recorded activity matches this category."
          />
        )
      )}
    </PageSection>
  );
}
