"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { displayModel, displayText } from "@/lib/display";
import { type Gateway, type GatewayRequest, type GatewayRequestDetail, gatewayDecision, gatewayMetric, gatewayOutcome } from "@/lib/gateways";
import { usePagedResource, useResource } from "@/lib/use-resource";
import { useTimeZone } from "@/components/time-zone-context";
import { CollectionFooter, EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { CodeBlock, InlineCode } from "@/components/ui/code-block";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Status } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

function Decision({ value, evaluated }: { value: string | null; evaluated?: boolean }) {
  return <Status tone={value === "deny" ? "critical" : value === "allow" ? "info" : "neutral"}>{value ? gatewayDecision(value) : evaluated ? "Not evaluated" : "Unavailable"}</Status>;
}

function RequestOutcome({ value }: { value: GatewayRequest["outcome"] }) {
  return <Status tone={value === "blocked" ? "critical" : value === "fail_open" ? "warning" : value === "forwarded" ? "info" : "neutral"}>{gatewayOutcome(value)}</Status>;
}

type Filters = { gateway_id: string; node_id: string; route_id: string; provider: string; model: string; consumer_id: string; mode: string; status: string; outcome: string; since: string; until: string };
function initialFilters(gatewayId = ""): Filters { return { gateway_id: gatewayId, node_id: "", route_id: "", provider: "", model: "", consumer_id: "", mode: "", status: "", outcome: "", since: "", until: "" }; }
function requestPath(filters: Filters) {
  const query = new URLSearchParams({ limit: "50" });
  Object.entries(filters).forEach(([key, value]) => {
    if (!value.trim()) return;
    query.set(key, key === "since" || key === "until" ? new Date(value).toISOString() : value.trim());
  });
  return `gateways/requests?${query}`;
}

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: { value: string; label: string }[]; onChange: (value: string) => void }) {
  return <div className="min-w-0 space-y-1"><Label>{label}</Label><Select value={value || "all"} onValueChange={(value) => onChange(value === "all" ? "" : value)}><SelectTrigger aria-label={label} className="w-full min-w-0"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All</SelectItem>{options.map((option) => <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>)}</SelectContent></Select></div>;
}

export function GatewayRequests({ gatewayId = "", live = false, timeWindow }: { gatewayId?: string; live?: boolean; timeWindow?: { since: string; until: string } }) {
  const { dateTime } = useTimeZone();
  const [draft, setDraft] = useState(() => initialFilters(gatewayId));
  const [applied, setApplied] = useState(() => initialFilters(gatewayId));
  const [filterError, setFilterError] = useState("");
  const instances = useResource<{ items: Gateway[]; next_cursor: string }>("gateways?limit=100");
  function withWindow(filters: Filters): Filters {
    return { ...filters, since: filters.since || timeWindow?.since || "", until: filters.until || timeWindow?.until || "" };
  }
  const result = usePagedResource<GatewayRequest>(requestPath(withWindow(applied)));
  const reload = result.reload;
  useEffect(() => {
    if (!live) return;
    const timer = setInterval(() => { if (!document.hidden) reload(); }, 30_000);
    return () => clearInterval(timer);
  }, [live, reload]);
  function set(key: keyof Filters, value: string) { setDraft({ ...draft, [key]: value }); }
  function apply(event: React.FormEvent) {
    event.preventDefault();
    const window = withWindow(draft);
    if (window.since && window.until && new Date(window.since) >= new Date(window.until)) { setFilterError("Start time must be before end time."); return; }
    setFilterError(""); setApplied({ ...draft });
  }
  const gatewayOptions = instances.data?.items.map((gateway) => ({ value: gateway.id, label: gateway.name })) ?? [];
  if (draft.gateway_id && !gatewayOptions.some((option) => option.value === draft.gateway_id)) gatewayOptions.push({ value: draft.gateway_id, label: draft.gateway_id });
  return <div className="space-y-4">
    <PageNotice title="Gateway model requests"><p>Evaluated decisions, returned decisions, and reported outcomes describe different stages. An absent outcome is unconfirmed. Provider and model labels are reported or requested identities; they do not verify actual upstream routing. Gateway requests do not prove local tool execution.</p></PageNotice>
    <PageSection title="Gateway request ledger" description={timeWindow ? "Uses the history time range unless time filters override it. Filters below apply only to this ledger." : live ? "Refreshes every 30 seconds. The default time window is the past 24 hours." : "The default time window is the past 24 hours. Apply a start and end time to inspect older retained requests."} action={<Button variant="outline" size="sm" onClick={result.reload} disabled={result.loading}>Refresh requests</Button>}>
      <form onSubmit={apply} className="mb-4 space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4"><FilterSelect label="Gateway" value={draft.gateway_id} options={gatewayOptions} onChange={(value) => set("gateway_id", value)} /><FilterSelect label="Mode" value={draft.mode} options={[{ value: "shadow", label: "Shadow" }, { value: "enforce", label: "Enforce" }]} onChange={(value) => set("mode", value)} /><FilterSelect label="Evaluation" value={draft.status} options={[{ value: "pending", label: "Pending" }, { value: "evaluated", label: "Evaluated" }, { value: "unavailable", label: "Unavailable" }]} onChange={(value) => set("status", value)} /><FilterSelect label="Outcome" value={draft.outcome} options={[{ value: "blocked", label: "Blocked" }, { value: "forwarded", label: "Forwarded" }, { value: "fail_open", label: "Fail open" }, { value: "unconfirmed", label: "Unconfirmed" }]} onChange={(value) => set("outcome", value)} /></div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">{([{ key: "model", label: "Requested model" }, { key: "provider", label: "Reported provider" }, { key: "route_id", label: "Route ID" }, { key: "consumer_id", label: "Caller / consumer ID" }] as const).map(({ key, label }) => <div key={key} className="space-y-1"><Label htmlFor={`gateway-filter-${key}`}>{label}</Label><Input id={`gateway-filter-${key}`} value={draft[key]} onChange={(event) => set(key, event.target.value)} placeholder="Exact value" /></div>)}</div>
        <details className="text-sm"><summary className="w-fit cursor-pointer text-muted-foreground">Time and node filters</summary><div className="mt-3 grid gap-3 sm:grid-cols-3"><div className="space-y-1"><Label htmlFor="gateway-filter-node">Node ID</Label><Input id="gateway-filter-node" value={draft.node_id} onChange={(event) => set("node_id", event.target.value)} /></div>{(["since", "until"] as const).map((key) => <div className="min-w-0 space-y-1" key={key}><Label htmlFor={`gateway-filter-${key}`}>{key === "since" ? "Start time (local)" : "End time (local)"}</Label><Input id={`gateway-filter-${key}`} type="datetime-local" value={draft[key]} onChange={(event) => set(key, event.target.value)} /></div>)}</div></details>
        {instances.error && <p className="text-xs text-muted-foreground">Instance choices could not be loaded. Other request filters remain available.</p>}{filterError && <p role="alert" className="text-sm text-status-critical">{filterError}</p>}
        <div className="flex flex-wrap items-center gap-2"><Button type="submit" size="sm">Apply filters</Button><Button type="button" variant="outline" size="sm" onClick={() => { const empty = initialFilters(); setDraft(empty); setApplied(empty); setFilterError(""); }}>Clear filters</Button>{result.updated && <span className="text-xs text-muted-foreground">Updated {dateTime(result.updated.toISOString())}</span>}</div>
      </form>
      {result.error && <ErrorState message={result.error} onRetry={result.reload} />}
      {result.loading && !result.items.length ? <LoadingState /> : !result.items.length && !result.error ? <EmptyState title="No matching gateway requests" description="Requests appear when a connected plugin reports model activity. No requests does not mean the gateway is unhealthy." /> : result.items.length > 0 && <TableLayout footer={<CollectionFooter count={result.items.length} hasMore={Boolean(result.nextCursor)} busy={result.loadingMore} onLoadMore={result.loadMore} label="requests" />}><Table><TableHeader><TableRow><TableHead>Request</TableHead><TableHead>Model / provider</TableHead><TableHead>Route / caller</TableHead><TableHead>Evaluated</TableHead><TableHead>Returned</TableHead><TableHead>Reported outcome</TableHead><TableHead>Latency</TableHead></TableRow></TableHeader><TableBody>{result.items.map((request) => <TableRow key={request.id}>
        <TableCell className="font-medium"><Link className="text-primary hover:underline" href={`/gateways/requests/${encodeURIComponent(request.id)}`}>{request.gateway_name}</Link><p className="mt-1 text-xs text-muted-foreground">{dateTime(request.created_at)}</p><p className="text-xs text-muted-foreground">{request.mode === "shadow" ? "Shadow" : request.mode === "enforce" ? "Enforce" : "Mode unavailable"}</p></TableCell>
        <TableCell><span>{request.model ? displayModel(request.model) : "Model not reported"}</span><p className="text-xs text-muted-foreground">{request.provider ? displayText(request.provider) : "Provider not reported"}</p></TableCell><TableCell><span>{request.route_id || "Route not reported"}</span><p className="text-xs text-muted-foreground">{request.consumer_id || "Caller unknown"}</p></TableCell>
        <TableCell><Decision value={request.evaluated_decision} evaluated={request.status !== "evaluated"} />{request.status !== "evaluated" && <p className="text-xs text-muted-foreground">{request.status === "pending" ? "Pending" : "Evaluation unavailable"}</p>}{request.mode === "shadow" && request.evaluated_decision === "deny" && <p className="text-xs text-muted-foreground">Would deny</p>}</TableCell><TableCell><Decision value={request.returned_decision} /></TableCell><TableCell><RequestOutcome value={request.outcome} /></TableCell><TableCell>{gatewayMetric(request.latency_ms, " ms")}<p className="text-xs text-muted-foreground">Policy {gatewayMetric(request.policy_latency_ms, " ms")}</p></TableCell>
      </TableRow>)}</TableBody></Table></TableLayout>}
    </PageSection>
  </div>;
}

export function GatewayRequestView({ id }: { id: string }) {
  const { dateTime } = useTimeZone();
  const result = useResource<GatewayRequestDetail>(`gateways/requests/${encodeURIComponent(id)}`);
  const request = result.data;
  return <div className="space-y-4"><Button asChild variant="outline" size="sm"><Link href="/guardrail/history?source=gateways">All gateway requests</Link></Button>{result.error && <ErrorState message={result.error} onRetry={() => void result.reload()} />}{!request ? !result.error && <LoadingState /> : <>
    <PageSection title="Request decisions" description="Evaluated and returned decisions are separate from the plugin's reported outcome." action={<Button variant="outline" size="sm" onClick={() => void result.reload()} disabled={result.loading}>Refresh</Button>}>
      <dl className="grid gap-4 sm:grid-cols-4"><div><dt className="text-xs text-muted-foreground">Mode</dt><dd className="mt-1 text-sm">{request.mode === "shadow" ? "Shadow" : request.mode === "enforce" ? "Enforce" : "Unavailable"}</dd></div><div><dt className="text-xs text-muted-foreground">Evaluated decision</dt><dd className="mt-1"><Decision value={request.evaluated_decision} evaluated={request.status !== "evaluated"} />{request.mode === "shadow" && request.evaluated_decision === "deny" && <p className="text-xs text-muted-foreground">Would deny in Shadow</p>}</dd></div><div><dt className="text-xs text-muted-foreground">Returned decision</dt><dd className="mt-1"><Decision value={request.returned_decision} /></dd></div><div><dt className="text-xs text-muted-foreground">Reported outcome</dt><dd className="mt-1"><RequestOutcome value={request.outcome} /></dd></div></dl>
      <p className="mt-4 text-sm text-muted-foreground">{request.outcome === "fail_open" ? "The policy path failed and the plugin allowed traffic. Provider completion is not confirmed." : !request.outcome || request.outcome === "unconfirmed" ? "No confirmed enforcement or dispatch outcome is available. A returned decision alone does not prove it was applied." : request.outcome === "forwarded" ? "The plugin reported forwarding the request. This does not establish successful model completion." : "The plugin reported blocking the request."}</p>
      {request.reason && <div className="mt-4"><p className="text-xs text-muted-foreground">Decision reason</p><p className="mt-1 whitespace-pre-wrap break-words text-sm">{request.reason}</p></div>}{request.failure_reason && <div className="mt-4"><p className="text-xs text-muted-foreground">Failure reason</p><p className="mt-1 whitespace-pre-wrap break-words text-sm">{request.failure_reason}</p></div>}
    </PageSection>
    <PageSection title="Request context" description="Reported and requested identities do not verify actual upstream routing or local tool execution."><dl className="grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-3">
      <div className="min-w-0"><dt className="text-xs text-muted-foreground">Gateway</dt><dd className="mt-1 break-words"><Link className="text-primary hover:underline" href={`/gateways/instances/${encodeURIComponent(request.gateway_id)}`}>{request.gateway_name}</Link></dd></div>
      {[
        ["Requested model", request.model ? displayModel(request.model) : "Not reported"], ["Reported provider", request.provider ? displayText(request.provider) : "Not reported"], ["Route", request.route_id || "Not reported"], ["Service", request.service_id || "Not reported"], ["Caller / consumer", request.consumer_id || "Unknown"], ["Caller name", request.consumer_name || "Not reported"], ["Application", request.application_name || "Not reported"], ["Node", request.node_id || "Not reported"], ["Protocol", request.protocol], ["Stream requested", request.stream ? "Yes" : "No"], ["Evaluation status", request.status], ["Created", dateTime(request.created_at)], ["Completed", dateTime(request.completed_at)], ["Request latency", gatewayMetric(request.latency_ms, " ms")], ["Policy latency", gatewayMetric(request.policy_latency_ms, " ms")], ["HTTP status", gatewayMetric(request.status_code)], ["Usage and cost", "Unavailable"], ["Settings version", gatewayMetric(request.settings_version)], ["Policy version", gatewayMetric(request.policy_version)],
      ].map(([label, value]) => <div key={label} className="min-w-0"><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 break-words">{value}</dd></div>)}
    </dl><div className="mt-4"><p className="mb-1 text-xs text-muted-foreground">Plugin request ID</p><InlineCode className="break-all">{request.request_id}</InlineCode></div></PageSection>
    <PageSection title="Retained evidence" description="Evidence is shown exactly as retained and redacted by the server. Missing content does not mean a clean assessment."><div className="space-y-4"><div><h3 className="mb-2 text-sm font-medium">Prompt messages</h3>{request.messages === null ? <p className="text-sm text-muted-foreground">Unavailable. Content was not retained or is not available to this request.</p> : <CodeBlock>{JSON.stringify(request.messages, null, 2)}</CodeBlock>}</div><div><h3 className="mb-2 text-sm font-medium">Assessment record</h3>{request.assessment === null ? <p className="text-sm text-muted-foreground">Unavailable. No content assessment is available.</p> : <CodeBlock>{JSON.stringify(request.assessment, null, 2)}</CodeBlock>}</div></div></PageSection>
  </>}</div>;
}
