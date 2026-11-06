"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, RefreshCw, Search } from "lucide-react";
import { ActivityCategoryFilters, ActivitySessionButton, ActivityTimelineButton } from "@/components/activity-presentation";
import { useTimeZone } from "@/components/time-zone-context";
import { EventContent } from "@/components/event-content";
import { EventSourceBadge, ExportDetailDialog, OpenTelemetryRecordButton } from "@/components/telemetry-panels";
import { CollectionFooter, EmptyState, ErrorState, LoadingState, PageNotice, PageSection } from "@/components/page-layout";
import { SessionArchiveLink } from "@/components/session-links";
import { Button } from "@/components/ui/button";
import { CodeBlock, InlineCode } from "@/components/ui/code-block";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { eventDetail, productLabel, type AgentEvent } from "@/lib/api";
import { categoryOf, CATEGORIES, type ActivityCategory } from "@/lib/activity";
import { binaryFields, collectionNotes, downloadRaw, summarize, withoutBinary } from "@/lib/event-content";
import { EMPTY_EVIDENCE_FILTERS, EVIDENCE_KINDS, evidenceGroups, evidencePath, type EvidenceFilters } from "@/lib/evidence";
import { isGuardrailDecision } from "@/lib/guardrail";
import { usePagedResource } from "@/lib/use-resource";
import { cn } from "@/lib/utils";
import { GatewaySourceView } from "@/components/gateway-source-view";

type ExportTarget = { exportId: string; record: number };

function EvidenceRow({ event, expanded, onToggle, onRaw, onExport }: { event: AgentEvent; expanded: boolean; onToggle: () => void; onRaw: (event: AgentEvent) => void; onExport: (target: ExportTarget) => void }) {
  const detail = eventDetail(event);
  const summary = summarize(detail, event.truncated === true);
  const category = categoryOf(event.kind);
  const kind = event.kind === "hook.decision"
    ? (isGuardrailDecision(event) ? "Guardrail decision" : "Agent permission")
    : EVIDENCE_KINDS.find(([value]) => value === event.kind)?.[1] || event.kind;
  const sessionId = event.session?.id || event.session_id;
  return <li className="timeline-item min-w-0" data-category={category} data-event-id={event.id}>
    <span aria-hidden="true" className="timeline-dot" style={{ background: CATEGORIES[category].color }} />
    <ActivityTimelineButton category={category} at={event.time}
      toolName={category === "tool" || category === "result" ? event.tool?.name : undefined}
      summary={event.kind === "hook.decision" ? `${kind}: ${summary.line}` : summary.line || "Open event"}
      monospace={(category === "tool" || category === "result") && !summary.binary}
      onClick={onToggle}
      aria-expanded={expanded} aria-controls={`evidence-${event.id}`}
      aria-label={`Open event ${event.id}: ${summary.line || event.kind}`} title={summary.line || undefined}
    >
      <span className="hidden shrink-0 xl:inline-flex"><EventSourceBadge event={event} /></span>
    </ActivityTimelineButton>
    {expanded && <section id={`evidence-${event.id}`} aria-label="Activity details" className="mt-3 min-w-0 space-y-4 rounded-md bg-muted/30 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><h5 className="text-sm font-semibold">{kind} details</h5><EventSourceBadge event={event} /><Button variant="ghost" size="xs" onClick={() => onRaw(event)}>View raw event</Button></div>
      <EventContent text={detail} label="evidence" truncated={event.truncated === true} notes={collectionNotes(event)} className="[&_.font-mono]:text-sm [&_pre]:text-sm [&_pre]:font-normal" />
      {event.kind !== "tool.result" && typeof event.tool?.output === "string" && event.tool.output && <div className="space-y-2"><h6 className="text-xs text-muted-foreground">Output</h6><EventContent text={event.tool.output} label="output" truncated={event.truncated === true} className="[&_.font-mono]:text-sm [&_pre]:text-sm [&_pre]:font-normal" /></div>}
      <dl className="grid gap-3 sm:grid-cols-2">
        <div className="min-w-0"><dt className="text-xs text-muted-foreground">User</dt><dd className="mt-1 break-all text-sm">{event.host?.user || "User not reported"}</dd></div>
        <div className="min-w-0"><dt className="text-xs text-muted-foreground">Device</dt><dd className="mt-1 break-all text-sm">{event.host?.hostname || "Device not reported"}</dd></div>
        <div className="min-w-0"><dt className="text-xs text-muted-foreground">Agent</dt><dd className="mt-1 text-sm">{productLabel(event.agent?.product)}</dd></div>
        <div className="min-w-0"><dt className="text-xs text-muted-foreground">Session ID</dt><dd className="mt-1 break-all font-mono text-sm font-normal">{sessionId || "Not reported"}</dd></div>
        <div className="min-w-0"><dt className="text-xs text-muted-foreground">Working directory</dt><dd className="mt-1 break-all font-mono text-sm font-normal">{event.session?.cwd || event.command?.cwd || "Not reported"}</dd></div>
      </dl>
      <OpenTelemetryRecordButton event={event} onOpen={onExport} />
    </section>}
  </li>;
}

export default function EvidencePage() {
  return <GatewaySourceView><EndpointEvidencePage /></GatewaySourceView>;
}

function EndpointEvidencePage() {
  const { mode, localZone, timeZone, label: zoneLabel, dateTime } = useTimeZone();
  const [draft, setDraft] = useState<EvidenceFilters>(EMPTY_EVIDENCE_FILTERS);
  const [applied, setApplied] = useState<{ path: string; filters: EvidenceFilters; zone: string } | null>(null);
  const [sessionKey, setSessionKey] = useState<string | null>(null);
  const [detailOnPhone, setDetailOnPhone] = useState(false);
  const [picked, setPicked] = useState<Set<ActivityCategory>>(() => new Set());
  const [open, setOpen] = useState<string | null>(null);
  const [selected, setSelected] = useState<AgentEvent | null>(null);
  const [exportTarget, setExportTarget] = useState<ExportTarget | null>(null);
  useEffect(() => {
    if (applied || !localZone) return;
    const date = new Intl.DateTimeFormat("en-CA", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
    const filters = { ...EMPTY_EVIDENCE_FILTERS, date };
    setDraft(filters);
    setApplied({ path: evidencePath(filters, mode === "utc"), filters, zone: timeZone });
  }, [applied, localZone, mode, timeZone]);
  const result = usePagedResource<AgentEvent>(applied?.path ?? null);
  const groups = useMemo(() => evidenceGroups(result.items), [result.items]);
  const devices = useMemo(() => {
    const grouped = new Map<string, { name: string; sessions: typeof groups }>();
    for (const group of groups) {
      const last = group.events[group.events.length - 1];
      const key = last.sensor_id || last.host?.hostname || "unknown";
      if (!grouped.has(key)) grouped.set(key, { name: last.host?.hostname || "Device not reported", sessions: [] });
      grouped.get(key)!.sessions.push(group);
    }
    return [...grouped.entries()];
  }, [groups]);
  const session = groups.find(group => group.key === sessionKey) ?? groups[0];
  const latest = session?.events[session.events.length - 1];
  const visible = session?.events.filter(event => !picked.size || picked.has(categoryOf(event.kind))) ?? [];
  const days = new Map<string, AgentEvent[]>();
  const dayFormat = new Intl.DateTimeFormat("en-US", { timeZone, month: "short", day: "numeric", year: "numeric" });
  for (const event of visible) {
    const day = dayFormat.format(new Date(event.time));
    if (!days.has(day)) days.set(day, []);
    days.get(day)!.push(event);
  }
  useEffect(() => {
    setSessionKey(session?.key ?? null);
    setOpen(null);
  }, [session?.key]);
  const submit = (filters: EvidenceFilters) => {
    const path = evidencePath(filters, mode === "utc");
    if (path !== applied?.path) {
      setSessionKey(null);
      setDetailOnPhone(false);
      setPicked(new Set());
      setOpen(null);
    }
    setApplied({ path, filters, zone: timeZone });
    if (path === applied?.path) result.reload();
  };
  const clear = () => { setDraft(EMPTY_EVIDENCE_FILTERS); submit(EMPTY_EVIDENCE_FILTERS); };
  const toggleCategory = (category: ActivityCategory) => setPicked(previous => {
    const next = new Set(previous);
    if (next.has(category)) next.delete(category);
    else next.add(category);
    return next;
  });
  return (
    <PageSection title="Activity" description="Search retained agent activity. Timeline categories filter the loaded matches in the selected session." action={<Button variant="ghost" size="sm" onClick={result.reload} disabled={!applied || result.loading}><RefreshCw size={14} />Refresh</Button>}>
      <form aria-label="Evidence filters" onSubmit={event => { event.preventDefault(); submit(draft); }} className="mb-4 grid grid-cols-2 items-end gap-3 lg:grid-cols-3 2xl:grid-cols-[1fr_1fr_1fr_1fr_1fr_auto]">
        {([['username', 'User name', 'All users'], ['hostname', 'Device name', 'All devices'], ['session', 'Session ID', 'All sessions']] as const).map(([key, label, placeholder]) => <div key={key} className="min-w-0 space-y-2">
          <Label htmlFor={`filter-${key}`}>{label}</Label><Input id={`filter-${key}`} type="search" placeholder={placeholder} value={draft[key]} maxLength={1024} autoComplete="off" spellCheck={false}
            className={key === "session" ? "font-mono text-sm font-normal" : undefined} onChange={event => setDraft({ ...draft, [key]: event.target.value })} />
        </div>)}
        <div className="min-w-0 space-y-2"><Label htmlFor="filter-date">Date ({zoneLabel})</Label><Input id="filter-date" aria-label="Date" type="date" min="0001-01-01" max="9999-12-30" value={draft.date} onChange={event => setDraft({ ...draft, date: event.target.value })} /></div>
        <div className="min-w-0 space-y-2"><Label htmlFor="filter-kind">Activity type</Label><Select value={draft.kind} onValueChange={kind => setDraft({ ...draft, kind })}><SelectTrigger id="filter-kind" aria-label="Activity type" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All activity types</SelectItem>{EVIDENCE_KINDS.map(([value, label]) => <SelectItem key={value} value={value}>{label}</SelectItem>)}</SelectContent></Select></div>
        <Button type="submit" disabled={!applied}><Search size={14} />Search</Button>
      </form>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div role="status" aria-live="polite" className="min-w-0 text-sm text-muted-foreground">{result.items.length} {result.items.length === 1 ? "activity" : "activities"} loaded{applied?.filters.date && ` · ${applied.filters.date} (${applied.zone})`}</div>
        <Button variant="ghost" onClick={clear}>Clear filters</Button>
      </div>
      <div className="mb-3"><PageNotice title="Search coverage" collapsible>
        <p>Search all retained agent events by recorded user name, device name, session ID, date, and activity type. Names match without case; session IDs match literal text, including partial IDs. Blank filters include all values.</p>
        <p>Sessions use the session ID within its device and agent. Counts cover loaded matches, not complete sessions. Load more to see older matching activity. Events without a usable session identity stay separate.</p>
        <p>The date applies to the selected Local or UTC calendar day when you press Search. Changing the time display keeps that search window. Raw telemetry is available from linked events; metric and trace batches are not agent activities.</p>
      </PageNotice></div>
      {result.error && <ErrorState message={result.error} onRetry={result.reload} />}
      {(!applied || result.loading) && !result.items.length ? <LoadingState label="Loading activity" /> : result.items.length ? (
        <div className="-mx-4 -mb-4 border-t">
          <div className="grid min-w-0 lg:h-[calc(100dvh-24rem)] lg:min-h-112 lg:grid-cols-[320px_minmax(0,1fr)]">
            <nav aria-label="Matching sessions" className={cn("min-h-0 min-w-0 overflow-y-auto border-b max-lg:max-h-[70vh] lg:border-r lg:border-b-0", detailOnPhone && "max-lg:hidden")}>
              {devices.map(([key, device]) => <section key={key} aria-label={`Sessions on ${device.name}`}>
                <h3 className="sticky top-0 z-10 flex items-center gap-2 border-b bg-card px-4 py-2 text-xs font-semibold">
                  <span className="min-w-0 flex-1 truncate" title={device.name}>{device.name}</span>
                  <span className="number shrink-0 font-normal text-muted-foreground">{device.sessions.length} {device.sessions.length === 1 ? "session" : "sessions"}</span>
                </h3>
                <ul className="divide-y">{device.sessions.map(group => {
                  const last = group.events[group.events.length - 1];
                  const preview = group.events.findLast(event => event.kind === "prompt" && event.text) ?? last;
                  const summary = summarize(eventDetail(preview), preview.truncated === true).line;
                  return <li key={group.key}>
                    <ActivitySessionButton product={last.agent?.product || "unknown"} current={session?.key === group.key}
                      aria-controls="evidence-session-details" title={`Session ID: ${group.sessionId || "Session not reported"}`}
                      aria-label={`${productLabel(last.agent?.product)}: ${summary || "No prompt text"}. Session ID: ${group.sessionId || "Session not reported"}`}
                      onClick={() => { setSessionKey(group.key); setDetailOnPhone(true); }} summary={summary}
                      metadata={<><time dateTime={last.time}>{dateTime(last.time)}</time> · {group.events.length} {group.events.length === 1 ? "activity" : "activities"}</>}
                    />
                  </li>;
                })}</ul>
              </section>)}
            </nav>
            {session && latest && <section key={session.key} id="evidence-session-details" aria-label="Session details" className={cn("flex min-h-0 min-w-0 flex-col", !detailOnPhone && "max-lg:hidden")}>
              <header className="border-b px-4 py-3">
                <Button variant="ghost" size="xs" className="mb-2 lg:hidden" onClick={() => setDetailOnPhone(false)}><ArrowLeft aria-hidden="true" />Sessions</Button>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <h3 className="text-sm font-semibold">{productLabel(latest.agent?.product)}</h3><SessionArchiveLink sessionId={latest.session_id} />
                  <span className="min-w-0 break-all text-xs text-muted-foreground">{latest.host?.user || "User not reported"} @ {latest.host?.hostname || "Device not reported"}</span>
                  {(latest.session?.cwd || latest.command?.cwd) && <InlineCode className="min-w-0 max-w-80 truncate [direction:rtl]" title={latest.session?.cwd || latest.command?.cwd}>{latest.session?.cwd || latest.command?.cwd}</InlineCode>}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">Session ID <code className="break-all font-mono font-normal">{session.sessionId || "Not reported"}</code></p>
                <p className="number mt-1 text-xs text-muted-foreground">{session.events.length} matching {session.events.length === 1 ? "activity" : "activities"} loaded · Oldest first · {zoneLabel}{picked.size > 0 && ` · ${visible.length} shown`}</p>
                <ActivityCategoryFilters picked={picked} onToggle={toggleCategory} onReset={() => setPicked(new Set())} />
              </header>
              <div role="region" aria-label="Session activity" tabIndex={0} className="min-h-0 min-w-0 flex-1 overflow-y-auto px-4 py-2 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring max-lg:max-h-[70dvh]">
                {visible.length ? <ol aria-label="Session timeline" className="space-y-3">{[...days].map(([day, events]) => <li key={day}>
                  <h4 className="py-2 text-xs font-medium text-muted-foreground">{day}</h4>
                  <ol className="timeline">{events.map(event => <EvidenceRow key={event.id} event={event} expanded={open === event.id}
                    onToggle={() => setOpen(current => current === event.id ? null : event.id)} onRaw={setSelected} onExport={setExportTarget} />)}</ol>
                </li>)}</ol> : <p className="py-6 text-center text-sm text-muted-foreground">No matching activities in the selected categories.</p>}
              </div>
            </section>}
          </div>
          <div className="space-y-1 border-t px-4 py-3"><CollectionFooter count={result.items.length} hasMore={!!result.nextCursor} busy={result.loadingMore || result.loading} onLoadMore={result.loadMore} label="activities" /><p className="text-xs text-muted-foreground">Counts include loaded search matches only. Load more to find older activity and sessions.</p></div>
        </div>
      ) : !result.error ? <EmptyState title="No activity found" description="Try another user, device, session ID, date, or activity type." action={<Button variant="ghost" onClick={clear}>Clear filters</Button>} /> : null}
      <Dialog
        open={!!selected}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Event evidence</DialogTitle>
            <DialogDescription>
              Collected event data for this tenant.
            </DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="flex flex-wrap items-center gap-2">
                <span className="text-muted-foreground">Source</span>
                <EventSourceBadge event={selected} />
                {selected.export && (
                  <span className="text-muted-foreground">
                    Record{" "}
                    <span className="number">{selected.export.record}</span> in
                    export{" "}
                    <code className="font-mono" title={selected.export.id}>
                      {selected.export.id.slice(0, 8)}…
                    </code>
                  </span>
                )}
              </span>
              <OpenTelemetryRecordButton
                event={selected}
                onOpen={setExportTarget}
              />
            </div>
          )}
          {selected &&
            binaryFields(selected).map(({ name, raw, binary }) => (
              <p key={name} className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                {name === "text" ? "Text" : "Output"}: {binary}
                <Button
                  variant="outline"
                  size="xs"
                  onClick={() => downloadRaw(raw, `${selected.id}-${name}.txt`)}
                >
                  Download raw {name}
                </Button>
              </p>
            ))}
          {selected && collectionNotes(selected).length > 0 && (
            <p className="text-xs text-muted-foreground">{collectionNotes(selected).join(" ")}</p>
          )}
          <CodeBlock className="max-h-[60vh] whitespace-pre">
            {JSON.stringify(selected && withoutBinary(selected), null, 2)}
          </CodeBlock>
        </DialogContent>
      </Dialog>
      <ExportDetailDialog
        exportId={exportTarget?.exportId ?? null}
        highlightRecord={exportTarget?.record ?? null}
        onClose={() => setExportTarget(null)}
      />
    </PageSection>
  );
}
