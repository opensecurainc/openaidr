"use client";

import { displayText } from "@/lib/display";
import { useTimeZone } from "@/components/time-zone-context";
import { useId, useState } from "react";
import { ChevronRight, RefreshCw } from "lucide-react";
import { CollectionFooter, EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { RetainedRecord } from "@/components/session-evidence";
import { EventContent } from "@/components/event-content";
import { Button } from "@/components/ui/button";
import { InlineCode } from "@/components/ui/code-block";
import { Status, type StatusTone } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { humanize, objectValue, storedScore, textValue, type ApprovalGeneration, type GuardrailAction, type InlineDecision } from "@/lib/session";
import { usePagedResource } from "@/lib/use-resource";
import { cn } from "@/lib/utils";

export function RecordedState({ value }: { value: string | null | undefined }) {
  const tone: StatusTone = value === "block" || value === "deny" || value === "rejected" ? "critical" :
    ["ask", "pending", "uncertain", "unavailable", "missing", "expired", "revoked"].includes(value ?? "") ? "warning" : "neutral";
  return value ? <Status tone={tone}>{humanize(value)}</Status> : <span className="text-muted-foreground">Not recorded</span>;
}

function DecisionHistory({ sessionId, actionId }: { sessionId: string; actionId: string }) {
  const { dateTime } = useTimeZone();
  const query = new URLSearchParams({ view: "decisions", action_id: actionId, limit: "50" });
  const resource = usePagedResource<InlineDecision>(`sessions/${sessionId}/guardrail-actions?${query}`);
  return <div className="space-y-3">
    {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
    {resource.loading && !resource.items.length && <LoadingState label="Loading decision history…" />}
    {!resource.loading && !resource.error && !resource.items.length && <p className="text-sm text-muted-foreground">No recorded decisions.</p>}
    {resource.items.length > 0 && <TableLayout footer={<CollectionFooter count={resource.items.length} hasMore={Boolean(resource.nextCursor)} busy={resource.loadingMore} onLoadMore={resource.loadMore} label="decisions" />}>
      <Table aria-label="Decision history"><TableHeader><TableRow>
        <TableHead>Decision</TableHead><TableHead>Policy / settings</TableHead><TableHead>Recorded at</TableHead><TableHead>Request</TableHead>
      </TableRow></TableHeader><TableBody>{resource.items.map((row) => <TableRow key={row.id}>
        <TableCell className="font-medium"><RecordedState value={row.decision?.action} />
          {row.decision?.reason && <p className="mt-1 max-w-lg whitespace-pre-wrap break-words text-xs text-muted-foreground">{row.decision.reason}</p>}
          {row.decision?.warnings?.map((warning, index) => <p key={index} className="mt-1 max-w-lg whitespace-pre-wrap break-words text-xs">Warning: {warning}</p>)}
        </TableCell>
        <TableCell>{row.policy_version} / {row.settings_version}<p className="text-xs text-muted-foreground">Requested minimum: {humanize(row.requested_policy_floor)}</p></TableCell>
        <TableCell>{dateTime(row.created_at)}</TableCell>
        <TableCell><details><summary className="cursor-pointer py-1">Identifiers</summary>
          <p className="mt-1 text-xs text-muted-foreground">Request alias</p><InlineCode className="break-all">{row.request_id}</InlineCode>
          <p className="mt-1 text-xs text-muted-foreground">Decision</p><InlineCode className="break-all">{row.id}</InlineCode>
        </details></TableCell>
      </TableRow>)}</TableBody></Table>
    </TableLayout>}
  </div>;
}

function ApprovalHistory({ sessionId, actionId }: { sessionId: string; actionId: string }) {
  const { dateTime } = useTimeZone();
  const query = new URLSearchParams({ view: "approvals", action_id: actionId, limit: "50" });
  const resource = usePagedResource<ApprovalGeneration>(`sessions/${sessionId}/guardrail-actions?${query}`);
  return <div className="space-y-3">
    <p className="text-sm text-muted-foreground">Recorded generations are read-only here. Expiry times remain authoritative even when the stored state has not been updated.</p>
    {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
    {resource.loading && !resource.items.length && <LoadingState label="Loading approval history…" />}
    {!resource.loading && !resource.error && !resource.items.length && <p className="text-sm text-muted-foreground">No recorded approval generations.</p>}
    {resource.items.length > 0 && <TableLayout footer={<CollectionFooter count={resource.items.length} hasMore={Boolean(resource.nextCursor)} busy={resource.loadingMore} onLoadMore={resource.loadMore} label="approval generations" />}>
      <Table aria-label="Approval history"><TableHeader><TableRow>
        <TableHead>Generation</TableHead><TableHead>Recorded state</TableHead><TableHead>Request expires</TableHead><TableHead>Approval valid until</TableHead><TableHead>Decision / revocation</TableHead>
      </TableRow></TableHeader><TableBody>{resource.items.map((row) => <TableRow key={row.id}>
        <TableCell className="font-medium">{row.generation}<p className="text-xs text-muted-foreground">Policy {row.policy_version} · settings {row.settings_version}</p>
          <details><summary className="cursor-pointer py-1 text-xs">Approval identifier</summary><InlineCode className="break-all">{row.id}</InlineCode></details>
        </TableCell>
        <TableCell><RecordedState value={row.status} />{row.reason_code && <p className="mt-1 text-xs text-muted-foreground">{humanize(row.reason_code)}</p>}</TableCell>
        <TableCell>{dateTime(row.expires_at)}</TableCell>
        <TableCell>{row.approved_until ? dateTime(row.approved_until) : "Not recorded"}</TableCell>
        <TableCell>{humanize(row.decision)}<p className="text-xs text-muted-foreground">{row.decided_at ? dateTime(row.decided_at) : "No decision time"}</p>
          {row.revoked_at && <p className="text-xs">Revoked {dateTime(row.revoked_at)}</p>}
        </TableCell>
      </TableRow>)}</TableBody></Table>
    </TableLayout>}
  </div>;
}

function ActionRow({ action, sessionId }: { action: GuardrailAction; sessionId: string }) {
  const { dateTime } = useTimeZone();
  const [open, setOpen] = useState(false);
  const id = useId();
  const event = action.target_body;
  const tool = objectValue(event.tool);
  const assessment = action.assessment.value;
  const decision = action.latest_decision?.decision;
  const approval = action.latest_approval;
  const outcome = textValue(action.reported_outcome?.captured_body?.outcome);
  return <li className="min-w-0 py-3" data-page-chat-exclude>
    <button type="button" aria-label={`${open ? "Collapse" : "Expand"} action ${action.logical_id}`} aria-expanded={open} aria-controls={id}
      onClick={() => setOpen((value) => !value)}
      className="flex w-full flex-wrap items-center gap-2 rounded-sm py-1 text-left text-sm focus-visible:outline-2 focus-visible:outline-ring">
      <ChevronRight aria-hidden="true" className={cn("size-4 shrink-0", open && "rotate-90")} />
      <span className="font-medium">{humanize(textValue(event.kind))}{tool?.name ? ` · ${textValue(tool.name)}` : ""}</span>
      <span className="text-xs text-muted-foreground">{dateTime(action.created_at)}</span>
      <RecordedState value={decision?.action} />
      <span className="text-xs text-muted-foreground">Risk {storedScore(assessment?.score)} · assessment {displayText(action.assessment.status)}</span>
    </button>
    {open && <div id={id} className="mt-3 space-y-4">
      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2 xl:grid-cols-3" aria-label="Action state">
        <div><dt className="text-xs text-muted-foreground">Assessment</dt><dd>{humanize(action.assessment.status)} · {storedScore(assessment?.score)}
          {action.assessment.rubric_version != null && <p className="text-xs text-muted-foreground">Rubric {action.assessment.rubric_version}</p>}
          {typeof assessment?.reason === "string" && <p className="mt-1 whitespace-pre-wrap break-words">{assessment.reason}</p>}
        </dd></div>
        <div><dt className="text-xs text-muted-foreground">Recorded decision</dt><dd><RecordedState value={decision?.action} />
          {decision?.reason && <p className="mt-1 whitespace-pre-wrap break-words">{decision.reason}</p>}
          {decision?.warnings?.map((warning, index) => <p key={index} className="mt-1 whitespace-pre-wrap break-words">Warning: {warning}</p>)}
        </dd></div>
        <div><dt className="text-xs text-muted-foreground">Latest approval generation</dt><dd>{approval ? <>
          <RecordedState value={approval.status} /><p className="mt-1 text-xs">Generation {approval.generation} · request expires {dateTime(approval.expires_at)}</p>
          {approval.approved_until && <p className="text-xs">Approved until {dateTime(approval.approved_until)}</p>}
        </> : "Not recorded"}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Release consumption</dt><dd>{action.release ? `Consumed ${dateTime(action.release.consumed_at)}` : "Not recorded"}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Recorded release outcome</dt><dd><RecordedState value={action.release?.outcome} /></dd></div>
        <div><dt className="text-xs text-muted-foreground">Reported native or delivery outcome</dt><dd><RecordedState value={outcome} />
          {action.reported_outcome && <p className="mt-1 text-xs text-muted-foreground">Received {dateTime(action.reported_outcome.received_at)}</p>}
        </dd></div>
      </dl>
      <section aria-labelledby={`${id}-evidence`} className="space-y-3 border-t pt-4">
        <h3 id={`${id}-evidence`} className="text-sm font-semibold">Evidence</h3>
        <RetainedRecord body={event} label="Action target" />
        {action.captured_context && <details><summary className="w-fit cursor-pointer py-2 text-sm font-medium">Captured assessment context</summary>
          <EventContent text={JSON.stringify(action.captured_context, null, 2)} label="Assessment context" />
        </details>}
        {(action.release?.outcome_details || action.reported_outcome) && <details><summary className="w-fit cursor-pointer py-2 text-sm font-medium">Reported outcome details</summary>
          <EventContent text={JSON.stringify({ release: action.release?.outcome_details ?? null, reported: action.reported_outcome }, null, 2)} label="Outcome details" />
        </details>}
        <details><summary className="w-fit cursor-pointer py-2 text-sm font-medium">Action identifiers</summary>
          <dl className="space-y-2 text-sm">
            <div><dt>Logical target</dt><dd><InlineCode className="break-all">{action.logical_id}</InlineCode></dd></div>
            <div><dt>Canonical assessment</dt><dd>{action.action_id ? <InlineCode className="break-all">{action.action_id}</InlineCode> : "Missing assessment; retained delivery receipt"}</dd></div>
            <div><dt>Event</dt><dd><InlineCode className="break-all">{action.event_id}</InlineCode></dd></div>
          </dl>
        </details>
      </section>
      <section aria-labelledby={`${id}-decisions`} className="space-y-3 border-t pt-4">
        <h3 id={`${id}-decisions`} className="text-sm font-semibold">Decision history{action.action_id && ` (${action.decision_count})`}</h3>
        {action.action_id ? <DecisionHistory sessionId={sessionId} actionId={action.action_id} /> :
          <p className="text-sm text-muted-foreground">Decision history is unavailable because this action has no canonical assessment.</p>}
      </section>
      <section aria-labelledby={`${id}-approvals`} className="space-y-3 border-t pt-4">
        <h3 id={`${id}-approvals`} className="text-sm font-semibold">Approval history{action.action_id && ` (${action.approval_count})`}</h3>
        {action.action_id ? <ApprovalHistory sessionId={sessionId} actionId={action.action_id} /> :
          <p className="text-sm text-muted-foreground">Approval history is unavailable because this action has no canonical assessment.</p>}
      </section>
    </div>}
  </li>;
}

export function SessionGuardrailActions({ sessionId }: { sessionId: string }) {
  const { dateTime } = useTimeZone();
  const resource = usePagedResource<GuardrailAction>(`sessions/${sessionId}/guardrail-actions?limit=50`);
  return <PageSection title="Guardrail actions" description="One row per currently known logical target, with separate decision, approval, consumption, and outcome facts."
    action={<Button variant="outline" disabled={resource.loading || resource.loadingMore} onClick={resource.reload}><RefreshCw aria-hidden="true" />Refresh actions</Button>}>
    <div className="space-y-3">
      <PageNotice title="Reading managed action states" collapsible>
        <p>An approved request keeps its recorded ask decision. Approval does not prove consumption or native execution. A reported outage outcome does not imply a backend release. Native permissions are independent.</p>
        <p>These live pages can change. Refresh to see new actions; a missing-assessment receipt may become a canonical assessed row. Request aliases do not count as extra targets. Use a retained snapshot for immutable evidence.</p>
        <p>Operator access is read-only. Approval decisions remain in the separate owner approval flow.</p>
      </PageNotice>
      {resource.error && <ErrorState message={`${resource.error}${resource.items.length ? ` Showing the last successful response${resource.updated ? ` from ${dateTime(resource.updated.toISOString())}` : ""}.` : ""}`} onRetry={resource.reload} />}
      {resource.loading && !resource.items.length && <LoadingState label="Loading guardrail actions…" />}
      {!resource.loading && !resource.error && !resource.items.length && <EmptyState title="No managed actions recorded" description="Legacy activity and unreported boundaries do not appear as scored managed targets." />}
      <ul className="divide-y" aria-label="Canonical guardrail actions">{resource.items.map((action) => <ActionRow key={action.id} action={action} sessionId={sessionId} />)}</ul>
      <CollectionFooter count={resource.items.length} hasMore={Boolean(resource.nextCursor)} busy={resource.loadingMore || resource.loading} onLoadMore={resource.loadMore} label="logical targets" />
    </div>
  </PageSection>;
}
