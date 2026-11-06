"use client";

import { useTimeZone } from "@/components/time-zone-context";
import Link from "next/link";
import { RefreshCw } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { SessionGuardrailActions } from "@/components/session-guardrail-actions";
import { SessionDetectionOwner } from "@/components/session-detection-owner";
import { SessionInvestigation, SessionInvestigations } from "@/components/session-investigation";
import { RetainedSnapshot } from "@/components/session-evidence";
import { Button } from "@/components/ui/button";
import { InlineCode } from "@/components/ui/code-block";
import { Status } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { productLabel } from "@/lib/api";
import { displayText } from "@/lib/display";
import { humanize, isUuid, sessionHref, storedCount, storedScore, type SessionSelection, type SessionSummary } from "@/lib/session";
import { useResource } from "@/lib/use-resource";
import { EligibilityDecision } from "@/components/detection-eligibility";

function Overview({ data }: { data: SessionSummary }) {
  const { dateTime } = useTimeZone();
  const { session, registration, projection, detection } = data;
  const stored = projection.available ? detection : null;
  const counts = stored?.counts;
  const owner = registration?.owner;
  const verified = Boolean(registration?.verified_at);
  return <>
    {!projection.available && <PageNotice title="No stored detection summary">Risk, counts, and coverage are unavailable. An unprocessed session is not a zero-risk session.</PageNotice>}
    {projection.finalization_error && <PageNotice title="Finalization failed">{humanize(projection.finalization_error)}. The stored summary is not current.</PageNotice>}
    {(projection.dirty || projection.evaluation_due) && <PageNotice title="Stored summary is awaiting an update">New input or a scheduled evaluation can change the stored values below.</PageNotice>}
    {projection.settings_changed && <PageNotice title="Routing settings have changed">The stored summary uses an earlier settings version. This is separate from snapshot content freshness.</PageNotice>}
    <PageSection title="Session overview" description={projection.updated_at ? `Risk, counts, and coverage stored as of ${dateTime(projection.updated_at)}.` : "No aggregation result has been stored for this session."}>
      <div className="space-y-4">
        <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2 xl:grid-cols-4" aria-label="Session identity">
          <div><dt className="text-xs text-muted-foreground">Client</dt><dd className="font-medium">{productLabel(session.client.product || session.product)}{session.client.version ? ` ${displayText(session.client.version)}` : ""}</dd></div>
          <div><dt className="text-xs text-muted-foreground">Device</dt><dd className="font-medium">{session.device.hostname || "Not reported"}<p className="text-xs text-muted-foreground">{[session.device.os, session.device.arch].filter(Boolean).join(" · ")}</p></dd></div>
          {registration && <div><dt className="text-xs text-muted-foreground">Verified account</dt><dd className="font-medium">{verified ? owner?.name || owner?.email || "Account no longer available" : "Not verified"}
            {verified && owner?.name && owner?.email && <p className="break-words text-xs text-muted-foreground">{owner.email}</p>}
            {verified && !registration!.owner_available && <p className="text-xs text-muted-foreground">Account unavailable for current execution</p>}
          </dd></div>}
          <div><dt className="text-xs text-muted-foreground">Reported OS user</dt><dd className="font-medium">{session.device.reported_user || "Not reported"}</dd></div>
        </dl>
        {(session.device.sensor_disabled || session.device.sensor_deleted_at) && <p className="text-sm">Sensor {session.device.sensor_deleted_at ? "deleted" : "disabled"}. Retained archive access does not grant execution authority.</p>}
        <dl className="grid grid-cols-2 gap-x-6 gap-y-4 border-t pt-4 sm:grid-cols-3 xl:grid-cols-4" aria-label="Stored session measures">
          {[
            ["Stored risk total", storedScore(stored?.risk_total)], ["Maximum target risk", storedScore(stored?.risk_max)],
            ["Logical targets", storedCount(counts?.logical_targets)], ["Assessed targets", storedCount(counts?.assessed)],
            ["Blocked targets", storedCount(counts?.blocked)],
            ...(registration ? [["Pending approvals", storedCount(counts?.pending_approvals)]] : []),
            ["Unreported outcomes", storedCount(counts?.unreported_outcomes)], ["Uncertain outcomes", storedCount(counts?.uncertain_outcomes)],
          ].map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="number mt-1 text-base font-semibold">{value}</dd></div>)}
        </dl>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          {registration && <span>Managed lifecycle: {stored ? humanize(stored.lifecycle) : "Unknown"}</span>}
          <span>Native end: {session.ended_at ? dateTime(session.ended_at) : "Not reported"}</span>
          {registration && <span>Delivery: {stored ? `${storedCount(stored.delivery?.received)} of ${storedCount(stored.delivery?.expected)} receipts` : "Unknown"}</span>}
        </div>
        <section aria-label="Detection eligibility" className="space-y-2 border-t pt-4">
          <h3 className="text-sm font-semibold">Detection eligibility</h3>
          <EligibilityDecision value={data.eligibility} />
          {data.eligibility && <p className="text-xs text-muted-foreground">{data.eligibility.history_available ? "Verified ownership permits recent user sessions as context." : "Recent user history is unavailable. Ordinary sessions can be investigated using their own evidence."}</p>}
          {stored?.routing?.job_id && <Link className="text-sm font-medium hover:underline" href={sessionHref(session.id, { investigation: stored.routing.job_id }, "investigation")}>View routed investigation</Link>}
        </section>
        <details><summary className="w-fit cursor-pointer py-2 text-sm font-medium">Assessment counts and session metadata</summary>
          <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
            {[
              ["Unavailable assessments", storedCount(counts?.unavailable)], ["Pending assessments", storedCount(counts?.pending)],
              ["Missing assessments", storedCount(counts?.missing_assessments)], ["Invalid assessments", storedCount(counts?.invalid_assessments)],
              ...(registration ? [["Approved but not consumed", storedCount(counts?.approved_unconsumed)]] : []),
              ["Started", session.started_at ? dateTime(session.started_at) : "Not reported"],
              ["Latest native event", session.last_event_at ? dateTime(session.last_event_at) : "Not reported"],
              ...(registration ? [
                ["Owner binding verified", registration.verified_at ? dateTime(registration.verified_at) : "Not verified"],
                ["Assessment mode", humanize(registration.assessment_mode)],
                ["Delivery protocol", registration.delivery_protocol ?? "Not reported"],
              ] : []),
              ["Native event rows", storedCount(session.events_total)],
            ].map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="break-words">{value}</dd></div>)}
            {[
              ["Session ID", session.id], ["Native session ID", session.external_id],
              ["Agent ID", session.agent_id], ["Sensor ID", session.sensor_id], ["Working directory", session.cwd],
              ["Git branch", session.git_branch],
              ...(registration ? [["Registration ID", registration.id], ["Delivery epoch", registration.delivery_epoch]] : []),
            ].map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd>{value ? <InlineCode className="break-all">{value}</InlineCode> : "Not reported"}</dd></div>)}
          </dl>
        </details>
        <PageNotice title="How to read session risk" collapsible>
          <p>The receiver stores risk once per canonical assessed target. Request aliases and approval generations do not add scores. A stored zero differs from missing assessment. This page does not calculate risk from the live timeline.</p>
          <p>A native end event, idle state, approved request, or absence of findings does not prove complete delivery or execution. Verified account ownership is distinct from a reported operating-system username.</p>
        </PageNotice>
      </div>
    </PageSection>
  </>;
}

function Coverage({ data }: { data: SessionSummary }) {
  const coverage = data.projection.available ? data.detection?.coverage : null;
  return <PageSection title="Coverage" description="Coverage of retained session evidence. Missing records and unsupported native paths remain explicit gaps.">
    <TableLayout><Table aria-label="Session coverage"><TableHeader><TableRow>
      <TableHead>Axis</TableHead><TableHead>Stored status</TableHead><TableHead>Reasons</TableHead>
    </TableRow></TableHeader><TableBody>{(["content", "delivery", "assessment", "execution"] as const).map((name) => {
      const axis = coverage?.[name];
      return <TableRow key={name}><TableCell className="font-medium capitalize">{name}</TableCell>
        <TableCell><Status tone={axis?.status === "complete" ? "ok" : axis?.status === "incomplete" ? "warning" : "neutral"}>{humanize(axis?.status ?? "unknown")}</Status></TableCell>
        <TableCell>{axis ? axis.reasons.length ? <ul className="space-y-1">{axis.reasons.map((reason) => <li key={reason}>{humanize(reason)}</li>)}</ul> : "No gaps recorded for this axis" : "No stored coverage"}</TableCell>
      </TableRow>;
    })}</TableBody></Table></TableLayout>
  </PageSection>;
}

export function SessionDetail({ sessionId, selection }: { sessionId: string; selection: SessionSelection | null }) {
  const { dateTime } = useTimeZone();
  const { user } = useDashboard();
  const valid = isUuid(sessionId) && selection !== null;
  const resource = useResource<SessionSummary>(user && valid ? `sessions/${sessionId}/detection?limit=20` : null, 30000);
  const data = resource.data;
  if (!valid) return <ErrorState message="The session link contains an invalid session, report, snapshot, or citation identifier." />;
  const snapshotId = selection.snapshot ?? (!selection.investigation ? data?.projection.snapshot_id : null);
  return <div className="min-w-0 space-y-4" data-page-chat-exclude>
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-xs text-muted-foreground">Retained operator archive{resource.updated ? ` · fetched ${dateTime(resource.updated.toISOString())}` : ""}</p>
      <Button variant="outline" disabled={resource.loading || !user} onClick={() => void resource.reload()}><RefreshCw aria-hidden="true" />Refresh session</Button>
    </div>
    {resource.error && <ErrorState message={`${resource.error}${data ? " Showing the last successful response." : ""}`} onRetry={resource.reload} />}
    {(!user || (!data && !resource.error)) && <LoadingState label="Loading session…" />}
    {data && <>
      <Overview data={data} />
      {!data.registration && <SessionDetectionOwner sessionId={sessionId} />}
      <Coverage data={data} />
      {data.projection.snapshot_id && !data.projection.snapshot_current && <PageNotice title="Snapshot is stale">The retained snapshot does not cover all current session input. Opening it keeps that exact evidence version.</PageNotice>}
      {data.registration && <SessionGuardrailActions key={sessionId} sessionId={sessionId} />}
      <SessionInvestigations sessionId={sessionId} page={data.investigations} />
    </>}
    {user && selection.investigation && <SessionInvestigation key={`${selection.investigation}:${selection.attempt ?? "latest"}`} sessionId={sessionId} selection={{ ...selection, investigation: selection.investigation }} />}
    {user && snapshotId && data && <RetainedSnapshot key={snapshotId} snapshotId={snapshotId} sessionId={sessionId} registrationId={data.registration?.id ?? null} selection={selection} />}
  </div>;
}
