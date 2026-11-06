"use client";

import { useTimeZone } from "@/components/time-zone-context";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { RefreshCw } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { CollectionFooter, EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { RecordedState } from "@/components/session-guardrail-actions";
import { RetainedReadDialog, RetainedSnapshot } from "@/components/session-evidence";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { InlineCode } from "@/components/ui/code-block";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  detectionCategoryLabel, humanize, investigationHref, investigationOutcomeLabel, sessionHref, storedCount, type ArchivePage, type Investigation,
  type EvidenceCitation, type InvestigationFinding, type InvestigationRef, type InvestigationReport, type SessionSelection, type SessionSummary,
} from "@/lib/session";
import { useResource } from "@/lib/use-resource";
import { canAccessPage } from "@/lib/roles";
import { cn } from "@/lib/utils";

function JobRows({ sessionId, page, before = 0 }: { sessionId: string; page: ArchivePage<InvestigationRef>; before?: number }) {
  const { dateTime } = useTimeZone();
  const [more, setMore] = useState(false);
  return <>
    <TableLayout><Table aria-label="Session investigations"><TableHeader><TableRow>
      <TableHead>Investigation</TableHead><TableHead>State</TableHead><TableHead>Snapshot</TableHead><TableHead>Configuration</TableHead>
    </TableRow></TableHeader><TableBody>{page.items.map((job) => <TableRow key={job.id}>
      <TableCell className="font-medium"><Link href={sessionHref(sessionId, { investigation: job.id, snapshot: job.snapshot_id }, "investigation")}
        aria-label={`Open investigation ${job.id}`} className="hover:underline focus-visible:outline-2 focus-visible:outline-ring">{dateTime(job.created_at)}</Link>
        <p className="text-xs text-muted-foreground">{humanize(job.routing_reason)}</p></TableCell>
      <TableCell><RecordedState value={job.state} /></TableCell>
      <TableCell>Revision {job.revision}<p className="text-xs text-muted-foreground">{job.snapshot_current ? "Current stored snapshot" : "Snapshot is stale"}</p></TableCell>
      <TableCell>{job.detector_config_version}<p className="text-xs text-muted-foreground">{job.configuration_current ? "Current configuration" : "Investigation configuration is stale"}</p></TableCell>
    </TableRow>)}</TableBody></Table></TableLayout>
    {more && page.next_cursor ? <JobContinuation sessionId={sessionId} cursor={page.next_cursor} before={before + page.items.length} /> :
      <div className="mt-3"><CollectionFooter count={before + page.items.length} hasMore={Boolean(page.next_cursor)} busy={false} onLoadMore={() => setMore(true)} label="investigations" /></div>}
  </>;
}
function JobContinuation({ sessionId, cursor, before }: { sessionId: string; cursor: string; before: number }) {
  const resource = useResource<SessionSummary>(`sessions/${sessionId}/detection?limit=20&cursor=${encodeURIComponent(cursor)}`);
  return <div className="mt-3 space-y-3">
    {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
    {!resource.data && !resource.error && <LoadingState label="Loading more investigations…" />}
    {resource.data && <JobRows sessionId={sessionId} page={resource.data.investigations} before={before} />}
  </div>;
}
export function SessionInvestigations({ sessionId, page }: { sessionId: string; page: ArchivePage<InvestigationRef> }) {
  return <PageSection title="Investigations" description="Stored runs and their exact content snapshots. This page does not start model work.">
    {page.items.length ? <JobRows key={page.items.map((item) => item.id).join(":")} sessionId={sessionId} page={page} /> :
      <EmptyState title="No investigations recorded" description="No retained job is available for this session. This does not establish low risk or complete coverage." />}
  </PageSection>;
}

function reportEvidenceHref(sessionId: string | null, pin: SessionSelection, anchor = "") {
  return sessionId ? sessionHref(sessionId, pin, anchor) : investigationHref(pin.investigation!, pin, anchor);
}

function EvidenceLink({ citation, sessionId, pin }: {
  citation: EvidenceCitation; sessionId: string | null; pin: SessionSelection;
}) {
  return citation.source === "target" ?
    <Link className="font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring"
      aria-label={`View target record ${citation.ordinal}, bytes ${citation.start} to ${citation.end}`}
      href={reportEvidenceHref(sessionId, { ...pin, ordinal: citation.ordinal, start: citation.start, end: citation.end }, "snapshot")}>
      Target record {citation.ordinal} · bytes {citation.start} to {citation.end} (end excluded)
    </Link> : <Link className="font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring"
      aria-label={`View retained history read ${citation.read_id}, item ${citation.item}`} data-retained-read-id={citation.read_id}
      href={reportEvidenceHref(sessionId, { ...pin, read: citation.read_id, item: citation.item }, "investigation")}>
      Retained history · item {citation.item}
    </Link>;
}

function ReportTextList({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return <section aria-label={title} className="space-y-2 text-sm">
    <h4 className="font-semibold">{title}</h4>
    {items.length ? <ul className="list-disc space-y-1 pl-5">{items.map((item, index) =>
      <li key={index} className="max-w-4xl whitespace-pre-wrap break-words">{item}</li>)}</ul> : <p className="text-muted-foreground">{empty}</p>}
  </section>;
}

function AuthorizationAnalysis({ authorization, evidence, sessionId, selection }: {
  authorization: NonNullable<InvestigationReport["authorization"]>; evidence: EvidenceCitation[];
  sessionId: string | null; selection: SessionSelection;
}) {
  return <section aria-label="Authorization and policy" className="space-y-2 text-sm">
    <h4 className="font-semibold">Authorization and policy</h4>
    <p className="max-w-4xl whitespace-pre-wrap break-words">{authorization.assessment}</p>
    <p className="max-w-4xl whitespace-pre-wrap break-words">{authorization.policy_basis}</p>
    {authorization.policy_quote && <blockquote className="max-w-4xl whitespace-pre-wrap break-words border-l-2 pl-3">{authorization.policy_quote}</blockquote>}
    {authorization.policy_revision != null && <p className="text-xs text-muted-foreground">Policy revision {authorization.policy_revision}</p>}
    <ul className="space-y-1 text-xs">{authorization.evidence_indices.map((reference, index) => <li key={index}>
      {evidence[reference] ? <EvidenceLink citation={evidence[reference]} sessionId={sessionId} pin={selection} /> : "Evidence reference unavailable"}
    </li>)}</ul>
  </section>;
}

export function ReportNarrative({ report, sessionId, selection }: { report: InvestigationReport; sessionId: string | null; selection: SessionSelection }) {
  const { dateTime } = useTimeZone();
  const outcome = report.outcome ?? (report.status === "finding" ? "actionable_findings" : report.status === "no_finding" ? "no_actionable_findings" : "inconclusive");
  const scope = report.scope;
  const evidence = report.evidence ?? [];
  const label = investigationOutcomeLabel(outcome, report.verdict);
  return <div className="space-y-5 border-b pb-5">
    <div className="space-y-2">
      {report.title && <h3 className="break-words text-base font-semibold">{report.title}</h3>}
      <section aria-label="Investigation verdict" className="space-y-1">
        <p className="text-xs font-medium text-muted-foreground">{outcome === "inconclusive" ? "Status" : "Verdict"}</p>
        <p className="text-base font-semibold">{label}</p>
        {outcome === "inconclusive" && <p className="text-sm text-muted-foreground">No verdict assigned. More evidence or further investigation is needed.</p>}
        {label === "Not classified" && <p className="text-sm text-muted-foreground">This older report did not distinguish a false alert from correctly detected benign activity.</p>}
      </section>
    </div>
    <section aria-label="Executive summary" className="space-y-2 text-sm"><h4 className="font-semibold">Executive summary</h4>
      <p className="max-w-4xl whitespace-pre-wrap break-words">{report.summary || "No summary recorded."}</p>
    </section>
    {report.conclusion && <section aria-label="Investigation conclusion" className="space-y-2 text-sm">
      <h4 className="font-semibold">{outcome === "inconclusive" ? "What prevents a verdict" : "Verdict rationale"}</h4><p className="max-w-4xl whitespace-pre-wrap break-words">{report.conclusion}</p>
    </section>}
    {report.impact && <section aria-label="Investigation impact" className="space-y-2 text-sm">
      <h4 className="font-semibold">Impact</h4>
      <dl className="grid gap-3 sm:grid-cols-2">
        <div><dt className="font-medium">Observed</dt><dd className="max-w-4xl whitespace-pre-wrap break-words">{report.impact.observed}</dd></div>
        <div><dt className="font-medium">Potential</dt><dd className="max-w-4xl whitespace-pre-wrap break-words">{report.impact.potential}</dd></div>
      </dl>
    </section>}
    {report.recommendations && <section aria-label="Prioritized recommended response" className="space-y-2 text-sm">
      <h4 className="font-semibold">Recommended response</h4>
      <p className="text-xs text-muted-foreground">Recommendations only. The investigator has not performed these actions.</p>
      {report.recommendations.length ? <ol className="list-decimal space-y-3 pl-5">{report.recommendations.map((item, index) => <li key={index}>
        <p className="text-xs font-medium">{humanize(item.priority)} priority</p>
        <p className="max-w-4xl whitespace-pre-wrap break-words font-medium">{item.action}</p>
        <p className="max-w-4xl whitespace-pre-wrap break-words">{item.rationale}</p>
      </li>)}</ol> : <p>No response actions recommended in the reviewed evidence.</p>}
    </section>}
    {scope ? <section aria-label="Investigation scope" className="space-y-3 text-sm">
      <h4 className="font-semibold">Scope and reviewed evidence</h4>
      <dl className="grid min-w-0 gap-3 sm:grid-cols-2">
        <div className="min-w-0"><dt className="font-medium">User identity</dt><dd>{scope.ownership_verified ? "Verified tenant user" : "User ownership is not verified"}</dd>
          {scope.subject && <dd className="break-words">{scope.ownership_verified ? scope.subject.name || scope.subject.email : scope.subject.reported_user || "User not reported"}</dd>}
          {scope.user_id && <dd className="break-all text-xs text-muted-foreground">{scope.user_id}</dd>}</div>
        <div><dt className="font-medium">Review cutoff</dt><dd>{dateTime(scope.review_cutoff)}</dd></div>
        {scope.devices && <div className="min-w-0"><dt className="font-medium">Devices</dt><dd className="break-words">{scope.devices.map((device) => device.hostname || "Unnamed device").join(", ") || "Not recorded"}</dd></div>}
        {scope.projects && <div className="min-w-0"><dt className="font-medium">Projects</dt><dd className="break-words">{scope.projects.join(", ") || "Not recorded"}</dd></div>}
      </dl>
      {scope.target_sessions && scope.reviewed_sessions.length === 0 && <p>The investigation targeted {scope.target_sessions.length} session(s), but did not complete its review.</p>}
      <h5 className="font-medium">Reviewed sessions ({scope.reviewed_sessions.length})</h5>
      <ul className="space-y-3" aria-label="Reviewed sessions">{scope.reviewed_sessions.map((session, index) => <li key={index} className="min-w-0 space-y-1">
        {session.session_id ? <Link className="break-all font-medium hover:underline" href={sessionHref(session.session_id, { snapshot: session.snapshot_id }, "snapshot")}>{session.session_id}</Link> : <span>Archived session</span>}
        <p>Revision {session.revision} · {dateTime(session.started_at)} to {dateTime(session.ended_at)}</p>
        <p className="break-all text-xs text-muted-foreground">Snapshot {session.snapshot_id}</p>
      </li>)}</ul>
      <h5 className="font-medium">Sessions retrieved as context ({new Set(scope.context_sessions.map((session) => session.session_id).filter(Boolean)).size})</h5>
      <p className="text-xs text-muted-foreground">Context access does not establish that the complete session was reviewed or cleared.</p>
      {scope.context_sessions.length ? <ul className="space-y-2" aria-label="Context sessions">{scope.context_sessions.map((session, index) => <li key={index} className="min-w-0">
        <Link className="break-all font-medium hover:underline" data-retained-read-id={session.read_id}
          href={reportEvidenceHref(sessionId, { ...selection, read: session.read_id, item: undefined }, "investigation")}>
          {session.session_id || "Archived context session"}
        </Link>
        <p className="break-all text-xs text-muted-foreground">Read receipt {session.read_id}</p>
      </li>)}</ul> : <p className="text-muted-foreground">No additional sessions were retrieved.</p>}
    </section> : <p className="text-sm text-muted-foreground">This historical report did not record a structured scope. Its pinned snapshot and retained history reads remain available below.</p>}
    {report.timeline && <section aria-label="Investigation timeline" className="space-y-2 text-sm">
      <h4 className="font-semibold">Activity timeline</h4>
      <ol className="space-y-3 border-l pl-4">{report.timeline.map((entry, index) => <li key={index} className="space-y-1">
        <p className="max-w-4xl whitespace-pre-wrap break-words">{entry.description}</p>
        <ul className="space-y-1 text-xs">{entry.evidence_indices.map((reference, n) => <li key={n}>
          {evidence[reference] ? <EvidenceLink citation={evidence[reference]} sessionId={sessionId} pin={selection} /> : "Evidence reference unavailable"}
        </li>)}</ul>
      </li>)}</ol>
    </section>}
    {report.authorization && <AuthorizationAnalysis authorization={report.authorization} evidence={evidence} sessionId={sessionId} selection={selection} />}
    {report.alternative_explanations && <ReportTextList title="Report alternative explanations" items={report.alternative_explanations} empty="No alternative explanations recorded." />}
    {report.limitations && <ReportTextList title="Evidence and limitations" items={report.limitations} empty="No additional limitations recorded. Report coverage gaps still apply." />}
    {evidence.length > 0 && <section aria-label="Report evidence" className="space-y-2 text-sm">
      <h4 className="font-semibold">Evidence references</h4>
      <ul className="space-y-2">{evidence.map((citation, index) => <li key={index}><EvidenceLink citation={citation} sessionId={sessionId} pin={selection} /></li>)}</ul>
    </section>}
  </div>;
}

export function ReportFinding({ finding, index, sessionId, selection }: {
  finding: InvestigationFinding; index: number; sessionId: string | null; selection: SessionSelection;
}) {
  const matched = selection.finding === index;
  const element = useRef<HTMLLIElement>(null);
  const scrolled = useRef(false);
  useEffect(() => {
    if (matched && !scrolled.current && selection.ordinal === undefined && !selection.read) {
      scrolled.current = true;
      element.current?.scrollIntoView({ block: "nearest", behavior: "instant" });
    }
  }, [matched, selection.ordinal, selection.read]);
  const variant = finding.severity === "info" ? "informational" : finding.severity === "critical" || finding.severity === "high" || finding.severity === "medium" || finding.severity === "low" ? finding.severity : "outline";
  const pin = { investigation: selection.investigation, attempt: selection.attempt, snapshot: selection.snapshot, finding: index };
  return <li ref={element} aria-current={matched ? "true" : undefined} className={cn("space-y-3 py-3", matched && "border-l-[3px] border-primary bg-primary/5 pl-3")}>
    <div className="flex flex-wrap items-center gap-2"><h3 className="text-sm font-semibold">{finding.title}</h3><Badge variant={variant}>{humanize(finding.severity)}</Badge>
      {matched && <span className="text-xs font-medium">Matched finding</span>}</div>
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
      <span>Category: {detectionCategoryLabel(finding.category)}</span>
      {finding.tags?.length ? <span>Additional categories: {finding.tags.map(detectionCategoryLabel).join(", ")}</span> : null}
    </div>
    <p className="max-w-3xl whitespace-pre-wrap break-words text-sm">{finding.explanation}</p>
    {finding.authorization && <AuthorizationAnalysis authorization={finding.authorization} evidence={finding.evidence} sessionId={sessionId} selection={pin} />}
    {finding.alternative_explanations && <ReportTextList title="Alternative explanations" items={finding.alternative_explanations} empty="No alternatives recorded." />}
    {finding.severity_rationale && <section className="space-y-1 text-sm" aria-label="Severity rationale">
      <h4 className="font-semibold">Severity rationale</h4>
      <p className="max-w-3xl whitespace-pre-wrap break-words">{finding.severity_rationale}</p>
    </section>}
    {finding.timeline && <section className="space-y-2 text-sm" aria-label="Incident timeline">
      <h4 className="font-semibold">Timeline</h4>
      <ol className="space-y-3 border-l pl-4">{finding.timeline.map((entry, order) => <li key={order} className="space-y-1">
        <p className="max-w-3xl whitespace-pre-wrap break-words">{entry.description}</p>
        <ul className="space-y-1 text-xs">{entry.evidence_indices.map((reference, n) => <li key={n}>
          {finding.evidence[reference] ? <EvidenceLink citation={finding.evidence[reference]} sessionId={sessionId} pin={pin} /> : "Evidence reference unavailable"}
        </li>)}</ul>
      </li>)}</ol>
    </section>}
    {finding.impact && <section className="space-y-2 text-sm" aria-label="Incident impact">
      <h4 className="font-semibold">Impact</h4>
      <dl className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border p-3"><dt className="font-medium">Observed</dt><dd className="mt-1 whitespace-pre-wrap break-words">{finding.impact.observed}</dd></div>
        <div className="rounded-lg border p-3"><dt className="font-medium">Potential</dt><dd className="mt-1 whitespace-pre-wrap break-words">{finding.impact.potential}</dd></div>
      </dl>
    </section>}
    {finding.recommended_actions && <section className="space-y-2 text-sm" aria-label="Recommended response">
      <h4 className="font-semibold">Recommended response</h4>
      <p className="text-xs text-muted-foreground">Recommendations from the investigation. These actions have not been performed by the detector.</p>
      {finding.recommended_actions.length ? <ol className="list-decimal space-y-2 pl-5">{finding.recommended_actions.map((item, order) => <li key={order}>
        {item.priority && <p className="text-xs font-medium">{humanize(item.priority)} priority</p>}
        <p className="whitespace-pre-wrap break-words font-medium">{item.action}</p>
        <p className="whitespace-pre-wrap break-words">{item.rationale}</p>
      </li>)}</ol> : <p>No response actions recommended.</p>}
    </section>}
    {finding.uncertainties && <section className="space-y-2 text-sm" aria-label="Uncertainty and missing evidence">
      <h4 className="font-semibold">Uncertainty and missing evidence</h4>
      {finding.uncertainties.length ? <ul className="list-disc space-y-1 pl-5">{finding.uncertainties.map((item, order) =>
        <li key={order} className="whitespace-pre-wrap break-words">{item}</li>)}</ul> : <p>No additional uncertainties recorded in this finding. Session coverage gaps still apply.</p>}
    </section>}
    <ul aria-label={`Evidence citations for finding ${index}`} className="space-y-2 text-sm">
      {finding.evidence.map((citation, order) => <li key={order}><EvidenceLink citation={citation} sessionId={sessionId} pin={pin} /></li>)}
    </ul>
    {finding.action_outcomes.length > 0 && <details><summary className="w-fit cursor-pointer py-2 text-sm font-medium">Cited action outcomes</summary>
      <ul className="divide-y text-sm">{finding.action_outcomes.map((action, order) => <li key={order} className="py-2">
        <p>Execution: {humanize(action.execution)} · authorization: {humanize(action.authorization)}</p>
        <InlineCode className="break-all">{action.logical_id}</InlineCode>
      </li>)}</ul>
    </details>}
  </li>;
}

function AttemptHistory({ data, sessionId }: { data: Investigation; sessionId: string | null }) {
  const { dateTime } = useTimeZone();
  const { user } = useDashboard();
  return <details>
    <summary className="w-fit cursor-pointer py-2 text-sm font-medium">Investigation attempts ({data.attempt_count})</summary>
    {data.attempts_truncated && <PageNotice title="Attempt history is bounded">Showing {data.attempts.length} most recent attempts of {data.attempt_count}. The pinned report can still belong to an older retained attempt.</PageNotice>}
    <TableLayout><Table aria-label="Investigation attempts"><TableHeader><TableRow>
      <TableHead>Attempt</TableHead><TableHead>State</TableHead><TableHead>Completed</TableHead><TableHead>Captured records</TableHead>
    </TableRow></TableHeader><TableBody>{data.attempts.map((attempt) => <TableRow key={attempt.id} aria-current={attempt.id === data.report_attempt_id ? "true" : undefined}>
      <TableCell className="font-medium"><Link className="hover:underline" href={reportEvidenceHref(sessionId, {
        investigation: data.id, snapshot: data.snapshot_id, attempt: attempt.id,
      }, "investigation")}>Attempt {attempt.ordinal}</Link>
        <p className="text-xs text-muted-foreground">{dateTime(attempt.created_at)}</p>
      </TableCell>
      <TableCell><RecordedState value={attempt.state} /></TableCell>
      <TableCell>{dateTime(attempt.completed_at)}</TableCell>
      <TableCell className="number">{storedCount(attempt.target_item_count)}</TableCell>
    </TableRow>)}</TableBody></Table></TableLayout>
    {canAccessPage(user, "/costs/openaidr") && <Link href="/costs/openaidr" className="mt-3 inline-block text-sm underline underline-offset-4">View credit usage</Link>}
  </details>;
}

export function SessionInvestigation({ sessionId, selection }: { sessionId: string | null; selection: SessionSelection & { investigation: string } }) {
  const { dateTime } = useTimeZone();
  const router = useRouter();
  const query = selection.attempt ? `?attempt_id=${encodeURIComponent(selection.attempt)}` : "";
  const resource = useResource<Investigation>(`session-investigations/${selection.investigation}${query}`, 30000);
  const data = resource.data;
  const mismatch = Boolean(data && ((sessionId !== null && data.session_id !== sessionId) || data.id !== selection.investigation ||
    (selection.attempt && data.report_attempt_id !== selection.attempt) || (selection.snapshot && data.snapshot_id !== selection.snapshot)));
  const pin: SessionSelection = {
    ...selection, snapshot: data?.snapshot_id ?? selection.snapshot,
    attempt: data?.report_attempt_id ?? selection.attempt,
  };
  const closeRead = () => router.replace(reportEvidenceHref(sessionId, { ...pin, read: undefined, item: undefined }, "investigation"), { scroll: false });
  const report = data?.report;
  return <div id="investigation" tabIndex={-1} className="scroll-mt-4" data-page-chat-exclude>
    <PageSection title="Investigation report" description="Verdict, impact, and recommended actions for the reviewed activity."
      action={<Button variant="outline" disabled={resource.loading} onClick={() => void resource.reload()}><RefreshCw aria-hidden="true" />Refresh report</Button>}>
      <div className="space-y-4">
        {resource.error && <ErrorState message={`${resource.error} The requested investigation was not replaced.${data ? " Showing the last successful response." : ""}`} onRetry={resource.reload} />}
        {!data && !resource.error && <LoadingState label="Loading retained investigation…" />}
        {mismatch && <ErrorState message="The retained investigation does not match this session, attempt, or snapshot. No alternate report was selected." />}
        {data && !mismatch && <>
          {data.report_generated_from_state && <PageNotice title="Investigation incomplete">No completed model report was retained for this attempt. Review the interruption before investigating again.</PageNotice>}
          {!data.snapshot_current && <PageNotice title="Snapshot is stale">This report covers an earlier retained snapshot. Later activity or unfinished finalization is not included.</PageNotice>}
          {!data.configuration_current && <PageNotice title="Investigation configuration is stale">The report used detector configuration {data.detector_config_version}. Current configuration is different.</PageNotice>}
          {sessionId === null && data.session_id && <Link className="text-sm font-medium hover:underline" href={sessionHref(data.session_id)}>View triggering session</Link>}
          {!report ? <EmptyState title="No retained report" description="This selected attempt has not stored a report. Job state does not establish a completed assessment." /> : <>
            <ReportNarrative report={report} sessionId={sessionId} selection={pin} />
            {report.reason && <p className="text-sm">Stopped: {humanize(report.reason)}.</p>}
            {report.gaps.length > 0 && <PageNotice title="Report coverage gaps"><ul className="list-disc space-y-1 pl-4">{report.gaps.map((gap) => <li key={gap}>{humanize(gap)}</li>)}</ul></PageNotice>}
            {report.coverage && <p className="text-sm text-muted-foreground">Target processing: {humanize(report.coverage.status)} · {storedCount(report.coverage.target_item_count)} records · {storedCount(report.coverage.target_byte_count)} bytes · {storedCount(report.coverage.completed_chunks)} of {storedCount(report.coverage.target_chunk_count)} chunks completed.</p>}
            {selection.finding !== undefined && selection.finding >= report.findings.length && <PageNotice title="Finding reference is unavailable">The exact report does not contain finding {selection.finding}. No other finding was substituted.</PageNotice>}
            <h3 className="text-sm font-semibold">Findings and reasoning ({report.findings.length})</h3>
            <ul className="divide-y" aria-label="Retained investigation findings">{report.findings.map((finding, index) => <ReportFinding key={index} finding={finding} index={index} sessionId={sessionId} selection={pin} />)}</ul>
            <PageNotice title="Report interpretation" collapsible><p>No finding is a result for the retained evidence and stated coverage, not proof that the entire session was safe. A completed target scan does not establish complete source delivery or native execution.</p></PageNotice>
          </>}
          <details><summary className="w-fit cursor-pointer py-2 text-sm font-medium">Retained history reads ({data.read_count})</summary>
            {data.reads_truncated && <p className="text-sm">The latest {data.reads.length} of {data.read_count} receipts are listed. Citations can still open an older retained receipt directly.</p>}
            <ul className="divide-y text-sm">{data.reads.map((read) => <li key={read.id} className="flex flex-wrap items-center justify-between gap-2 py-3">
              <div><p className="font-medium">{humanize(read.tool_name)} · {humanize(read.status)}</p><p className="text-xs text-muted-foreground">{dateTime(read.created_at)}</p></div>
              <Link aria-label={`Open retained read ${read.id}`} data-retained-read-id={read.id} className="font-medium hover:underline" href={reportEvidenceHref(sessionId, { ...pin, read: read.id, item: undefined }, "investigation")}>Open retained read</Link>
            </li>)}</ul>
          </details>
          <AttemptHistory data={data} sessionId={sessionId} />
          <details><summary className="w-fit cursor-pointer py-2 text-sm font-medium">Report identifiers</summary>
            <div className="mb-3 flex flex-wrap items-center gap-3 text-sm"><RecordedState value={data.state} /><span>Snapshot revision {data.snapshot_revision}</span>
              <span>Settings {data.settings_version} · detector configuration {data.detector_config_version}</span>
              <Link className="font-medium hover:underline" href={reportEvidenceHref(sessionId, pin, "snapshot")}>View retained snapshot</Link>
            </div>
            <dl className="space-y-2 text-sm"><div><dt>Job</dt><dd><InlineCode className="break-all">{data.id}</InlineCode></dd></div>
              <div><dt>Selected attempt</dt><dd>{data.report_attempt_id ? <InlineCode className="break-all">{data.report_attempt_id}</InlineCode> : "Not recorded"}</dd></div>
              <div><dt>Snapshot</dt><dd><InlineCode className="break-all">{data.snapshot_id}</InlineCode></dd></div></dl>
          </details>
          <RetainedReadDialog key={selection.read ?? "none"} readId={selection.read ?? null} jobId={data.id} attemptId={data.report_attempt_id} item={selection.item} onClose={closeRead} />
        </>}
      </div>
    </PageSection>
    {sessionId === null && data && !mismatch && <div className="mt-4"><RetainedSnapshot snapshotId={data.snapshot_id} sessionId={data.session_id ?? ""} registrationId={data.registration_id} selection={pin} /></div>}
  </div>;
}
