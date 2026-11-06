"use client";

import Link from "next/link";
import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { CollectionFooter, EmptyState, ErrorState, LoadingState, PageSection, PageToolbar } from "@/components/page-layout";
import { useTimeZone } from "@/components/time-zone-context";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { humanize, investigationHref, investigationOutcomeLabel, type InvestigationReportListItem } from "@/lib/session";
import { usePagedResource } from "@/lib/use-resource";

export function InvestigationReports() {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const [outcome, setOutcome] = useState("all");
  const reports = usePagedResource<InvestigationReportListItem>(user ? `session-investigations?limit=25&outcome=${outcome}` : null);
  return <PageSection title="Investigation reports" description="Verdicts, impact, and recommended actions for investigated activity.">
    <PageToolbar action={<Button variant="outline" size="sm" onClick={reports.reload} disabled={reports.loading}><RefreshCw aria-hidden="true" />Refresh reports</Button>}>
      <Select value={outcome} onValueChange={setOutcome}>
        <SelectTrigger aria-label="Report outcomes" className="h-auto min-h-10 w-full max-w-sm whitespace-normal text-left"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All report outcomes</SelectItem>
          {["true_positive", "false_positive", "true_positive_non_malicious", "inconclusive"].map((value) =>
            <SelectItem key={value} value={value}>{investigationOutcomeLabel(value)}</SelectItem>)}
          <SelectItem value="pending">Awaiting report</SelectItem>
        </SelectContent>
      </Select>
    </PageToolbar>
    {reports.error && <ErrorState message={`${reports.error}${reports.updated ? " Showing the last successful reports." : ""}`} onRetry={reports.reload} />}
    {reports.loading && !reports.updated ? <LoadingState label="Loading investigation reports…" /> : reports.items.length ? <>
      <ul className="divide-y" aria-label="Investigation report list">
        {reports.items.map((report) => {
          const severity = report.severity;
          const tone = severity === "high" || severity === "critical" || severity === "medium" || severity === "low" ? severity : "outline";
          return <li key={report.id} className="min-w-0 space-y-3 py-4" data-page-chat-exclude>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 flex-1 space-y-1">
                <Link className="break-words text-sm font-semibold underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                  href={investigationHref(report.id, { attempt: report.report_attempt_id ?? undefined, snapshot: report.snapshot_id })}>
                  {report.title || "Session investigation"}
                </Link>
                <p className="max-w-4xl whitespace-pre-wrap break-words text-sm text-muted-foreground">{report.summary || "The investigation has not retained a summary."}</p>
              </div>
              {severity && <Badge variant={tone}>{humanize(severity)} severity</Badge>}
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-2 text-xs">
              <span className="font-medium">{investigationOutcomeLabel(report.outcome, report.verdict)}</span>
              {!report.outcome && <span>Run: {humanize(report.state)}</span>}
            </div>
            <dl className="grid gap-x-4 gap-y-2 text-xs sm:grid-cols-2 xl:grid-cols-4">
              <div className="min-w-0"><dt className="text-muted-foreground">{report.subject.ownership_verified ? "Verified user" : "Reported user"}</dt>
                <dd className="break-words">{report.subject.ownership_verified ? report.subject.name || report.subject.email || "Unavailable" : report.subject.reported_user || "Not reported"}</dd></div>
              <div className="min-w-0"><dt className="text-muted-foreground">Device</dt><dd className="break-words">{report.subject.hostname || "Not reported"}</dd></div>
              <div><dt className="text-muted-foreground">Created</dt><dd>{dateTime(report.created_at)}</dd></div>
              <div><dt className="text-muted-foreground">Evidence and configuration</dt><dd>{report.snapshot_current ? "Current snapshot" : "Earlier snapshot"} · {report.configuration_current ? "Current configuration" : "Earlier configuration"}</dd></div>
            </dl>
          </li>;
        })}
      </ul>
      <CollectionFooter count={reports.items.length} label="investigations" hasMore={Boolean(reports.nextCursor)} busy={reports.loadingMore} onLoadMore={reports.loadMore} />
    </> : !reports.error && <EmptyState title="No investigation reports match" description="Select another outcome or wait for new investigations. An empty list does not establish that activity is safe." />}
  </PageSection>;
}
