"use client";

import Link from "next/link";
import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { CollectionFooter, EmptyState, ErrorState, LoadingState, PageSection, PageToolbar, TableLayout } from "@/components/page-layout";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Status } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { sessionHref, type DetectionEligibility } from "@/lib/session";
import { productLabel } from "@/lib/api";
import { usePagedResource } from "@/lib/use-resource";

const labels: Record<string, string> = {
  disabled: "Detection off", eligible: "Eligible, waiting", waiting: "Waiting",
  selected: "Selected", reviewed: "Reviewed", not_selected: "Not selected",
  excluded: "Not eligible", unavailable: "Unavailable",
};
const reasons: Record<string, string> = {
  tenant_disabled: "Session investigations are disabled for this tenant.",
  scheduling_disabled: "This session passed selection, but server scheduling is disabled.",
  worker_unavailable: "This session passed selection, but no ready worker is available for the configured model.",
  evaluation_pending: "Waiting for an up-to-date selection evaluation.",
  evaluation_failed: "The last selection evaluation failed. Eligibility is not established.",
  sensor_unavailable: "The session's sensor is disabled or deleted.",
  legacy_session: "This managed session uses legacy assessment and is outside this investigation pipeline.",
  owner_unavailable: "This managed session needs a verified, active tenant owner.",
  queued: "Queued for investigation, subject to worker capacity and configured budgets.",
  running: "An investigation is running for the selected snapshot.",
  completed: "An investigation completed. Its report applies to the reviewed snapshot.",
  inconclusive: "The investigation was inconclusive. This does not clear the session.",
  reviewed_evidence: "This evidence was already reviewed with the current detector configuration.",
  outside_history_window: "The session's last activity is outside the configured recent-history window.",
  pending_signals: "Waiting for risk summaries from other sessions before ranking candidates.",
  pending_assessments: "Waiting for pending action assessments.",
  session_active: "Waiting for session end or idle time, delivery grace, and pending evidence.",
  coverage_incomplete: "Waiting for evidence coverage or the configured gap policy.",
  outside_selection_budget: "Not selected by the current risk criteria and investigation budget. This does not establish low risk.",
  threshold_not_exceeded: "The stored risk total does not exceed the configured legacy threshold.",
};

export function EligibilityDecision({ value }: { value?: DetectionEligibility }) {
  const { dateTime } = useTimeZone();
  if (!value) return <p className="text-sm text-muted-foreground">Detection eligibility is not reported by this backend.</p>;
  return <div className="min-w-0 space-y-1 text-sm">
    <Status tone={value.status === "eligible" || value.status === "selected" ? "info" : value.status === "disabled" || value.status === "unavailable" ? "warning" : "neutral"}>{labels[value.status] ?? "Unknown"}</Status>
    <p className="max-w-xl whitespace-normal break-words">{reasons[value.reason] ?? "No recognized selection explanation is available."}</p>
    <p className="text-xs text-muted-foreground">{value.evaluated_at ? `Last evaluated ${dateTime(value.evaluated_at)}` : "No stored selection evaluation"}</p>
  </div>;
}

type EligibilityRow = {
  id: string; started_at: string; last_event_at: string; product: string;
  hostname: string; reported_user: string; eligibility: DetectionEligibility;
};

export function DetectionEligibilityList({ range }: { range: string }) {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState("");
  const sessions = usePagedResource<EligibilityRow>(user ? `detections/eligibility?limit=25&range=${range}&q=${encodeURIComponent(query)}` : null);
  return <PageSection title="Session eligibility" description={`Captured sessions started in the last ${range.slice(0, -1)} days. Eligibility uses the latest stored selection decision; worker readiness and budgets still apply.`}>
    <PageToolbar action={<Button variant="outline" size="sm" disabled={sessions.loading} onClick={sessions.reload}><RefreshCw aria-hidden="true" />Refresh eligibility</Button>}>
      <form className="flex w-full max-w-xl flex-wrap gap-2" onSubmit={(event) => { event.preventDefault(); setQuery(draft.trim()); }}>
        <Input aria-label="Search detection eligibility" placeholder="User, device, or session ID" maxLength={200} value={draft} onChange={(event) => setDraft(event.target.value)} className="min-w-0 flex-1 basis-48" />
        <Button type="submit" variant="outline">Search</Button>
      </form>
    </PageToolbar>
    <p className="mb-4 max-w-4xl text-xs text-muted-foreground">Eligibility is decided per session. Verified user ownership permits recent-session context; ordinary sessions without a verified owner can still be investigated using their own evidence. A reported OS username does not grant history access.</p>
    {sessions.error && <ErrorState title="Unable to load session eligibility" message={`${sessions.error}${sessions.updated ? " Showing the last successful result." : ""}`} onRetry={sessions.reload} />}
    {sessions.loading && !sessions.updated ? <LoadingState label="Loading session eligibility…" /> : sessions.items.length ? <>
      <TableLayout><Table aria-label="Session detection eligibility" className="min-w-[760px] table-fixed"><TableHeader><TableRow>
        <TableHead>Session</TableHead><TableHead>User and context</TableHead><TableHead>Eligibility and reason</TableHead>
      </TableRow></TableHeader><TableBody>{sessions.items.map((session) => <TableRow key={session.id} data-page-chat-exclude>
        <TableCell className="max-w-xs align-top whitespace-normal break-words"><Link href={sessionHref(session.id)} className="font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring">{productLabel(session.product)} · {session.hostname || "Unnamed device"}</Link>
          <p className="mt-1 text-xs text-muted-foreground">Started {dateTime(session.started_at)}</p><p className="break-all text-xs text-muted-foreground">{session.id}</p></TableCell>
        <TableCell className="max-w-xs align-top whitespace-normal"><p className="break-words">{session.eligibility.owner ? session.eligibility.owner.name || session.eligibility.owner.email : session.reported_user || "Not reported"}</p>
          <p className="text-xs text-muted-foreground">{session.eligibility.owner ? "Verified tenant user" : "Reported OS user; ownership unverified"}</p>
          <p className="mt-1 text-xs">{session.eligibility.history_available ? "Recent user history available" : "Session evidence only"}</p></TableCell>
        <TableCell className="max-w-lg align-top whitespace-normal"><EligibilityDecision value={session.eligibility} /></TableCell>
      </TableRow>)}</TableBody></Table></TableLayout>
      <CollectionFooter count={sessions.items.length} label="sessions" hasMore={Boolean(sessions.nextCursor)} busy={sessions.loadingMore} onLoadMore={sessions.loadMore} />
    </> : !sessions.error && <EmptyState title="No sessions match" description="Try another user, device, session ID, or date range." />}
  </PageSection>;
}
