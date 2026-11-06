"use client";

import Link from "next/link";
import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTimeZone } from "@/components/time-zone-context";
import { number, productLabel } from "@/lib/api";
import { sessionHref } from "@/lib/session";
import { useResource } from "@/lib/use-resource";

type Band = "all" | "meets" | "below" | "unknown";
type Group = "sessions" | "users";
const bands: [Band, string][] = [["all", "All"], ["meets", "Meets threshold"], ["below", "Below"], ["unknown", "Unknown"]];
const coverageLabels = { complete: "Assessed", partial: "Partially assessed", pending: "Assessment pending",
  not_assessed: "Not assessed", updating: "Updating summary", unknown: "Coverage unknown" };
type Ranking = {
  group: Group; band: Band; selection_policy: string; history_days: number; until: string;
  criteria: { action_risk_threshold: number; urgent_risk_threshold: number; session_high_risk_actions: number; user_high_risk_actions: number };
  summary: { total: number; meets: number; below: number; unknown: number } | null;
  items: { id: string; rank: number; product: string | null; hostname: string | null; reported_user: string | null;
    user_id: string | null; user_name: string | null; user_email: string | null;
    peak: number | null; high_actions: number | null; session_count: number; high_risk_sessions: number | null;
    band: Exclude<Band, "all">; last_event_at: string; updated_at: string | null;
    score_coverage?: { status: keyof typeof coverageLabels; assessed: number | null; targets: number | null; pending: number | null } }[];
  next_cursor: string;
};

export function DetectionRankings() {
  const [group, setGroup] = useState<Group>("sessions");
  const [band, setBand] = useState<Band>("all");
  const [cursors, setCursors] = useState<string[]>([]);
  const { dateTime } = useTimeZone();
  const resource = useResource<Ranking>(`detections/rankings?group=${group}&band=${band}&limit=5&cursor=${encodeURIComponent(cursors.at(-1) ?? "")}`);
  const data = resource.data?.group === group && resource.data.band === band ? resource.data : null;
  const criteria = data?.criteria;
  const threshold = criteria && (group === "sessions" ? criteria.session_high_risk_actions : criteria.user_high_risk_actions);
  const refresh = () => { if (cursors.length) setCursors([]); else void resource.reload(); };
  return <PageSection title="Highest risk scores" description={data?.history_days != null ? `Recent activity: ${data.history_days} days · Highest score first` : undefined}
    action={<>
      <div role="group" aria-label="Rank sessions or users" className="flex gap-1">
        {(["sessions", "users"] as const).map(value => <Button key={value} size="responsive" variant={group === value ? "outline" : "ghost"} aria-pressed={group === value}
          onClick={() => { setGroup(value); setBand("all"); setCursors([]); }}>{value === "sessions" ? "Sessions" : "Users"}</Button>)}
      </div>
      <Button variant="outline" size="header-icon" aria-label="Refresh rankings" onClick={refresh} disabled={resource.loading}><RefreshCw aria-hidden="true" /></Button>
    </>}>
    {resource.error && <ErrorState title="Unable to load risk rankings" message={`${resource.error}${data ? " Showing the last successful comparison." : ""}`} onRetry={refresh} />}
    {!data && !resource.error && <LoadingState label="Loading risk rankings…" />}
    {data && data.selection_policy !== "risk_budget" && <p className="text-sm text-muted-foreground">Risk threshold rankings are available for percentage-based selection. This tenant uses legacy selection. <Link href="/detection-rules" className="underline">View investigation settings</Link>.</p>}
    {data?.summary && criteria && threshold != null && <>
      <div role="group" aria-label="Filter by threshold comparison" className="mb-2 flex flex-wrap gap-1">
        {bands.map(([value, label]) => <Button key={value} size="responsive" variant={band === value ? "secondary" : "ghost"} aria-pressed={band === value}
          onClick={() => { setBand(value); setCursors([]); }}>
          <span>{label}</span><span className="font-semibold">{number(data.summary![value === "all" ? "total" : value])}</span>
        </Button>)}
      </div>
      <p className="mb-3 text-xs text-muted-foreground"><strong>High-risk action: score ≥ {criteria.action_risk_threshold}.</strong>{" "}
        {group === "sessions" ? `Session threshold: ${threshold} high-risk actions or urgent score ≥ ${criteria.urgent_risk_threshold}.` : `User pattern: ${threshold} high-risk actions across 2+ verified sessions.`}</p>
      {data.items.length ? <TableLayout><Table aria-label="Detection risk rankings" className="min-w-[720px] table-fixed"><TableHeader><TableRow>
        <TableHead className="w-12">Rank</TableHead><TableHead className="w-1/3">{group === "sessions" ? "Session / user" : "Verified user"}</TableHead>
        <TableHead>Highest score</TableHead><TableHead>High-risk actions</TableHead>{group === "users" && <TableHead>Sessions</TableHead>}<TableHead>{group === "users" ? "User pattern" : "Threshold"}</TableHead>
      </TableRow></TableHeader><TableBody>{data.items.map(row => <TableRow key={row.id} data-page-chat-exclude>
        <TableCell className="align-top">{row.rank}</TableCell>
        <TableCell className="align-top whitespace-normal break-words">{group === "sessions" ?
          <Link href={sessionHref(row.id)} title={`Session ${row.id}`} className="font-medium hover:underline">{productLabel(row.product || "")} · {row.hostname || "Unnamed device"}</Link>
          : <p className="font-medium" title={`${number(row.session_count)} recent sessions`}>{row.user_name || row.user_email}</p>}
          <p className="text-xs text-muted-foreground">{group === "sessions" ? <>
            {row.user_id ? row.user_name || row.user_email : row.reported_user || "User not reported"}{!row.user_id && " (unverified)"} · <span title={row.id}>{row.id.slice(0, 8)}</span>
          </> : row.user_email} · {coverageLabels[row.score_coverage?.status ?? "unknown"] ?? coverageLabels.unknown}
            {row.score_coverage?.assessed != null && row.score_coverage.targets != null && ` · ${number(row.score_coverage.assessed)} / ${number(row.score_coverage.targets)} actions`}
            {!!row.score_coverage?.pending && ` · ${number(row.score_coverage.pending)} pending`}
          </p>
        </TableCell>
        <TableCell className="align-top whitespace-normal">{row.peak == null ? "Unavailable" : <>
          <span className="font-semibold">{row.peak}</span>{group === "sessions" && <p className="text-xs text-muted-foreground">{row.peak >= criteria.urgent_risk_threshold ? "Urgent" : `${Number((criteria.urgent_risk_threshold - row.peak).toFixed(2))} below urgent`}</p>}
        </>}</TableCell>
        <TableCell className="align-top whitespace-normal">{row.high_actions == null ? "Unavailable" : <>
          <span className="font-medium">{number(row.high_actions)} / {threshold}</span>{row.high_actions < threshold && <p className="text-xs text-muted-foreground">{threshold - row.high_actions} short</p>}
        </>}</TableCell>
        {group === "users" && <TableCell className="align-top whitespace-normal">{row.high_risk_sessions == null ? "Unavailable" : <><span className="font-medium">{row.high_risk_sessions} / 2</span>{row.high_risk_sessions < 2 && <p className="text-xs text-muted-foreground">{2 - row.high_risk_sessions} short</p>}</>}</TableCell>}
        <TableCell className="align-top whitespace-normal"><Status tone={row.band === "meets" ? "critical" : "neutral"} title={row.updated_at ? `Scores updated ${dateTime(row.updated_at)}` : undefined}>{bands.find(([value]) => value === row.band)?.[1]}</Status></TableCell>
      </TableRow>)}</TableBody></Table></TableLayout> : <EmptyState title="No matching risk comparisons" description="Choose another threshold filter or refresh recent activity." />}
      <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>Page {cursors.length + 1} · {data.items.length} shown · {number(data.summary[band === "all" ? "total" : band])} {group} in this filter</span>
        <div className="flex gap-2"><Button variant="outline" size="responsive" disabled={!cursors.length || resource.loading} onClick={() => setCursors(cursors.slice(0, -1))}>Previous</Button>
          <Button variant="outline" size="responsive" disabled={!data.next_cursor || resource.loading} onClick={() => setCursors([...cursors, data.next_cursor])}>Next</Button></div>
      </div>
      <div className="mt-1"><PageNotice title="How ranking works" collapsible>
        <p>Highest action score first; ties use high-risk action count and recent activity. As of {dateTime(data.until)}. Rankings can change as scores arrive.</p>
        <p>This follows the scheduler&apos;s recent-activity window, independently of the pipeline&apos;s session start date range. Active sensors and eligible managed-session ownership are required to enter this view.</p>
        <p>{group === "sessions"
          ? "Threshold comparison includes the session action count or urgent score. User patterns can also select a session."
          : "A user's score is the highest action score across their verified recent sessions. Threshold comparison uses the user-pattern action count across at least two contributing sessions with high-risk actions. Individual sessions can also qualify on their own risk."} Meeting a threshold does not guarantee selection or a completed inspection. Session settling, worker availability, and budgets still apply.</p>
        <p>Counts cover the full population, including when detection is off. Missing or stale scores are unknown; a user with any session without current scores also has an unknown comparison. Unscored actions can change these comparisons. Below threshold does not mean safe.</p>
        <p>Coverage counts distinct actions with stored scores. Assessment pending means an assessment is in progress; updating summary means stored activity is being aggregated. Activity without a live score stays not assessed. Aggregation makes no model calls.</p>
      </PageNotice></div>
    </>}
  </PageSection>;
}
