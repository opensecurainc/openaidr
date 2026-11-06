"use client";

import { hasRole } from "@/lib/roles";

import { RefreshCw } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useResource } from "@/lib/use-resource";

type Query = { query_id: string; label: string; calls: number; total_exec_time: number; shared_blks_hit: number; shared_blks_read: number };
type Scan = { relid: number; relname: string; seq_scan: number; seq_tup_read: number; idx_scan: number };
type Observed<T> = { status: "ok" | "warming" | "disabled" | "limited"; items: T[]; without_baseline: number };
type SourceObservation = {
  query_id: string; label: string; calls: number; failures: number; total_time_ms: number;
  source: { page: string; card: string; endpoint: string; job: string };
};
type Diagnostics = {
  status: "ok" | "warming" | "disabled" | "unavailable";
  message?: string;
  stale?: boolean;
  checked_at: string;
  window_start: string;
  window_seconds: number;
  queries: Observed<Query>;
  sources?: {
    status: "ok" | "limited"; items: SourceObservation[]; window_seconds: number;
    omitted_groups: number; dropped_observations: number; collection_started_at: string;
  };
  scans: Observed<Scan>;
  active_total: number;
  active: { pid: number; query_id: string | null; label: string; seconds: number; wait_event_type: string | null; wait_event: string | null }[];
};
const count = (value: number) => value.toLocaleString();
const elapsed = (ms: number) => ms > 0 && ms < 0.1 ? "<0.1 ms" : ms < 1000 ? `${ms.toFixed(1)} ms` : `${(ms / 1000).toFixed(2)} s`;

function ObservationState({ status, empty, kind }: { status: Observed<unknown>["status"]; empty: boolean; kind: "queries" | "scans" }) {
  if (status === "disabled") return <EmptyState title="Query statistics unavailable" description="An operator must load and enable pg_stat_statements in this database. Active queries and table scans do not require the extension." />;
  if (status === "limited") return <EmptyState title="Statistics limit reached" description="The database contains more entries than this bounded diagnostic can compare. No partial ranking is shown." />;
  if (status === "warming") return <EmptyState title="Collecting a baseline" description="The server collects samples in the background about every 30 seconds. Resets, restarts, and query eviction require a new observation window." />;
  if (empty) return <EmptyState title={`No ${kind === "queries" ? "completed queries" : "scan activity"} measured`} description="No comparable counter increases were recorded in this observation window." />;
  return null;
}

export function DatabaseDiagnosticsPanel() {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const permitted = hasRole(user, "it_admin");
  const resource = useResource<Diagnostics>(permitted ? "system/diagnostics" : null, 30000, true, { sourceCard: "database-diagnostics" });
  if (!permitted) return null;
  const data = resource.data;
  const available = data?.status === "ok";
  const historical = Boolean(resource.error || data?.stale);
  const maximum = available ? Math.max(...data.queries.items.map((item) => item.total_exec_time), 1) : 1;
  const sourceRows = data?.sources?.items.slice(0, 10) ?? [];
  const omittedSourceGroups = data?.sources ? data.sources.omitted_groups + data.sources.items.length - sourceRows.length : 0;
  return <PageSection title="PostgreSQL diagnostics" description="Query execution, waits, and scans sampled in the background about every 30 seconds."
    action={<Button variant="outline" size="sm" onClick={resource.reload} disabled={resource.loading} aria-label="Refresh database diagnostics"><RefreshCw className={`size-3.5 ${resource.loading ? "animate-spin" : ""}`} />Refresh</Button>}>
    <div className="space-y-4">
      {resource.error && <ErrorState message={`${resource.error}${data ? " Showing historical observations; current activity is unknown." : ""}`} onRetry={resource.reload} />}
      {!data && !resource.error && <LoadingState label="Loading database diagnostics" />}
      {data && !available && <EmptyState title={data.status === "warming" ? "Starting database diagnostics" : data.status === "disabled" ? "Database diagnostics not enabled" : "Database diagnostics unavailable"} description={data.message || "Database diagnostics could not be collected."} />}
      {available && <>
        {data.stale && !resource.error && <PageNotice title="Database diagnostics are delayed">Showing historical observations; current activity is unknown. The server will continue collecting in the background.</PageNotice>}
        <div role="region" aria-label="Queries by source">
          <h3 className="mb-1 text-sm font-semibold">Queries by source</h3>
          <p className="mb-3 text-xs text-muted-foreground">Page, card, API request, or background job recorded for each application query. Timings include database waits and transport; they are separate from the PostgreSQL totals below.</p>
          {!data.sources ? <p className="text-sm text-muted-foreground">Source attribution is unavailable on this backend.</p> : <>
            <p className="mb-3 text-xs text-muted-foreground">Observed {Math.round(data.sources.window_seconds)} seconds in this API process. Counts include failed calls. Page and card labels are reported by the dashboard; a shared request can serve several cards.</p>
            {data.sources.dropped_observations > 0 && <p className="mb-3 text-sm text-muted-foreground">Partial observations: {count(data.sources.dropped_observations)} calls were not retained since collection started.</p>}
            {!data.sources.items.length ? <p className="text-sm text-muted-foreground">No application queries observed in this sample. Collection continues in the background.</p> : <TableLayout><Table>
              <TableHeader><TableRow><TableHead>Query group</TableHead><TableHead>Source</TableHead><TableHead className="text-right">Calls</TableHead><TableHead className="text-right">Failed</TableHead><TableHead className="text-right">Total time</TableHead><TableHead className="text-right">Mean time</TableHead></TableRow></TableHeader>
              <TableBody>{sourceRows.map((row) => <TableRow key={`${row.query_id}:${JSON.stringify(row.source)}`}>
                <TableCell><span className="font-medium">{row.label}</span><p className="font-mono text-sm font-normal text-muted-foreground">{row.query_id}</p></TableCell>
                <TableCell className="min-w-48 max-w-80 whitespace-normal">
                  <p className="font-medium">{row.source.job ? `Background job: ${row.source.job}` : row.source.page || (row.source.endpoint ? "API request" : "Unknown source")}</p>
                  {row.source.card && <p>{row.source.card}</p>}
                  {row.source.page && !row.source.card && <p className="text-muted-foreground">Card not reported</p>}
                  {row.source.endpoint && <p className="break-all font-mono text-sm font-normal text-muted-foreground">{row.source.endpoint}</p>}
                </TableCell>
                <TableCell className="number text-right">{count(row.calls)}</TableCell><TableCell className="number text-right">{count(row.failures)}</TableCell>
                <TableCell className="number text-right">{elapsed(row.total_time_ms)}</TableCell><TableCell className="number text-right">{elapsed(row.total_time_ms / row.calls)}</TableCell>
              </TableRow>)}</TableBody>
            </Table></TableLayout>}
            {omittedSourceGroups > 0 && <p className="mt-2 text-xs text-muted-foreground">Showing the {count(sourceRows.length)} source groups with the most elapsed time; {count(omittedSourceGroups)} more groups are not shown.</p>}
          </>}
        </div>
        <p className="text-xs text-muted-foreground">Observed {Math.round(data.window_seconds)} seconds within the last 5 minutes · {dateTime(data.window_start)} to {dateTime(data.checked_at)}{historical ? " · Historical readings" : ""}</p>
        <div>
          <h3 className="mb-1 text-sm font-semibold">Top queries by execution time</h3>
          <p className="mb-3 text-xs text-muted-foreground">Elapsed execution time includes waits and is not CPU time. Up to 10 completed query groups, for the API database role.</p>
          <ObservationState status={data.queries.status} empty={!data.queries.items.length} kind="queries" />
          {data.queries.status === "ok" && data.queries.items.length > 0 && <TableLayout><Table>
            <TableHeader><TableRow><TableHead>Query group</TableHead><TableHead className="text-right">Calls</TableHead><TableHead className="text-right">Total time</TableHead><TableHead className="text-right">Mean time</TableHead><TableHead className="text-right">Buffer hits</TableHead><TableHead className="text-right">Buffer reads</TableHead></TableRow></TableHeader>
            <TableBody>{data.queries.items.map((row) => <TableRow key={row.query_id}>
              <TableCell><span className="font-medium">{row.label}</span><p className="font-mono text-sm font-normal text-muted-foreground">{row.query_id}</p></TableCell>
              <TableCell className="number text-right">{count(row.calls)}</TableCell>
              <TableCell className="number text-right">{elapsed(row.total_exec_time)}<div className="mt-1 h-2 w-full overflow-hidden rounded-xs bg-muted" aria-hidden="true"><div className="h-full rounded-xs bg-chart-1" style={{ width: `${100 * row.total_exec_time / maximum}%` }} /></div></TableCell>
              <TableCell className="number text-right">{elapsed(row.total_exec_time / row.calls)}</TableCell>
              <TableCell className="number text-right">{count(row.shared_blks_hit)}</TableCell><TableCell className="number text-right">{count(row.shared_blks_read)}</TableCell>
            </TableRow>)}</TableBody>
          </Table></TableLayout>}
          {data.queries.without_baseline > 0 && <p className="mt-2 text-xs text-muted-foreground">{count(data.queries.without_baseline)} query groups lack a comparable baseline and are excluded.</p>}
        </div>
        <div>
          <h3 className="mb-1 text-sm font-semibold">{historical ? "Last observed active queries" : "Active queries and waits"}</h3>
          <p className="mb-3 text-xs text-muted-foreground">{count(data.active_total)} active · Snapshot at {dateTime(data.checked_at)} · Up to 10 oldest client queries for the API database role.</p>
          {!data.active.length ? <p className="text-sm text-muted-foreground">No active queries observed in this sample.</p> : <TableLayout><Table>
            <TableHeader><TableRow><TableHead>Query group</TableHead><TableHead className="text-right">PID</TableHead><TableHead className="text-right">Elapsed</TableHead><TableHead>Wait</TableHead></TableRow></TableHeader>
            <TableBody>{data.active.map((row) => <TableRow key={row.pid}><TableCell><span className="font-medium">{row.label}</span><p className="font-mono text-sm font-normal text-muted-foreground">{row.query_id || "Query ID unavailable"}</p></TableCell><TableCell className="number text-right">{row.pid}</TableCell><TableCell className="number text-right">{elapsed(row.seconds * 1000)}</TableCell><TableCell>{row.wait_event_type ? `${row.wait_event_type}: ${row.wait_event}` : "No wait reported"}</TableCell></TableRow>)}</TableBody>
          </Table></TableLayout>}
        </div>
        <div>
          <h3 className="mb-1 text-sm font-semibold">Table scan activity</h3>
          <p className="mb-3 text-xs text-muted-foreground">Up to 10 application tables or partitions, ranked by rows read in sequential scans. Scans are not attributed to individual queries.</p>
          <ObservationState status={data.scans.status} empty={!data.scans.items.length} kind="scans" />
          {data.scans.status === "ok" && data.scans.items.length > 0 && <TableLayout><Table>
            <TableHeader><TableRow><TableHead>Table or partition</TableHead><TableHead className="text-right">Sequential scans</TableHead><TableHead className="text-right">Rows read</TableHead><TableHead className="text-right">Index scans</TableHead></TableRow></TableHeader>
            <TableBody>{data.scans.items.map((row) => <TableRow key={row.relid}><TableCell className="max-w-80 break-all whitespace-normal font-mono text-sm font-normal">{row.relname}</TableCell><TableCell className="number text-right">{count(row.seq_scan)}</TableCell><TableCell className="number text-right">{count(row.seq_tup_read)}</TableCell><TableCell className="number text-right">{count(row.idx_scan)}</TableCell></TableRow>)}</TableBody>
          </Table></TableLayout>}
          {data.scans.without_baseline > 0 && <p className="mt-2 text-xs text-muted-foreground">{count(data.scans.without_baseline)} tables lack a comparable baseline and are excluded.</p>}
        </div>
      </>}
      <PageNotice title="About database diagnostics" collapsible>
        Application source rows measure cursor execute calls in this API process, including failed calls, and use template hashes unrelated to PostgreSQL query IDs. They cover a rolling 5-minute window and continue while this page is closed. A failed or stopped background collector clears source history. Statistics are sampled in the background about every 30 seconds and retained in memory for 5 minutes. You can close this page; collection continues. Refresh reads the latest sample without starting collection. API restarts clear the history. Samples older than 60 seconds are marked as delayed. These observations cannot explain spikes from before collection started or capture every brief wait. Query labels are inferred from known query shapes; query IDs support operator investigation without exposing SQL text or values. Buffer reads can be served by the operating system cache. An operator must enable diagnostics for a database dedicated to one tenant; shared databases are not supported. See the <a className="text-primary underline" href="https://github.com/opensecurainc/openaidr/blob/main/deploy/README.md#postgresql-diagnostics" target="_blank" rel="noreferrer">deployment guide</a> for setup and reset limitations.
      </PageNotice>
    </div>
  </PageSection>;
}
