"use client";

import { hasRole } from "@/lib/roles";

import { RefreshCw } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { number } from "@/lib/api";
import { useResource } from "@/lib/use-resource";

type DatabaseHealth = { status: "disabled"; message: string } | {
  ok: boolean;
  checked_at: string;
  latency_ms: number | null;
  pools: {
    name: string;
    size: number;
    available: number;
    maximum: number;
    waiting: number;
  }[];
  activity: {
    active_queries: number;
    long_running_queries: number;
    lock_waits: number;
    idle_transactions: number;
    oldest_query_seconds: number;
    oldest_transaction_seconds: number;
    untracked_sessions: number;
  } | null;
};

function elapsed(seconds: number) {
  if (seconds > 0 && seconds < 1) return "<1 s";
  if (seconds < 60) return `${Math.floor(seconds)} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${Math.floor(seconds % 60)} s`;
  return `${Math.floor(seconds / 3600)} h ${Math.floor((seconds % 3600) / 60)} min`;
}

export function DatabaseHealthPanel({ connection, connectionStale }: {
  connection?: { ok: boolean; latency_ms: number };
  connectionStale: boolean;
}) {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const permitted = hasRole(user, "it_admin");
  const resource = useResource<DatabaseHealth>(permitted ? "system/database" : null, 30000, false, { sourceCard: "database-health" });
  const health = resource.data && "pools" in resource.data ? resource.data : null;
  const disabled = resource.data && "status" in resource.data ? resource.data.message : "";
  const activity = health?.activity;
  const pressure = health?.pools.some((pool) => pool.waiting > 0 ||
    (pool.available === 0 && pool.size >= pool.maximum));
  return (
    <PageSection
      title="Database health"
      className="min-w-0"
      action={permitted && (
        <Button variant="outline" size="sm" onClick={resource.reload} disabled={resource.loading}>
          <RefreshCw aria-hidden="true" className={resource.loading ? "animate-spin" : ""} />
          {resource.loading ? "Refreshing" : "Refresh"}
        </Button>
      )}
    >
      {resource.error && (
        <ErrorState
          message={`${resource.error}${resource.data ? " Showing stale data from the last successful response." : ""}`}
          onRetry={resource.reload}
        />
      )}
      {!permitted || disabled ? (
        <div className="space-y-3">
          {connection && (
            <div>
              <Status tone={connectionStale ? "neutral" : connection.ok ? "ok" : "critical"}>
                {connection.ok ? "Reachable" : "Check failed"}
              </Status>
              <p className="mt-1 text-xs text-muted-foreground">
                {connectionStale ? "Last API check is stale." : "Last API check."}
                {connection.ok && ` ${number(connection.latency_ms)} ms round trip.`}
              </p>
            </div>
          )}
          <p className="text-sm text-muted-foreground">{disabled || "Pool and query diagnostics require the IT Admin role."}</p>
        </div>
      ) : (
        <>
          {!health ? (
            !resource.error && <LoadingState label="Loading database health" />
          ) : (
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Status tone={!health.ok ? "critical" : pressure ? "warning" : "ok"} className="text-sm">
                  {!health.ok ? "Check unavailable" : pressure ? "Connection pressure" : "Reachable"}
                </Status>
                {health.ok && <span className="text-xs text-muted-foreground">Check time {number(health.latency_ms ?? 0)} ms</span>}
              </div>
              {!health.ok && (
                <p className="text-sm text-muted-foreground">The API could not complete the database check.</p>
              )}
              {health.pools.length > 0 ? <div>
                <table className="w-full text-sm">
                  <caption className="sr-only">Connection pools for this API process. Busy or opening connections / pool limit.</caption>
                  <thead className="text-xs text-muted-foreground">
                    <tr>
                      <th scope="col" className="pb-1 text-left font-normal">Connection pool</th>
                      <th scope="col" className="pb-1 pl-4 text-right font-normal">Busy / opening</th>
                      <th scope="col" className="pb-1 pl-4 text-right font-normal">Waiting</th>
                    </tr>
                  </thead>
                  <tbody>
                    {health.pools.map((pool) => (
                      <tr key={pool.name}>
                        <th scope="row" className="pt-1 text-left font-normal">{pool.name === "data" ? "Data" : "Authentication"}</th>
                        <td className="number pt-1 pl-4 text-right">{number(Math.max(0, pool.size - pool.available))} / {number(pool.maximum)}</td>
                        <td className="number pt-1 pl-4 text-right">{number(pool.waiting)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div> : <p className="text-sm text-muted-foreground">Connection pool statistics unavailable.</p>}
              {activity ? (
                <>
                  <dl className="grid grid-cols-2 gap-x-4 gap-y-1 border-t pt-2">
                    {[
                      ["Active queries", number(activity.active_queries)],
                      ["Queries over 30 s", number(activity.long_running_queries)],
                      ["Waiting on locks", number(activity.lock_waits)],
                      ["Idle transactions", number(activity.idle_transactions)],
                      ["Oldest active query", elapsed(activity.oldest_query_seconds)],
                      ["Oldest transaction", elapsed(activity.oldest_transaction_seconds)],
                    ].map(([label, value]) => (
                      <div key={label} className="flex flex-wrap items-baseline justify-between gap-x-2 gap-y-0.5">
                        <dt className="text-xs text-muted-foreground">{label}</dt>
                        <dd className="number shrink-0 text-sm font-semibold">{value}</dd>
                      </div>
                    ))}
                  </dl>
                  {activity.untracked_sessions > 0 && (
                    <p className="text-sm text-muted-foreground">Activity is incomplete: {number(activity.untracked_sessions)} sessions do not report query activity.</p>
                  )}
                </>
              ) : (
                <p className="border-t pt-2 text-sm text-muted-foreground">Query activity unavailable.</p>
              )}
              <p className="text-xs text-muted-foreground">Checked {dateTime(health.checked_at)}</p>
            </div>
          )}
        </>
      )}
    </PageSection>
  );
}
