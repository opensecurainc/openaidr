"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { GatewayRequests } from "@/components/gateway-requests";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { displayText } from "@/lib/display";
import { useTimeZone } from "@/components/time-zone-context";
import { useMemo, useState } from "react";
import { useDashboard } from "@/components/dashboard-context";
import { RefreshCw } from "lucide-react";
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageNotice,
  PageSection,
  PageToolbar,
  TableLayout,
} from "@/components/page-layout";
import { GuardrailFlow } from "@/components/guardrail-flow";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card";
import { TimeRangeControl } from "@/components/ui/time-range-control";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ChartReadout, TimeAxisTick } from "@/components/chart-readout";
import type { ActivitySource } from "@/lib/guardrail-flow";
import { chartTicks, isUtcDailySeries, showSample } from "@/lib/chart";
import {
  number,
  relative,
  type DeviceStatus,
} from "@/lib/api";
import {
  RULE_ACTION_VARIANTS,
  formatMs,
  formatPercent,
  isDecision,
  percentOf,
  type Decision,
  type GuardrailStats,
  type GuardrailHistoryStats,
} from "@/lib/guardrail";
import { useResource } from "@/lib/use-resource";

/** Overview and Live Guardrail share complete window aggregates. */
export function LiveGuardrail({ overview = false }: { overview?: boolean } = {}) {
  const { user } = useDashboard();
  const health = useResource<{ items: DeviceStatus[] }>(user && !overview ? "guardrail/devices" : null, 30000);
  return <GuardrailFlow overview={overview} devices={health.data?.items ?? []} />;
}

const RANGES = [
  ["1h", "Last hour"],
  ["24h", "Last 24 hours"],
  ["7d", "Last 7 days"],
  ["30d", "Last 30 days"],
] as const;
const COUNT_SERIES = [{ key: "total", label: "Decisions", color: "var(--chart-1)" }];
/** Allow includes evaluated warnings, as in the summary. */
const RATE_SERIES = [
  { key: "allow", label: "Allow", color: "var(--chart-1)", dash: undefined },
  { key: "ask", label: "Ask", color: "var(--chart-2)", dash: "5 3" },
  { key: "deny", label: "Deny", color: "var(--chart-3)", dash: "2 3" },
] as const;
const LATENCY_SERIES = [
  { key: "e2e_p50", label: "p50", color: "var(--chart-1)", dash: undefined },
  { key: "e2e_p95", label: "p95", color: "var(--chart-1)", opacity: 0.58, width: 1 },
  { key: "e2e_p99", label: "p99", color: "var(--chart-1)", opacity: 0.36, width: 1 },
] as const;
const LATENCY_BANDS = [
  { lower: "e2e_p50", upper: "e2e_p95", label: "p50 to p95", opacity: 0.25 },
  { lower: "e2e_p95", upper: "e2e_p99", label: "p95 to p99", opacity: 0.1 },
] as const;
const FAILURE_SERIES = [{ key: "failure", label: "Failure rate", color: "var(--chart-1)" }];

type Series = readonly { key: string; label: string; color: string; dash?: string; opacity?: number; width?: number }[];

/** A legend key drawn like the plotted line: same color and dash. */
function LineKey({ color, dash }: { color: string; dash?: string }) {
  return (
    <svg aria-hidden="true" width="16" height="8" className="mr-1.5 inline-block align-middle">
      <line x1="1" y1="4" x2="15" y2="4" stroke={color} strokeWidth="2" strokeDasharray={dash} strokeLinecap="round" />
    </svg>
  );
}

/**
 * Trend lines on the shared chart frame (DESIGN.md, Charts): the
 * selected window as the time domain, a zero-based scale with a round-number top, hollow
 * sample markers where samples are at least 12px apart or isolated, and gaps
 * where an interval had no decisions.
 */
function TrendChart({
  label,
  data,
  series,
  since,
  until,
  daily,
  format,
  axis,
  integer = false,
  percentage = false,
  latencyBands = false,
  syncId,
}: {
  label: string;
  data: Record<string, number | null>[];
  series: Series;
  since: number;
  until: number;
  daily: boolean;
  format: (value: number) => string;
  axis: (value: number) => string;
  integer?: boolean;
  percentage?: boolean;
  latencyBands?: boolean;
  syncId: string;
}) {
  const { chartTimestamp } = useTimeZone();
  const [width, setWidth] = useState(0);
  const axisWidth = 64;
  const max = Math.max(
    0,
    ...data.flatMap((row) => series.map((item) => row[item.key] ?? 0)),
  );
  const ticks = percentage ? [0, 25, 50, 75, 100] : chartTicks(max, integer);
  const stamps = data.map((row) => row.time ?? 0);
  const plotWidth = width - axisWidth - 16;
  const Chart = latencyBands ? ComposedChart : LineChart;
  return (
    <div
      className="h-64 min-w-0 text-xs number [&_.recharts-surface]:focus-visible:outline-2 [&_.recharts-surface]:focus-visible:outline-ring"
    >
      <ResponsiveContainer width="100%" height="100%" minWidth={0} onResize={setWidth}>
        <Chart
          data={data}
          syncId={syncId}
          syncMethod="value"
          margin={{ top: 12, right: 16, bottom: 4, left: 0 }}
          accessibilityLayer
          aria-label={label}
        >
          <CartesianGrid vertical={false} stroke="var(--chart-grid)" strokeWidth={1} />
          <XAxis
            dataKey="time"
            type="number"
            domain={[since, until]}
            ticks={[since, since + (until - since) / 2, until]}
            tick={<TimeAxisTick start={since} end={until} daily={daily} />}
            minTickGap={24}
            tickLine={false}
            axisLine={false}
          />
          <YAxis
            domain={[0, ticks[ticks.length - 1]]}
            ticks={ticks}
            tickFormatter={axis}
            tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
            width={axisWidth}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            filterNull={false}
            isAnimationActive={false}
            cursor={{ stroke: "var(--chart-axis)", strokeWidth: 1 }}
            content={({ active, payload }) => {
              const row = payload?.[0]?.payload as Record<string, number | null> | undefined;
              return active && row ? (
                <ChartReadout
                  timestamp={chartTimestamp(row.time ?? 0, daily)}
                  rows={series.map((item) => ({
                    label: item.label,
                    color: item.color,
                    dash: item.dash,
                    value:
                      row[item.key] === null || row[item.key] === undefined
                        ? "No data"
                        : format(row[item.key]!),
                  }))}
                />
              ) : null;
            }}
          />
          {latencyBands && LATENCY_BANDS.map((band) => (
            <Area
              key={band.label}
              dataKey={(row: Record<string, number | null>) =>
                row[band.lower] == null || row[band.upper] == null
                  ? null
                  : [row[band.lower], row[band.upper]]
              }
              type="linear"
              fill="var(--chart-1)"
              fillOpacity={band.opacity}
              stroke="none"
              dot={false}
              activeDot={false}
              legendType="none"
              tooltipType="none"
              isAnimationActive={false}
              connectNulls={false}
            />
          ))}
          {series.map((item) => (
            <Line
              key={item.key}
              dataKey={item.key}
              name={item.label}
              type={latencyBands ? "linear" : "monotone"}
              stroke={item.color}
              strokeWidth={item.width ?? 2}
              strokeOpacity={item.opacity ?? 1}
              strokeDasharray={item.dash}
              strokeLinejoin="round"
              strokeLinecap="round"
              isAnimationActive={false}
              connectNulls={false}
              activeDot={{ r: 4, fill: item.color, stroke: "var(--card)", strokeWidth: 2 }}
              dot={({ cx, cy, index = 0 }: { cx?: number; cy?: number; index?: number }) => {
                const value = data[index]?.[item.key];
                const isolated =
                  data[index - 1]?.[item.key] == null && data[index + 1]?.[item.key] == null;
                const spaced = showSample(stamps, index, plotWidth, since, until);
                return value != null && cx != null && cy != null && (spaced || isolated) ? (
                  <circle
                    key={`${item.key}-${index}`}
                    cx={cx}
                    cy={cy}
                    r={3}
                    stroke={item.color}
                    strokeWidth={2}
                    strokeDasharray=""
                    fill="var(--card)"
                  />
                ) : (
                  <g key={`${item.key}-${index}`} />
                );
              }}
            />
          ))}
        </Chart>
      </ResponsiveContainer>
    </div>
  );
}

/** History applies the selected source and range to one set of charts. */
export function GuardrailHistory() {
  const { chartTimestamp } = useTimeZone();
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const selected = searchParams.get("source");
  const source: ActivitySource = selected === "endpoints" || selected === "gateways" ? selected : "all";
  const gatewayId = searchParams.get("gateway_id") || "";
  const [range, setRange] = useState<(typeof RANGES)[number][0]>("24h");
  const resource = useResource<GuardrailHistoryStats>(
    `guardrail/stats?range=${range}&source=${source}&view=unified`,
  );
  const data = resource.data;
  const current = data?.source === source && data.sources && typeof data.totals?.attempted === "number" ? data : null;
  function changeSource(value: string) {
    const query = new URLSearchParams(searchParams);
    query.set("source", value);
    router.replace(`${pathname}?${query}`, { scroll: false });
  }
  return <div className="space-y-4">
    <PageNotice title="Guardrail analytics" collapsible>
      <p>Source filters all four charts. All combines recorded endpoint and gateway checks. Missing reports remain unknown. Native agent permissions are separate.</p>
      <p>Decision rates use completed policy evaluations before Shadow mode changes the returned action. A recorded decision does not prove enforcement.</p>
      <p>End-to-end latency includes guardrail processing and network time, excluding tool execution and model response generation. Only recorded timing samples are included.</p>
      <p>Failure rate is the percentage of recorded attempted checks that did not return a valid decision in time. A valid allow or deny is successful. Disabled or unsupported evaluations are Not evaluated. Pending checks and unconfirmed delivery are excluded.</p>
    </PageNotice>
    <PageToolbar action={<>
      <TimeRangeControl value={range} onChange={setRange} options={RANGES} />
      <Button variant="outline" size="sm" onClick={resource.reload} disabled={resource.loading} aria-label="Refresh guardrail statistics">
        <RefreshCw className={`size-3.5 ${resource.loading ? "animate-spin" : ""}`} />Refresh
      </Button>
    </>}>
      <div className="flex flex-wrap items-center gap-3">
        <Label htmlFor="history-source">Source</Label>
        <Select value={source} onValueChange={changeSource}>
          <SelectTrigger id="history-source" aria-label="Source"><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="endpoints">Endpoints</SelectItem><SelectItem value="gateways">Gateways</SelectItem></SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">{current ? `${chartTimestamp(current.since)} to ${chartTimestamp(current.until)}` : "Loading range"}</p>
      </div>
    </PageToolbar>
    {resource.error && <ErrorState message={`${resource.error}${current ? " Showing the last successful response." : ""}`} onRetry={resource.reload} />}
    {!current && !resource.error && (resource.loading
      ? <LoadingState label="Loading statistics" />
      : <ErrorState message="Statistics are unavailable for the selected source." onRetry={resource.reload} />)}
    {current && <GuardrailHistoryMetrics data={current} />}
    {current?.source === "all" && Object.entries(current.sources).map(([key, group]) =>
      group && group.totals.total + group.totals.attempted + group.totals.not_evaluated + group.totals.unconfirmed === 0
        ? <p key={key} className="text-sm text-muted-foreground">No {key === "gateways" ? "gateway" : "endpoint"} data in this range.</p> : null)}
    {current && source !== "gateways" && <GuardrailHistoryRules data={{ rules: current.rules, totals: { total: current.sources.endpoints?.totals.total ?? 0 } }} />}
    {source !== "endpoints" && <p className="text-sm text-muted-foreground">Charts cover all selected sources. Request ledger filters apply only to the ledger.</p>}
    {source !== "endpoints" && <GatewayRequests key={gatewayId} gatewayId={gatewayId} timeWindow={current ? { since: current.since, until: current.until } : undefined} />}
  </div>;
}

function GuardrailHistoryMetrics({ data }: { data: GuardrailHistoryStats }) {
  const { label } = useTimeZone();
  const chart = useMemo(
    () =>
      data.series.map((bucket, index) => ({
        time: new Date(bucket.start).getTime(),
        total: bucket.total,
        allow: percentOf(bucket.allow + bucket.warn, bucket.total),
        deny: percentOf(bucket.deny, bucket.total),
        ask: percentOf(bucket.ask, bucket.total),
        e2e_p50: bucket.e2e_p50,
        e2e_p95: bucket.e2e_p95,
        e2e_p99: bucket.e2e_p99,
        failure: percentOf(bucket.failed, bucket.attempted),
        endpoints: data.sources.endpoints?.series[index]?.total ?? 0,
        gateways: data.sources.gateways?.series[index]?.total ?? 0,
      })),
    [data],
  );
  const t = data.totals;
  const latencyTitle = "End-to-end latency";
  const counts = data.source === "all" ? [
    { key: "endpoints", label: "Endpoints", color: "var(--chart-1)" },
    { key: "gateways", label: "Gateways", color: "var(--chart-2)" },
  ].filter((item) => (data.sources[item.key as "endpoints" | "gateways"]?.totals.total ?? 0) > 0) : COUNT_SERIES;
  const daily = isUtcDailySeries(
    data?.bucket_seconds ?? 0,
    (data?.series ?? []).map((bucket) => bucket.start),
  );
  const zoneLabel = daily ? "UTC" : label;

  return (
    <div className="space-y-4">
      {data && t && t.legacy > 0 && (
        <PageNotice title="Older records excluded from rates and latency">
          {number(t.legacy)} decisions in this range came from sensors that
          recorded only matched rules. They are left out of rates and latency.
        </PageNotice>
      )}
      {data && t && (
        <section
          aria-label="Guardrail metrics over time"
          className="@container"
          onPointerMoveCapture={(event) => {
            // A focused chart's keyboard selection takes priority over hover sync.
            const focused = document.activeElement;
            const hovered = event.target instanceof Element ? event.target.closest(".recharts-wrapper") : null;
            if (hovered && focused instanceof SVGElement && event.currentTarget.contains(focused) && !hovered.contains(focused)) {
              focused.blur();
            }
          }}
        >
          <div className="grid min-w-0 grid-cols-1 gap-4 @2xl:grid-cols-2 @7xl:grid-cols-4">
            {[
              {
                id: "total", title: "Decisions", value: number(t.total),
                hint: "Completed policy evaluations", series: counts,
                format: number, axis: number, integer: true,
                empty: t.total === 0, emptyTitle: "No decisions in this range",
                emptyDescription: "Select a longer range, or check that the source is reporting evaluations.",
                footer: "Decision count per interval",
              },
              {
                id: "rates", title: "Policy decision rates", value: "",
                hint: t.total ? `${formatPercent(percentOf(t.warn, t.total))} of evaluated checks have a warning` : "No evaluated checks",
                series: RATE_SERIES, format: formatPercent, axis: (value: number) => `${value}%`, percentage: true,
                empty: t.total === 0, emptyTitle: "No decisions in this range",
                emptyDescription: "Rates need at least one completed policy evaluation.",
                footer: "Evaluated decisions. Shadow mode allows all calls.",
              },
              {
                id: "latency", title: `${latencyTitle}, p50`, value: formatMs(t.e2e_p50),
                hint: `p95 ${formatMs(t.e2e_p95)} · p99 ${formatMs(t.e2e_p99)}`,
                series: LATENCY_SERIES, format: formatMs, axis: formatMs,
                empty: !chart.some((row) => row.e2e_p50 !== null), emptyTitle: "No latency samples",
                emptyDescription: `No ${latencyTitle.toLowerCase()} was recorded in this range.`,
                footer: "",
              },
              {
                id: "failure", title: "Failure rate",
                value: t.attempted
                  ? formatPercent(percentOf(t.failed, t.attempted))
                  : "Not recorded",
                hint: `${number(t.failed)} failures / ${number(t.attempted)} recorded attempts`,
                series: FAILURE_SERIES, format: formatPercent, axis: (value: number) => `${value}%`,
                empty: !chart.some((row) => row.failure !== null), emptyTitle: "Trend not recorded",
                emptyDescription: "No confirmed check outcomes are available in this range.",
                footer: `${number(t.not_evaluated)} Not evaluated · ${number(t.unconfirmed)} Pending or unconfirmed`,
              },
            ].map((metric) => (
              <Card key={metric.id} role="region" aria-labelledby={`metric-${data.source}-${metric.id}`} className="row-span-3 grid min-w-0 grid-rows-subgrid gap-3">
                <CardHeader className="block">
                  <h2 id={`metric-${data.source}-${metric.id}`} className="text-sm font-medium text-muted-foreground" title={metric.id === "failure" ? "Percentage of recorded attempted guardrail checks that did not return a valid decision in time." : undefined}>{metric.title}</h2>
                  {metric.id === "rates" ? (
                    <div className="mt-1 grid grid-cols-[repeat(3,minmax(max-content,1fr))] gap-2">
                      {RATE_SERIES.map((item) => {
                        const count = item.key === "allow" ? t.allow + t.warn : t[item.key];
                        return (
                          <div key={item.key} className="min-w-0">
                            <p data-testid={`stat-${item.key}`} className={`font-semibold ${t.total ? "figure text-display" : "text-sm"}`}>{formatPercent(percentOf(count, t.total))}</p>
                            <p className="mt-1 text-xs text-muted-foreground"><LineKey color={item.color} dash={item.dash} />{item.label}</p>
                            <p className="number text-xs text-muted-foreground">{number(count)} checks</p>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p data-testid={`stat-${metric.id}`} className="figure mt-1 text-display font-semibold">{metric.value}</p>
                  )}
                  <p className="mt-1 text-xs text-muted-foreground">{metric.hint}</p>
                </CardHeader>
                <CardContent>
                  {metric.empty ? (
                    <div className="flex h-64 items-center justify-center">
                      <EmptyState title={metric.emptyTitle} description={metric.emptyDescription} />
                    </div>
                  ) : (
                    <TrendChart
                      syncId={`guardrail-history-${data.source}`}
                      label={`${metric.id === "latency" ? latencyTitle : metric.title} over time`}
                      data={chart}
                      daily={daily}
                      series={metric.series}
                      since={new Date(data.since).getTime()}
                      until={new Date(data.until).getTime()}
                      format={metric.format}
                      axis={metric.axis}
                      integer={metric.integer}
                      percentage={metric.percentage}
                      latencyBands={metric.id === "latency"}
                    />
                  )}
                </CardContent>
                <CardFooter className="flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                  {metric.id === "latency" ? (
                    <>
                      <span><LineKey color="var(--chart-1)" />p50</span>
                      {LATENCY_BANDS.map((band) => (
                        <span key={band.label}>
                          <svg aria-hidden="true" width="16" height="10" className="mr-1.5 inline-block align-middle">
                            <rect x="0.5" y="0.5" width="15" height="9" fill="var(--chart-1)" fillOpacity={band.opacity} stroke="var(--chart-1)" strokeOpacity={0.58} />
                          </svg>
                          {band.label}
                        </span>
                      ))}
                    </>
                  ) : metric.id === "total" && data.source === "all" ? counts.map((item) => <span key={item.key}><LineKey color={item.color} />{item.label}</span>) : metric.footer}
                </CardFooter>
              </Card>
            ))}
          </div>
          <p className="mt-3 text-xs text-muted-foreground">
            {data.bucket_seconds < 3600 ? `${data.bucket_seconds / 60}-minute` : `${data.bucket_seconds / 3600}-hour`} intervals · {zoneLabel}
          </p>
        </section>
      )}
    </div>
  );
}

function GuardrailHistoryRules({ data }: { data: { rules: GuardrailStats["rules"]; totals: { total: number } } }) {
  const { chartTimestamp } = useTimeZone();
  return (
    <div>
      {data && (
        <PageSection
          title="Endpoint decisions by rule"
          description="Completed policy evaluations by matched rule, before Shadow mode is applied. The model can restrict a check even when no fixed rule matches."
        >
          {data.rules.length === 0 ? (
            <EmptyState
              title="No decisions in this range"
              description="No checks were recorded in this range."
            />
          ) : (
            <TableLayout footer={`${number(data.rules.length)} rules`}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rule</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead className="text-right">Checks</TableHead>
                    <TableHead className="text-right">Share</TableHead>
                    <TableHead className="text-right">Allow</TableHead>
                    <TableHead className="text-right">Warn</TableHead>
                    <TableHead className="text-right">Ask</TableHead>
                    <TableHead className="text-right">Deny</TableHead>
                    <TableHead className="text-right">p95 latency</TableHead>
                    <TableHead>Last decided</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.rules.map((rule) => (
                    <TableRow key={rule.rule_id || "none"}>
                      <TableCell className="min-w-48">
                        <p className="font-medium">
                          {rule.rule_id
                            ? displayText(rule.rule_name || rule.rule_id)
                            : "No rule matched"}
                        </p>
                        {rule.rule_id && !rule.in_policy && (
                          <p className="text-xs text-muted-foreground">
                            No longer in the policy
                          </p>
                        )}
                      </TableCell>
                      <TableCell>
                        {!rule.rule_id ? (
                          <span className="text-xs text-muted-foreground">No fixed rule</span>
                        ) : isDecision(rule.action) ? (
                          <Badge variant={RULE_ACTION_VARIANTS[rule.action]}>
                            {ruleAction(rule.action)}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            Unknown
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="number text-right">
                        {number(rule.total)}
                      </TableCell>
                      <TableCell className="number text-right">
                        {formatPercent(percentOf(rule.total, data.totals.total))}
                      </TableCell>
                      <TableCell className="number text-right">
                        {number(rule.allow)}
                      </TableCell>
                      <TableCell className="number text-right">
                        {number(rule.warn)}
                      </TableCell>
                      <TableCell className="number text-right">
                        {number(rule.ask)}
                      </TableCell>
                      <TableCell className="number text-right">
                        {number(rule.deny)}
                      </TableCell>
                      <TableCell className="number text-right whitespace-nowrap">
                        {formatMs(rule.e2e_p95)}
                      </TableCell>
                      <TableCell
                        className="whitespace-nowrap"
                        title={chartTimestamp(rule.last_seen_at)}
                      >
                        {relative(rule.last_seen_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableLayout>
          )}
        </PageSection>
      )}
    </div>
  );
}

function ruleAction(action: Decision) {
  return { allow: "Allow", warn: "Warn", ask: "Ask", deny: "Deny" }[action];
}
