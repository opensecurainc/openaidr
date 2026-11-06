"use client";

import { useTimeZone } from "@/components/time-zone-context";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ChartReadout, SampleMarker, TimeAxisTick } from "@/components/chart-readout";
import { chartTicks, isUtcDailySeries, showSample } from "@/lib/chart";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  ArrowRight,
  ChevronRight,
  Download,
  FileSearch,
  RefreshCw,
} from "lucide-react";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { CodeBlock } from "@/components/ui/code-block";
import { Status } from "@/components/ui/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState, ErrorState, LoadingState, PageNotice, TableLayout } from "@/components/page-layout";
import { useResource } from "@/lib/use-resource";
import {
  eventSourceLabel,
  number,
  records,
  relative,
  type AgentEvent,
  type Device,
  type DeviceHealth,
  type Export,
  type ExportDetail,
  type ExportRecord,
  type Overview,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { sensorCpu } from "@/lib/sensor-metrics";
import { healthStatus, SensorHealthCell } from "@/components/sensor-health";
import { AppVersionAge } from "@/components/app-version-age";
export const signalNames = {
  logs: "Logs",
  metrics: "Metrics",
  traces: "Traces",
};
/** Fixed categorical order (logs, metrics, traces); validated for CVD separation. */
const colors = {
  logs: "var(--chart-1)",
  metrics: "var(--chart-2)",
  traces: "var(--chart-3)",
};
const linePatterns = { logs: undefined, metrics: "5 3", traces: "2 3" };
function Sparkline({ values, color }: { values: number[]; color: string }) {
  const width = 88;
  const height = 28;
  const max = Math.max(...values, 1);
  const stepX = values.length > 1 ? width / (values.length - 1) : width;
  const points = values.map(
    (value, index) =>
      `${(index * stepX).toFixed(1)},${(height - 2 - (value / max) * (height - 4)).toFixed(1)}`,
  );
  return (
    <svg
      aria-hidden="true"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="shrink-0 overflow-visible"
    >
      <polygon
        points={`0,${height} ${points.join(" ")} ${width},${height}`}
        fill={color}
        fillOpacity={0.08}
      />
      <polyline
        points={points.join(" ")}
        fill="none"
        stroke={color}
        strokeWidth={2}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}
type TooltipEntry = {
  name?: string;
  value?: number | string;
  color?: string;
  dataKey?: string | number;
};
function ChartTooltip({
  active,
  payload,
  label,
  stale,
  daily,
}: {
  stale?: boolean;
  daily?: boolean;
  active?: boolean;
  payload?: ReadonlyArray<TooltipEntry>;
  label?: unknown;
}) {
  const { chartTimestamp } = useTimeZone();
  if (!active || !payload?.length) return null;
  const entries = ["log_records", "metric_points", "spans"]
    .map((key) => payload.find((entry) => entry.dataKey === key))
    .filter((entry) => entry != null);
  const total = entries.every((entry) => entry.value != null)
    ? entries.reduce((sum, entry) => sum + Number(entry.value), 0)
    : null;
  return (
    <ChartReadout
      timestamp={chartTimestamp(Number(label), daily)}
      rows={entries.map((entry, index) => ({
        label: entry.name || String(entry.dataKey),
        value:
          entry.value == null ? "Not reported" : number(Number(entry.value)),
        color: entry.color || "var(--chart-1)",
        dash: index === 1 ? "5 3" : index === 2 ? "2 3" : undefined,
      }))}
    >
      <p>Total: {total == null ? "Not reported" : number(total)} records</p>
      {stale && <p>Stale</p>}
    </ChartReadout>
  );
}
export function Empty({
  title = "No telemetry yet",
  description = "Connect a sensor and enable agent telemetry to see activity here.",
}: {
  title?: string;
  description?: string;
}) {
  return <EmptyState title={title} description={description} />;
}
export function PageSkeleton() {
  return (
    <div aria-label="Loading telemetry" role="status">
      <Skeleton className="mb-4 h-28 rounded-lg" />
      <Skeleton className="h-[365px] rounded-lg" />
      <Skeleton className="mt-4 h-[200px] rounded-lg" />
    </div>
  );
}
export function StatCards({ data, health, healthLoading, healthError }: {
  data: Overview | null;
  health?: DeviceHealth[];
  healthLoading: boolean;
  healthError: boolean;
}) {
  const s = data?.summary;
  const devices = health ? {
    devices: health.length,
    online_devices: health.filter((device) => device.status === "online").length,
    offline_devices: health.filter((device) => device.status === "offline").length,
    disabled_devices: health.filter((device) => device.status === "disabled").length,
  } : s;
  const trend = data?.activity.map((bucket) => records(bucket)) || [];
  const stats: {
    id: string;
    label: string;
    value: number | null;
    hint: string;
    trend?: number[];
  }[] = [
    {
      id: "records",
      label: "Telemetry records",
      value: s?.records ?? null,
      hint: "Logs, metric points, and spans",
      trend: trend.length > 1 && (s?.records ?? 0) > 0 ? trend : undefined,
    },
    {
      id: "exports",
      label: "Exports received",
      value: s?.exports ?? null,
      hint: "Accepted OpenTelemetry batches",
    },
    {
      id: "devices",
      label: "Devices in view",
      value: devices?.devices ?? null,
      hint: !health && data?.service
        ? "Devices matching this service"
        : "Enrolled devices in your workspace",
    },
    {
      id: "online-devices",
      label: "Devices online",
      value: devices?.online_devices ?? null,
      hint: devices ? `${number(devices.offline_devices)} offline · ${number(devices.disabled_devices)} disabled` : "App health unavailable",
    },
  ];
  // One strip with hairline dividers keeps the fleet summaries together.
  return (
    <section
      aria-label="Telemetry summary"
      className="mb-4 grid grid-cols-1 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-[1fr_1fr_1fr_1fr_1.6fr]"
    >
      {stats.map(({ id, label, value, hint, trend }) => (
        <div key={label} className="min-w-0 bg-card px-4 py-3">
          <p className="text-xs font-medium text-muted-foreground">{label}</p>
          <div className="mt-1 flex flex-wrap items-end justify-between gap-3">
            <p
              data-testid={`stat-${id}`}
              className="figure text-display font-semibold"
            >
              {value === null ? "N/A" : number(value)}
            </p>
            {trend && <Sparkline values={trend} color={colors.logs} />}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
        </div>
      ))}
      <AppVersionAge devices={health} loading={healthLoading} error={healthError} />
    </section>
  );
}
export function ActivityPanel({ data, stale = false }: { data: Overview; stale?: boolean }) {
  const { chartTimeTick, chartTimestamp, label } = useTimeZone();
  const hasTraces = data.activity.some((bucket) => bucket.spans > 0);
  const daily = isUtcDailySeries(
    data.bucket_seconds,
    data.activity.map((bucket) => bucket.start),
  );
  const zoneLabel = daily ? "UTC" : label;
  const [width, setWidth] = useState(0);
  const ticks = chartTicks(
    Math.max(0, ...data.activity.map((bucket) => records(bucket))),
    true,
  );
  const raw = data.activity.map((bucket) => ({
    ...bucket,
    timestamp: new Date(bucket.start).getTime(),
  }));
  const series = raw.flatMap((bucket, index) => {
    const previous = raw[index - 1];
    return previous &&
      bucket.timestamp - previous.timestamp > data.bucket_seconds * 1500
      ? [
          {
            start: new Date(
              previous.timestamp + data.bucket_seconds * 1000,
            ).toISOString(),
            timestamp: previous.timestamp + data.bucket_seconds * 1000,
            log_records: null,
            metric_points: null,
            spans: null,
          },
          bucket,
        ]
      : [bucket];
  });
  const end = data.generated_at
    ? new Date(data.generated_at).getTime()
    : (raw.at(-1)?.timestamp ?? Date.now());
  const start = data.window_start
    ? new Date(data.window_start).getTime()
    : end -
      Number.parseInt(data.range) *
        (data.range.endsWith("d") ? 86400000 : 3600000);
  const timestamps = series.map((bucket) => bucket.timestamp);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Telemetry activity</CardTitle>
        <CardDescription>
          Records received over time, in {data.bucket_seconds / 3600}-hour
          buckets ({zoneLabel})
        </CardDescription>
      </CardHeader>
      <CardContent>
        {raw.length > 0 &&
          raw[0].timestamp > start + data.bucket_seconds * 1000 && (
            <p className="mb-2 text-xs text-muted-foreground">
              Data since {chartTimestamp(raw[0].timestamp, daily)}. Choose a shorter
              range to inspect recent activity.
            </p>
          )}
        <ul className="mb-2 flex flex-wrap gap-x-4 gap-y-1" aria-label="Series">
          {(["logs", "metrics", "traces"] as const).filter((signal) => signal !== "traces" || hasTraces).map((signal) => (
            <li
              key={signal}
              className="flex items-center gap-1.5 text-xs text-muted-foreground"
            >
              <svg aria-hidden="true" className="h-3 w-6" viewBox="0 0 24 12">
                <line
                  x1="0" x2="24" y1="6" y2="6"
                  stroke={colors[signal]}
                  strokeWidth={2}
                  strokeDasharray={linePatterns[signal]}
                />
              </svg>
              {signalNames[signal]}
            </li>
          ))}
        </ul>
        {data.summary.records === 0 ? (
          <Empty
            title="No activity in this window"
            description="Choose another time range or service, or send telemetry from a connected sensor."
          />
        ) : (
          <div
            className="h-64 min-w-0 w-full number [&_.recharts-surface]:focus-visible:outline-2 [&_.recharts-surface]:focus-visible:outline-ring"
            aria-label={hasTraces
              ? "Stacked chart of log records, metric points, and spans by received time"
              : "Stacked chart of log records and metric points by received time"}
          >
            <ResponsiveContainer
              width="100%"
              height="100%"
              minWidth={0}
              onResize={setWidth}
            >
              <AreaChart
                data={series}
                margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
                accessibilityLayer
                aria-label={`${hasTraces ? "Log records, metric points, and spans" : "Log records and metric points"} over received time, ${zoneLabel}`}
              >
                <CartesianGrid vertical={false} />
                <XAxis
                  dataKey="timestamp"
                  type="number"
                  domain={[start, end]}
                  ticks={[start, (start + end) / 2, end]}
                  axisLine={false}
                  tickLine={false}
                  minTickGap={38}
                  tickMargin={12}
                  tick={<TimeAxisTick start={start} end={end} daily={daily} />}
                  tickFormatter={(value) =>
                    chartTimeTick(Number(value), daily)
                  }
                />
                <YAxis
                  allowDecimals={false}
                  axisLine={false}
                  tickLine={false}
                  tickMargin={8}
                  // Room for "10,000" in the interface face without clipping.
                  width={64}
                  ticks={ticks}
                  domain={[0, ticks[ticks.length - 1]]}
                  tickFormatter={(value) => number(Number(value))}
                />
                <Tooltip
                  content={<ChartTooltip stale={stale} daily={daily} />}
                  isAnimationActive={false}
                  filterNull={false}
                  cursor={{ stroke: "var(--chart-axis)" }}
                />
                <Area
                  type="monotone"
                  dataKey="log_records"
                  name="Log records"
                  stackId="records"
                  stroke={colors.logs}
                  fill={colors.logs}
                  fillOpacity={0.08}
                  strokeWidth={2}
                  activeDot={{
                    r: 4,
                    fill: colors.logs,
                    strokeWidth: 2,
                    stroke: "var(--card)",
                  }}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                  connectNulls={false}
                  dot={({ cx, cy, index = 0 }) => (
                    <SampleMarker
                      cx={cx}
                      cy={cy}
                      color={colors.logs}
                      show={
                        series[index]?.log_records != null &&
                        ((series[index - 1]?.log_records == null &&
                          series[index + 1]?.log_records == null) ||
                          showSample(
                            timestamps,
                            index,
                            width - 72,
                            start,
                            end,
                          ))
                      }
                    />
                  )}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="metric_points"
                  name="Metric points"
                  stackId="records"
                  stroke={colors.metrics}
                  fill={colors.metrics}
                  fillOpacity={0.08}
                  strokeDasharray={linePatterns.metrics}
                  strokeWidth={2}
                  activeDot={{
                    r: 4,
                    fill: colors.metrics,
                    strokeWidth: 2,
                    stroke: "var(--card)",
                  }}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                  connectNulls={false}
                  dot={({ cx, cy, index = 0 }) => (
                    <SampleMarker
                      cx={cx}
                      cy={cy}
                      color={colors.metrics}
                      show={
                        series[index]?.metric_points != null &&
                        ((series[index - 1]?.metric_points == null &&
                          series[index + 1]?.metric_points == null) ||
                          showSample(
                            timestamps,
                            index,
                            width - 72,
                            start,
                            end,
                          ))
                      }
                    />
                  )}
                  isAnimationActive={false}
                />
                {hasTraces && <Area
                  type="monotone"
                  dataKey="spans"
                  name="Spans"
                  stackId="records"
                  stroke={colors.traces}
                  fill={colors.traces}
                  fillOpacity={0.08}
                  strokeDasharray={linePatterns.traces}
                  strokeWidth={2}
                  activeDot={{
                    r: 4,
                    fill: colors.traces,
                    strokeWidth: 2,
                    stroke: "var(--card)",
                  }}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                  connectNulls={false}
                  dot={({ cx, cy, index = 0 }) => (
                    <SampleMarker
                      cx={cx}
                      cy={cy}
                      color={colors.traces}
                      show={
                        series[index]?.spans != null &&
                        ((series[index - 1]?.spans == null &&
                          series[index + 1]?.spans == null) ||
                          showSample(
                            timestamps,
                            index,
                            width - 72,
                            start,
                            end,
                          ))
                      }
                    />
                  )}
                  isAnimationActive={false}
                />}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
/** Stacked share of records by signal, with a 2px surface gap between segments. */
function SignalBreakdown({ data }: { data: Overview }) {
  const s = data.summary;
  const parts = [
    { key: "logs", label: "Logs", value: s.log_records },
    { key: "metrics", label: "Metrics", value: s.metric_points },
    { key: "traces", label: "Traces", value: s.spans },
  ] as const;
  const total = s.records;
  return (
    <div className="mt-auto border-t pt-3">
      <p className="text-xs font-medium text-muted-foreground">By signal</p>
      <div
        className="mt-2 flex h-2 gap-0.5 overflow-hidden rounded-xs"
        role="img"
        aria-label={parts
          .map((part) => `${part.label}: ${number(part.value)}`)
          .join(", ")}
      >
        {total > 0 ? (
          parts
            .filter((part) => part.value > 0)
            .map((part) => (
              <span
                key={part.key}
                className="h-full first:rounded-l-xs last:rounded-r-xs"
                style={{
                  width: `${(part.value / total) * 100}%`,
                  background: colors[part.key],
                }}
              />
            ))
        ) : (
          <span className="h-full w-full bg-muted" />
        )}
      </div>
      <dl className="mt-2 grid grid-cols-3 gap-2">
        {parts.map((part) => (
          <div key={part.key} className="min-w-0">
            <dt className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span
                aria-hidden="true"
                className="size-2 shrink-0 rounded-full"
                style={{ background: colors[part.key] }}
              />
              {part.label}
            </dt>
            <dd className="number mt-0.5 text-sm font-semibold">
              {number(part.value)}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
export function ServicesPanel({ data }: { data: Overview }) {
  const { dateTime } = useTimeZone();
  const total = data.services.reduce((sum, s) => sum + records(s), 0);
  const services = [...data.services].sort(
    (a, b) => records(b) - records(a) || a.name.localeCompare(b.name),
  );
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Source services</CardTitle>
        <CardDescription>Share of records by service label</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col">
        {!data.services.length ? (
          <Empty
            title="No source services"
            description="Services appear when agents send resource-tagged telemetry."
          />
        ) : (
          <div className="space-y-3">
            {services.slice(0, 6).map((s) => {
              const share = total ? (records(s) / total) * 100 : 0;
              const shareLabel =
                share > 0 && share < 1 ? "<1%" : `${Math.round(share)}%`;
              return (
                <div key={s.name}>
                  <div className="mb-1 flex items-baseline justify-between gap-2">
                    <span
                      className="min-w-0 truncate text-sm font-medium"
                      title={s.name}
                    >
                      {s.name}
                    </span>
                    <span className="number text-sm font-semibold">
                      {number(records(s))}
                      <span className="ml-1.5 text-xs font-normal text-muted-foreground">
                        {shareLabel}
                      </span>
                    </span>
                  </div>
                  <div
                    className="h-2 overflow-hidden rounded-xs bg-muted"
                    role="img"
                    aria-label={`${s.name}: ${number(records(s))} records, ${shareLabel} of total`}
                  >
                    <div
                      className="h-full rounded-xs bg-chart-1"
                      style={{ width: `${share}%` }}
                    />
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {number(s.exports)} exports
                  </p>
                </div>
              );
            })}
            {data.services.length > 6 && (
              <p className="text-xs text-muted-foreground">
                Showing top 6 of {number(data.services.length)} services by record
                count. Use the service filter to explore each source.
              </p>
            )}
          </div>
        )}
        <SignalBreakdown data={data} />
        <div className="mt-3 flex items-center justify-between border-t pt-3 text-sm">
          <span className="text-muted-foreground">Last export</span>
          <span
            className="font-medium"
            title={dateTime(data.summary.last_export_at)}
          >
            {relative(data.summary.last_export_at)}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
export function StatusBadge({ status }: { status: Device["status"] }) {
  return (
    <Status
      tone={
        status === "online" ? "ok" : status === "disabled" ? "neutral" : "warning"
      }
    >
      {status[0].toUpperCase() + status.slice(1)}
    </Status>
  );
}
/** Reported hardware identity with the earlier enrollments it matches. */
export function HardwareCell({ device }: { device: DeviceHealth & Partial<Device> }) {
  const { dateTime } = useTimeZone();
  const identity = device.device;
  const serial = identity?.serial_number ?? "";
  const uuid = identity?.hardware_uuid ?? "";
  const machine = identity?.machine_id ?? "";
  const matches = device.same_hardware ?? [];
  if (!serial && !uuid && !machine) {
    return <span className="text-muted-foreground">Not reported</span>;
  }
  const [value, kind] = serial
    ? [serial, "Serial number"]
    : uuid
      ? [uuid, "Hardware UUID"]
      : [machine, "OS installation ID"];
  const detail = [
    serial && `Serial number: ${serial}`,
    uuid && `Hardware UUID: ${uuid}`,
    machine && `OS installation ID: ${machine}`,
    identity?.source && `Source: ${identity.source}`,
  ].filter(Boolean).join("\n");
  const names = matches.map((match) => match.label || match.hostname || match.id);
  const matchDetail = matches
    .map((match) => `${match.label || match.hostname || match.id} · ${match.status} · enrolled ${dateTime(match.enrolled_at)}`)
    .join("\n");
  return (
    <div className="max-w-56">
      <p className="truncate font-mono text-xs" title={detail}>{value}</p>
      <p className="text-xs text-muted-foreground">{kind}</p>
      {matches.length > 0 && (
        <p
          className="truncate text-xs text-muted-foreground"
          title={`Same hardware as:\n${matchDetail}`}
          aria-label={`Same hardware as ${names.join(", ")}`}
        >
          Same hardware as {names.slice(0, 2).join(", ")}
          {names.length > 2 ? ` and ${names.length - 2} more` : ""}
        </p>
      )}
    </div>
  );
}
function compactMemory(value: number | null | undefined) {
  if (value == null) return "Not reported";
  if (value >= 1e9) return `${(value / 1e9).toFixed(2)}G`;
  if (value > 0 && value < 1e6) return "<1MB";
  return `${Math.round(value / 1e6)}MB`;
}

export function DeviceTable({
  devices,
  compact = false,
  onRefresh,
  refreshing = false,
}: {
  devices: (DeviceHealth & Partial<Device>)[];
  compact?: boolean;
  onRefresh?: () => void;
  refreshing?: boolean;
}) {
  const { dateTime } = useTimeZone();
  const rows = devices.map((device) => ({
    device,
    recordCount: device.log_records == null || device.metric_points == null || device.spans == null
      ? null : device.log_records + device.metric_points + device.spans,
  })).sort((a, b) =>
    Number(b.device.status === "online") - Number(a.device.status === "online") ||
    Number(a.device.status === "disabled") - Number(b.device.status === "disabled") ||
    Number(healthStatus(b.device) === "needs_attention") - Number(healthStatus(a.device) === "needs_attention") ||
    (b.recordCount ?? -1) - (a.recordCount ?? -1),
  );
  return (
    <Card className="overflow-hidden">
      <CardHeader className="border-b">
        <CardTitle>
          {compact ? "Connected devices" : "Device inventory"}
        </CardTitle>
        <CardDescription>
          {compact
            ? "App health across your workspace"
            : "Health is based on the most recent sensor heartbeat"}
        </CardDescription>
        {!compact && onRefresh && (
          <CardAction>
            <Button variant="outline" onClick={onRefresh} disabled={refreshing}>
              <RefreshCw className={refreshing ? "animate-spin" : ""} />
              Refresh apps
            </Button>
          </CardAction>
        )}
        {compact && (
          <CardAction>
            <Button variant="ghost" asChild>
              <Link href="/administration/app">
                View all devices
                <ArrowRight />
              </Link>
            </Button>
          </CardAction>
        )}
      </CardHeader>
      {!devices.length ? (
        <Empty
          title="No devices in view"
          description="Enroll the app on a device or choose a different service to see your devices."
        />
      ) : (
        <div tabIndex={0} role="region" aria-label="Scrollable device inventory" className="overflow-x-auto focus-visible:outline-2 focus-visible:outline-ring [&_:is(th,td):last-child]:pr-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-4">Device</TableHead>
                {!compact && <TableHead>Hardware</TableHead>}
                <TableHead>Connection</TableHead>
                <TableHead>Health</TableHead>
                {!compact && (
                  <>
                    <TableHead className="text-right">App CPU</TableHead>
                    <TableHead
                      className="text-right"
                      title="Current memory (maximum recorded in the past 24 hours)"
                    >App memory</TableHead>
                  </>
                )}
                <TableHead className="text-right">Records</TableHead>
                {!compact && (
                  <>
                    <TableHead className="text-right">Pending activity</TableHead>
                    <TableHead className="text-right">Pending exports</TableHead>
                  </>
                )}
                <TableHead>Last heartbeat</TableHead>
                {!compact && <TableHead>Last export</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map(({ device, recordCount }) => (
                <TableRow key={device.id}>
                  <TableCell className="pl-4">
                    <p
                      className="max-w-64 truncate font-medium"
                      title={
                        device.label || device.hostname || "Unnamed device"
                      }
                    >
                      {device.label || device.hostname || "Unnamed device"}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {device.os || "Unknown OS"} ·{" "}
                      {device.arch || "Unknown architecture"}
                      {!compact && ` · v${device.sensor_version || "unknown"}`}
                    </p>
                  </TableCell>
                  {!compact && (
                    <TableCell>
                      <HardwareCell device={device} />
                    </TableCell>
                  )}
                  <TableCell>
                    <StatusBadge status={device.status} />
                  </TableCell>
                  <TableCell><SensorHealthCell device={device} /></TableCell>
                  {!compact && (
                    <>
                      <TableCell
                        className="number text-right"
                        title={`Last heartbeat: ${dateTime(device.last_heartbeat_at)}`}
                      >
                        {sensorCpu(device.cpu_percent)}
                      </TableCell>
                      <TableCell
                        className="number text-right"
                        title={`Current memory (24-hour maximum). Last heartbeat: ${dateTime(device.last_heartbeat_at)}`}
                      >
                        <span>{compactMemory(device.memory_rss_bytes)}</span>{" "}
                        <span className="text-muted-foreground">
                          ({device.max_memory_rss_bytes_24h == null
                            ? "N/A"
                            : compactMemory(device.max_memory_rss_bytes_24h)})
                        </span>
                      </TableCell>
                    </>
                  )}
                  <TableCell className="number text-right">
                    {recordCount == null ? "N/A" : number(recordCount)}
                  </TableCell>
                  {!compact && (
                    <TableCell className="number text-right">
                      {device.queue_depth == null ? <span className="text-muted-foreground">Not reported</span> : number(device.queue_depth)}
                    </TableCell>
                  )}
                  {!compact && (
                    <TableCell className="number text-right">
                      {device.telemetry_queue_depth == null ? (
                        <span className="text-muted-foreground">
                          Not reported
                        </span>
                      ) : (
                        number(device.telemetry_queue_depth)
                      )}
                    </TableCell>
                  )}
                  <TableCell
                    className="text-muted-foreground"
                    title={dateTime(device.last_heartbeat_at)}
                  >
                    {relative(device.last_heartbeat_at)}
                  </TableCell>
                  {!compact && (
                    <TableCell
                      className="text-muted-foreground"
                      title={dateTime(device.latest_export_at)}
                    >
                      {device.latest_export_at === undefined ? "N/A" : relative(device.latest_export_at)}
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {!compact && (
        <div className="px-4 py-2">
          <PageNotice title="How sensor counts are reported" collapsible>
            Pending exports are reported by the sensor heartbeat. Older sensors
            show “Not reported.” Pending activity is the separate activity queue.
            Online means a heartbeat arrived within 90 seconds; it does not mean
            uploads are working. Health reports collection failures, failed uploads,
            stalled queues, dropped records, and telemetry receiver failures.
            Offline devices have unknown health. Health diagnostics require an updated sensor.
            Record totals follow the selected range and
            service. CPU and memory are the latest sensor process measurements;
            offline or disabled sensors show their last reported values.
            App memory shows current usage with the maximum recorded in the past
            24 hours in parentheses, using decimal MB and G (GB). The maximum
            uses the last reading stored each minute, not chart averages, and
            stays fixed to 24 hours when filters change. N/A means no memory
            readings are available in that window.
            Hardware shows the serial number, hardware UUID, or OS installation
            ID the sensor reported, and names other enrollments that reported
            the same hardware, such as an earlier install of the same laptop.
          </PageNotice>
        </div>
      )}
    </Card>
  );
}
export function ExportTable({
  exports,
}: {
  exports: Export[];
}) {
  const { dateTime } = useTimeZone();
  const [selected, setSelected] = useState<Export | null>(null);
  return (
    <>
      <TableLayout>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-4">Signal / source</TableHead>
              <TableHead>Device</TableHead>
              <TableHead className="text-right">Records</TableHead>
              <TableHead>Received</TableHead>
              <TableHead className="w-10">
                <span className="sr-only">Details</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {exports.map((item) => (
              <TableRow key={item.id}>
                <TableCell className="pl-4">
                  <div className="flex items-center gap-2">
                    <span
                      aria-hidden="true"
                      className="size-2 rounded-full"
                      style={{ background: colors[item.signal] }}
                    />
                    <span className="font-medium">
                      {signalNames[item.signal]}
                    </span>
                    {item.demo && <Badge variant="outline">Synthetic</Badge>}
                  </div>
                  <p
                    className="ml-4 max-w-56 truncate text-xs text-muted-foreground"
                    title={item.service_names.join(", ")}
                  >
                    {item.service_names.join(", ") || "Unknown service"}
                  </p>
                </TableCell>
                <TableCell
                  className="max-w-48 truncate"
                  title={item.hostname || item.sensor_id}
                >
                  {item.hostname || item.sensor_id}
                </TableCell>
                <TableCell className="number text-right">
                  {number(item.record_count)}
                </TableCell>
                <TableCell
                  className="text-muted-foreground"
                  title={dateTime(item.received_at)}
                >
                  {relative(item.received_at)}
                </TableCell>
                <TableCell className="pr-4">
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    aria-label={`View export ${item.id}`}
                    onClick={() => setSelected(item)}
                  >
                    <ChevronRight />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableLayout>
      <ExportDetailDialog
        exportId={selected?.id ?? null}
        summary={selected}
        onClose={() => setSelected(null)}
      />
    </>
  );
}
/** Where an agent event came from. Text label; never color alone. */
export function EventSourceBadge({
  event,
  className,
}: {
  event: Pick<AgentEvent, "source">;
  className?: string;
}) {
  return (
    <Badge variant="outline" className={className}>
      {eventSourceLabel(event)}
    </Badge>
  );
}
/**
 * Ghost action that opens the raw OTLP record behind an event. Renders
 * nothing when the event has no export reference.
 */
export function OpenTelemetryRecordButton({
  event,
  onOpen,
  className,
}: {
  event: Pick<AgentEvent, "export" | "event_name" | "kind">;
  onOpen: (target: { exportId: string; record: number }) => void;
  className?: string;
}) {
  const ref = event.export;
  if (!ref || typeof ref.record !== "number") return null;
  const name = event.event_name || event.kind;
  return (
    <Button
      variant="outline"
      size="xs"
      className={className}
      aria-label={`Open telemetry record for ${name}`}
      onClick={() => onOpen({ exportId: ref.id, record: ref.record })}
    >
      <FileSearch aria-hidden="true" />
      Open telemetry record
    </Button>
  );
}

function preciseTime(value: string | null | undefined, timeZone?: string) {
  if (!value) return "Not reported";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not reported";
  return date.toLocaleString(undefined, {
    timeZone,
    timeZoneName: "short",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  });
}
function plain(value: unknown) {
  if (value == null) return "";
  return typeof value === "string" ? value : JSON.stringify(value);
}
const RECORD_LIMIT = 250;
function AttributeList({ attributes }: { attributes: Record<string, unknown> }) {
  const entries = Object.entries(attributes);
  if (!entries.length)
    return <span className="text-muted-foreground">None</span>;
  return (
    <ul className="flex max-w-[520px] flex-wrap gap-1">
      {entries.map(([key, value]) => (
        <li
          key={key}
          className="max-w-full truncate rounded-sm bg-muted px-1.5 py-0.5 font-mono text-xs"
          title={`${key} = ${plain(value)}`}
        >
          <span className="text-muted-foreground">{key}=</span>
          {plain(value)}
        </li>
      ))}
    </ul>
  );
}
/**
 * Which slice of the records to show. The first RECORD_LIMIT rows by default;
 * when a highlighted record lies beyond that cap, a window centered on it.
 */
function recordWindow(total: number, highlight: number | null | undefined) {
  const valid =
    typeof highlight === "number" &&
    Number.isInteger(highlight) &&
    highlight >= 0 &&
    highlight < total;
  if (!valid || highlight < RECORD_LIMIT)
    return { start: 0, end: Math.min(total, RECORD_LIMIT), valid };
  const start = Math.max(0, highlight - Math.floor(RECORD_LIMIT / 2));
  return { start, end: Math.min(total, start + RECORD_LIMIT), valid };
}
function RecordsTable({
  signal,
  records: rows,
  highlight,
}: {
  signal: Export["signal"];
  records: ExportRecord[];
  /** Index into `records` of the record that produced the finding. */
  highlight?: number | null;
}) {
  const { timeZone } = useTimeZone();
  const matched = useRef<HTMLTableRowElement | null>(null);
  useEffect(() => {
    matched.current?.scrollIntoView({ block: "center" });
  }, [rows, highlight]);
  if (!rows.length)
    return (
      <EmptyState
        title="No records in this export"
        description="The batch was accepted but contains no log records, spans, or data points."
      />
    );
  const { start, end, valid } = recordWindow(rows.length, highlight);
  const shown = rows.slice(start, end);
  const windowed = start > 0 || end < rows.length;
  return (
    <div className="min-w-0 overflow-hidden rounded-md border">
      {typeof highlight === "number" && !valid && (
        <p
          role="status"
          className="border-b bg-status-warning/10 px-3 py-2 text-xs text-foreground"
        >
          Record #{number(highlight)} is not in this export (it has{" "}
          {number(rows.length)} records). The reference may point to a
          superseded payload.
        </p>
      )}
      <div tabIndex={0} role="region" aria-label="Scrollable export records" className="max-h-[46vh] overflow-auto focus-visible:outline-2 focus-visible:outline-ring">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-muted">
            <TableRow>
              <TableHead>Time</TableHead>
              {signal === "logs" && (
                <>
                  <TableHead>Event</TableHead>
                  <TableHead>Severity</TableHead>
                </>
              )}
              {signal === "traces" && (
                <>
                  <TableHead>Span</TableHead>
                  <TableHead className="text-right">Duration</TableHead>
                  <TableHead>Status</TableHead>
                </>
              )}
              {signal === "metrics" && (
                <>
                  <TableHead>Metric</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead className="text-right">Value</TableHead>
                </>
              )}
              <TableHead>Service</TableHead>
              <TableHead>Attributes</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shown.map((row, offset) => {
              const index = start + offset;
              const isMatch = valid && index === highlight;
              return (
              <TableRow
                key={index}
                ref={isMatch ? matched : undefined}
                aria-current={isMatch ? "true" : undefined}
                data-record-index={index}
                className={cn(
                  "[&>td]:align-top",
                  isMatch &&
                    "bg-primary/5 hover:bg-primary/8 [&>td:first-child]:shadow-[inset_3px_0_0_0_var(--primary)]",
                )}
              >
                <TableCell className="number whitespace-nowrap text-muted-foreground">
                  <div title={`Record #${number(index)}`}>
                    {preciseTime(row.time, timeZone)}
                  </div>
                  {isMatch && (
                    <Badge variant="info" className="mt-1">
                      Matched record
                    </Badge>
                  )}
                </TableCell>
                {signal === "logs" && (
                  <>
                    <TableCell>
                      <div className="font-medium">
                        {row.event_name || "Log record"}
                      </div>
                      {row.body != null &&
                        plain(row.body) !== (row.event_name || "") && (
                          <div
                            className="mt-0.5 max-w-[320px] truncate font-mono text-xs text-muted-foreground"
                            title={plain(row.body)}
                          >
                            {plain(row.body)}
                          </div>
                        )}
                    </TableCell>
                    <TableCell>
                      {row.severity ? (
                        <Badge
                          variant={
                            // A log level is a state, not a finding severity.
                            /ERROR|FATAL/i.test(row.severity)
                              ? "destructive"
                              : /WARN/i.test(row.severity)
                                ? "warning"
                                : "outline"
                          }
                        >
                          {row.severity}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">Not reported</span>
                      )}
                    </TableCell>
                  </>
                )}
                {signal === "traces" && (
                  <>
                    <TableCell>
                      <div className="font-medium">{row.name || "Span"}</div>
                      <div
                        className="mt-0.5 font-mono text-xs text-muted-foreground"
                        title={`trace ${row.trace_id || "?"} · span ${row.span_id || "?"}`}
                      >
                        {(row.span_id || "").slice(0, 16) || "no span id"}
                      </div>
                    </TableCell>
                    <TableCell className="number text-right">
                      {row.duration_ms == null
                        ? "Not reported"
                        : `${number(Math.round(row.duration_ms))} ms`}
                    </TableCell>
                    <TableCell>
                      {row.status === 2
                        ? `Error${row.status_message ? `: ${row.status_message}` : ""}`
                        : row.status === 1
                          ? "OK"
                          : "Unset"}
                    </TableCell>
                  </>
                )}
                {signal === "metrics" && (
                  <>
                    <TableCell className="font-medium">
                      {row.name || "Metric"}
                      {row.unit && (
                        <span className="ml-1 font-normal text-muted-foreground">
                          {row.unit}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {row.metric_type}
                    </TableCell>
                    <TableCell className="number text-right">
                      {plain(row.value) || "Not reported"}
                    </TableCell>
                  </>
                )}
                <TableCell>
                  <div>{row.service}</div>
                  {row.host && (
                    <div className="mt-0.5 text-xs text-muted-foreground">
                      {row.host}
                    </div>
                  )}
                </TableCell>
                <TableCell className="whitespace-normal">
                  <AttributeList attributes={row.attributes} />
                </TableCell>
              </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      {windowed && (
        <p className="border-t px-3 py-2 text-xs text-muted-foreground">
          {start > 0
            ? `Showing records ${number(start)}–${number(end - 1)} of ${number(rows.length)} around the matched record.`
            : `Showing the first ${number(shown.length)} of ${number(rows.length)} records.`}{" "}
          The raw payload tab contains every record.
        </p>
      )}
    </div>
  );
}
function RawPayload({ detail }: { detail: ExportDetail }) {
  const text = JSON.stringify(detail.payload, null, 2);
  const size = new Blob([text]).size;
  function download() {
    const url = URL.createObjectURL(
      new Blob([text], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `openaidr-export-${detail.signal}-${detail.id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>
          Canonical OTLP JSON · {number(size)} bytes · SHA-256{" "}
          <code className="font-mono" title={detail.payload_sha256}>
            {detail.payload_sha256.slice(0, 12)}…
          </code>
        </span>
        <Button variant="outline" onClick={download}>
          <Download />
          Download
        </Button>
      </div>
      <CodeBlock copyLabel="Copy JSON" className="max-h-[46vh] whitespace-pre">{text}</CodeBlock>
    </div>
  );
}
const METADATA_LABELS = [
  "Signal",
  "Services",
  "Device",
  "Received",
  "Records in current filter",
  "Synthetic fixture",
  "Export ID",
  "Batch ID",
  "Sensor ID",
] as const;
function ExportMetadata({ detail }: { detail: Export | null }) {
  const { dateTime } = useTimeZone();
  const values: Record<(typeof METADATA_LABELS)[number], string> | null =
    detail && {
      Signal: signalNames[detail.signal],
      Services: detail.service_names.join(", ") || "Unknown",
      Device: detail.hostname || detail.sensor_id,
      Received: dateTime(detail.received_at),
      "Records in current filter": number(detail.record_count),
      "Synthetic fixture": detail.demo
        ? "Yes · demo resource label"
        : "No demo label",
      "Export ID": detail.id,
      "Batch ID": detail.batch_id,
      "Sensor ID": detail.sensor_id,
    };
  return (
    <dl
      className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3"
      aria-busy={!values}
    >
      {METADATA_LABELS.map((key) => (
        <div key={key} className="min-w-0">
          <dt className="text-xs text-muted-foreground">{key}</dt>
          <dd className="break-all text-sm">
            {values ? (
              values[key]
            ) : (
              <Skeleton aria-hidden="true" className="mt-1 h-3.5 w-2/3" />
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}
export function ExportDetailDialog({
  exportId,
  onClose,
  highlightRecord = null,
  summary = null,
}: {
  /** Stored export to open; `null` keeps the dialog closed. */
  exportId: string | null;
  onClose: () => void;
  /** Index into `ExportDetail.records` to mark and scroll to on open. */
  highlightRecord?: number | null;
  /**
   * Optional list-row metadata for the same export. Used only when the
   * detail request fails (for example, a viewer without the analyst role),
   * so the header still shows what the list already displayed.
   */
  summary?: Export | null;
}) {
  const detail = useResource<ExportDetail>(
    exportId ? `telemetry/exports/${exportId}` : null,
  );
  const denied = /requires role/i.test(detail.error);
  const fallback = summary && summary.id === exportId ? summary : null;
  const metadata = detail.data ?? (detail.error ? fallback : null);
  const metadataMissing = !metadata && !detail.loading && !!detail.error;
  return (
    <Dialog
      open={!!exportId}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="flex max-h-[90vh] flex-col gap-0 overflow-hidden p-0 sm:max-w-5xl">
        <DialogHeader className="border-b px-5 py-4 text-left">
          <DialogTitle>Export evidence</DialogTitle>
          <DialogDescription>
            The OpenTelemetry batch exactly as the sensor delivered it. Content
            gates on the device decide whether prompts and tool details are
            present.
            {typeof highlightRecord === "number" && (
              <>
                {" "}
                Opened from a finding: record #{number(highlightRecord)} is
                marked below.
              </>
            )}
          </DialogDescription>
        </DialogHeader>
        {exportId && (
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
            {detail.loading && !detail.data && (
              <p role="status" aria-live="polite" className="sr-only">
                Loading export {exportId}…
              </p>
            )}
            {metadataMissing ? (
              <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
                <div className="min-w-0">
                  <dt className="text-xs text-muted-foreground">Export ID</dt>
                  <dd className="break-all text-sm">{exportId}</dd>
                </div>
              </dl>
            ) : (
              <ExportMetadata detail={metadata} />
            )}
            <Tabs defaultValue="records" className="mt-4">
              <TabsList>
                <TabsTrigger value="records" className="px-3">
                  Records
                  {detail.data && (
                    <span className="number ml-1 text-muted-foreground">
                      {number(detail.data.records.length)}
                    </span>
                  )}
                </TabsTrigger>
                <TabsTrigger value="raw" className="px-3">
                  Raw payload
                </TabsTrigger>
              </TabsList>
              {detail.loading && !detail.data ? (
                <LoadingState label="Loading export payload…" />
              ) : detail.error ? (
                denied ? (
                  <EmptyState
                    title="Payload requires the analyst role"
                    description="Your account can review export metadata. Ask an administrator for the analyst role or higher to inspect record contents."
                  />
                ) : (
                  <ErrorState message={detail.error} onRetry={detail.reload} />
                )
              ) : detail.data ? (
                <>
                  <TabsContent value="records">
                    <RecordsTable
                      signal={detail.data.signal}
                      records={detail.data.records}
                      highlight={highlightRecord}
                    />
                  </TabsContent>
                  <TabsContent value="raw">
                    <RawPayload detail={detail.data} />
                  </TabsContent>
                </>
              ) : null}
            </Tabs>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
