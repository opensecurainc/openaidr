"use client";

import { hasRole } from "@/lib/roles";

import { useTimeZone } from "@/components/time-zone-context";
import { useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartReadout, SampleMarker, TimeAxisTick } from "@/components/chart-readout";
import { chartTicks, showSample } from "@/lib/chart";
import { useDashboard } from "@/components/dashboard-context";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageNotice,
  PageSection,
} from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useResource } from "@/lib/use-resource";
import { ServiceCpuPanel } from "@/components/service-cpu";

type Sample = {
  time: string;
  gap_before?: boolean;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  disk_read_bytes_per_second: number;
  disk_write_bytes_per_second: number;
  cpu_count?: number;
  memory_used_bytes?: number;
  memory_total_bytes?: number;
  disk_used_bytes?: number;
  disk_total_bytes?: number;
  disk_available_bytes?: number;
  disk_is_root?: boolean;
  root_disk_percent?: number | null;
  root_disk_used_bytes?: number;
  root_disk_total_bytes?: number;
  root_disk_available_bytes?: number;
  service_cpu_percent?: { postgres: number | null; server: number | null; dashboard: number | null };
};
export type HostMetrics = {
  status: "ok" | "stale" | "waiting" | "disabled";
  message: string;
  hostname: string | null;
  disk_path: string;
  interval_seconds: number;
  last_sample_at: string | null;
  samples: Sample[];
  latest_sample?: Sample | null;
  service_cpu_summary?: {
    total_samples: number;
    services: Record<string, { count: number; percent: number | null; cores: number | null }>;
  };
};
const rangeHours: Record<string, number> = { "5m": 5 / 60, "1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720 };
type Metric = "cpu_percent" | "memory_percent" | "disk_percent" | "root_disk_percent"
  | "disk_read_bytes_per_second" | "disk_write_bytes_per_second";
type Plot = {
  title: string;
  description: string;
  unit: "%" | "KiB/s";
  series: { key: Metric; label: string }[];
};
const basePlots: Plot[] = [
  {
    title: "CPU usage",
    description: "Non-idle time, including I/O wait and steal.",
    unit: "%",
    series: [{ key: "cpu_percent", label: "CPU" }],
  },
  {
    title: "Memory usage",
    description: "Used memory reported by sysstat.",
    unit: "%",
    series: [{ key: "memory_percent", label: "Memory" }],
  },
  {
    title: "Disk space",
    description: "",
    unit: "%",
    series: [{ key: "disk_percent", label: "Disk" }],
  },
  {
    title: "Disk I/O",
    description: "Read and write activity across the host's block devices.",
    unit: "KiB/s",
    series: [
      { key: "disk_read_bytes_per_second", label: "Read" },
      { key: "disk_write_bytes_per_second", label: "Write" },
    ],
  },
];
const colors = ["var(--chart-1)", "var(--chart-2)"];
const rateTick = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1,
});
const percent = (value: number) =>
  value > 0 && value < 0.1 ? "<0.1%" : `${value.toFixed(1)}%`;
const rate = (value: number) =>
  value > 0 && value / 1024 < 0.1
    ? "<0.1 KiB/s"
    : `${(value / 1024).toFixed(1)} KiB/s`;

function diskAmount(value: number, fractionDigits = 1) {
  return new Intl.NumberFormat("en-US", {
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
    maximumSignificantDigits: 3,
    roundingPriority: "lessPrecision",
    useGrouping: false,
  }).format(value);
}

function bytes(value: number, disk = false) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${disk ? diskAmount(value, unit ? 1 : 0) : value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function capacityText(
  sample: Sample,
  metric: Metric,
) {
  if (metric === "cpu_percent") {
    return sample.cpu_count == null
      ? "Capacity not recorded"
      : `${((sample.cpu_percent / 100) * sample.cpu_count).toFixed(2)} of ${sample.cpu_count} logical cores in use`;
  }
  const used =
    metric === "memory_percent"
      ? sample.memory_used_bytes
      : metric === "root_disk_percent"
        ? sample.root_disk_used_bytes
      : sample.disk_used_bytes;
  const total =
    metric === "memory_percent"
      ? sample.memory_total_bytes
      : metric === "root_disk_percent"
        ? sample.root_disk_total_bytes
      : sample.disk_total_bytes;
  return used == null || total == null
    ? "Capacity not recorded"
    : `${bytes(used, metric !== "memory_percent")} used / ${bytes(total, metric !== "memory_percent")} total`;
}

function availableSpace(sample: Sample, metric: "disk_percent" | "root_disk_percent") {
  const value = metric === "disk_percent" ? sample.disk_available_bytes : sample.root_disk_available_bytes;
  if (value == null) return "Available space not recorded";
  const gib = value / 1024 ** 3;
  return `${gib > 0 && gib < 0.1 ? "<0.1" : diskAmount(gib)} GiB available`;
}

export function HostMetricsPanel() {
  const { chartTimeTick, chartTimestamp, label } = useTimeZone();
  const { user } = useDashboard();
  const permitted = hasRole(user, "it_admin");
  const [range, setRange] = useState("24h");
  const [plotWidth, setPlotWidth] = useState(0);
  const resource = useResource<HostMetrics>(
    permitted ? `system/metrics?range=${range}` : null,
    30000,
    false,
    { sourceCard: "host-metrics" },
  );
  const data = resource.data;
  const latest = data?.latest_sample ?? data?.samples.at(-1);
  const diskIsRoot = data?.disk_path === "/" || latest?.disk_is_root === true;
  const chartData = useMemo(() => {
    const result: Array<Record<string, number | null>> = [];
    let previous = 0;
    for (const sample of data?.samples || []) {
      const time = new Date(sample.time).getTime();
      if (previous && (sample.gap_before || time - previous > (data?.interval_seconds || 60) * 1500)) {
        result.push({ time: previous + 1000 });
      }
      result.push({
        cpu_percent: sample.cpu_percent,
        memory_percent: sample.memory_percent,
        disk_percent: diskIsRoot
          ? sample.root_disk_percent ?? (data?.disk_path === "/" || sample.disk_is_root === true ? sample.disk_percent : null)
          : sample.disk_percent,
        root_disk_percent: sample.root_disk_percent ?? null,
        time,
        disk_read_bytes_per_second: sample.disk_read_bytes_per_second / 1024,
        disk_write_bytes_per_second: sample.disk_write_bytes_per_second / 1024,
      });
      previous = time;
    }
    return result;
  }, [data, diskIsRoot]);
  if (!permitted) return null;
  const plots = basePlots.map((plot): Plot => plot.title !== "Disk space" ? plot : {
    ...plot,
    description: diskIsRoot && data?.disk_path !== "/"
      ? `Data path ${data?.disk_path} shares the boot filesystem.`
      : "",
    series: diskIsRoot
      ? [{ key: "disk_percent", label: "Boot disk (/)" }]
      : [
          { key: "root_disk_percent", label: "Boot disk (/)" },
          { key: "disk_percent", label: `Data disk (${data?.disk_path})` },
        ],
  });
  const end = (resource.updated || new Date()).getTime();
  const start = end - rangeHours[range] * 3600000;

  return (
    <>
    <PageSection
      title="Host resource usage"
      description="CPU, memory, and disk activity on the container host."
      action={
        <>
          <Select value={range} onValueChange={setRange}>
            <SelectTrigger
              aria-label="Host metrics time range"
              className="w-40"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="5m">Last 5 minutes</SelectItem>
              <SelectItem value="1h">Last hour</SelectItem>
              <SelectItem value="6h">Last 6 hours</SelectItem>
              <SelectItem value="24h">Last 24 hours</SelectItem>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="sm"
            onClick={resource.reload}
            disabled={resource.loading}
            aria-label="Refresh host metrics"
          >
            <RefreshCw
              className={`size-3.5 ${resource.loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        </>
      }
    >
      <div className="@container space-y-4">
        <PageNotice title="Host metrics collection" collapsible>
          Samples are collected every minute and retained for 30 days. The last
          24 hours show minute readings; 7-day and 30-day charts show 10-minute
          and 30-minute averages. Longer history accumulates after the collector
          is updated. Chart timestamps use {label}.
        </PageNotice>
        {data && data.interval_seconds > 60 && (
          <p className="text-xs text-muted-foreground">
            {data.interval_seconds / 60}-minute averages; summary values show the latest reading.
          </p>
        )}
        {resource.error && (
          <ErrorState
            message={`${resource.error}${data ? " Showing the last successful response." : ""}`}
            onRetry={resource.reload}
          />
        )}
        {!data && !resource.error ? (
          <LoadingState label="Loading host metrics" />
        ) : null}
        {data && data.status !== "ok" && data.samples.length > 0 && (
          <PageNotice title="Host metrics delayed">{data.message}</PageNotice>
        )}
        {data && !latest ? (
          <EmptyState
            title={
              data.status === "ok" || data.status === "stale"
                ? "No samples in this time range"
                : "Host metrics unavailable"
            }
            description={
              data.message ||
              "Select a longer time range or wait for the next sample."
            }
          />
        ) : data && latest ? (
          <>
            <p className="text-xs text-muted-foreground">
              {data.hostname} · Last sample{" "}
              {chartTimestamp(data.last_sample_at!)}
              {resource.error || data.status === "stale"
                ? " · Historical readings"
                : ""}
            </p>
            {data.samples.length > 0 &&
              new Date(data.samples[0].time).getTime() >
                start + data.interval_seconds * 1000 && (
                <p className="text-xs text-muted-foreground">
                  Data since {chartTimestamp(data.samples[0].time)}. Choose a
                  shorter range to inspect recent samples.
                </p>
              )}
            <div className="grid min-w-0 grid-cols-1 gap-4 @2xl:grid-cols-2 @4xl:grid-cols-4">
              {plots.map((plot) => (
                <div key={plot.title} className="row-span-3 grid min-w-0 grid-rows-subgrid gap-2">
                  <div className="space-y-2">
                    <h3 className="text-sm font-semibold">{plot.title}</h3>
                    <div className="flex flex-wrap gap-x-4 gap-y-1">
                      {plot.series.map((series, index) => (
                        <div key={series.key} className="min-w-0 space-y-1">
                          <p className="text-sm break-words">
                            <svg
                              aria-hidden="true"
                              className="mr-1.5 inline-block h-3 w-6"
                              viewBox="0 0 24 12"
                            >
                              <line
                                x1="0"
                                x2="24"
                                y1="6"
                                y2="6"
                                stroke={colors[index]}
                                strokeWidth={2}
                              />
                            </svg>
                            {series.label}:{" "}
                            <span className="number font-semibold">
                              {latest[series.key] == null ? "Not recorded" : plot.unit === "%"
                                ? percent(latest[series.key]!)
                                : rate(latest[series.key]!)}
                            </span>
                          </p>
                          {plot.unit === "%" && (
                            series.key === "disk_percent" || series.key === "root_disk_percent" ? (
                              <p className="flex flex-wrap gap-x-2 text-xs number text-muted-foreground">
                                <span>{capacityText(latest, series.key)}</span>
                                <span>{availableSpace(latest, series.key)}</span>
                              </p>
                            ) : (
                              <p className="text-sm number">
                                {capacityText(latest, series.key)}
                              </p>
                            )
                          )}
                        </div>
                      ))}
                    </div>
                    {plot.description && (
                      <p className="text-xs text-muted-foreground">
                        {plot.description}
                      </p>
                    )}
                  </div>
                  <div
                    className="h-64 min-w-0 w-full number [&_.recharts-surface]:focus-visible:outline-2 [&_.recharts-surface]:focus-visible:outline-ring"
                    aria-label={`${plot.title} over time`}
                  >
                    <ResponsiveContainer
                      width="100%"
                      height="100%"
                      minWidth={0}
                      onResize={setPlotWidth}
                    >
                      <LineChart
                        data={chartData}
                        syncId="host-resource-usage"
                        syncMethod="value"
                        margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
                        accessibilityLayer
                        aria-label={`${plot.title} over time, ${plot.unit}, ${label}`}
                      >
                        <CartesianGrid
                          vertical={false}
                          stroke="var(--chart-grid)"
                          strokeWidth={1}
                        />
                        <XAxis
                          dataKey="time"
                          type="number"
                          scale="time"
                          domain={[start, end]}
                          ticks={plotWidth < 400 ? [start, end] : [start, (start + end) / 2, end]}
                          tickFormatter={(value) =>
                            chartTimeTick(Number(value))
                          }
                          tick={<TimeAxisTick start={start} end={end} stacked />}
                          interval={0}
                          height={44}
                          axisLine={false}
                          tickLine={false}
                        />
                        <YAxis
                          domain={
                            plot.unit === "%"
                              ? [0, 100]
                              : [
                                  0,
                                  chartTicks(
                                    Math.max(
                                      ...chartData.map((row) =>
                                        Math.max(
                                          Number(
                                            row.disk_read_bytes_per_second ||
                                              0,
                                          ),
                                          Number(
                                            row.disk_write_bytes_per_second ||
                                              0,
                                          ),
                                        ),
                                      ),
                                    ),
                                  ).at(-1)!,
                                ]
                          }
                          tickFormatter={(value: number) =>
                            plot.unit === "%"
                              ? `${value}%`
                              : value > 0 && value < 0.1 ? "<0.1" : rateTick.format(value)
                          }
                          tickCount={5}
                          width={48}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          isAnimationActive={false}
                          filterNull={false}
                          cursor={{
                            stroke: "var(--chart-axis)",
                            strokeWidth: 1,
                          }}
                          content={({ active, payload, label }) =>
                            active && payload?.length ? (
                              <ChartReadout
                                timestamp={chartTimestamp(Number(label))}
                                rows={plot.series.map((series, index) => {
                                  const value = payload.find(
                                    (entry) => entry.dataKey === series.key,
                                  )?.value;
                                  return {
                                    label: series.label,
                                    value:
                                      value == null
                                        ? "Not reported"
                                        : plot.unit === "%"
                                          ? percent(Number(value))
                                          : rate(Number(value) * 1024),
                                    color: colors[index],
                                  };
                                })}
                              >
                                {(resource.error ||
                                  data.status === "stale") && <p>Stale</p>}
                              </ChartReadout>
                            ) : null
                          }
                        />
                        {plot.series.map((series, index) => (
                          <Line
                            key={series.key}
                            dataKey={series.key}
                            name={series.label}
                            stroke={colors[index]}
                            strokeWidth={2}
                            type="linear"
                            strokeLinejoin="round"
                            strokeLinecap="round"
                            activeDot={{
                              r: 4,
                              fill: colors[index],
                              stroke: "var(--card)",
                              strokeWidth: 2,
                            }}
                            dot={({ cx, cy, index: pointIndex = 0 }) => {
                              const row = chartData[pointIndex];
                              const isolated =
                                chartData[pointIndex - 1]?.[series.key] ==
                                  null &&
                                chartData[pointIndex + 1]?.[series.key] ==
                                  null;
                              const timestamps = chartData.map((point) =>
                                Number(point.time),
                              );
                              return (
                                <SampleMarker
                                  cx={cx}
                                  cy={cy}
                                  color={colors[index]}
                                  show={
                                    row?.[series.key] != null &&
                                    (isolated ||
                                      showSample(
                                        timestamps,
                                        pointIndex,
                                        plotWidth - 60,
                                        start,
                                        end,
                                      ))
                                  }
                                />
                              );
                            }}
                            isAnimationActive={false}
                            connectNulls={false}
                          />
                        ))}
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                  {plot.unit === "KiB/s" && (
                    <p className="text-xs text-muted-foreground">KiB/s</p>
                  )}
                </div>
              ))}
            </div>
          </>
        ) : null}
      </div>
    </PageSection>
    {data && <ServiceCpuPanel data={data} start={start} end={end} stale={Boolean(resource.error) || data.status === "stale"} />}
    </>
  );
}
