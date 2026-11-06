"use client";

import { useMemo, useState } from "react";
import { Info, RefreshCw } from "lucide-react";
import { useTimeZone } from "@/components/time-zone-context";
import {
  CartesianGrid,
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  ChartReadout,
  SampleMarker,
  TimeAxisTick,
} from "@/components/chart-readout";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageSection,
} from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { type Device, type DeviceHealth } from "@/lib/api";
import { chartTicks, showSample } from "@/lib/chart";
import { sensorCpu, sensorMemory } from "@/lib/sensor-metrics";
import { useResource } from "@/lib/use-resource";

type Measurement = {
  cpu_percent: number | null;
  memory_rss_bytes: number | null;
};
type SensorMetrics = {
  sensor_id: string;
  range: string;
  window_start: string;
  generated_at: string;
  bucket_seconds: number;
  latest: Measurement & {
    last_heartbeat_at: string | null;
    status: Device["status"];
  };
  samples: (Measurement & { time: string })[];
};
const plots = [
  {
    key: "cpu_percent",
    title: "CPU usage",
    format: sensorCpu,
    color: "var(--chart-1)",
  },
  {
    key: "memory_rss_bytes",
    title: "Memory usage",
    format: sensorMemory,
    color: "var(--chart-1)",
  },
] as const;

export function SensorMetricsPanel({
  devices,
  sensorId,
  onSensorChange,
  range,
  onRangeChange,
}: {
  devices: DeviceHealth[];
  sensorId: string;
  onSensorChange: (value: string) => void;
  range: string;
  onRangeChange: (value: string) => void;
}) {
  const { chartTimestamp, label: timeZoneLabel } = useTimeZone();
  const [plotWidth, setPlotWidth] = useState(0);
  const selected =
    devices.find((device) => device.id === sensorId) || devices[0];
  const resource = useResource<SensorMetrics>(
    selected ? `sensors/${selected.id}/metrics?range=${range}` : null,
    30000,
  );
  // Do not show another sensor's readings while the selection is changing.
  const data =
    resource.data?.sensor_id === selected?.id && resource.data?.range === range
      ? resource.data
      : null;
  const chartData = useMemo(() => {
    const points: (Measurement & { time: number })[] = [];
    let previous = 0;
    for (const sample of data?.samples || []) {
      const time = new Date(sample.time).getTime();
      if (previous && time - previous > data!.bucket_seconds * 1000) {
        points.push({
          time: previous + data!.bucket_seconds * 1000,
          cpu_percent: null,
          memory_rss_bytes: null,
        });
      }
      points.push({ ...sample, time });
      previous = time;
    }
    return points;
  }, [data]);
  const start = data ? new Date(data.window_start).getTime() : 0;
  const end = data ? new Date(data.generated_at).getTime() : 0;
  const stale = Boolean(resource.error) || data?.latest.status !== "online";

  return (
    <PageSection
      title="App resource usage"
      titleAction={
        data && (
          <Popover>
            <PopoverTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="header-icon"
                aria-label="How sensor usage is measured"
                className="text-muted-foreground"
              >
                <Info aria-hidden="true" />
              </Button>
            </PopoverTrigger>
            <PopoverContent
              align="start"
              aria-label="How sensor usage is measured"
            >
              CPU is averaged between heartbeats and can exceed 100% when
              multiple cores are used. Memory is the process's current
              resident memory. Desktop UI, coding agents, and helper
              processes are excluded. History keeps the last reading each
              minute for 30 days. Charts show {data.bucket_seconds / 60}
              -minute averages in {timeZoneLabel}; missing measurements leave gaps.
              Device filters select the available sensors; the chart has its
              own time range.
            </PopoverContent>
          </Popover>
        )
      }
      description="CPU and resident memory used by the background sensor process."
      className="mb-4"
      action={
        selected && (
          <>
            <Select value={selected.id} onValueChange={onSensorChange}>
              <SelectTrigger
                aria-label="Sensor for resource usage"
                className="w-52"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {devices.map((device) => (
                  <SelectItem key={device.id} value={device.id}>
                    {device.label || device.hostname || device.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={range} onValueChange={onRangeChange}>
              <SelectTrigger
                aria-label="Sensor metrics time range"
                className="w-36"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
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
              aria-label="Refresh sensor metrics"
            >
              <RefreshCw
                className={`size-3.5 ${resource.loading ? "animate-spin" : ""}`}
              />
              Refresh
            </Button>
          </>
        )
      }
    >
      <div className="space-y-4">
        {!selected ? (
          <EmptyState
            title="No sensors in view"
            description="Enroll a sensor or adjust the device filters to view resource usage."
          />
        ) : (
          <>
            {resource.error && (
              <ErrorState
                message={`${resource.error}${data ? " Showing the last successful response." : ""}`}
                onRetry={resource.reload}
              />
            )}
            {!data && !resource.error && (
              <LoadingState label="Loading app resource usage" />
            )}
            {data && (
              <>
                <p className="text-xs text-muted-foreground">
                  {stale ? "Last reported" : "Latest heartbeat"}:{" "}
                  {data.latest.last_heartbeat_at
                    ? chartTimestamp(data.latest.last_heartbeat_at)
                    : "Not reported"}
                  {stale && " · Readings may be stale"}
                </p>
                {chartData.length > 0 &&
                  chartData[0].time > start + data.bucket_seconds * 1000 && (
                    <p className="text-xs text-muted-foreground">
                      Data since {chartTimestamp(chartData[0].time)}.
                      {range !== "1h" && " Choose a shorter range to inspect recent samples."}
                    </p>
                  )}
                <div className="grid min-w-0 gap-6 lg:grid-cols-2">
                  {plots.map((plot) => {
                    const scale = plot.key === "cpu_percent" ? 1 : 1024 ** 2;
                    const ticks = chartTicks(
                      Math.max(
                        ...chartData.map((row) => (row[plot.key] || 0) / scale),
                      ),
                      false,
                      0.1,
                    ).map((value) => value * scale);
                    return (
                      <div key={plot.key} className="min-w-0 space-y-2">
                        <h3 className="text-sm font-semibold">{plot.title}</h3>
                        <p className="figure number text-display font-semibold">
                          {plot.format(data.latest[plot.key])}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {plot.key === "cpu_percent"
                            ? "100% equals one logical CPU core."
                            : "Resident set size (RSS), in MiB."}
                        </p>
                        {chartData.some((row) => row[plot.key] != null) ? (
                          <div
                            className="h-64 min-w-0 w-full number [&_.recharts-surface]:focus-visible:outline-2 [&_.recharts-surface]:focus-visible:outline-ring"
                            aria-label={`Sensor ${plot.title.toLowerCase()} over time`}
                          >
                            <ResponsiveContainer
                              width="100%"
                              height="100%"
                              minWidth={0}
                              onResize={setPlotWidth}
                            >
                              <AreaChart
                                data={chartData}
                                margin={{
                                  top: 12,
                                  right: 12,
                                  bottom: 8,
                                  left: 0,
                                }}
                              >
                                <CartesianGrid
                                  vertical={false}
                                  stroke="var(--chart-grid)"
                                />
                                <XAxis
                                  dataKey="time"
                                  type="number"
                                  domain={[start, end]}
                                  ticks={
                                    plotWidth < 420
                                      ? [start, end]
                                      : [start, (start + end) / 2, end]
                                  }
                                  tick={
                                    <TimeAxisTick
                                      start={start}
                                      end={end}
                                    />
                                  }
                                  height={40}
                                  axisLine={false}
                                  tickLine={false}
                                />
                                <YAxis
                                  domain={[0, ticks.at(-1)!]}
                                  ticks={ticks}
                                  tickFormatter={(value: number) =>
                                    plot.format(value)
                                  }
                                  width={86}
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
                                        timestamp={chartTimestamp(
                                          Number(label),
                                        )}
                                        rows={[
                                          {
                                            label: plot.title,
                                            value: plot.format(
                                              payload[0]?.value == null
                                                ? null
                                                : Number(payload[0].value),
                                            ),
                                            color: plot.color,
                                          },
                                        ]}
                                      >
                                        <p>
                                          {data.bucket_seconds / 60}-minute
                                          average
                                          {stale ? " · Historical reading" : ""}
                                        </p>
                                      </ChartReadout>
                                    ) : null
                                  }
                                />
                                <Area
                                  dataKey={plot.key}
                                  stroke={plot.color}
                                  strokeWidth={2}
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  fill={plot.color}
                                  fillOpacity={0.08}
                                  type="linear"
                                  connectNulls={false}
                                  isAnimationActive={false}
                                  activeDot={{
                                    r: 4,
                                    fill: plot.color,
                                    stroke: "var(--card)",
                                    strokeWidth: 2,
                                  }}
                                  dot={({ cx, cy, index = 0 }) => (
                                    <SampleMarker
                                      cx={cx}
                                      cy={cy}
                                      color={plot.color}
                                      show={
                                        chartData[index]?.[plot.key] != null &&
                                        ((chartData[index - 1]?.[plot.key] ==
                                          null &&
                                          chartData[index + 1]?.[plot.key] ==
                                            null) ||
                                          showSample(
                                            chartData.map(
                                              (point) => point.time,
                                            ),
                                            index,
                                            plotWidth - 100,
                                            start,
                                            end,
                                          ))
                                      }
                                    />
                                  )}
                                />
                              </AreaChart>
                            </ResponsiveContainer>
                          </div>
                        ) : (
                          <div className="flex h-64 items-center justify-center">
                            <EmptyState
                              title="No measurements in this range"
                              description="Updated sensors report usage with each heartbeat. CPU needs two samples after startup."
                            />
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </>
        )}
      </div>
    </PageSection>
  );
}
