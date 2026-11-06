"use client";

import { useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartReadout, SampleMarker, TimeAxisTick } from "@/components/chart-readout";
import { EmptyState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { useTimeZone } from "@/components/time-zone-context";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { showSample } from "@/lib/chart";
import type { HostMetrics } from "@/components/host-metrics";

const series = [
  { key: "postgres", label: "PostgreSQL", color: "var(--chart-1)", dash: undefined },
  { key: "server", label: "API server", color: "var(--chart-2)", dash: "6 4" },
  { key: "dashboard", label: "Dashboard", color: "var(--chart-3)", dash: "2 3" },
] as const;
const percent = (value: number) => value > 0 && value < 0.1 ? "<0.1%" : `${value.toFixed(1)}%`;
const cores = (value: number) => value > 0 && value < 0.01 ? "<0.01" : value.toFixed(2);

export function ServiceCpuPanel({ data, start, end, stale }: {
  data: HostMetrics;
  start: number;
  end: number;
  stale: boolean;
}) {
  const { chartTimestamp, label } = useTimeZone();
  const [width, setWidth] = useState(0);
  const points: Array<Record<string, number | null>> = [];
  let previous = 0;
  for (const sample of data.samples) {
    const time = new Date(sample.time).getTime();
    if (previous && (sample.gap_before || time - previous > data.interval_seconds * 1500)) {
      points.push({ time: previous + 1000, postgres: null, server: null, dashboard: null });
    }
    points.push({ time, ...Object.fromEntries(series.map(({ key }) => [key, sample.service_cpu_percent?.[key] ?? null])) });
    previous = time;
  }
  const summaries = series.map((item) => {
    const summary = data.service_cpu_summary?.services[item.key];
    if (summary) return { ...item, ...summary };
    const measured = data.samples.filter((sample) => sample.service_cpu_percent?.[item.key] != null);
    return {
      ...item,
      count: measured.length,
      percent: measured.length ? measured.reduce((sum, sample) => sum + sample.service_cpu_percent![item.key]!, 0) / measured.length : null,
      cores: measured.length ? measured.reduce((sum, sample) => sum + sample.service_cpu_percent![item.key]! * sample.cpu_count! / 100, 0) / measured.length : null,
    };
  });
  const available = summaries.some((item) => item.count > 0);
  return (
    <PageSection title="CPU by service" description="Average share of host CPU capacity over the selected range.">
      {stale && <PageNotice title="Historical CPU readings">The last successful samples are shown. Current service CPU usage is unknown.</PageNotice>}
      {!available ? (
        <EmptyState title="Service CPU unavailable" description="No service CPU measurements in this range. Collection requires readable Docker cgroup v2 counters; older samples contain host totals only." />
      ) : (
        <div className="grid min-w-0 gap-4 xl:grid-cols-2">
          <div className="min-w-0">
            <div className="h-64 min-w-0 number [&_.recharts-surface]:focus-visible:outline-2 [&_.recharts-surface]:focus-visible:outline-ring" aria-label="Service CPU over time">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} onResize={setWidth}>
                <LineChart data={points} margin={{ top: 8, right: 12, left: 0, bottom: 0 }} accessibilityLayer aria-label={`Service CPU over time, percent of host capacity, ${label}`}>
                  <CartesianGrid vertical={false} stroke="var(--chart-grid)" strokeWidth={1} />
                  <XAxis dataKey="time" type="number" scale="time" domain={[start, end]} ticks={[start, (start + end) / 2, end]} tick={<TimeAxisTick start={start} end={end} />} minTickGap={38} axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tickFormatter={(value) => `${value}%`} width={48} axisLine={false} tickLine={false} />
                  <Tooltip isAnimationActive={false} filterNull={false} cursor={{ stroke: "var(--chart-axis)", strokeWidth: 1 }} content={({ active, payload, label: time }) => active && payload?.length ? (
                    <ChartReadout timestamp={chartTimestamp(Number(time))} rows={series.map((item) => {
                      const value = payload.find((entry) => entry.dataKey === item.key)?.value;
                      return { label: item.label, value: typeof value === "number" ? percent(value) : "Not recorded", color: item.color, dash: item.dash };
                    })} />
                  ) : null} />
                  {series.map((item) => (
                    <Line key={item.key} type="linear" dataKey={item.key} stroke={item.color} strokeWidth={2} strokeDasharray={item.dash} strokeLinecap="round" strokeLinejoin="round" isAnimationActive={false} connectNulls={false}
                      dot={(props) => <SampleMarker key={props.key} {...props} color={item.color} show={
                        (points[props.index - 1]?.[item.key] == null && points[props.index + 1]?.[item.key] == null)
                        || showSample(points.map((point) => point.time!), props.index, width - 60, start, end)
                      } />}
                      activeDot={{ r: 4, fill: item.color, stroke: "var(--card)", strokeWidth: 2 }} />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
            <ul className="flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-label="Service CPU legend">
              {series.map((item) => <li key={item.key} className="flex items-center gap-1.5"><svg aria-hidden="true" className="h-3 w-6" viewBox="0 0 24 12"><line x1="0" x2="24" y1="6" y2="6" stroke={item.color} strokeWidth={2} strokeDasharray={item.dash} /></svg>{item.label}</li>)}
            </ul>
          </div>
          <TableLayout>
            <Table>
              <TableHeader><TableRow><TableHead>Service</TableHead><TableHead className="text-right">Cores</TableHead><TableHead className="text-right">Host CPU</TableHead></TableRow></TableHeader>
              <TableBody>
                {summaries.map((item) => <TableRow key={item.key}>
                  <TableCell><span className="font-medium">{item.label}</span><p className="text-xs text-muted-foreground">{item.count} of {data.service_cpu_summary?.total_samples ?? data.samples.length} samples</p></TableCell>
                  <TableCell className="number text-right">{item.cores == null ? "Not recorded" : cores(item.cores)}</TableCell>
                  <TableCell className="number text-right">{item.percent == null ? "Not recorded" : <><span>{percent(item.percent)}</span><div className="mt-1 h-2 w-full overflow-hidden rounded-xs bg-muted" aria-hidden="true"><div className="h-full rounded-xs bg-chart-1" style={{ width: `${item.percent}%` }} /></div></>}</TableCell>
                </TableRow>)}
              </TableBody>
            </Table>
          </TableLayout>
        </div>
      )}
      <PageNotice title="Service CPU measurement" collapsible>
        Docker containers are grouped by process name across this host. API server includes ingest and detection work in the same container. Other host workloads are excluded. Missing counters and container changes leave gaps, not zeroes. Averages use only measured samples. CPU execution excludes I/O wait and steal, which the host CPU chart includes.
      </PageNotice>
    </PageSection>
  );
}
