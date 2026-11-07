"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useDashboard } from "@/components/dashboard-context";
import { ChartReadout, TimeAxisTick } from "@/components/chart-readout";
import { EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { number } from "@/lib/api";
import { chartTicks, isUtcDailySeries } from "@/lib/chart";
import { creditAmount, creditServices, validCreditSnapshot, type CreditService, type CreditSnapshot } from "@/lib/credits";
import { useResource } from "@/lib/use-resource";

const categories: { name: string; color: string; services: CreditService[] }[] = [
  { name: "Live Guardrail", color: "var(--chart-model-cost-guardrail)", services: ["guardrail"] },
  { name: "Investigations", color: "var(--chart-1)", services: ["investigations"] },
  { name: "AI Assets", color: "var(--chart-2)", services: ["application_research", "skill_assessment"] },
  { name: "Assistant", color: "var(--chart-3)", services: ["assistant", "overview_summaries", "session_summaries"] },
  { name: "Rules", color: "var(--chart-model-cost-verification)", services: ["rule_generation"] },
  { name: "Threat Intelligence", color: "var(--chart-model-cost-benchmark)", services: ["url_reputation", "package_vulnerabilities"] },
];
const statusText = {
  disabled: ["Credit charging is off", "New operations do not deduct credits while charging is off. A credit balance is not available in this mode."],
  unconfigured: ["Credits are not configured", "Credit rates or an account allowance have not been set. A current credit balance is unavailable."],
  exhausted: ["No credits available", "Your available credit balance is exhausted or reserved for unfinished operations. Contact your administrator."],
  unavailable: ["Credit information is unavailable", "The credit service could not confirm your balance and usage. Try refreshing this page."],
} as const;
const chartNumber = (value: number) => value.toLocaleString(undefined, { maximumFractionDigits: 6 });

function UsageChart({ data }: { data: CreditSnapshot }) {
  const { chartTimestamp } = useTimeZone();
  const daily = isUtcDailySeries(data.bucket_seconds, data.series.map(row => row.time));
  const series = data.series.map(row => ({ ...row, timestamp: Math.max(Date.parse(data.since), Date.parse(row.time)),
    ...Object.fromEntries(categories.map(category => {
      const amounts = row.by_service.filter(item => category.services.includes(item.service)).map(item => item.credits_charged);
      const known = amounts.filter((value): value is string => value !== null);
      return [category.name, known.length ? known.reduce((sum, value) => sum + Number(value), 0) : amounts.length || row.credits_charged === null ? null : 0];
    })),
  }));
  const ticks = chartTicks(Math.max(0, ...data.series.map(row => Number(row.credits_charged ?? 0))), false, 0.000001);
  const timeTicks = [...new Set([series[0]?.timestamp, series[Math.floor(series.length / 2)]?.timestamp, series.at(-1)?.timestamp])].filter((value): value is number => value !== undefined);
  const visible = categories.filter(category => data.by_service.some(row => category.services.includes(row.service) && row.operations > 0));
  return <>
    <p className="mb-3 text-xs text-muted-foreground">{daily ? "Daily" : "Hourly"} credit usage{daily ? " · UTC" : ""}</p>
    <div className="h-48 min-w-0 text-xs number" aria-label="Credit usage chart">
      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
        <BarChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: 0 }} maxBarSize={36} barCategoryGap={daily ? "5%" : "10%"} accessibilityLayer aria-label="Credits used over time">
          <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
          <XAxis dataKey="timestamp" ticks={timeTicks} tick={<TimeAxisTick start={timeTicks[0]} end={timeTicks.at(-1)!} daily={daily} />} tickLine={false} axisLine={false} minTickGap={36} />
          <YAxis ticks={ticks} domain={[0, ticks.at(-1)!]} tickFormatter={chartNumber} tickLine={false} axisLine={false} width={Math.max(40, ...ticks.map(value => chartNumber(value).length * 7 + 12))} />
          <Tooltip content={({ active, payload }) => {
            const row = payload?.[0]?.payload as typeof series[number] | undefined;
            return active && row ? <ChartReadout timestamp={chartTimestamp(row.time, daily)} rows={visible.map(category => ({
              label: category.name, color: category.color,
              value: row[category.name as keyof typeof row] == null ? "Unavailable" : `${chartNumber(Number(row[category.name as keyof typeof row]))} credits`,
            }))}>
              <p>{number(row.operations)} operations</p>
              {row.pending_operations > 0 && <p>{number(row.pending_operations)} pending</p>}
            </ChartReadout> : null;
          }} />
          {visible.map(category => <Bar key={category.name} dataKey={category.name} stackId="credits" fill={category.color} isAnimationActive={false} />)}
        </BarChart>
      </ResponsiveContainer>
    </div>
    <ul aria-label="Credit usage categories" className="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-xs text-muted-foreground">
      {visible.map(category => <li key={category.name} className="flex items-center gap-2"><span aria-hidden className="size-2 rounded-xs" style={{ backgroundColor: category.color }} />{category.name}</li>)}
    </ul>
  </>;
}

export function Credits() {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const [range, setRange] = useState("24h");
  const [sort, setSort] = useState<{ key: "operations" | "credits_charged"; order: "asc" | "desc" }>({ key: "credits_charged", order: "desc" });
  const resource = useResource<CreditSnapshot>(user ? `credits?range=${range}` : null, 30000, false, { validate: validCreditSnapshot });
  const data = resource.data && validCreditSnapshot(resource.data) && resource.data.tenant_id === user?.tenant.id ? resource.data : null;
  const invalid = resource.data !== null && data === null;
  const status = data && data.status !== "active" ? statusText[data.status] : null;
  const showUsage = data && (["active", "exhausted"].includes(data.status) || data.summary.operations > 0 || data.summary.credits_charged !== null);
  const services = [...(data?.by_service ?? [])].sort((a, b) => {
    const left = a[sort.key], right = b[sort.key];
    if (left === null) return right === null ? 0 : 1;
    if (right === null) return -1;
    return (Number(left) - Number(right)) * (sort.order === "asc" ? 1 : -1);
  });
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div role="group" aria-label="Credit time range" className="flex gap-1 rounded-md bg-muted p-1">
        {["24h", "30d", "90d"].map(value => <Button key={value} variant={range === value ? "outline" : "ghost"} size="sm" aria-pressed={range === value} onClick={() => setRange(value)}>{value}</Button>)}
      </div>
      <Button variant="outline" size="sm" disabled={resource.loading} onClick={() => void resource.reload()}>Refresh credits</Button>
    </div>
    {resource.error && <ErrorState message={`Credit information could not be refreshed.${data ? " Showing the last loaded information." : ""}`} onRetry={resource.reload} />}
    {invalid && <ErrorState message="The credit service returned information that could not be verified." onRetry={resource.reload} />}
    {!data && !invalid && !resource.error && <LoadingState label="Loading credits…" />}
    {data && <>
      {status && <PageNotice title={status[0]}>{status[1]}</PageNotice>}
      <PageSection title="Credit balance" description="$1 = 100 credits. Fractional credits apply to small operations.">
        <dl className="grid gap-5 sm:grid-cols-3">
          <div><dt className="text-sm text-muted-foreground">Available credits</dt><dd className="figure number mt-1 break-words text-display font-semibold">{creditAmount(data.balance.available)}</dd></div>
          <div><dt className="text-sm text-muted-foreground">Reserved credits</dt><dd className="figure number mt-1 break-words text-display font-semibold">{creditAmount(data.balance.reserved)}</dd><p className="mt-1 text-xs text-muted-foreground">Held for unfinished operations</p></div>
          <div><dt className="text-sm text-muted-foreground">Credits used in this period</dt><dd className="figure number mt-1 break-words text-display font-semibold">{creditAmount(data.summary.credits_charged)}</dd></div>
        </dl>
      </PageSection>
      <PageSection title="Credit usage" description={`${dateTime(data.since)} to ${dateTime(data.until)}`}>
        <p className="mb-3 text-xs text-muted-foreground">Updated {dateTime(resource.updated?.toISOString())}</p>
        {!showUsage ? <EmptyState title="Credit usage is unavailable" description="Confirmed credit usage will appear here when it is available." /> :
          data.summary.operations === 0 ? <EmptyState title="No operations in this period" description="Choose another time range to view recorded credit usage." /> :
            data.summary.credits_charged === null ? <EmptyState title="Credit charges are not available" description="Operations were recorded, but their credit charges have not been confirmed." /> : <UsageChart data={data} />}
        {showUsage && data.summary.pending_operations > 0 && <p className="mt-3 text-sm">{number(data.summary.pending_operations)} {data.summary.pending_operations === 1 ? "operation is" : "operations are"} pending. Reserved credits are separate from confirmed charges.</p>}
      </PageSection>
      {showUsage && data.by_service.length > 0 && <PageSection title="Usage by feature">
        <TableLayout><Table aria-label="Credit usage by feature"><TableHeader><TableRow>
          <TableHead>Feature</TableHead>
          {([["operations", "Operations"], ["credits_charged", "Credits used"]] as const).map(([key, label]) => <TableHead key={key} className="text-right" aria-sort={sort.key === key ? (sort.order === "desc" ? "descending" : "ascending") : "none"}>
            <button type="button" className="inline-flex min-h-8 items-center gap-1 rounded-sm focus-visible:outline-2 focus-visible:outline-ring" onClick={() => setSort({ key, order: sort.key === key && sort.order === "desc" ? "asc" : "desc" })}>
              {label}
              {sort.key !== key ? <ArrowUpDown className="size-3" aria-hidden="true" /> : sort.order === "desc" ? <ArrowDown className="size-3" aria-hidden="true" /> : <ArrowUp className="size-3" aria-hidden="true" />}
            </button>
          </TableHead>)}
        </TableRow></TableHeader><TableBody>{services.map(row => <TableRow key={row.service}>
          <TableCell className="font-medium">{creditServices[row.service]}</TableCell><TableCell className="number text-right">{number(row.operations)}</TableCell>
          <TableCell className="number text-right">{creditAmount(row.credits_charged)}</TableCell>
        </TableRow>)}</TableBody></Table></TableLayout>
      </PageSection>}
      <PageNotice title="How credits work" collapsible>
        <p>Credits pay for OpenAIDR features. One US dollar buys 100 credits. Each operation uses the service rate that applies when it starts. Your credit usage begins when credit accounting is enabled. Pausing charging keeps earlier credit usage visible.</p>
        <p>Reserved credits are held while an operation is unfinished. Confirmed charges appear as credits used.</p>
        <p>Your coding tools have separate usage records on <Link href="/costs/agents" className="underline underline-offset-4">AI Agent Costs</Link>.</p>
      </PageNotice>
    </>}
  </div>;
}
