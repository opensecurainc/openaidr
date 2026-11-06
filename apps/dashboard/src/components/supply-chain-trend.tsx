"use client";

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Info, TableProperties } from "lucide-react";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { chartTicks, chartTimestamp } from "@/lib/chart";
import { supplyChainSources, inventorySources, type SupplyChainSource } from "@/lib/use-inventory-pages";

type Counts = { components: number; device_weighted: number };
type Day = { date: string; captured_at: string | null; categories: Record<SupplyChainSource, Counts> | null };
export type AttentionHistory = { timezone: "UTC"; scope: "tenant"; checks_enabled: boolean; days: Day[] };
type Measure = keyof Counts;
const fills = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-supply-chain-plugins)"];
const dayLabel = (day: string) => new Date(`${day}T00:00:00Z`).toLocaleDateString("en-US", { timeZone: "UTC", month: "short", day: "numeric" });
const total = (day: Day, measure: Measure) => day.categories ? supplyChainSources.reduce((sum, source) => sum + day.categories![source][measure], 0) : null;

function validHistory(data: AttentionHistory) {
  return data.scope === "tenant" && data.timezone === "UTC" && typeof data.checks_enabled === "boolean"
    && Array.isArray(data.days) && data.days.length === 30 && data.days.every((day, index) =>
      day && typeof day === "object" && /^\d{4}-\d{2}-\d{2}$/.test(day.date) && Number.isFinite(Date.parse(day.date))
      && (!index || Date.parse(day.date) - Date.parse(data.days[index - 1].date) === 86400000)
      && (day.categories === null ? day.captured_at === null
        : typeof day.captured_at === "string" && Number.isFinite(Date.parse(day.captured_at))
          && supplyChainSources.every((source) => {
            const value = day.categories?.[source];
            return value && Number.isSafeInteger(value.components) && value.components >= 0
              && Number.isSafeInteger(value.device_weighted) && value.device_weighted >= value.components;
          })));
}

export function SupplyChainTrend({ data, error, loading, reload, actions }: {
  data: AttentionHistory | null; error: string; loading: boolean; reload: () => void; actions?: ReactNode;
}) {
  const [measure, setMeasure] = useState<Measure>("device_weighted");
  const [active, setActive] = useState<number | null>(null);
  const [help, setHelp] = useState(false);
  const [table, setTable] = useState(false);
  const [width, setWidth] = useState(900);
  const host = useRef<HTMLDivElement>(null);
  const id = useId();
  const valid = data && validHistory(data);
  const days = valid ? data.days : [];
  const latest = days.findLast((day) => day.categories !== null);
  const missing = days.filter((day) => day.categories === null).length;
  const unit = measure === "device_weighted" ? "Component-device pairs" : "Components";
  const ticks = chartTicks(Math.max(0, ...days.map((day) => total(day, measure) ?? 0)), true);
  const max = ticks.at(-1)!;
  const left = 36, right = 12, top = 12, plotHeight = 148, slot = (width - left - right) / 30;
  const barWidth = Math.min(24, Math.max(2, slot - 4));
  const selected = active === null ? null : days[active];
  useEffect(() => {
    if (!host.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(host.current);
    return () => observer.disconnect();
  }, [valid, latest !== undefined]);
  const keys = <ul aria-label="Chart categories" className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
    {supplyChainSources.map((source, i) => <li key={source} className="flex items-center gap-2"><span aria-hidden className="size-2.5 rounded-xs" style={{ background: fills[i] }} />{inventorySources[source]}</li>)}
  </ul>;
  return <section aria-label="Component attention history" className="min-w-0"><Card className="gap-0">
    <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-2">
      <div><h2 id={`${id}-title`} className="text-base font-semibold">Components needing attention</h2>
        <p className="text-xs text-muted-foreground">Last 30 days · Known vulnerabilities only · All devices · UTC</p></div>
      <div className="flex flex-wrap items-center gap-2">
        <fieldset className="flex rounded-md border border-input p-0.5" aria-label="Count measure">
          {(["components", "device_weighted"] as const).map((value) => <label key={value} className={`cursor-pointer rounded-sm px-3 py-2.5 text-sm has-focus-visible:outline-2 has-focus-visible:outline-ring sm:py-1 ${measure === value ? "bg-primary text-primary-foreground" : "text-foreground"}`}>
            <input type="radio" name={`${id}-measure`} value={value} checked={measure === value} className="sr-only"
              onChange={() => { setMeasure(value); setActive(null); }} />{value === "components" ? "Unweighted" : "Device-weighted"}</label>)}
        </fieldset>
        <Button variant="outline" size="header-icon" aria-label="How counts are calculated" title="How counts are calculated" aria-expanded={help} aria-controls={`${id}-help`} onClick={() => setHelp(!help)}><Info /></Button>
        <Button variant="outline" size="header-icon" aria-label="View daily data" title="View daily data" aria-expanded={table} aria-controls={`${id}-data`} onClick={() => setTable(!table)}><TableProperties /></Button>
        {actions}
      </div>
    </div>
    {error && <div className="px-4 py-2"><ErrorState onRetry={reload} message={`Attention history: ${error}${latest ? " Showing the last loaded history." : ""}`} /></div>}
    {data && !valid && <div className="px-4 py-2"><ErrorState onRetry={reload} message="Attention history is unavailable: invalid response." /></div>}
    {data && valid && !data.checks_enabled && <p className="px-4 pt-2 text-xs text-muted-foreground">Vulnerability checks are disabled. Only previously recorded history is shown.</p>}
    {loading && !data ? <div className="px-4 py-3"><LoadingState label="Loading attention history…" /></div>
      : valid && !latest ? <EmptyState title="No attention history recorded yet" description="Daily snapshots start after the history worker is deployed. Missing days are unavailable, not zero." />
      : latest && <>
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2">
          <p className="text-xs text-muted-foreground" data-testid="attention-history-latest">Last snapshot {dayLabel(latest.date)}: <strong className="number text-sm text-foreground">{total(latest, measure)}</strong> {unit.toLowerCase()}
            <span className="mx-2" aria-hidden>·</span>{total(latest, measure === "components" ? "device_weighted" : "components")} {measure === "components" ? "component-device pairs" : "components"}
            {missing > 0 && <span> · {missing} days without snapshots</span>}
            <span className="sr-only">. Last recorded {chartTimestamp(latest.captured_at!, false, "UTC")}</span></p>{keys}
        </div>
        <div ref={host} className="relative mx-4 h-48 min-w-0" onPointerLeave={() => { if (!host.current?.contains(document.activeElement)) setActive(null); }}
          onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setActive(null); }}>
          <svg width="100%" height="192" viewBox={`0 0 ${width} 192`} role="group" aria-label={`${unit} by day and category, UTC`}>
            {ticks.map((tick) => <g key={tick}><line x1={left} x2={width - right} y1={top + plotHeight * (1 - tick / max)} y2={top + plotHeight * (1 - tick / max)} stroke="var(--chart-grid)" />
              <text x={left - 8} y={top + plotHeight * (1 - tick / max) + 4} textAnchor="end" fill="var(--muted-foreground)" className="text-xs">{tick}</text></g>)}
            {days.map((day, index) => {
              const x = left + (index + 0.5) * slot, amount = total(day, measure);
              let used = 0;
              const description = day.categories ? supplyChainSources.map((source) => `${inventorySources[source]}: ${day.categories![source].components} components, ${day.categories![source].device_weighted} component-device pairs`).join("; ") : "No snapshot recorded";
              return <g key={day.date} data-day={day.date} role="button" tabIndex={0} aria-label={`${dayLabel(day.date)}. ${description}`}
                onFocus={() => setActive(index)} onPointerEnter={() => setActive(index)} onClick={() => setActive(index)}
                onKeyDown={(event) => {
                  if (event.key === "Escape") { setActive(null); return; }
                  if (!["ArrowLeft", "ArrowRight", "Home", "End", "Enter", " "].includes(event.key)) return;
                  event.preventDefault();
                  const target = event.key === "Home" ? 0 : event.key === "End" ? 29 : Math.max(0, Math.min(29, index + (event.key === "ArrowLeft" ? -1 : event.key === "ArrowRight" ? 1 : 0)));
                  host.current?.querySelectorAll<SVGGElement>("[data-day]")[target]?.focus(); setActive(target);
                }}>
                <rect x={left + index * slot} y={top} width={slot} height={plotHeight} fill="transparent" />
                {day.categories && supplyChainSources.map((source, i) => {
                  const value = day.categories![source][measure], height = value / max * plotHeight;
                  used += value;
                  return value > 0 && <rect key={source} data-category={source} data-value={value} x={x - barWidth / 2} y={top + plotHeight * (1 - used / max)} width={barWidth} height={height} fill={fills[i]} stroke="var(--card)" strokeWidth={1} />;
                })}
                {amount === 0 && <circle cx={x} cy={top + plotHeight} r={2} fill="var(--muted-foreground)" />}
                {active === index && <line x1={x} x2={x} y1={top} y2={top + plotHeight} stroke="var(--chart-axis)" />}
              </g>;
            })}
            {days.map((day, index) => (index === 0 || index === 29 || (width < 600 ? index === 14 : index % 5 === 0)) &&
              <text key={day.date} x={left + (index + 0.5) * slot} y={184} textAnchor={index === 0 ? "start" : index === 29 ? "end" : "middle"} fill="var(--muted-foreground)" className="text-xs">{dayLabel(day.date)}</text>)}
          </svg>
          {selected && <div role="tooltip" className="pointer-events-none absolute top-0 z-20 w-80 max-w-full rounded-lg border bg-card p-3 text-xs shadow-overlay" style={{ left: Math.max(0, Math.min(width - Math.min(320, width), left + (active! < 15 ? active! + 1 : active! - 1) * slot - (active! < 15 ? 0 : 320))) }}>
            <p className="mb-2 text-muted-foreground">{chartTimestamp(`${selected.date}T00:00:00Z`, true)}</p>
            {selected.categories ? <><div className="grid grid-cols-[1fr_72px_64px] gap-1"><span>Category</span><span className="text-right">Unweighted</span><span className="text-right">Weighted</span>
              {supplyChainSources.map((source, i) => <div key={source} className="contents"><span className="flex items-center gap-1"><span className="size-2 rounded-xs" style={{ background: fills[i] }} />{inventorySources[source]}</span><span className="number text-right">{selected.categories![source].components}</span><span className="number text-right">{selected.categories![source].device_weighted}</span></div>)}
              <strong>Total</strong><strong className="number text-right">{total(selected, "components")}</strong><strong className="number text-right">{total(selected, "device_weighted")}</strong></div>
              <p className="mt-2 text-muted-foreground">Recorded {chartTimestamp(selected.captured_at!, false, "UTC")}</p></> : "No snapshot recorded"}
          </div>}
        </div>
      </>}
    <div id={`${id}-help`} hidden={!help} className="space-y-2 border-t p-4 text-sm text-muted-foreground">
      <p>Unweighted counts each component with a known vulnerability once within its category. Device-weighted sums its distinct affected devices. Versions and copies on one device count once; CVSS does not change the weight.</p>
      <p>A component on two devices plus another on one device is two components and three component-device pairs. These are outstanding findings in the last recorded snapshot each day, not new findings per day. The current UTC day can change as new snapshots arrive.</p>
      <p>History covers the full tenant and does not follow the inventory filters below. The live review table covers loaded records and can differ from the last snapshot. Missing days are gaps. Zero findings does not establish complete assessment or safety. Stale findings remain counted until a successful check replaces them.</p>
    </div>
    <div id={`${id}-data`} hidden={!table} className="border-t">
      <div tabIndex={0} role="region" aria-label="Daily attention data" className="max-h-80 overflow-auto">
        <Table><TableHeader><TableRow><TableHead>Date (UTC)</TableHead>{supplyChainSources.map((source) => <TableHead key={source}>{inventorySources[source]}</TableHead>)}<TableHead>Total {unit.toLowerCase()}</TableHead><TableHead>Recorded (UTC)</TableHead></TableRow></TableHeader>
          <TableBody>{days.map((day) => <TableRow key={day.date}><TableCell>{day.date}</TableCell>{supplyChainSources.map((source) => <TableCell key={source} className="number">{day.categories?.[source][measure] ?? "Unavailable"}</TableCell>)}<TableCell className="number">{total(day, measure) ?? "Unavailable"}</TableCell><TableCell>{day.captured_at ? chartTimestamp(day.captured_at, false, "UTC") : "No snapshot"}</TableCell></TableRow>)}</TableBody></Table>
      </div>
    </div>
  </Card></section>;
}
