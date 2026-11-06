import { useMemo, useState, type ReactNode } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useChartColors } from "../hooks/useChartColors";
import { compact } from "../utils/format";
import { Button } from "./Form";
import { IconChart, IconTable } from "./icons";

interface Point { x: string; y: number }

function tickFormatter(range: "hour" | "day") {
  return (v: string) => {
    const d = new Date(v);
    return range === "hour" ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  };
}

function TooltipBox({ active, payload, label, name, color, bucket }: { active?: boolean; payload?: { value?: number }[]; label?: string; name: string; color: string; bucket: "hour" | "day" }) {
  if (!active || !payload?.length || !label) return null;
  const d = new Date(label);
  const when = bucket === "hour" ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  return (
    <div className="chart__tooltip">
      <strong>{(payload[0]?.value ?? 0).toLocaleString()}</strong>
      <div className="chart__tooltip-row"><i style={{ background: color }} />{name}<span className="muted" style={{ marginLeft: "auto" }}>{when}</span></div>
    </div>
  );
}

function ChartFrame({ title, children, table, height }: { title: string; children: ReactNode; table: ReactNode; height: number }) {
  const [view, setView] = useState<"chart" | "table">("chart");
  return (
    <div className="chart">
      <div className="row row--between" style={{ marginBottom: 6 }}>
        <span className="small muted">{title}</span>
        <Button size="sm" variant="ghost" onClick={() => setView((v) => (v === "chart" ? "table" : "chart"))} icon={view === "chart" ? <IconTable /> : <IconChart />} aria-label={view === "chart" ? "Show as table" : "Show as chart"}>{view === "chart" ? "Table" : "Chart"}</Button>
      </div>
      {view === "chart" ? <div style={{ width: "100%", height }}>{children}</div> : <div className="table-wrap" style={{ maxHeight: height, overflowY: "auto" }}>{table}</div>}
    </div>
  );
}

/** Single-series time series. Area for volumes, columns for counts. */
export function TimeSeriesChart({ data, name, bucket, kind = "area", height = 200, slot = 0 }: { data: Point[]; name: string; bucket: "hour" | "day"; kind?: "area" | "column"; height?: number; slot?: number }) {
  const c = useChartColors();
  const color = c.cat[slot] ?? c.cat[0]!;
  const fmt = tickFormatter(bucket);
  const rows = useMemo(() => data.map((d) => ({ x: d.x, y: d.y })), [data]);
  const total = rows.reduce((n, r) => n + r.y, 0);
  const table = (
    <table className="table table--compact">
      <thead><tr><th>Time</th><th className="num">{name}</th></tr></thead>
      <tbody>{rows.map((r) => <tr key={r.x}><td>{fmt(r.x)}</td><td className="num">{r.y.toLocaleString()}</td></tr>)}</tbody>
    </table>
  );
  const axisProps = { tick: { fill: c.textMuted, fontSize: 11 }, axisLine: { stroke: c.grid }, tickLine: false as const };
  return (
    <ChartFrame title={`${name}: ${compact(total)} total`} table={table} height={height}>
      <ResponsiveContainer width="100%" height="100%">
        {kind === "area" ? (
          <AreaChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid stroke={c.grid} vertical={false} />
            <XAxis dataKey="x" tickFormatter={fmt} minTickGap={32} {...axisProps} />
            <YAxis width={44} tickFormatter={(v: number) => compact(v)} {...axisProps} />
            <Tooltip content={<TooltipBox name={name} color={color} bucket={bucket} />} cursor={{ stroke: c.muted, strokeWidth: 1 }} />
            <Area type="monotone" dataKey="y" stroke={color} strokeWidth={2} fill={color} fillOpacity={0.1} dot={false} activeDot={{ r: 4, stroke: c.surface, strokeWidth: 2, fill: color }} isAnimationActive={false} />
          </AreaChart>
        ) : (
          <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: 0 }} barCategoryGap="30%">
            <CartesianGrid stroke={c.grid} vertical={false} />
            <XAxis dataKey="x" tickFormatter={fmt} minTickGap={32} {...axisProps} />
            <YAxis width={44} allowDecimals={false} tickFormatter={(v: number) => compact(v)} {...axisProps} />
            <Tooltip content={<TooltipBox name={name} color={color} bucket={bucket} />} cursor={{ fill: c.grid, fillOpacity: 0.5 }} />
            <Bar dataKey="y" fill={color} maxBarSize={24} radius={[4, 4, 0, 0]} isAnimationActive={false} />
          </BarChart>
        )}
      </ResponsiveContainer>
    </ChartFrame>
  );
}

/** Horizontal bar list for nominal categories: one hue, values labeled. */
export function BarList({ items, max, format = (n) => n.toLocaleString(), slot = 0, onClick }: { items: { label: string; value: number; key?: string }[]; max?: number; format?: (n: number) => string; slot?: number; onClick?: (key: string) => void }) {
  const c = useChartColors();
  const color = c.cat[slot] ?? c.cat[0]!;
  const m = max ?? Math.max(1, ...items.map((i) => i.value));
  if (items.length === 0) return <div className="empty">No data</div>;
  return (
    <div className="bars" role="list">
      {items.map((it) => {
        const k = it.key ?? it.label;
        const inner = (
          <>
            <span className="bars__label" title={it.label}>{it.label}</span>
            <span className="bars__track" aria-hidden="true"><span className="bars__fill" style={{ width: `${Math.max(2, (it.value / m) * 100)}%`, background: color }} /></span>
            <span className="bars__value">{format(it.value)}</span>
          </>
        );
        return onClick ? (
          <button key={k} type="button" className="bars__row-btn" role="listitem" style={{ display: "contents", background: "none", border: 0, font: "inherit", color: "inherit", cursor: "pointer", textAlign: "left" }} onClick={() => onClick(k)} aria-label={`${it.label}: ${format(it.value)}`}>{inner}</button>
        ) : <div key={k} role="listitem" style={{ display: "contents" }}>{inner}</div>;
      })}
    </div>
  );
}

/** Severity split as a labeled stacked meter with a legend. */
export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const c = useChartColors();
  const order = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((n, k) => n + (counts[k] ?? 0), 0);
  return (
    <div>
      <div className="sev-bar" aria-hidden="true">
        {order.map((k) => (counts[k] ?? 0) > 0 && <span key={k} style={{ width: `${((counts[k] ?? 0) / Math.max(1, total)) * 100}%`, background: c.sev[k] }} />)}
      </div>
      <div className="chart__legend" style={{ marginTop: 8 }}>
        {order.map((k) => <span key={k}><i className="is-rect" style={{ background: c.sev[k] }} />{k} <b className="num">{counts[k] ?? 0}</b></span>)}
      </div>
    </div>
  );
}
