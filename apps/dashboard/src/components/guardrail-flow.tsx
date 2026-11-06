"use client";

import { useCallback, useEffect, useLayoutEffect, useRef, useState, type RefObject } from "react";
import { ArrowRight, Bot, CircleCheck, CircleDashed, CircleHelp, FileOutput, KeyRound, MessageSquareWarning, Network, Package, Pause, Play, Search, ShieldCheck, Terminal, X } from "lucide-react";
import { ActivityExplorer, ActivityGroups } from "@/components/activity-explorer";
import { AgentLogo } from "@/components/agent-logo";
import { LiveActivityFeed, RISK_CATEGORIES } from "@/components/live-activity";
import { EmptyState, ErrorState, LoadingState, PageNotice, PageSection } from "@/components/page-layout";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { FlowGate, FlowNode } from "@/components/ui/flow-node";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Status } from "@/components/ui/status";
import { number, type DeviceStatus } from "@/lib/api";
import { activityIdentity, activityProduct, identityInitials, type ActivityFilters, type ActivitySummary } from "@/lib/activity-flow";
import { DECISION_TONES, formatMs, type GuardrailActive } from "@/lib/guardrail";
import type { ActivitySource } from "@/lib/guardrail-flow";
import { useResource } from "@/lib/use-resource";

const RISKS = [
  { key: "none", icon: CircleCheck }, { key: "secret_exfiltration", icon: KeyRound },
  { key: "data_exfiltration", icon: FileOutput }, { key: "destructive_command", icon: Terminal },
  { key: "supply_chain", icon: Package }, { key: "excessive_agency", icon: Bot },
  { key: "hallucination", icon: MessageSquareWarning }, { key: "unknown", icon: CircleHelp },
  { key: "unassessed", icon: CircleDashed },
] as const;
const riskLabel = (risk: string) => risk === "unassessed" ? "Unassessed" : RISK_CATEGORIES[risk as keyof typeof RISK_CATEGORIES] || "Insufficient context";
const DECISIONS = [
  { key: "allow", label: "Allow" }, { key: "ask", label: "Ask" }, { key: "deny", label: "Deny" },
  { key: "warn", label: "Warn" }, { key: "unavailable", label: "Check failed" }, { key: "unknown", label: "Unknown decision" },
] as const;
const RANGES = [["15m", "Last 15 minutes"], ["1h", "Last hour"], ["24h", "Last 24 hours"]] as const;
type SelectFilter = (key: keyof ActivityFilters, value: string, label: string) => void;
type PacketData = { id: string; routes: string[]; delay: number };

function Packet({ packet, paths, paused, onEnd }: {
  packet: PacketData; paths: RefObject<Map<string, SVGPathElement>>; paused: boolean; onEnd: (id: string) => void;
}) {
  const dot = useRef<SVGCircleElement>(null);
  const elapsed = useRef(-packet.delay);
  useEffect(() => {
    let previous = performance.now();
    let frame = 0;
    const draw = (time: number) => {
      if (!document.hidden) elapsed.current += Math.min(time - previous, 50);
      previous = time;
      const route = Math.floor(Math.max(elapsed.current, 0) / 1100);
      if (route >= packet.routes.length) { onEnd(packet.id); return; }
      const path = paths.current.get(packet.routes[route]);
      if (path && dot.current && elapsed.current >= 0) {
        const point = path.getPointAtLength(path.getTotalLength() * (elapsed.current % 1100) / 1100);
        dot.current.setAttribute("cx", String(point.x));
        dot.current.setAttribute("cy", String(point.y));
        dot.current.setAttribute("visibility", "visible");
      }
      frame = requestAnimationFrame(draw);
    };
    if (!paused) frame = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(frame);
  }, [packet, paths, paused, onEnd]);
  return <circle ref={dot} data-check-packet={packet.id} r="4" visibility="hidden"
    fill="var(--chart-1)" stroke="var(--card)" strokeWidth="2" />;
}

function Diagram({ data, filters, paused, onFilter, onFind }: {
  data: ActivitySummary; filters: ActivityFilters; paused: boolean; onFilter: SelectFilter; onFind: () => void;
}) {
  const canvas = useRef<HTMLDivElement>(null);
  const paths = useRef(new Map<string, SVGPathElement>());
  const [drawn, setDrawn] = useState<{ id: string; d: string }[]>([]);
  const [packets, setPackets] = useState<PacketData[]>([]);
  const previous = useRef<Set<string> | null>(null);
  const [reduced, setReduced] = useState(true);
  useEffect(() => {
    const media = matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  useEffect(() => {
    if (!data.recent_checks) return;
    const before = previous.current;
    previous.current = new Set(data.recent_checks.map(check => `${check.source}:${check.id}`));
    if (!before || paused || reduced || document.hidden) return;
    const arrivals = data.recent_checks.filter(check => !before.has(`${check.source}:${check.id}`)).slice(0, 24).reverse();
    if (arrivals.length) setPackets(current => [...current, ...arrivals.map((check, index) => ({
      id: `${check.source}:${check.id}`,
      routes: [`identities:${check.product_key}`, `source:${check.product_key}`, `risk:${check.risk}`],
      delay: index * 80,
    }))].slice(-24));
  }, [data, paused, reduced]);
  useEffect(() => { if (reduced) setPackets([]); }, [reduced]);
  const removePacket = useCallback((id: string) => setPackets(current => current.filter(packet => packet.id !== id)), []);
  useLayoutEffect(() => {
    const root = canvas.current;
    if (!root) return;
    const draw = () => {
      const bounds = root.getBoundingClientRect();
      const nodes = new Map([...root.querySelectorAll<HTMLElement>("[data-flow-node]")].map(node => [node.dataset.flowNode, node.getBoundingClientRect()]));
      const routes = data.sources.flatMap(source => [[`identities:${source.product_key}`, "identities", source.product_key], [`source:${source.product_key}`, source.product_key, "guardrail"]]);
      for (const risk of RISKS) if (data.risks[risk.key]) routes.push([`risk:${risk.key}`, "guardrail", `risk:${risk.key}`]);
      setDrawn(routes.flatMap(([id, from, to]) => {
        const a = nodes.get(from), b = nodes.get(to);
        if (!a || !b) return [];
        const x1 = a.right - bounds.left, y1 = a.top + a.height / 2 - bounds.top;
        const x2 = b.left - bounds.left, y2 = b.top + b.height / 2 - bounds.top;
        const bend = (x2 - x1) / 2;
        return [{ id, d: `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}` }];
      }));
    };
    draw();
    const observer = new ResizeObserver(draw);
    observer.observe(root);
    root.querySelectorAll<HTMLElement>("[data-flow-node]").forEach(node => observer.observe(node));
    return () => observer.disconnect();
  }, [data]);
  const selected = filters.identity ? data.top_identities.find(group => group.key === filters.identity!.value) : null;
  const remaining = data.totals.identities - data.top_identities.length;
  return <div role="region" aria-label="Activity flow diagram" tabIndex={0} className="overflow-x-auto rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring">
    <div ref={canvas} className="flow-canvas relative grid min-w-[1000px] grid-cols-[1fr_1.13fr_1.02fr_1.18fr] gap-x-12">
      <svg aria-hidden="true" className="pointer-events-none absolute inset-0 h-full w-full overflow-visible">
        {drawn.map(({ id, d }) => <path key={id} data-route={id} ref={path => {
          if (path) paths.current.set(id, path); else paths.current.delete(id);
        }} d={d} fill="none" stroke="var(--input)" strokeWidth="1.25" />)}
        {packets.map(packet => <Packet key={packet.id} packet={packet} paths={paths} paused={paused} onEnd={removePacket} />)}
      </svg>
      <div className="relative flex min-w-0 flex-col">
        <h3 className="text-sm font-semibold">Reported identities</h3><p className="mt-1 text-xs text-muted-foreground">{selected ? "Focused identity" : "Complete selected window"}</p>
        <div className="mt-4 flex min-h-[440px] flex-1 flex-col justify-center pb-4">
          <div data-flow-node="identities" className="rounded-md border border-input bg-card p-3">
            {selected ? <span aria-hidden="true" className="mb-3 flex size-9 items-center justify-center rounded-full bg-muted text-xs font-semibold">{identityInitials(selected.identity)}</span> : <>
              <div role="group" aria-label="Top identities by completed checks" className="grid max-w-56 grid-cols-5 gap-1.5">
                {data.top_identities.map(group => {
                  const identity = activityIdentity(group.identity);
                  const label = `${identity.title}\n${number(group.checks)} checks`;
                  return <Button key={group.key} variant="outline" className="aspect-square h-auto w-full max-w-9 rounded-full bg-muted p-0 text-xs font-semibold"
                    title={label} aria-label={`Inspect ${identity.label}, ${number(group.checks)} checks`}
                    onClick={() => onFilter("identity", group.key, identity.label)}>{identityInitials(group.identity)}</Button>;
                })}
              </div>
              <div className="mt-2 flex flex-wrap items-center justify-between gap-1 text-xs text-muted-foreground">
                <span>Top {data.top_identities.length} by checks</span>
                {remaining > 0 && <Button variant="outline" size="xs" onClick={onFind} aria-label={`${number(remaining)} more identities. Browse all identities`}>+{number(remaining)} more</Button>}
              </div>
            </>}
            <p className="mt-4 break-words text-base font-semibold" title={selected ? activityIdentity(selected.identity).title : undefined}>
              {selected ? activityIdentity(selected.identity).label : <><span data-testid="stat-users">{number(data.totals.identities)}</span> identities</>}
            </p>
            <p className="mt-1 break-words text-xs text-muted-foreground">{selected ? activityIdentity(selected.identity).detail : "All identities with matching checks"}</p>
            <p className="mt-4 flex flex-wrap justify-between gap-2 border-t pt-3 text-xs text-muted-foreground">Completed checks <b className="number text-sm text-foreground">{number(data.totals.checks)}</b></p>
          </div>
          <Button className="mt-2 w-full" onClick={onFind}><Search aria-hidden="true" />{selected ? "Switch identity" : "Find an identity"}<ArrowRight aria-hidden="true" /></Button>
          <p className="mt-2 text-center text-xs text-muted-foreground">Every identity contributes to the flow.</p>
        </div>
      </div>
      <div className="relative flex min-w-0 flex-col">
        <h3 className="text-sm font-semibold">Activity sources</h3><p className="mt-1 text-xs text-muted-foreground">Grouped by agent or gateway</p>
        <div className="mt-4 flex min-h-[440px] flex-1 flex-col justify-center gap-2 pb-4">
          {data.sources.map(source => <FlowNode key={source.product_key} data-flow-node={source.product_key}
            label={<span className="flex items-center gap-2">{source.source === "gateway" ? <Network aria-hidden="true" className="size-5 shrink-0" /> : <AgentLogo product={source.product} />}<span className="truncate">{activityProduct(source.source, source.product)}</span></span>}
            detail={`${number(source.identities)} identities · ${number(source.sessions)} ${source.source === "gateway" ? "routes" : "sessions"}`}
            count={source.checks} selected={filters.product?.value === source.product_key}
            aria-label={`Inspect ${activityProduct(source.source, source.product)}, ${number(source.checks)} checks`}
            onClick={() => onFilter("product", filters.product?.value === source.product_key ? "" : source.product_key, activityProduct(source.source, source.product))} />)}
        </div>
      </div>
      <div className="relative flex min-w-0 flex-col">
        <h3 className="text-sm font-semibold">Guardrail</h3><p className="mt-1 text-xs text-muted-foreground">Evaluated policy decisions</p>
        <div className="mt-4 flex min-h-[440px] flex-1 items-center pb-4">
          <FlowGate data-flow-node="guardrail"><p className="flex items-center gap-2 text-xs font-medium"><ShieldCheck aria-hidden="true" className="size-4 text-muted-foreground" />Combined policy result</p>
            {DECISIONS.filter(item => item.key !== "unknown" || data.decisions.unknown).map(item => <FlowNode compact key={item.key}
              label={<Status tone={item.key in DECISION_TONES ? DECISION_TONES[item.key as keyof typeof DECISION_TONES] : "neutral"}>{item.label}</Status>}
              count={data.decisions[item.key] || 0} selected={filters.decision?.value === item.key}
              onClick={() => onFilter("decision", filters.decision?.value === item.key ? "" : item.key, item.label)} />)}
            <div className="space-y-2 border-t pt-3 text-xs text-muted-foreground"><p>Shadow: {number(data.totals.shadow)} · Enforce: {number(data.totals.enforce)}</p><p>Shadow returns Allow. Failed checks allow the action.</p></div>
          </FlowGate>
        </div>
      </div>
      <div className="relative flex min-w-0 flex-col">
        <h3 className="text-sm font-semibold">Risk categories</h3><p className="mt-1 text-xs text-muted-foreground">Assessments from the same checks</p>
        <div className="mt-4 flex min-h-[440px] flex-1 flex-col justify-center gap-2 pb-4">
          {RISKS.map(({ key, icon: Icon }) => <FlowNode compact key={key} data-flow-node={`risk:${key}`}
            label={<span className="flex items-center gap-2"><Icon aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" /><span className="truncate">{riskLabel(key)}</span></span>}
            count={data.risks[key] || 0} selected={filters.risk?.value === key} title={riskLabel(key)}
            onClick={() => onFilter("risk", filters.risk?.value === key ? "" : key, riskLabel(key))} />)}
        </div>
      </div>
    </div>
  </div>;
}

function Measurements({ metrics }: { metrics?: GuardrailActive["jev"] }) {
  return <div role="group" aria-label="Guardrail measurements" className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
    <span>Last 5 min · All sources</span>
    <Popover><PopoverTrigger asChild><Button variant="ghost" size="xs" aria-label="Guardrail latency details">p95 <span className="number">{metrics ? formatMs(metrics.latency_p95_ms) : "Unavailable"}</span></Button></PopoverTrigger>
      <PopoverContent aria-label="Guardrail latency details"><p>Guardrail latency · p95</p><p className="mt-2">{metrics ? `${number(metrics.latency_samples)} completed attempts` : "No measurements reported"}</p><p className="mt-2 text-xs text-muted-foreground">Service operation duration. Last 5 minutes across all sources and identities, independent of the flow filters.</p></PopoverContent></Popover>
  </div>;
}

export function GuardrailFlow({ overview = false, devices }: { overview?: boolean; devices: DeviceStatus[] }) {
  const [range, setRange] = useState("1h");
  const [source, setSource] = useState<ActivitySource>("all");
  const [filters, setFilters] = useState<ActivityFilters>({});
  const [until, setUntil] = useState("");
  const [browseVersion, setBrowseVersion] = useState(0);
  const [findIdentity, setFindIdentity] = useState(false);
  const [directoryUntil, setDirectoryUntil] = useState("");
  const [inspect, setInspect] = useState(false);
  const [view, setView] = useState<"identities" | "sessions" | "checks">("identities");
  const { dateTime } = useTimeZone();
  const params = new URLSearchParams({ range, source });
  if (until) params.set("until", until);
  for (const [key, filter] of Object.entries(filters)) if (filter) params.set(key, filter.value);
  const resource = useResource<ActivitySummary>(`guardrail/flow?${params}&view=checks`, 0, Boolean(until));
  const measurements = useResource<GuardrailActive>("guardrail/active", 5000);
  const data = resource.data;
  const { loading, reload } = resource;
  useEffect(() => {
    if (until || loading) return;
    const timer = setInterval(() => { if (!document.hidden) void reload(); }, 5000);
    return () => clearInterval(timer);
  }, [until, loading, reload]);
  // Detail pagination pins the time window. It never becomes the input
  // to the overview, and a busy identity cannot evict quieter identities.
  const pin = () => { if (data && !until) setUntil(data.until); };
  const onFilter: SelectFilter = (key, value, label) => {
    setFilters(current => {
      const next = { ...current };
      if (value) next[key] = { value, label }; else delete next[key];
      if (key === "identity" || key === "product") delete next.session;
      return next;
    });
    setView(key === "identity" || key === "product" ? "sessions" : "checks");
  };
  const reset = () => { setFilters({}); setView("identities"); };
  const changeScope = () => { reset(); setUntil(""); };
  const details = new URLSearchParams(params);
  if (data) details.set("until", until || data.until);
  const filterKey = `${range}:${source}:${JSON.stringify(filters)}`;
  const directory = new URLSearchParams(details);
  if (directoryUntil) directory.set("until", directoryUntil);
  directory.delete("identity"); directory.delete("session");
  const openDirectory = () => { if (data) setDirectoryUntil(until || data.until); setFindIdentity(true); };
  const explorer = (data || until) && <ActivityExplorer key={`${filterKey}:${browseVersion}`} query={details.toString()} filterKey={filterKey} filters={filters} view={view} onView={setView} onFilter={onFilter} onInteract={pin} />;
  return <div className={overview ? "overview-activity space-y-4" : "space-y-4"}>
    <PageSection title="Activity flow" description="All completed checks in the selected window. Select an identity, source, or outcome to investigate."
      action={<>
        <Select value={range} onValueChange={value => { setRange(value); changeScope(); }}><SelectTrigger className="w-40" aria-label="Activity time window"><SelectValue /></SelectTrigger><SelectContent>{RANGES.map(([value, label]) => <SelectItem key={value} value={value}>{label}</SelectItem>)}</SelectContent></Select>
        <Select value={source} onValueChange={value => { setSource(value as ActivitySource); changeScope(); }}><SelectTrigger className="w-36" aria-label="Activity source"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All sources</SelectItem><SelectItem value="endpoints">Endpoints</SelectItem><SelectItem value="gateways">Gateways</SelectItem></SelectContent></Select>
        <Button variant="outline" onClick={() => { if (until) { setUntil(""); setBrowseVersion(value => value + 1); } else pin(); }} disabled={!data}>{until ? <Play aria-hidden="true" /> : <Pause aria-hidden="true" />}{until ? "Resume live" : "Pause view"}</Button>
      </>}>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b pb-3">
        <div className="flex flex-wrap items-center gap-2"><Button variant="ghost" size="xs" onClick={reset}>All identities</Button>
          {Object.entries(filters).map(([key, filter]) => filter && <Button key={key} variant="outline" size="xs" className="max-w-full" aria-label={`Remove ${filter.label} filter`} onClick={() => onFilter(key as keyof ActivityFilters, "", "")}><span className="truncate">{filter.label}</span><X aria-hidden="true" /></Button>)}</div>
        <Button variant="ghost" size="sm" onClick={openDirectory} disabled={!data}><Search aria-hidden="true" />Find an identity</Button>
      </div>
      {resource.error && <ErrorState message={`${resource.error}${data ? " Showing the last loaded activity." : ""}`} onRetry={reload} />}
      {loading && !data ? <LoadingState label="Loading activity flow" /> : data && <>
        <p className="mb-4 text-xs text-muted-foreground" aria-label="Activity window">{dateTime(data.since)} to {dateTime(data.until)} · {until ? "Fixed time window" : "Live window"}</p>
        <div className="mb-5 grid grid-cols-2 gap-4 border-b pb-4 lg:grid-cols-4" aria-label="Activity summary">
          {[["Completed checks", data.totals.checks, "stat-decisions"], ["Reported identities", data.totals.identities, "summary-identities"], ["Sessions & routes", data.totals.sessions, "stat-sessions"], ["Flagged checks", data.totals.flagged, "stat-flagged"]].map(([label, count, id]) => <div key={label}><p className="text-xs text-muted-foreground">{label}</p><p className="number mt-1 text-display font-semibold" data-testid={id}>{number(Number(count))}</p></div>)}
        </div>
        {data.totals.checks ? <Diagram key={filterKey} data={data} filters={filters} paused={Boolean(until)} onFilter={onFilter} onFind={openDirectory} /> : <EmptyState title="No matching checks" description="Choose a wider time window or clear the filters to see other activity." />}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t pt-3 text-xs text-muted-foreground"><span>{number(data.totals.checks)} matching checks · All represented</span><span>{number(data.totals.failed)} failed checks</span></div>
      </>}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <Measurements metrics={measurements.data?.jev} />
        {overview && <Button variant="ghost" size="xs" onClick={() => { pin(); setInspect(true); }} disabled={!data}>Explore activity<ArrowRight aria-hidden="true" /></Button>}
      </div>
      {measurements.error && <ErrorState message={`Guardrail measurements unavailable: ${measurements.error}`} onRetry={measurements.reload} />}
      <PageNotice collapsible title="Flow scope and Guardrail measurements">
        <p>The flow includes all completed backend checks in the selected time window and filters. Each check counts once per source, decision, and risk category. Identity counts are distinct; one identity can use several agents. Selecting a filter keeps live updates running. Searching or paging the detail lists fixes the time window; late assessments can update between requests. The identity directory holds its own window while the flow stays live.</p>
        <p>Dots show newly received checks from the latest 100 matching checks, with up to 24 dots at once. Initial history and filter changes do not replay. Counts include every matching check. Dots pause with the view and respect reduced motion.</p>
        <p>Reported accounts, device-scoped OS users, and gateway callers are not verified people. Different identifiers remain distinct, even when labels or initials match. Gateway callers remain separate from endpoint identities. Checks that never reach the backend are not included.</p>
        <p>Connections show associated activity, not evaluation order. Shadow returns Allow; Enforce returns supported decisions. Failed checks allow the action. A failed assessment adds no restriction; valid rule decisions still apply. Unassessed means the assessment is unavailable, not that the action was allowed. A returned restriction does not prove enforcement.</p>
        <p>Guardrail measurements cover service operations started in the last five minutes, independently of flow filters. Latency measures service operation duration.</p>
      </PageNotice>
    </PageSection>
    <Dialog open={findIdentity} onOpenChange={setFindIdentity}><DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-[850px]"><DialogHeader><DialogTitle>Find an identity</DialogTitle><DialogDescription>Search every reported identity matching this time window and source or outcome filters.</DialogDescription></DialogHeader>
      {(data || until) && <ActivityGroups key={directory.toString()} query={directory.toString()} view="identities" onInteract={() => {}} onSelect={group => { onFilter("identity", group.key, activityIdentity(group.identity).label); setFindIdentity(false); }} />}
    </DialogContent></Dialog>
    {overview ? <Dialog open={inspect} onOpenChange={setInspect}><DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-[1100px]"><DialogHeader><DialogTitle>Activity details</DialogTitle><DialogDescription>All matching activity in the fixed time window. Close this view and select Resume live to update the window.</DialogDescription></DialogHeader>{explorer}</DialogContent></Dialog>
      : <>{source !== "gateways" && <LiveActivityFeed devices={devices} />}{explorer}</>}
  </div>;
}
