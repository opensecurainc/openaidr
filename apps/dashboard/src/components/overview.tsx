"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { BookOpen, CircleDollarSign, Cpu, Radar, RefreshCw, ScanLine, Shield, TriangleAlert, type LucideIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useDashboard } from "@/components/dashboard-context";
import { useTimeZone } from "@/components/time-zone-context";
import { LiveGuardrail } from "@/components/guardrail";
import { Button } from "@/components/ui/button";
import { CodeBlock } from "@/components/ui/code-block";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { PageNotice } from "@/components/page-layout";
import { Badge } from "@/components/ui/badge";
import { api, APIError, relative } from "@/lib/api";
import { displayText } from "@/lib/display";
import { canAccessPage } from "@/lib/roles";

// Most urgent first. The label is always shown, so color is never the only signal.
const tones = {
  critical: { label: "Critical", badge: "critical", text: "text-severity-critical-text", rail: "border-severity-critical-text", icon: "bg-severity-critical/12" },
  high: { label: "High", badge: "high", text: "text-severity-high-text", rail: "border-severity-high-text", icon: "bg-severity-high/12" },
  warning: { label: "Warning", badge: "warning", text: "text-status-warning", rail: "border-status-warning", icon: "bg-status-warning/10" },
  info: { label: "Info", badge: "info", text: "text-status-info", rail: "border-status-info", icon: "bg-status-info/10" },
  neutral: { label: "Note", badge: "outline", text: "text-foreground", rail: "border-border", icon: "bg-muted" },
  positive: { label: "OK", badge: "ok", text: "text-status-ok", rail: "border-status-ok", icon: "bg-status-ok/10" },
} as const;
const topicIcons = new Map<string, LucideIcon>([
  ["Findings", TriangleAlert],
  ["Detection", Radar],
  ["Guardrail", Shield],
  ["Coverage", ScanLine],
  ["Assets", Cpu],
  ["Costs", CircleDollarSign],
]);
const toneOrder = Object.keys(tones);
// Summaries saved before the dashboard labeled tones carry the label in the text.
const tonePrefix = /^(critical|high|warning|info|positive|neutral|ok)\s*[:.\u2013\u2014-]\s*/i;
type Source = {
  id: string; path: string; title: string; scope: string; captured_at: string;
  status: "available" | "unavailable"; facts: Record<string, unknown>;
};
type SummaryItem = {
  topic: string; headline?: string; caption?: string; text: string; detail: string;
  tone: keyof typeof tones; citations: string[];
};
type Summary = { items: SummaryItem[]; sources: Source[]; generated_at: string };
const SHOWN_CITATIONS = 2;

function itemText(item: SummaryItem) {
  const text = displayText(item.text).replace(tonePrefix, "");
  return text ? text[0].toUpperCase() + text.slice(1) : displayText(item.text);
}

function validSummary(value: Summary) {
  return value && Number.isFinite(Date.parse(value.generated_at)) &&
    Array.isArray(value.sources) && value.sources.length > 0 && value.sources.every((source) =>
      source && typeof source.id === "string" && typeof source.path === "string" &&
      source.path.startsWith("/") && !source.path.startsWith("//") &&
      typeof source.title === "string" && typeof source.scope === "string" &&
      ["available", "unavailable"].includes(source.status) && Number.isFinite(Date.parse(source.captured_at))) &&
    Array.isArray(value.items) && value.items.length > 0 && value.items.length <= 6 && value.items.every((item) =>
      item && typeof item.topic === "string" && typeof item.text === "string" && typeof item.detail === "string" &&
      (item.headline === undefined || typeof item.headline === "string") &&
      (item.caption === undefined || typeof item.caption === "string") &&
      Object.hasOwn(tones, item.tone) && Array.isArray(item.citations) && item.citations.length > 0 &&
      item.citations.every((id) => value.sources.some((source) => source.id === id)));
}

export function Overview() {
  const { user } = useDashboard();
  return <div className="overview-layout">
    <AISummary key={`${user?.tenant.id}:${user?.id}:${user?.roles.join(",")}`} />
    {canAccessPage(user, "/guardrail/live") ? <LiveGuardrail overview /> :
      <PageNotice title="Activity flow requires the Security Analyst role"><p>Your summary includes the pages available to your assigned roles.</p></PageNotice>}
  </div>;
}

function AISummary() {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const router = useRouter();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [panel, setPanel] = useState<"summary" | "sources" | null>(null);
  const [sourceId, setSourceId] = useState("");
  const active = useRef<AbortController | null>(null);
  const generate = useCallback(async (refresh = false) => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setLoading(true);
    setError("");
    try {
      if (!refresh) {
        try {
          const cached = await api<{ summary: Summary | null; stale: boolean }>("overview/summary", { signal: controller.signal });
          if (controller.signal.aborted) return;
          if (!cached || typeof cached.stale !== "boolean" || (cached.summary !== null && !validSummary(cached.summary))) {
            throw new Error("The server returned an incomplete summary.");
          }
          if (cached.summary) {
            setSummary(cached.summary);
            if (!cached.stale) return;
          }
        } catch (cause) {
          // Older APIs deny the unknown GET route. POST checks access independently.
          if (!(cause instanceof APIError && [403, 404, 405].includes(cause.status))) throw cause;
        }
      }
      const result = await api<Summary>("overview/summary", {
        method: "POST", body: JSON.stringify({ refresh }), signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      if (!validSummary(result)) throw new Error("The server returned an incomplete summary.");
      setSummary(result);
    } catch (cause) {
      if (controller.signal.aborted) return;
      if (cause instanceof APIError && [401, 403].includes(cause.status)) {
        setSummary(null);
        if (cause.status === 403) window.dispatchEvent(new Event("dashboard-access-denied"));
        else router.replace("/login");
      }
      setError(cause instanceof Error ? cause.message : "The summary could not be generated.");
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, [router]);
  useEffect(() => {
    const timer = setTimeout(() => void generate(), 0);
    return () => { clearTimeout(timer); active.current?.abort(); };
  }, [generate]);
  useEffect(() => {
    if (panel !== "sources" || !sourceId) return;
    const frame = requestAnimationFrame(() => document.getElementById(`summary-source-${sourceId}`)?.scrollIntoView({ block: "nearest" }));
    return () => cancelAnimationFrame(frame);
  }, [panel, sourceId]);
  // Keep the relative age current while the page stays open.
  const [, setTick] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setTick((tick) => tick + 1), 60_000);
    return () => clearInterval(timer);
  }, []);
  const showSource = (id: string) => { setSourceId(id); setPanel("sources"); };
  const citations = (item: SummaryItem, limit = item.citations.length) => {
    const chips = item.citations.slice(0, limit).map((id) => {
      const source = summary!.sources.find((entry) => entry.id === id)!;
      return <button key={id} type="button" className="summary-citation" aria-label={`Source ${id}: ${source.title}`} title={source.title} onClick={() => showSource(id)}>{id}</button>;
    });
    const hidden = item.citations.length - chips.length;
    if (hidden > 0) chips.push(<button key="more" type="button" className="summary-citation summary-citation-more" aria-label={`${hidden} more ${hidden === 1 ? "source" : "sources"}`} title={`${hidden} more ${hidden === 1 ? "source" : "sources"}`} onClick={() => showSource(item.citations[limit])}>+{hidden}</button>);
    return chips;
  };
  // The topic opens the first cited page the viewer can access, other than Overview itself.
  const topicPath = (item: SummaryItem) => item.citations
    .map((id) => summary!.sources.find((entry) => entry.id === id)!.path)
    .find((path) => path !== "/" && canAccessPage(user, path));
  const items = summary ? [...summary.items].sort((a, b) => toneOrder.indexOf(a.tone) - toneOrder.indexOf(b.tone)) : [];
  const missing = summary?.sources.filter((source) => source.status === "unavailable").length ?? 0;
  return <section aria-labelledby="ai-summary-title" className="overview-summary rounded-lg border bg-card px-4 py-2">
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h2 id="ai-summary-title" className="flex items-center gap-2 text-base font-semibold"><BookOpen className="size-4 text-primary" aria-hidden="true" /> AI summary</h2>
        <p className="text-xs text-muted-foreground">{summary ? `Generated ${dateTime(summary.generated_at)} · ${relative(summary.generated_at)}${missing ? ` · ${missing} sources unavailable` : ""}` : "Across your accessible pages"}</p>
        {loading && <p role="status" className="text-xs text-muted-foreground">{summary ? "Refreshing summary…" : "Generating summary… This can take about 20 seconds. You can keep using this page."}</p>}
      </div>
      <div className="flex items-center gap-2">
        {summary && <><Button variant="ghost" size="xs" onClick={() => setPanel("summary")}>Full summary</Button><Button variant="ghost" size="xs" onClick={() => { setSourceId(""); setPanel("sources"); }}>{summary.sources.length} sources</Button></>}
        <Button variant="outline" size="xs" disabled={loading} onClick={() => void generate(true)} title="Generate a new summary"><RefreshCw className={loading ? "animate-spin" : ""} aria-hidden="true" /> Regenerate</Button>
      </div>
    </div>
    {error && <p role="alert" className="mt-2 text-sm text-status-critical">{error}{summary && " Showing the previous summary."} <button className="underline" disabled={loading} onClick={() => void generate(true)}>Retry</button></p>}
    {loading && !summary && <div aria-hidden="true" className="summary-points mt-2 grid gap-x-3 gap-y-3 md:grid-cols-3 xl:grid-cols-6">
      {Array.from({ length: 6 }, (_, index) => <div key={index} className="space-y-2 border-l-[3px] border-border py-0.5 pl-2.5 motion-safe:animate-pulse"><div className="h-5 w-1/2 rounded-xs bg-muted" /><div className="h-3 rounded-xs bg-muted" /><div className="h-3 w-4/5 rounded-xs bg-muted" /></div>)}
    </div>}
    {summary && <div className="summary-points mt-2 grid gap-x-3 gap-y-3 md:grid-cols-3 xl:grid-cols-6">
      {items.map((item) => {
        const tone = tones[item.tone];
        const Icon = topicIcons.get(item.topic) ?? BookOpen;
        const path = topicPath(item);
        const caption = item.caption ? displayText(item.caption) : "";
        const topic = path ? <Link href={path} className="font-semibold hover:underline">{item.topic}</Link> : <span className="font-semibold">{item.topic}</span>;
        return <article key={item.topic} aria-label={item.topic} className={`flex min-w-0 flex-col gap-1 border-l-[3px] pl-2.5 ${tone.rail}`}>
          <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
            <h3 className="flex items-center gap-2 text-xs">
              <span className={`flex size-7 shrink-0 items-center justify-center rounded-md ${tone.icon} ${tone.text}`}><Icon className="size-4" aria-hidden="true" /></span>
              {topic}
            </h3>
            <Badge variant={tone.badge} className="ml-auto">{tone.label}</Badge>
          </div>
          {item.headline && <p className="flex min-w-0 items-center">
            <span className={`summary-headline figure truncate text-base font-bold leading-none ${tone.text}`} title={caption || undefined}>{displayText(item.headline)}{caption && <span className="sr-only"> {caption} </span>}</span>
          </p>}
          <p className="summary-text text-xs leading-4 break-words">{itemText(item)}{citations(item, SHOWN_CITATIONS).map((chip) => <span key={chip.key} className="ml-1 inline-block align-text-bottom">{chip}</span>)}</p>
        </article>;
      })}
    </div>}
    <Dialog open={panel !== null} onOpenChange={(open) => { if (!open) setPanel(null); }}>
      <DialogContent className="max-h-[85dvh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{panel === "summary" ? "AI summary" : "Summary sources"}</DialogTitle>
          <DialogDescription>{summary && `Generated ${dateTime(summary.generated_at)}. `}AI-written from page aggregates. Verify the linked sources before taking action.</DialogDescription>
        </DialogHeader>
        {panel === "summary" ? <div className="space-y-5">{items.map((item) => <div key={item.topic}><h3 className={`flex flex-wrap items-center gap-2 font-semibold ${tones[item.tone].text}`}><Badge variant={tones[item.tone].badge}>{tones[item.tone].label}</Badge>{item.topic}{item.headline && `: ${displayText(item.headline)}${item.caption ? ` ${displayText(item.caption)}` : ""}`}</h3><p className="mt-1 text-sm leading-relaxed">{itemText(item)} {displayText(item.detail)} <span className="inline-flex gap-1">{citations(item)}</span></p></div>)}</div> : <ol className="space-y-4">{summary?.sources.map((source) => <li id={`summary-source-${source.id}`} key={source.id} className={`scroll-m-4 rounded-md border p-3 ${source.id === sourceId ? "border-primary bg-accent" : ""}`}>
          <div className="flex items-start justify-between gap-3"><h3 className="font-medium">{source.id}. {source.title}</h3>{canAccessPage(user, source.path) && <Link href={source.path} onClick={() => setPanel(null)} className="shrink-0 text-sm text-primary underline">Open page</Link>}</div>
          <p className="mt-1 text-xs text-muted-foreground">Captured {dateTime(source.captured_at)} · {source.status === "available" ? "Available" : "Unavailable"}</p><p className="mt-2 text-sm">{source.scope}</p>
          {source.status === "available" && <details className="mt-2 text-xs"><summary className="cursor-pointer text-primary">View captured aggregates</summary><CodeBlock className="mt-2">{JSON.stringify(source.facts, null, 2)}</CodeBlock></details>}
        </li>)}</ol>}
        <p className="text-xs text-muted-foreground">Sources are captured separately and can have different time windows. Summaries refresh hourly in the background. Opening Overview updates summaries older than five minutes while showing the saved result, retained for up to seven days. Check the generation time. Regenerate requests a new summary. Raw evidence and credentials are excluded.</p>
      </DialogContent>
    </Dialog>
  </section>;
}
