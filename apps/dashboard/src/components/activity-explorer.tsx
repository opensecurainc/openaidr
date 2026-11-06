"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowRight, Network, Search } from "lucide-react";
import { AgentLogo } from "@/components/agent-logo";
import { ClassifiedActions } from "@/components/hook-policy";
import { EmptyState, ErrorState, LoadingState, PageSection, TableLayout } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTimeZone } from "@/components/time-zone-context";
import { number } from "@/lib/api";
import { activityIdentity, activityProduct, identityInitials, type ActivityFilters, type ActivityGroup, type ActivitySummary } from "@/lib/activity-flow";
import type { FlowDecision, GuardrailCheckPage } from "@/lib/guardrail-flow";
import { useResource } from "@/lib/use-resource";

function detailScope(path: string) {
  const [route, query] = path.split("?");
  const params = new URLSearchParams(query);
  params.delete("until");
  return `${route}?${params}`;
}

function useActivityDetails<T>(path: string) {
  const latest = useRef(path);
  latest.current = path;
  const [request, setRequest] = useState(path);
  const resource = useResource<T>(request, 0, true);
  const { loading, setData } = resource;
  useEffect(() => {
    // A deliberate search or page change replaces the old request immediately.
    if (detailScope(request) !== detailScope(path)) {
      setData(null);
      setRequest(path);
    }
  }, [path, request, setData]);
  useEffect(() => {
    if (loading) return;
    // Summary polling can advance while a detail read is still in flight.
    // Wait for that read and an idle interval before adopting its latest window.
    const timer = setInterval(() => { if (!document.hidden) setRequest(latest.current); }, 5000);
    return () => clearInterval(timer);
  }, [loading, request]);
  return resource;
}

export function ActivityGroups({ query, view, onSelect, onInteract }: {
  query: string; view: "identities" | "sessions";
  onSelect: (group: ActivityGroup) => void; onInteract: () => void;
}) {
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const { dateTime } = useTimeZone();
  const resource = useActivityDetails<ActivitySummary>(`guardrail/flow?${query}&view=${view}&limit=20&offset=${offset}&search=${encodeURIComponent(search)}`);
  const data = resource.data;
  return <>
    <label className="mb-3 flex max-w-sm items-center gap-2">
      <Search aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
      <Input type="search" aria-label={view === "identities" ? "Search all identities" : "Search sessions and routes"}
        placeholder={view === "identities" ? "Search name, account, or device" : "Search project, identity, or source"}
        value={search} onChange={(event) => { onInteract(); setSearch(event.target.value); setOffset(0); }} />
    </label>
    {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
    {resource.loading && !data ? <LoadingState label="Loading activity details" /> : data && <>
      <p className="mb-2 text-xs text-muted-foreground">{number(data.total)} {view === "identities" ? "reported identities" : "sessions and routes"} · Most checks first · Full selected window</p>
      {!data.items.length ? <EmptyState title="No matching activity" description="Change the search or flow filters to see other activity." /> : <TableLayout><Table>
        <TableHeader><TableRow><TableHead>{view === "identities" ? "Reported identity" : "Project or route"}</TableHead>
          <TableHead>{view === "identities" ? "Sessions / routes" : "Reported identity"}</TableHead>
          <TableHead className="text-right">Checks</TableHead><TableHead className="text-right">Flagged</TableHead>
          <TableHead className="text-right">Failed</TableHead><TableHead>Last check</TableHead><TableHead><span className="sr-only">Inspect activity</span></TableHead>
        </TableRow></TableHeader>
        <TableBody>{data.items.map((group) => {
          const identity = activityIdentity(group.identity);
          return <TableRow key={group.key}>
            <TableCell><button className="flex max-w-sm items-center gap-2 rounded-sm text-left outline-none hover:text-primary focus-visible:ring-2 focus-visible:ring-ring" onClick={() => onSelect(group)}>
              {view === "identities" ? <span aria-hidden="true" className="flex size-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold">{identityInitials(group.identity)}</span>
                : group.source === "gateway" ? <Network className="size-5 shrink-0" aria-hidden="true" /> : <AgentLogo product={group.product} />}
              <span className="min-w-0"><span className="block truncate font-medium" title={view === "identities" ? identity.title : group.detail}>{view === "identities" ? identity.label : group.detail}</span>
                <span className="block truncate text-xs text-muted-foreground" title={identity.detail}>{view === "identities" ? identity.detail : activityProduct(group.source, group.product)}</span></span>
            </button></TableCell>
            <TableCell title={identity.title}>{view === "identities" ? number(group.sessions) : identity.label}</TableCell>
            <TableCell className="number text-right">{number(group.checks)}</TableCell><TableCell className="number text-right">{number(group.flagged)}</TableCell>
            <TableCell className="number text-right">{number(group.failed)}</TableCell><TableCell className="whitespace-nowrap text-xs text-muted-foreground">{dateTime(group.last_seen)}</TableCell>
            <TableCell><Button variant="ghost" size="icon-xs" aria-label={`Inspect ${view === "identities" ? identity.label : group.detail}`} onClick={() => onSelect(group)}><ArrowRight aria-hidden="true" /></Button></TableCell>
          </TableRow>;
        })}</TableBody>
      </Table></TableLayout>}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>{data.total ? `${number(offset + 1)} to ${number(offset + data.items.length)} of ${number(data.total)}` : "No matching results"}</span>
        <div className="flex gap-2"><Button variant="outline" size="sm" disabled={!offset || resource.loading} onClick={() => { onInteract(); setOffset(offset - 20); }}>Previous</Button>
          <Button variant="outline" size="sm" disabled={!data.has_more || resource.loading} onClick={() => { onInteract(); setOffset(offset + 20); }}>Next</Button></div>
      </div>
    </>}
  </>;
}

function ActivityChecks({ query, filters, onFilter, onInteract }: {
  query: string; filters: ActivityFilters; onFilter: (key: keyof ActivityFilters, value: string, label: string) => void; onInteract: () => void;
}) {
  const [cursor, setCursor] = useState("");
  const history = useActivityDetails<GuardrailCheckPage>(`guardrail/checks?${query}&limit=100&cursor=${encodeURIComponent(cursor)}`);
  return <ClassifiedActions history={history} page={history.data} cursor={cursor}
    onPage={(value) => { onInteract(); setCursor(value); }}
    boundary={filters.boundary?.value || "all"} onBoundary={(value) => onFilter("boundary", value === "all" ? "" : value, value)}
    decision={(filters.decision?.value || "all") as FlowDecision} onDecision={(value) => onFilter("decision", value === "all" ? "" : value, value)} />;
}

export function ActivityExplorer({ query, filterKey, filters, view, onView, onFilter, onInteract }: {
  query: string; filterKey: string; filters: ActivityFilters; view: "identities" | "sessions" | "checks"; onView: (view: "identities" | "sessions" | "checks") => void;
  onFilter: (key: keyof ActivityFilters, value: string, label: string) => void; onInteract: () => void;
}) {
  const views = [{ key: "identities", label: "Identities" }, { key: "sessions", label: "Sessions & routes" }, { key: "checks", label: "Checks" }] as const;
  return <PageSection title="Explore activity" description="Full selected window. Paging and searching these lists do not change the flow totals.">
    <div className="mb-4 flex flex-wrap gap-1" role="tablist" aria-label="Activity details">
      {views.map(({ key, label }, index) => <Button key={key} role="tab" aria-selected={view === key} tabIndex={view === key ? 0 : -1}
        variant={view === key ? "secondary" : "ghost"} size="sm" onClick={() => onView(key)}
        onKeyDown={(event) => {
          if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
          event.preventDefault();
          const next = event.key === "Home" ? 0 : event.key === "End" ? 2 : (index + (event.key === "ArrowLeft" ? 2 : 1)) % 3;
          (event.currentTarget.parentElement?.children[next] as HTMLButtonElement)?.click();
          (event.currentTarget.parentElement?.children[next] as HTMLButtonElement)?.focus();
        }}>{label}</Button>)}
    </div>
    <div role="tabpanel" aria-label={views.find((item) => item.key === view)!.label}>
      {view === "checks" ? <ActivityChecks key={filterKey} query={query} filters={filters} onFilter={onFilter} onInteract={onInteract} />
        : <ActivityGroups key={`${filterKey}:${view}`} query={query} view={view} onInteract={onInteract}
          onSelect={(group) => onFilter(view === "identities" ? "identity" : "session", group.key, view === "identities" ? activityIdentity(group.identity).label : group.detail)} />}
    </div>
  </PageSection>;
}
