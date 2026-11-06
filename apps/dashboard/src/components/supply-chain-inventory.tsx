"use client";

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Radar, TriangleAlert } from "lucide-react";
import type { Component, Root } from "@/components/component-inventory";
import { EndpointAlerts } from "@/components/endpoint-alerts";
import { CollectionFooter, EmptyState, LoadingState, TableLayout } from "@/components/page-layout";
import { ReviewCard, reviewTable, reviewTableHeader } from "@/components/review-card";
import { Button } from "@/components/ui/button";
import { Popover, PopoverAnchor, PopoverContent } from "@/components/ui/popover";
import { Status, type StatusTone } from "@/components/ui/status";
import { hasVulnerabilities, VulnerabilitySignals } from "@/components/inventory-vulnerabilities";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTimeZone } from "@/components/time-zone-context";
import { relative } from "@/lib/api";
import { cn } from "@/lib/utils";
import { inventorySources, supplyChainSources, type SupplyChainSource, type useInventoryPages } from "@/lib/use-inventory-pages";

type Group = {
  key: string;
  name: string;
  source: Component["source"];
  records: Component[];
  versions: string[];
  vulnerable: boolean;
};
type Pages = ReturnType<typeof useInventoryPages<Component>>;
type RootPages = ReturnType<typeof useInventoryPages<Root>>;
export type InventorySort = "devices" | "name";
// Short category names for inline row metadata; the full label stays on the
// category control and in accessible names.
const shortSources: Record<SupplyChainSource, string> = {
  "osquery-npm-packages": "npm",
  "osquery-python-packages": "Python",
  "openaidr-mcp-servers": "MCP",
  "openaidr-plugins": "Plugins",
};
const scanLabels: Record<Root["status"], string> = { ok: "Successful", partial: "Partial", error: "Failed", unavailable: "Unavailable" };
const scanTones: Record<Root["status"], StatusTone> = { ok: "ok", partial: "warning", error: "critical", unavailable: "neutral" };

export function retainedRecord(record: Component) {
  return record.root_status !== "ok" && Boolean(record.root_collected_at && Date.parse(record.last_seen_at) < Date.parse(record.root_collected_at));
}

/** Never group by display name: identifiers and categories are the reported identity. */
export function groupComponents(records: Component[]): Group[] {
  const groups = new Map<string, Component[]>();
  const seen = new Set<string>();
  for (const record of records) {
    if (seen.has(record.id)) continue;
    seen.add(record.id);
    const key = JSON.stringify([record.source, record.identifier || record.id]);
    const list = groups.get(key) || [];
    list.push(record);
    groups.set(key, list);
  }
  return [...groups].map(([key, records]) => ({
    key,
    name: records[0].name || records[0].identifier,
    source: records[0].source,
    records,
    versions: [...new Set(records.map((record) => record.version).filter((version) => version.trim()))].sort(),
    vulnerable: records.some(hasVulnerabilities),
  }));
}

/** Distinct devices, optionally only those with a record carrying findings. */
export function groupDevices(group: Group, affectedOnly = false) {
  return [...new Map((affectedOnly ? group.records.filter(hasVulnerabilities) : group.records)
    .map((record) => [record.sensor_id, record])).values()];
}

export function sortGroups(groups: Group[], sort: InventorySort, affectedOnly = false) {
  return [...groups].sort((a, b) => (sort === "devices" ? groupDevices(b, affectedOnly).length - groupDevices(a, affectedOnly).length : 0)
    || a.name.localeCompare(b.name) || a.key.localeCompare(b.key));
}

/** Loaded-count label: Unknown when a category failed before loading, "+" when more pages exist. */
export function countLabel(components: Pages, sources: readonly SupplyChainSource[], count: number) {
  const pages = sources.map((source) => components.bySource[source]).filter(Boolean) as NonNullable<Pages["bySource"][SupplyChainSource]>[];
  if (pages.some((page) => !page.items.length && (page.loading || page.error))) return "Unknown";
  return `${count.toLocaleString()}${pages.some((page) => page.nextCursor) ? "+" : ""}`;
}

/** Categories whose request failed before any record loaded; their counts are unknown. */
function failedSources(components: Pages, sources: readonly SupplyChainSource[]) {
  return sources.filter((source) => {
    const page = components.bySource[source];
    return page && Boolean(page.error) && !page.items.length;
  });
}

function latestSeen(records: Component[]) {
  return records.reduce((latest, record) => record.last_seen_at > latest ? record.last_seen_at : latest, "");
}

function GroupName({ group, onSelect, records, compact = false }: { group: Group; onSelect: (records: Component[], trigger: HTMLButtonElement) => void; records: Component[]; compact?: boolean }) {
  return <>
    <button type="button" className="text-left text-sm font-medium wrap-anywhere text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring"
      aria-label={`View details for ${group.name}`} onClick={(event) => onSelect(records, event.currentTarget)}>{group.name}</button>
    <span className="ml-1.5 text-xs text-muted-foreground">
      {shortSources[group.source as SupplyChainSource] ?? inventorySources[group.source]} ·{" "}
      {group.versions.length
        ? <span className="font-mono text-sm font-normal">{group.versions.slice(0, 2).join(", ")}{group.versions.length > 2 && ` +${group.versions.length - 2}`}</span>
        : "Version not reported"}
      {!compact && <> · {group.records.length} {group.records.length === 1 ? "record" : "records"}</>}
    </span>
  </>;
}

function DeviceCount({ devices, onDevice }: { devices: Component[]; onDevice: (record: Component) => void }) {
  const first = devices[0];
  return <span className="inline-flex items-center justify-end gap-1 whitespace-nowrap">
    <span className="number">{devices.length}</span>
    {first && <Button variant="ghost" size="xs" className="max-w-40" title={first.hostname || first.sensor_id}
      aria-label={`Filter by device ${first.hostname || first.sensor_id}`} onClick={() => onDevice(first)}>
      <span className="truncate">{first.hostname || first.sensor_id}</span>
    </Button>}
    {devices.length > 1 && <span className="text-xs text-muted-foreground">+{devices.length - 1}</span>}
  </span>;
}

function AffectedDeviceCount({ devices, name, onDevice }: { devices: Component[]; name: string; onDevice: (record: Component) => void }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const content = useRef<HTMLDivElement>(null);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const cancelClose = () => clearTimeout(closeTimer.current);
  useEffect(() => () => clearTimeout(closeTimer.current), []);
  const show = () => { cancelClose(); setOpen(true); };
  const closeAfterLeave = () => {
    cancelClose();
    closeTimer.current = setTimeout(() => {
      if (!trigger.current?.contains(document.activeElement) && !content.current?.contains(document.activeElement)) setOpen(false);
    }, 150);
  };
  const focusList = () => {
    show();
    requestAnimationFrame(() => content.current?.querySelector("button")?.focus());
  };
  return <Popover open={open} onOpenChange={setOpen}>
    <PopoverAnchor asChild>
      <Button ref={trigger} variant="ghost" size="xs" className="number min-h-10 min-w-10 text-sm sm:min-h-6 sm:min-w-6"
        aria-label={`Show ${devices.length} affected ${devices.length === 1 ? "device" : "devices"} for ${name}`}
        aria-haspopup="dialog" aria-expanded={open} aria-controls={open ? id : undefined}
        onPointerEnter={(event) => { if (event.pointerType === "mouse") show(); }}
        onPointerLeave={(event) => { if (event.pointerType === "mouse") closeAfterLeave(); }}
        onFocus={show} onBlur={closeAfterLeave} onClick={focusList}
        onKeyDown={(event) => { if (event.key === "ArrowDown") { event.preventDefault(); focusList(); } }}>
        {devices.length}
      </Button>
    </PopoverAnchor>
    <PopoverContent ref={content} id={id} aria-label={`Affected devices for ${name}`} className="max-h-[min(20rem,var(--radix-popover-content-available-height))] w-72 p-2"
      onPointerEnter={cancelClose} onPointerLeave={closeAfterLeave} onFocus={cancelClose} onBlur={closeAfterLeave}
      onOpenAutoFocus={(event) => event.preventDefault()} onCloseAutoFocus={(event) => event.preventDefault()}
      onEscapeKeyDown={() => { trigger.current?.focus(); setOpen(false); }}>
      <p className="px-2 py-1 text-xs font-medium text-muted-foreground">{devices.length} affected {devices.length === 1 ? "device" : "devices"}</p>
      <ul>{devices.map((device) => <li key={device.sensor_id}>
        <Button variant="ghost" size="responsive" className={cn("h-auto min-h-10 w-full justify-start whitespace-normal px-2 py-1.5 text-left sm:h-auto sm:min-h-8", !device.hostname && "font-mono text-sm font-normal")}
          aria-label={`Filter by device ${device.hostname || device.sensor_id}`}
          onClick={() => { setOpen(false); onDevice(device); }}>
          <span className="min-w-0 wrap-anywhere">{device.hostname || device.sensor_id}</span>
        </Button>
      </li>)}</ul>
    </PopoverContent>
  </Popover>;
}

/** Components with known vulnerability findings, most affected devices first. */
export function SupplyChainAttention({ groups, components, onSelect, onDevice, actions }: {
  groups: Group[];
  components: Pages;
  onSelect: (records: Component[], trigger: HTMLButtonElement) => void;
  onDevice: (record: Component) => void;
  actions?: ReactNode;
}) {
  const attention = sortGroups(groups.filter((group) => group.vulnerable), "devices", true);
  const count = countLabel(components, supplyChainSources, attention.length);
  const pending = components.loading && !components.items.length;
  // A category that failed before loading leaves its findings unknown, so the
  // queue never claims there is nothing to review while one is missing.
  const failed = failedSources(components, supplyChainSources);
  return <ReviewCard className="[&_[data-slot=review-card-header]]:flex-wrap" tone="critical" icon={TriangleAlert} title="Needs attention" label="Components needing attention"
    count={<span className="flex items-center gap-3">{actions}<span>{count} of {countLabel(components, supplyChainSources, groups.length)} loaded</span></span>}>
    {failed.length > 0 && !pending && (
      <p className="border-b px-4 py-2 text-sm text-muted-foreground">
        {failed.length === supplyChainSources.length
          ? "Inventory unavailable. Use Retry above to load components."
          : `${failed.map((source) => inventorySources[source]).join(", ")} inventory unavailable. Use Retry above to reload; findings there are unknown.`}
      </p>
    )}
    {pending ? <div className="px-4 py-3"><LoadingState label="Loading components…" /></div>
      : !attention.length && failed.length ? null
      : !attention.length ? <EmptyState title="No known vulnerabilities in loaded records"
        description="Unassessed, pending, and outdated checks are not evidence of safety. Review assessment status in All components." />
      : <Table aria-label="Components needing attention" className={cn(reviewTable, "table-fixed min-w-[900px] [&_td]:py-1")}>
        <TableHeader className={reviewTableHeader}><TableRow>
          <TableHead className="w-[35%]">Component</TableHead><TableHead className="w-[34%]">Why attention</TableHead>
          <TableHead className="w-[14%] text-right">Affected devices</TableHead><TableHead className="text-right">Notify users</TableHead>
        </TableRow></TableHeader>
        <TableBody>{attention.map((group) => {
          const affected = group.records.filter(hasVulnerabilities);
          const affectedIds = new Set(affected.map((record) => record.id));
          const ordered = [...affected, ...group.records.filter((record) => !affectedIds.has(record.id))];
          return <TableRow key={group.key} data-component={group.key}>
            <TableCell><div className="truncate" title={`${group.name} · ${group.versions.join(", ")}`}><GroupName group={group} records={ordered} onSelect={onSelect} compact /></div></TableCell>
            <TableCell className="whitespace-normal"><div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
              <VulnerabilitySignals records={group.records} compact />
            </div></TableCell>
            <TableCell className="text-right"><AffectedDeviceCount devices={groupDevices(group, true)} name={group.name} onDevice={onDevice} /></TableCell>
            <TableCell className="text-right"><EndpointAlerts applicationId={`component:${JSON.stringify([group.source, group.records[0].identifier])}`}
              name={group.name} recipients={affected.map(record => ({ id: record.sensor_id, name: record.hostname, versions: record.version ? [record.version] : [] }))}
              scopeNote="Only affected devices in the loaded component records are included. Load more records to include additional devices."
              notification={{ title: `Security update needed: ${group.name}`.slice(0, 160),
                message: `Known vulnerabilities were found in ${group.name} on your device.\n\nUpdate the application or project that includes this component to a version that resolves the findings. Contact IT if you need help.`.slice(0, 2000) }} /></TableCell>
          </TableRow>;
        })}</TableBody>
      </Table>}
  </ReviewCard>;
}

/** Coverage summarizes loaded locations; the collection dialog retains all details. */
export function SupplyChainCoverage({ roots, action }: { roots: RootPages; action: ReactNode }) {
  const { dateTime } = useTimeZone();
  const items = roots.items;
  const latest = items.reduce((value, item) => item.collected_at > value ? item.collected_at : value, "");
  const suffix = roots.nextCursor ? "+" : "";
  const count = roots.loading && !items.length ? "Loading" : !items.length && roots.error ? "Unknown"
    : `${items.length}${suffix} locations · ${new Set(items.map((item) => item.sensor_id)).size}${suffix} devices`;
  return <ReviewCard className="[&_[data-slot=review-card-header]]:flex-wrap" tone="neutral" icon={Radar} title="Scan coverage" label="Loaded scan coverage" count={count}>
    {roots.loading && !items.length ? <div className="px-4 py-3"><LoadingState label="Loading scan coverage…" /></div>
      : !items.length ? <EmptyState title={roots.error ? "Scan coverage unavailable" : "No scan locations reported"}
        description={roots.error ? "Use Retry above to reload coverage." : "Coverage is unknown. A sensor must report a component scan for this device scope."} />
      : <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-1">
        <div className="flex flex-wrap gap-x-4 gap-y-1" aria-label="Loaded scan status counts">
          {(Object.keys(scanLabels) as Root["status"][]).map((status) => <Status key={status} tone={scanTones[status]}>
            {items.filter((item) => item.status === status).length}{suffix} {scanLabels[status].toLowerCase()}
          </Status>)}
        </div>
        <span className="text-xs text-muted-foreground sm:ml-auto" title={dateTime(latest)}>Latest loaded scan {relative(latest)}</span>
        {action}
        {roots.nextCursor && <p className="basis-full text-xs text-muted-foreground">More locations available in scan details; these are loaded counts.</p>}
      </div>}
  </ReviewCard>;
}

/** Every loaded component in the selected category, one row per reported identifier. */
export function SupplyChainTable({ groups, components, category, sort, filtered, onSelect, onDevice }: {
  groups: Group[];
  components: Pages;
  category: SupplyChainSource | "all";
  sort: InventorySort;
  filtered: boolean;
  onSelect: (records: Component[], trigger: HTMLButtonElement) => void;
  onDevice: (record: Component) => void;
}) {
  const { dateTime } = useTimeZone();
  const sources = category === "all" ? supplyChainSources : [category];
  const pages = sources.map((source) => components.bySource[source]!);
  const recordCount = pages.reduce((sum, page) => sum + page.items.length, 0);
  const shown = sortGroups(groups.filter((group) => category === "all" || group.source === category), sort);
  const pending = pages.every((page) => page.loading && !page.items.length);
  if (pending) return <LoadingState label="Loading inventory…" />;
  if (!shown.length && pages.some((page) => page.error && !page.items.length))
    return <p className="text-sm text-muted-foreground">Inventory unavailable. Use Retry above to load components.</p>;
  if (!shown.length) return <EmptyState title={filtered ? "No matching records" : "No records reported"}
    description={filtered ? "Change the search or clear filters to see other records." : "Check Collection details for scan coverage. An empty inventory does not establish that components are absent."} />;
  return <TableLayout footer={<CollectionFooter count={recordCount} label={recordCount === 1 ? "record" : "records"}
    hasMore={pages.some((page) => Boolean(page.nextCursor))} busy={pages.some((page) => page.loading || page.loadingMore)}
    onLoadMore={() => pages.forEach((page) => page.loadMore())} />}>
    <Table className="min-w-[760px]" aria-label="All components">
      <TableHeader><TableRow>
        <TableHead>Component</TableHead><TableHead>Review status</TableHead>
        <TableHead className="text-right">Devices</TableHead><TableHead>Last seen</TableHead>
      </TableRow></TableHeader>
      <TableBody>{shown.map((group) => {
        const latest = latestSeen(group.records);
        return <TableRow key={group.key} data-component={group.key}>
          <TableCell className="w-full whitespace-normal"><GroupName group={group} records={group.records} onSelect={onSelect} /></TableCell>
          <TableCell className="whitespace-normal"><div className="flex flex-wrap items-center gap-x-3 gap-y-0.5"><VulnerabilitySignals records={group.records} /></div></TableCell>
          <TableCell className="text-right"><DeviceCount devices={groupDevices(group)} onDevice={onDevice} /></TableCell>
          <TableCell title={dateTime(latest)}><span className="text-xs text-muted-foreground">{relative(latest)}</span></TableCell>
        </TableRow>;
      })}</TableBody>
    </Table>
  </TableLayout>;
}
