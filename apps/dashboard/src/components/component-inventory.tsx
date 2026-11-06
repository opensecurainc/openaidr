"use client";

import { useTimeZone } from "@/components/time-zone-context";
import { EndpointAlerts } from "@/components/endpoint-alerts";
import { useId, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";
import {
  CollectionFooter,
  EmptyState,
  ErrorState,
  LoadingState,
  PageNotice,
  PageSection,
  PageToolbar,
  TableLayout,
} from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Status, type StatusTone } from "@/components/ui/status";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { relative } from "@/lib/api";
import { useResource, usePagedResource } from "@/lib/use-resource";

import { inventorySources as sources, useInventoryPages, type InventorySource as Source, type SupplyChainSource, supplyChainSources } from "@/lib/use-inventory-pages";
import { SupplyChainAttention, SupplyChainCoverage, SupplyChainTable, countLabel, groupComponents, retainedRecord, type InventorySort } from "@/components/supply-chain-inventory";
import { SupplyChainTrend, type AttentionHistory } from "@/components/supply-chain-trend";
import { VulnerabilityDetails, type VulnerabilityAssessment } from "@/components/inventory-vulnerabilities";

type ScanStatus = "ok" | "partial" | "error" | "unavailable";
type Location = {
  sensor_id: string;
  hostname: string;
  os: string;
  source: Source;
  root: string;
  scope: string;
  user: string;
  environment: string;
};
export type Component = Location & {
  id: string;
  root_id: string;
  identifier: string;
  name: string;
  version: string;
  path: string;
  publisher: string;
  architecture: string;
  evidence: "installed" | "declared" | "configured" | "observed";
  last_seen_at: string;
  root_status: ScanStatus;
  root_collected_at?: string;
  vulnerability?: VulnerabilityAssessment;
  metadata: {
    description?: string;
    license?: string;
    repository_url?: string;
    source_url?: string;
    revision?: string;
    integrity?: string;
    content_sha256?: string;
    tools?: string[];
  };
};
export type Root = Location & {
  id: string;
  status: ScanStatus;
  message: string;
  collected_at: string;
  last_success_at: string | null;
  component_count: number;
};
type RelationshipComponent = {
  id: string;
  name: string;
  version: string;
  kind: string;
  path: string;
  root_status: ScanStatus;
};
type Relationship = {
  id: string;
  from_component_id: string;
  to_component_id: string;
  from_component?: RelationshipComponent;
  to_component?: RelationshipComponent;
  path: string;
  last_seen_at: string;
  root_status: ScanStatus;
};
const scanLabels: Record<ScanStatus, string> = {
  ok: "Successful",
  partial: "Partial",
  error: "Failed",
  unavailable: "Unavailable",
};
const scanTones: Record<ScanStatus, StatusTone> = {
  ok: "ok",
  partial: "warning",
  error: "critical",
  unavailable: "neutral",
};
const evidenceLabels = {
  installed: "Installed",
  declared: "Declared",
  configured: "Configured",
  observed: "Observed",
};

export function ComponentInventory({
  view,
}: {
  view: "supply-chain" | "skills";
}) {
  return (
    <div className={view === "supply-chain" ? "min-w-0 space-y-2" : "min-w-0 space-y-4"}>
      <InventoryRecords
        key={view}
        source={view === "skills" ? "openaidr-skills" : "all"}
        grouped={view === "supply-chain"}
      />
    </div>
  );
}

function InventoryRecords({ source, grouped }: {
  source: Source | "all";
  grouped: boolean;
}) {
  const { dateTime } = useTimeZone();
  const reviewId = useId();
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<InventorySort>("devices");
  const [category, setCategory] = useState<SupplyChainSource | "all">("all");
  const [device, setDevice] = useState<{ id: string; name: string } | null>(
    null,
  );
  const [root, setRoot] = useState<Root | null>(null);
  const [selected, setSelected] = useState<Component | null>(null);
  const [selectedRecords, setSelectedRecords] = useState<Component[]>([]);
  const [collectionOpen, setCollectionOpen] = useState(false);
  const [browseOpen, setBrowseOpen] = useState(true);
  const history = useResource<AttentionHistory>(grouped ? "inventory/attention-history" : null, 300_000);
  const collectionTrigger = useRef<HTMLButtonElement | null>(null);
  const detailTrigger = useRef<HTMLButtonElement | null>(null);
  const scope = new URLSearchParams({ limit: "50" });
  if (device) scope.set("sensor_id", device.id);
  const filters = new URLSearchParams(scope);
  if (query) filters.set("q", query);
  if (root) filters.set("root_id", root.id);
  const components = useInventoryPages<Component>("components", source, filters);
  const roots = useInventoryPages<Root>("roots", source, scope);
  const groups = groupComponents(components.items);
  const sourceLabel = source === "all" ? "All components" : sources[source];
  const filtered = Boolean(query || device || root || category !== "all");
  const visibleSources = category === "all" ? supplyChainSources : [category];
  const visibleGroups = groups.filter((group) => category === "all" || group.source === category);
  const devices = [...new Map([
    ...(device ? [[device.id, device.name] as const] : []),
    ...components.items.map((record) => [record.sensor_id, record.hostname || record.sensor_id] as const),
  ]).entries()].sort((a, b) => a[1].localeCompare(b[1]));
  // The review summary and cards always cover every category in the loaded
  // search and device scope; only the All components table follows the
  // category selection.
  const attentionGroups = groups.filter((group) => group.vulnerable);
  const totalLabel = countLabel(components, supplyChainSources, groups.length);
  const attentionLabel = countLabel(components, supplyChainSources, attentionGroups.length);
  function refresh() {
    setSelected(null);
    components.reload();
    roots.reload();
    if (grouped) void history.reload();
  }
  function filterDevice(location: Location) {
    setDevice({
      id: location.sensor_id,
      name: location.hostname || location.sensor_id,
    });
    setRoot(null);
  }
  function select(records: Component[], trigger: HTMLButtonElement) {
    detailTrigger.current = trigger;
    setSelectedRecords(records);
    setSelected(records[0]);
  }
  const collectionButton = (
    <Button ref={collectionTrigger} variant="ghost" size="responsive" aria-label="Collection details"
      onClick={(event) => { collectionTrigger.current = event.currentTarget; setCollectionOpen(true); }}>
      Collection details
    </Button>
  );
  const refreshButton = (
    <Button variant="outline" size={grouped ? "header-icon" : "responsive"} aria-label="Refresh" title="Refresh" onClick={refresh} disabled={components.loading || roots.loading}>
      <RefreshCw className="size-3.5" />{!grouped && "Refresh"}
    </Button>
  );
  const scopeLine = (device || root) && (
    <p className="mt-1 break-all text-sm">
      {device && <>Device: {device.name}</>}
      {root && <> · Scan location: {root.root}</>}
    </p>
  );
  const errors = (
    <>
      {roots.error && (
        <ErrorState
          onRetry={roots.reload}
          message={`Scan coverage: ${roots.error}${roots.items.length ? " Showing the last loaded scan results." : " Coverage is unknown."}`}
        />
      )}
      {components.error && (
        <ErrorState
          onRetry={components.reload}
          message={`Inventory: ${components.error}${components.items.length ? " Showing the last loaded records." : ""}`}
        />
      )}
    </>
  );
  return (
    <>
      {grouped ? <>
        {errors}
        <SupplyChainTrend data={history.data} error={history.error} loading={history.loading} reload={history.reload} actions={refreshButton} />
        <section aria-labelledby={reviewId} className="space-y-2">
          <h2 id={reviewId} className="sr-only">Component review</h2>
          <p data-slot="review-summary" className="sr-only">{totalLabel === "Unknown" ? "Loaded component counts are unavailable for a failed category." : `${attentionLabel} of ${totalLabel} loaded components need attention.`}</p>
          {(query || device || root) && <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <span>Review is filtered{query ? ` by “${query}”` : ""}. History still covers all devices.</span>{scopeLine}
            <Button variant="ghost" size="responsive" onClick={() => { setQuery(""); setDevice(null); setRoot(null); setCategory("all"); }}>Clear review filters</Button>
          </div>}
          <SupplyChainAttention groups={groups} components={components} onSelect={select} onDevice={filterDevice}
            actions={<button type="button" className="min-h-10 underline underline-offset-4 sm:min-h-6 focus-visible:outline-2 focus-visible:outline-primary-foreground" aria-expanded={browseOpen} aria-controls={`${reviewId}-inventory`} onClick={() => setBrowseOpen(!browseOpen)}>All components</button>} />
          <SupplyChainCoverage roots={roots} action={<Button variant="outline" size="responsive" onClick={(event) => { collectionTrigger.current = event.currentTarget; setCollectionOpen(true); }}>View scan locations</Button>} />

        </section>
        <div id={`${reviewId}-inventory`} hidden={!browseOpen}>
        <PageSection title="All components"
          titleAction={<span className="number text-xs text-muted-foreground">{countLabel(components, visibleSources, visibleGroups.length)}</span>}>
          <div role="group" aria-label="Component filters" className="mb-3 flex min-w-0 flex-wrap items-center gap-2">
            <Input
              type="search"
              size="responsive"
              aria-label="Search inventory"
              placeholder="Search name, identifier, or path"
              maxLength={1024}
              className="w-full sm:w-64"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <Select value={device?.id || "all"} onValueChange={(id) => { setDevice(id === "all" ? null : { id, name: devices.find(([key]) => key === id)?.[1] || id }); setRoot(null); }}>
              <SelectTrigger size="responsive" aria-label="Device" className="w-full sm:w-44"><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value="all">All devices</SelectItem>
                {devices.map(([id, name]) => <SelectItem key={id} value={id}>{name}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={sort} onValueChange={(value) => setSort(value as InventorySort)}>
              <SelectTrigger size="responsive" aria-label="Sort components" className="w-full sm:w-44"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="devices">Most devices</SelectItem>
                <SelectItem value="name">Component name</SelectItem>
              </SelectContent>
            </Select>
            {filtered && (
              <Button variant="ghost" size="responsive" onClick={() => { setQuery(""); setDevice(null); setRoot(null); setCategory("all"); }}>
                Clear filters
              </Button>
            )}
            <div role="group" aria-label="Category" className="flex flex-wrap gap-1 sm:ml-auto">
              <Button variant={category === "all" ? "secondary" : "ghost"} size="responsive" aria-pressed={category === "all"} onClick={() => setCategory("all")}>All</Button>
              {supplyChainSources.map((source) => (
                <Button key={source} variant={category === source ? "secondary" : "ghost"} size="responsive" aria-pressed={category === source}
                  aria-label={`Show ${sources[source]}`} onClick={() => setCategory(source)}>
                  {{ "osquery-npm-packages": "npm", "osquery-python-packages": "Python", "openaidr-mcp-servers": "MCP", "openaidr-plugins": "Plugins" }[source]}
                </Button>
              ))}
            </div>
          </div>
          <SupplyChainTable groups={groups} components={components} category={category} sort={sort} filtered={filtered} onSelect={select} onDevice={filterDevice} />
          <PageNotice title="How attention and discovery are counted" collapsible>
            <p>Each reported identifier counts once within its category. Only records with known vulnerability findings need attention, at any severity. Missing versions, retained records, unknown freshness and multiple versions do not trigger attention. Affected devices include only records with vulnerability findings. The component drawer shows each record’s last-seen time.</p>
            <p>Scan coverage is reported per location; the full list is in Collection details. An incomplete location does not mean every reported component failed collection. Record age and scan coverage remain separate from vulnerability assessment.</p>
            <p>Counts cover loaded records in the current search and device scope. The category selection scopes only the All components table. More records are available when counts are marked +. A zero count does not establish complete discovery or safety.</p>
            <p>OSV checks reported npm and Python package versions. Advisory aliases and repeated checks do not create duplicate findings. Previous findings stay visible when a check is outdated or unavailable. Pending and unassessed records are not evidence of safety.</p>
            <p>MCP servers and plugins without a reported registry package identity remain unassessed. Records establish presence, not agent use, trust, provenance, reachability, or exploitation.</p>
          </PageNotice>
        </PageSection>
        </div>
      </> : (
      <Card role="region" aria-label={sourceLabel}>
        <CardHeader className="items-center justify-between">
          <CardTitle>{sourceLabel}</CardTitle>
          <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">{collectionButton}{refreshButton}</div>
        </CardHeader>
        <CardContent data-slot="section-body">
        <PageToolbar>
          <Input
            type="search"
            aria-label="Search inventory"
            placeholder="Search name, identifier, or path"
            maxLength={1024}
            className="sm:w-80"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          {filtered && (
            <Button variant="ghost" onClick={() => { setQuery(""); setDevice(null); setRoot(null); setCategory("all"); }}>
              Clear filters
            </Button>
          )}
        </PageToolbar>
        {scopeLine}
        <div className="mb-3 space-y-3">
          <ScanSummary roots={roots} />
          {errors}
          {components.items.some((item) => item.root_status !== "ok") && (
            <p className="text-xs text-muted-foreground">
              Some records may be retained from earlier scans. Check Last seen
              and Collection details before treating them as current.
            </p>
          )}
        </div>
        {components.loading && !components.items.length ? (
          <LoadingState label="Loading inventory…" />
        ) : components.items.length ? (
          <TableLayout
            footer={
              <CollectionFooter
                count={components.items.length}
                label={components.items.length === 1 ? "record" : "records"}
                hasMore={Boolean(components.nextCursor)}
                busy={components.loading || components.loadingMore}
                onLoadMore={components.loadMore}
              />
            }
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="hidden sm:table-cell">
                    Version
                  </TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {components.items.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="max-w-xs whitespace-normal break-words">
                      <button
                        type="button"
                        className="min-h-10 text-left font-medium text-primary underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring sm:min-h-0"
                        aria-label={`View details for ${item.name || item.identifier}`}
                        onClick={(event) => {
                          detailTrigger.current = event.currentTarget;
                          setSelected(item);
                        }}
                      >
                        {item.name || item.identifier}
                      </button>
                      <p className="text-xs text-muted-foreground sm:hidden">
                        {item.version || "Version not reported"}
                      </p>
                      {item.root_status !== "ok" && (
                        <p className="mt-1">
                          <Status
                            tone={scanTones[item.root_status]}
                            className="text-xs"
                          >
                            {scanLabels[item.root_status]} scan
                          </Status>
                        </p>
                      )}
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      {item.version || "Not reported"}
                    </TableCell>
                    <TableCell className="max-w-48 whitespace-normal break-words">
                      <DeviceFilter location={item} onSelect={filterDevice} />
                    </TableCell>
                    <TableCell title={dateTime(item.last_seen_at)}>
                      {relative(item.last_seen_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableLayout>
        ) : (
          !components.error && (
            <EmptyState
              title={filtered ? "No matching records" : "No records reported"}
              description={
                filtered
                  ? "Change the search or clear filters to see other records."
                  : "Check Collection details for scan coverage. An empty inventory does not establish that components are absent."
              }
            />
          )
        )}
        </CardContent>
      </Card>
      )}

      <Dialog open={collectionOpen} onOpenChange={setCollectionOpen}>
        <DialogContent
          className="max-h-[85vh] overflow-y-auto sm:max-w-5xl"
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            collectionTrigger.current?.focus();
          }}
        >
          <DialogHeader>
            <DialogTitle>Collection details</DialogTitle>
            <DialogDescription>
              {sourceLabel} locations
              {device ? " on the selected device" : " across devices"}. Record
              search does not filter scan coverage. Refresh reloads reported
              data; it does not start a device scan.
            </DialogDescription>
          </DialogHeader>
          <section aria-label="Scan coverage" className="min-w-0 space-y-3">
            <h3 className="text-sm font-semibold">Scan coverage</h3>
            <div className="mb-3 space-y-3">
              <PageNotice title="How scan coverage works" collapsible>
                Each row is a reported scan location. Partial, failed, and
                unavailable scans retain earlier records; omitted locations
                remain unchanged. Last successful scan and Last seen help
                identify older data. A successful scan covers only that
                location. A discovery record reports incomplete discovery of
                default locations.
              </PageNotice>
              {roots.error && (
                <ErrorState
                  onRetry={roots.reload}
                  message={`Scan coverage: ${roots.error}${roots.items.length ? " Showing the last loaded scan results." : " Coverage is unknown."}`}
                />
              )}
            </div>
            {roots.loading && !roots.items.length ? (
              <LoadingState label="Loading scan coverage…" />
            ) : roots.items.length ? (
              <TableLayout
                footer={
                  <CollectionFooter
                    count={roots.items.length}
                    label={
                      roots.items.length === 1
                        ? "scan location"
                        : "scan locations"
                    }
                    hasMore={Boolean(roots.nextCursor)}
                    busy={roots.loading || roots.loadingMore}
                    onLoadMore={roots.loadMore}
                  />
                }
              >
                <Table className="min-w-[900px]">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Location / environment</TableHead>
                      <TableHead>Device / user</TableHead>
                      <TableHead>Latest scan</TableHead>
                      <TableHead>Last scan / last successful</TableHead>
                      <TableHead>Stored records</TableHead>
                      <TableHead>
                        <span className="sr-only">Filter records</span>
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[...roots.items].sort((a, b) => ({ error: 0, partial: 1, unavailable: 2, ok: 3 }[a.status] - { error: 0, partial: 1, unavailable: 2, ok: 3 }[b.status])).map((item) => (
                      <TableRow key={item.id}>
                        <TableCell className="min-w-48 max-w-sm whitespace-normal break-all">
                          <p className="font-medium">{item.root}</p>
                          <p className="text-xs text-muted-foreground">
                            {item.environment || "Environment not reported"} ·{" "}
                            {item.scope}
                          </p>
                        </TableCell>
                        <TableCell>
                          <DeviceFilter
                            location={item}
                            onSelect={(location) => {
                              filterDevice(location);
                              setCollectionOpen(false);
                            }}
                          />
                          <p className="text-xs text-muted-foreground">
                            {item.user || "User not reported"}
                          </p>
                        </TableCell>
                        <TableCell className="min-w-32 max-w-xs whitespace-normal break-words">
                          <Status tone={scanTones[item.status]}>
                            {scanLabels[item.status]}
                          </Status>
                          {item.message && (
                            <p className="mt-1 text-xs text-muted-foreground">
                              {item.message}
                            </p>
                          )}
                        </TableCell>
                        <TableCell>
                          <p title={item.collected_at}>
                            {dateTime(item.collected_at)}
                          </p>
                          <p
                            className="text-xs text-muted-foreground"
                            title={item.last_success_at || undefined}
                          >
                            {item.last_success_at
                              ? dateTime(item.last_success_at)
                              : "No successful scan reported"}
                          </p>
                        </TableCell>
                        <TableCell className="number">
                          {item.component_count.toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="xs"
                            aria-label={`View records from ${item.root}`}
                            aria-pressed={root?.id === item.id}
                            onClick={() => {
                              filterDevice(item);
                              setRoot(item);
                              setQuery("");
                              if (item.source !== "openaidr-skills") setCategory(item.source);
                              setCollectionOpen(false);
                            }}
                          >
                            View records
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableLayout>
            ) : (
              !roots.error && (
                <EmptyState
                  title="No scan locations reported"
                  description="Coverage is unknown. A sensor must report a component scan for this category and device scope."
                />
              )
            )}
          </section>
          <div className="border-t pt-4">
            <PageNotice title="What this inventory establishes" collapsible>
              <p>
                Records describe scanned locations on devices. Installed
                packages and skills, configured MCP servers, and declared plugin
                manifests have different evidence. Presence does not establish
                agent use, enablement, trust, or granted permissions.
              </p>
              <p>
                Search covers names, identifiers, and paths. Select a device in
                either table or use View records on a scan location to narrow
                the inventory. Counts describe loaded records, which may include
                the same component on several devices.
              </p>
              <p>
                Collection currently covers macOS and the configured scan
                locations. Python package metadata does not establish that a
                package came from the public PyPI registry. Missing versions,
                provenance, and tool declarations are not reported.
              </p>
            </PageNotice>
          </div>
          <DialogFooter showCloseButton />
        </DialogContent>
      </Dialog>
      <ComponentDetails
        selected={selected}
        records={grouped ? selectedRecords : undefined}
        onSelect={setSelected}
        onClose={() => setSelected(null)}
        onRestoreFocus={() => detailTrigger.current?.focus()}
      />
    </>
  );
}

function ScanSummary({
  roots,
}: {
  roots: ReturnType<typeof usePagedResource<Root>>;
}) {
  const { dateTime } = useTimeZone();
  if (roots.loading && !roots.items.length)
    return (
      <span role="status" className="text-xs text-muted-foreground">
        Loading scan status…
      </span>
    );
  if (!roots.items.length)
    return (
      <Status tone="neutral">{roots.error ? "Scan coverage unavailable" : "No scan locations reported"}</Status>
    );
  const attention = roots.items.filter(
    (item) => item.status === "partial" || item.status === "error",
  ).length;
  const unavailable = roots.items.filter(
    (item) => item.status === "unavailable",
  ).length;
  const latest = roots.items.reduce((a, b) =>
    a.collected_at > b.collected_at ? a : b,
  );
  const oldest = roots.items.reduce((a, b) =>
    a.collected_at < b.collected_at ? a : b,
  );
  return (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      <Status
        tone={
          roots.error
            ? "neutral"
            : attention
              ? "warning"
              : unavailable || roots.nextCursor
                ? "neutral"
                : "ok"
        }
      >
        {roots.error
          ? "Previously loaded scans"
          : attention
            ? `${attention} loaded scan ${attention === 1 ? "location is" : "locations are"} incomplete`
            : unavailable
              ? "Some scan locations are unavailable"
              : roots.nextCursor
                ? "Loaded scans succeeded"
                : `Scans succeeded for ${roots.items.length} ${roots.items.length === 1 ? "location" : "locations"}`}
      </Status>
      <span title={dateTime(latest.collected_at)}>
        {roots.error ? "Previously loaded scan" : "Latest loaded scan"}{" "}
        {relative(latest.collected_at)}
      </span>
      {oldest.collected_at !== latest.collected_at && <span title={dateTime(oldest.collected_at)}>Oldest loaded scan {relative(oldest.collected_at)}</span>}
      {roots.nextCursor && <span>More locations in Collection details.</span>}
    </span>
  );
}

function DeviceFilter({
  location,
  onSelect,
}: {
  location: Location;
  onSelect: (location: Location) => void;
}) {
  return (
    <Button
      variant="ghost"
      size="xs"
      className="h-auto max-w-full whitespace-normal break-words text-left"
      aria-label={`Filter by device ${location.hostname || location.sensor_id}`}
      onClick={() => onSelect(location)}
    >
      {location.hostname || location.sensor_id}
    </Button>
  );
}

function ComponentDetails({
  selected,
  records,
  onSelect,
  onClose,
  onRestoreFocus,
}: {
  selected: Component | null;
  records?: Component[];
  onSelect: (record: Component) => void;
  onClose: () => void;
  onRestoreFocus: () => void;
}) {
  const { dateTime } = useTimeZone();
  return (
    <Dialog
      open={Boolean(selected)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent
        className={records
          ? "inset-y-0 left-auto right-0 h-dvh max-h-dvh w-full max-w-full translate-x-0 translate-y-0 overflow-y-auto rounded-none sm:max-w-2xl"
          : "max-h-[85vh] overflow-y-auto sm:max-w-2xl"}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          onRestoreFocus();
        }}
      >
        <DialogHeader>
          <DialogTitle className="break-all pr-8">
            {selected?.name || selected?.identifier || "Component details"}
          </DialogTitle>
          <DialogDescription>
            Reported metadata for one record. Agent use and granted permissions
            are unknown.
          </DialogDescription>
        </DialogHeader>
        {selected && <div><EndpointAlerts applicationId={`component:${JSON.stringify([selected.source, selected.identifier])}`}
          name={selected.name || selected.identifier}
          recipients={(records || [selected]).map(record => ({id: record.sensor_id, name: record.hostname, versions: record.version ? [record.version] : []}))}
          scopeNote="Only devices in the loaded component records are available. Load additional records in the inventory to include more devices." /></div>}
        {records && selected && <VulnerabilityDetails records={records} />}
        {records && selected && (
          <section aria-label="Component records" className="min-w-0 space-y-3 border-b pb-4">
            <p className="text-sm text-muted-foreground">
              {records.length} loaded records on {new Set(records.map((record) => record.sensor_id)).size} devices.
              A shared identifier does not establish identical provenance or runtime use.
            </p>
            <div className="divide-y">
              {records.map((record) => (
                <Button key={record.id} variant={record.id === selected.id ? "secondary" : "ghost"}
                  aria-pressed={record.id === selected.id}
                  className="h-auto w-full flex-col items-start whitespace-normal break-all py-3 text-left"
                  onClick={() => onSelect(record)}>
                  <span>{record.hostname || record.sensor_id} · {record.version ? <span className="font-mono text-sm font-normal">{record.version}</span> : "Version not reported"}</span>
                  <span className="font-mono text-sm font-normal">{record.path}</span>
                  <span className="text-xs text-muted-foreground" title={dateTime(record.last_seen_at)}>Last seen {relative(record.last_seen_at)}</span>
                  {retainedRecord(record) && <Status tone="warning">Retained from earlier scan</Status>}
                </Button>
              ))}
            </div>
          </section>
        )}
        {selected && selected.root_status !== "ok" && <p className="text-sm text-muted-foreground">
          This scan location is {scanLabels[selected.root_status].toLowerCase()}. Coverage applies to the whole location.
          {retainedRecord(selected) ? " This record was retained from an earlier scan."
            : selected.root_collected_at ? " This record was reported in the latest scan of that location."
              : " The location scan time was not reported, so record freshness is unknown."}
        </p>}
        {selected &&
          ["openaidr-plugins", "openaidr-skills"].includes(selected.source) && (
            <ComponentRelationships key={selected.id} selected={selected} />
          )}
        {selected && (
          <dl className="grid min-w-0 gap-4 text-sm sm:grid-cols-2">
            {Object.entries({
              Identifier: selected.identifier,
              Version: selected.version,
              Evidence: evidenceLabels[selected.evidence],
              Category: sources[selected.source],
              "Last seen": dateTime(selected.last_seen_at),
              "Scan location status": scanLabels[selected.root_status],
              "Location last scanned": selected.root_collected_at ? dateTime(selected.root_collected_at) : "Not reported",
              Publisher: selected.publisher,
              License: selected.metadata.license,
              Description: selected.metadata.description,
              "Declared tools": selected.metadata.tools?.join(", "),
              Path: selected.path,
              "Scan location": selected.root,
              Scope: selected.scope,
              User: selected.user,
              Environment: selected.environment,
              Device: selected.hostname,
              "Sensor ID": selected.sensor_id,
              "Operating system": selected.os,
              Architecture: selected.architecture,
              "Collection source": selected.source,
              Revision: selected.metadata.revision,
              Integrity: selected.metadata.integrity,
              "Content SHA-256": selected.metadata.content_sha256,
            }).map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="text-xs text-muted-foreground">{label}</dt>
                <dd className={`mt-1 break-all ${value && ["Identifier", "Version", "Path", "Scan location", "Sensor ID", "Revision", "Integrity", "Content SHA-256"].includes(label) ? "font-mono text-sm font-normal" : ""}`}>{value || "Not reported"}</dd>
              </div>
            ))}
            {Object.entries({
              Repository: selected.metadata.repository_url,
              "Source URL": selected.metadata.source_url,
            }).map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="text-xs text-muted-foreground">{label}</dt>
                <dd className="mt-1 break-all">
                  <ProvenanceLink value={value} />
                </dd>
              </div>
            ))}
          </dl>
        )}
        <DialogFooter showCloseButton />
      </DialogContent>
    </Dialog>
  );
}

function ComponentRelationships({ selected }: { selected: Component }) {
  const { dateTime } = useTimeZone();
  const query = new URLSearchParams({
    component_id: selected.id,
    kind: "provides",
    evidence: "declared",
    limit: "50",
  });
  const relationships = usePagedResource<Relationship>(
    `inventory/relationships?${query}`,
  );
  return (
    <section
      aria-label="Declared relationships"
      className="min-w-0 space-y-3 border-b pb-4 text-sm"
    >
      <div>
        <h3 className="font-semibold">Declared relationships</h3>
        <p className="text-xs text-muted-foreground">
          Collected from supported plugin manifests.
        </p>
      </div>
      {relationships.error && (
        <ErrorState
          message={relationships.error}
          onRetry={relationships.reload}
        />
      )}
      {relationships.loading && <LoadingState label="Loading relationships" />}
      {!relationships.loading &&
        !relationships.error &&
        relationships.items.length === 0 && (
          <p className="text-muted-foreground">
            No declared relationships reported.
          </p>
        )}
      <ul className="space-y-4">
        {relationships.items.map((link) => {
          const outgoing = link.from_component_id === selected.id;
          const related = outgoing ? link.to_component : link.from_component;
          const retained =
            link.root_status !== "ok" ||
            [link.from_component, link.to_component].some(
              (item) => item && item.root_status !== "ok",
            );
          return (
            <li key={link.id} className="min-w-0 space-y-1">
              <p className="break-all">
                <span className="text-muted-foreground">
                  {outgoing ? "Provides" : "Provided by"}:{" "}
                </span>
                <span className="font-medium">
                  {related?.name ||
                    (outgoing ? link.to_component_id : link.from_component_id)}
                </span>
                {related?.version && (
                  <span className="text-muted-foreground">
                    {" "}
                    · {related.version}
                  </span>
                )}
              </p>
              {related?.path && (
                <p className="break-all text-xs text-muted-foreground">
                  {related.path}
                </p>
              )}
              <p className="break-all text-xs text-muted-foreground">
                Declared in: {link.path || "Not reported"}
              </p>
              <p
                className="text-xs text-muted-foreground"
                title={dateTime(link.last_seen_at)}
              >
                Last seen {relative(link.last_seen_at)}
              </p>
              {retained && (
                <Status tone="warning">
                  Scan incomplete; earlier evidence may be retained
                </Status>
              )}
            </li>
          );
        })}
      </ul>
      {relationships.items.length > 0 && (
        <CollectionFooter
          count={relationships.items.length}
          label={
            relationships.items.length === 1 ? "relationship" : "relationships"
          }
          hasMore={Boolean(relationships.nextCursor)}
          busy={relationships.loadingMore || relationships.loading}
          onLoadMore={relationships.loadMore}
        />
      )}
    </section>
  );
}

function ProvenanceLink({ value }: { value?: string }) {
  if (!value) return <>Not reported</>;
  try {
    const url = new URL(value);
    if (
      ["https:", "http:"].includes(url.protocol) &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      !/\s/.test(value)
    ) {
      return (
        <a
          href={value}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary underline underline-offset-4"
        >
          {value}
        </a>
      );
    }
  } catch {}
  return <>{value}</>;
}
