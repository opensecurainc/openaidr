"use client";

import { useTimeZone } from "@/components/time-zone-context";
import { useEffect, useState } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, Cpu, RefreshCw, X } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartReadout, TimeAxisTick } from "@/components/chart-readout";
import { chartTicks } from "@/lib/chart";
import { useDashboard } from "@/components/dashboard-context";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageNotice,
  PageSection,
  TableLayout,
} from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { number } from "@/lib/api";
import { costTick, money } from "@/lib/cost";
import { displayModel } from "@/lib/display";
import { useResource } from "@/lib/use-resource";

type Totals = {
  cost_usd: number | null;
  calls: number;
  priced_calls: number;
  unpriced_calls: number;
  reported_calls: number;
  calculated_calls: number;
  demo_calls: number;
  tokens: number;
};
type Row = Totals & { name: string };
type Sample = Totals & { time: string };
type UserSeries = Totals & { name: string | null; series: Sample[] };
type HookEstimate = {
  application: string; model: string; model_source: string;
  observations: number; priced_observations: number;
  estimated_input_tokens: number; estimated_output_tokens: number;
  estimated_cost_usd: string | null;
};
const dimensions = ["user", "model", "project", "activity", "reasoning_effort"] as const;
type Dimension = (typeof dimensions)[number];
type PageState = {
  offset: number;
  sort: "cost_usd";
  order: "asc" | "desc";
};
type Pagination = PageState & {
  limit: number;
  total: number;
  maximum: number | null;
};
type CostData = {
  range: string;
  since: string;
  until: string;
  price_date: string;
  price_dates?: string[];
  bucket_seconds: number;
  summary: Totals;
  series: Sample[];
  user_series?: UserSeries[];
  available_filters: Record<Dimension, string[]>;
  filters_truncated: Record<Dimension, boolean>;
  pagination: Record<Dimension, Pagination>;
  processing?: { pending_exports: number; pending_since: string | null; pending_project_sessions?: number };
} & Record<`by_${Dimension}`, Row[]>;
const labels: Record<Dimension, string> = {
  user: "Users",
  model: "Models",
  project: "Projects",
  activity: "Activity",
  reasoning_effort: "Reasoning effort",
};
const singular: Record<Dimension, string> = {
  user: "User",
  model: "Model",
  project: "Project",
  activity: "Activity",
  reasoning_effort: "Reasoning effort",
};
const emptyFilters: Record<Dimension, string> = {
  user: "",
  model: "",
  project: "",
  activity: "",
  reasoning_effort: "",
};
const effortLabels: Record<string, string> = {
  none: "None", minimal: "Minimal", low: "Low", medium: "Medium", high: "High",
  xhigh: "Extra high", max: "Max", ultra: "Ultra", auto: "Auto", unknown: "Unknown",
};
const effortLevels = ["none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"];
const effortColors: Record<string, string> = {
  none: "var(--chart-effort-none)",
  minimal: "var(--chart-effort-minimal)",
  low: "var(--chart-effort-low)",
  medium: "var(--chart-effort-medium)",
  high: "var(--chart-effort-high)",
  xhigh: "var(--chart-effort-xhigh)",
  max: "var(--chart-effort-max)",
  ultra: "var(--chart-effort-ultra)",
};

function effortRank(name: string, order: "asc" | "desc") {
  const rank = effortLevels.indexOf(name);
  return rank < 0 ? effortLevels.length + (name === "auto" ? 0 : 1)
    : rank * (order === "asc" ? 1 : -1);
}

function ModelLogo({ model }: { model: string }) {
  const name = displayModel(model).toLowerCase().split("/").at(-1) ?? "";
  const provider = /^(gpt-|chatgpt-|o\d(?:-|$)|codex(?:-|$))/.test(name)
    ? { name: "OpenAI", icon: "openai" }
    : name.startsWith("claude-") ? { name: "Anthropic", icon: "anthropic" }
    : name.startsWith("gemini-") ? { name: "Google Gemini", icon: "googlegemini" }
    : null;
  return provider ? (
    <span
      role="img"
      aria-label={provider.name}
      title={provider.name}
      className="mt-0.5 size-4 shrink-0 bg-current"
      style={{
        mask: `url(/app-icons/${provider.icon}.svg) center / contain no-repeat`,
        WebkitMask: `url(/app-icons/${provider.icon}.svg) center / contain no-repeat`,
      }}
    />
  ) : <Cpu aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />;
}

const displayDimension = (dimension: Dimension, name: string) =>
  dimension === "model" ? displayModel(name)
    : dimension === "reasoning_effort" ? effortLabels[name] ?? "Unknown" : name;
const initialPages = Object.fromEntries(
  dimensions.map((dimension) => [
    dimension,
    { offset: 0, sort: "cost_usd", order: "desc" },
  ]),
) as Record<Dimension, PageState>;
const exactMoney = (value: number | null) =>
  value === null ? "No price available" : `${value} USD`;

function Breakdown({
  dimension,
  rows,
  total,
  onFilter,
  pagination,
  onPage,
  loading,
}: {
  dimension: Dimension;
  rows: Row[];
  total: number | null;
  onFilter: (value: string) => void;
  pagination: Pagination;
  onPage: (page: PageState) => void;
  loading: boolean;
}) {
  const { offset, sort, order } = pagination;
  const [effortOrder, setEffortOrder] = useState<"asc" | "desc" | null>(null);
  const page = { offset, sort, order };
  const descending = order === "desc";
  const maximum = pagination.maximum ?? 0;
  // All ten normalized effort values fit in the API's 25-row page.
  const displayedRows = effortOrder
    ? [...rows].sort((a, b) => effortRank(a.name, effortOrder) - effortRank(b.name, effortOrder))
    : rows;
  return (
    <PageSection
      title={labels[dimension]}
      description={`${number(pagination.total)} ${dimension === "reasoning_effort" ? (pagination.total === 1 ? "effort level" : "effort levels") : dimension === "activity" ? "categories" : labels[dimension].toLowerCase()}`}
      className="min-w-0 [&_[data-slot=card-header]>div]:min-w-0 [&_[role=region]]:max-h-96"
    >
      {rows.length === 0 ? (
        <EmptyState
          title="No usage to show"
          description="Try a different time range or clear the filters."
        />
      ) : (
        <TableLayout>
          <Table className="table-fixed" aria-label={`Cost by ${singular[dimension].toLowerCase()}`}>
            <colgroup>
              <col />
              <col className="w-24" />
              <col className="w-16" />
            </colgroup>
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                <TableHead
                  className="whitespace-normal pr-2"
                  aria-sort={dimension === "reasoning_effort" ? (effortOrder === "asc" ? "ascending" : effortOrder === "desc" ? "descending" : "none") : undefined}
                >
                  {dimension === "reasoning_effort" ? (
                    <button
                      disabled={loading}
                      className="inline-flex min-h-8 items-center gap-1 rounded-sm text-left focus-visible:outline-2 focus-visible:outline-ring"
                      onClick={() => setEffortOrder(effortOrder === "asc" ? "desc" : "asc")}
                    >
                      Reasoning effort
                      {effortOrder === "asc" ? <ArrowUp className="size-3 shrink-0" aria-hidden="true" />
                        : effortOrder === "desc" ? <ArrowDown className="size-3 shrink-0" aria-hidden="true" />
                        : <ArrowUpDown className="size-3 shrink-0" aria-hidden="true" />}
                    </button>
                  ) : singular[dimension]}
                </TableHead>
                <TableHead
                  className="px-2 text-right"
                  aria-sort={effortOrder ? "none" : descending ? "descending" : "ascending"}
                >
                  <button
                    disabled={loading}
                    className="inline-flex min-h-8 items-center gap-1 rounded-sm focus-visible:outline-2 focus-visible:outline-ring"
                    onClick={() => {
                      setEffortOrder(null);
                      onPage({ offset: 0, sort: "cost_usd", order: !effortOrder && descending ? "asc" : "desc" });
                    }}
                  >
                    Cost
                    {effortOrder ? (
                      <ArrowUpDown className="size-3" aria-hidden="true" />
                    ) : descending ? (
                      <ArrowDown className="size-3" aria-hidden="true" />
                    ) : (
                      <ArrowUp className="size-3" aria-hidden="true" />
                    )}
                  </button>
                </TableHead>
                <TableHead className="pl-2 text-right">Share</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {displayedRows.map((row) => (
                <TableRow key={row.name}>
                  <TableCell className="whitespace-normal pr-2">
                    <button
                      disabled={loading}
                      onClick={() => onFilter(row.name)}
                      aria-label={`Filter by ${singular[dimension].toLowerCase()}: ${displayDimension(dimension, row.name)}`}
                      className="flex min-h-8 w-full items-start gap-2 rounded-sm text-left font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                      title={displayDimension(dimension, row.name)}
                    >
                      {dimension === "model" && <ModelLogo model={row.name} />}
                      <span className="flex min-w-0 flex-1 flex-col items-start gap-1">
                        <span className="max-w-full break-words">{displayDimension(dimension, row.name)}</span>
                        <span
                          aria-hidden="true"
                          className="h-1 w-full max-w-12 overflow-hidden rounded-xs bg-muted"
                        >
                          <span
                            className="block h-full rounded-xs bg-chart-1"
                            style={{
                              backgroundColor: dimension === "reasoning_effort"
                                ? effortColors[row.name] ?? "var(--chart-effort-unknown)" : undefined,
                              width: `${maximum ? ((row.cost_usd ?? 0) / maximum) * 100 : 0}%`,
                            }}
                          />
                        </span>
                      </span>
                    </button>
                  </TableCell>
                  <TableCell
                    className="number whitespace-normal break-words px-2 text-right font-medium"
                    title={exactMoney(row.cost_usd)}
                  >
                    {money(row.cost_usd)}
                    {row.unpriced_calls > 0 && (
                      <p className="text-xs font-normal text-muted-foreground">
                        {number(row.unpriced_calls)} unpriced
                      </p>
                    )}
                  </TableCell>
                  <TableCell className="number pl-2 text-right text-muted-foreground">
                    {row.cost_usd !== null && total !== null && total > 0
                      ? `${((row.cost_usd / total) * 100).toFixed(1)}%`
                      : "N/A"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableLayout>
      )}
      {(pagination.total > pagination.limit || page.offset > 0) && (
        <div
          className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3"
          aria-label={`${labels[dimension]} pagination`}
        >
          <span className="text-xs text-muted-foreground">
            {rows.length
              ? `${number(page.offset + 1)}–${number(page.offset + rows.length)} of ${number(pagination.total)}`
              : "No more results"}
          </span>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={loading || page.offset === 0}
              onClick={() =>
                onPage({
                  ...page,
                  offset: Math.max(0, page.offset - pagination.limit),
                })
              }
            >
              Previous
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={
                loading || page.offset + pagination.limit >= pagination.total
              }
              onClick={() =>
                onPage({ ...page, offset: page.offset + pagination.limit })
              }
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </PageSection>
  );
}

function DimensionFilter({
  dimension,
  range,
  value,
  options,
  truncated,
  onChange,
}: {
  dimension: Dimension;
  range: string;
  value: string;
  options: string[];
  truncated: boolean;
  onChange: (value: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(search), 250);
    return () => clearTimeout(timer);
  }, [search]);
  const query = new URLSearchParams({
    range, dimension,
    search: debounced,
  });
  const matches = useResource<{ items: string[]; has_more: boolean }>(
    truncated && debounced ? `costs/agents/filters?${query}` : null,
  );
  const choices = truncated && debounced ? matches.data?.items || [] : options;
  return (
    <div className="w-36 max-w-full space-y-1">
      {truncated && (
        <Input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          aria-label={`Search ${labels[dimension].toLowerCase()}`}
          placeholder={`Search ${labels[dimension].toLowerCase()}…`}
        />
      )}
      <Select
        value={value ? `filter:${value}` : "all"}
        onValueChange={(next) => onChange(next === "all" ? "" : next.slice(7))}
      >
        <SelectTrigger
          aria-label={`${singular[dimension]} filter`}
          className="w-full"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">
            All{" "}
            {dimension === "reasoning_effort" ? "efforts" : dimension === "activity"
              ? "activities"
              : labels[dimension].toLowerCase()}
          </SelectItem>
          {[...new Set([...choices, ...(value ? [value] : [])])].map(
            (option) => (
              <SelectItem key={option} value={`filter:${option}`}>
                {displayDimension(dimension, option)}
              </SelectItem>
            ),
          )}
        </SelectContent>
      </Select>
      {matches.loading && (
        <p role="status" className="text-xs text-muted-foreground">
          Searching…
        </p>
      )}
      {matches.error && (
        <p role="alert" className="text-xs text-status-critical">
          Unable to search. Try again.
        </p>
      )}
      {truncated && !matches.loading && (
        <p className="text-xs text-muted-foreground">
          {debounced && !choices.length
            ? "No matches"
            : !debounced || matches.data?.has_more
              ? "Search to narrow results"
              : `${choices.length} matches`}
        </p>
      )}
    </div>
  );
}

function CostChart({
  data,
  stale,
  loading,
}: {
  data: CostData;
  stale: boolean;
  loading: boolean;
}) {
  const { chartTimeTick, chartTimestamp, label } = useTimeZone();
  const [selected, setSelected] = useState<string | null>();
  const users = data.user_series ?? [];
  const selectedUser = users.find((user) => user.name === selected);
  const entries = users.length
    ? users
    : [{ ...data.summary, name: null, series: data.series }];
  const otherCount =
    data.pagination.user.total -
    users.filter((user) => user.name !== null).length;
  const userLabel = (user: UserSeries) =>
    user.name ?? `Other users (${number(otherCount)})`;
  const colors = entries.map(
    (_, index) =>
      `color-mix(in srgb, var(--chart-1) ${100 - (65 * index) / Math.max(entries.length - 1, 1)}%, var(--card))`,
  );
  const visible = entries
    .map((user, index) => ({ user, index }))
    .filter(({ user }) => !selectedUser || user === selectedUser);
  const series = data.series.map((sample, index) => ({
    ...(selectedUser?.series[index] ?? sample),
    timestamp: new Date(sample.time).getTime(),
    users: entries.map((user) => {
      const point = user.series[index];
      return { ...point, cost_usd: point.calls === 0 ? 0 : point.cost_usd };
    }),
  }));
  const summary = selectedUser ?? data.summary;
  const ticks = chartTicks(
    Math.max(...series.map((row) => row.cost_usd ?? 0), 0),
    false,
    0.01,
  );
  const daily = data.bucket_seconds === 86400;
  const zoneLabel = daily ? "UTC" : label;
  const timeLabel = (value: number) => chartTimeTick(value, daily);
  const timeTicks = [...new Set(
    [series[0], series[Math.floor(series.length / 2)], series.at(-1)]
      .filter((sample) => sample !== undefined)
      .map((sample) => sample.timestamp),
  )];
  return (
    <PageSection
      title={data.user_series ? "Cost over time by user" : "Cost over time"}
      description={`${daily ? "Daily" : "Hourly"} estimated spend in USD · ${zoneLabel}`}
      action={
        <>
          {users.length > 0 && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Button
                size="sm"
                variant="outline"
                aria-pressed={!selectedUser}
                disabled={loading || stale}
                onClick={() => setSelected(undefined)}
              >
                All users
              </Button>
              <span role="status">
                {selectedUser
                  ? `${userLabel(selectedUser)} only`
                  : `${number(data.pagination.user.total)} users`}
              </span>
            </div>
          )}
          <div className="text-right" aria-label="Displayed chart cost">
            <p className="text-xs text-muted-foreground">
              {summary.unpriced_calls ? "Known estimated cost" : "Estimated cost"}
            </p>
            <p
              className="number text-base font-semibold"
              title={exactMoney(summary.cost_usd)}
            >
              {money(summary.cost_usd)}
            </p>
          </div>
        </>
      }
    >
      {summary.calls === 0 ? (
        <EmptyState
          title="No usage recorded"
          description="Usage appears here when connected agents send per-request token or cost records. Try a longer time range."
        />
      ) : summary.priced_calls === 0 ? (
        <EmptyState
          title="Cost estimates are unavailable"
          description="Usage has been recorded, but these calls have no reported cost or supported model price."
        />
      ) : (
        <div
          className="h-48 w-full min-w-0 number [&_.recharts-surface]:focus-visible:outline-2 [&_.recharts-surface]:focus-visible:outline-ring"
          aria-label="Estimated cost over time"
        >
          <ResponsiveContainer width="100%" height="100%" minWidth={0}>
            <BarChart
              data={series}
              margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
              maxBarSize={daily ? undefined : 36}
              barCategoryGap={daily ? "5%" : "10%"}
              accessibilityLayer
              aria-label={`Estimated agent cost over time in USD, ${zoneLabel}`}
            >
              <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
              <XAxis
                dataKey="timestamp"
                ticks={timeTicks}
                tickFormatter={timeLabel}
                tick={
                  <TimeAxisTick
                    start={timeTicks[0]}
                    end={timeTicks.at(-1)!}
                    daily={daily}
                  />
                }
                tickLine={false}
                axisLine={false}
                minTickGap={36}
              />
              <YAxis
                domain={[0, ticks.at(-1)!]}
                ticks={ticks}
                tickFormatter={costTick}
                tickLine={false}
                axisLine={false}
                width={Math.max(
                  64,
                  ...ticks.map((value) => costTick(value).length * 7 + 12),
                )}
              />
              <Tooltip
                isAnimationActive={false}
                filterNull={false}
                cursor={{ fill: "var(--muted)" }}
                content={({ active, payload }) => {
                  const sample = payload?.[0]?.payload as
                    | (typeof series)[number]
                    | undefined;
                  return active && sample ? (
                    <ChartReadout
                      timestamp={chartTimestamp(sample.time, daily)}
                      rows={visible.map(({ user, index }) => ({
                        label: users.length ? userLabel(user) : "Estimated USD",
                        value: money(sample.users[index].cost_usd),
                        color: colors[index],
                      }))}
                    >
                      <p className="number font-medium text-foreground">
                        Estimated cost:{" "}
                        {money(sample.calls === 0 ? 0 : sample.cost_usd)}
                      </p>
                      <p>
                        {number(sample.calls)} calls
                        {sample.unpriced_calls > 0
                          ? `, ${number(sample.unpriced_calls)} unpriced · Partial estimate`
                          : ""}
                      </p>
                      {stale && <p>Stale</p>}
                    </ChartReadout>
                  ) : null;
                }}
              />
              {visible.map(({ user, index }) => (
                <Bar
                  key={index}
                  name={users.length ? userLabel(user) : "Estimated cost"}
                  dataKey={`users.${index}.cost_usd`}
                  stackId="cost"
                  fill={colors[index]}
                  isAnimationActive={false}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
      {users.length > 0 && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2 py-2 text-xs text-muted-foreground">
            <span className="font-medium text-foreground">Users</span>
            <span>Select a user to isolate their spend in this chart.</span>
          </div>
          {users.some((user) => user.name === null) && (
            <p className="mb-3 text-xs text-muted-foreground">
              Top 5 users by cost. Other users are combined. Use the User filter
              to inspect anyone.
            </p>
          )}
          <div
            className={`-mx-4 grid grid-cols-1 border-t ${users.length === 1 ? "" : users.length === 4 ? "sm:grid-cols-2 xl:grid-cols-4" : users.length === 2 ? "sm:grid-cols-2" : "sm:grid-cols-2 xl:grid-cols-3"}`}
            role="group"
            aria-label="Users in cost chart"
          >
            {users.map((user, index) => (
              <button
                key={index}
                disabled={loading || stale}
                aria-label={`Show ${userLabel(user)} only`}
                aria-pressed={selectedUser === user}
                title={userLabel(user)}
                onClick={() =>
                  setSelected(selectedUser === user ? undefined : user.name)
                }
                className={`grid min-w-0 grid-cols-[minmax(0,1fr)_auto] gap-x-2 border-b px-3 py-2 text-left hover:bg-muted focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring disabled:opacity-50 ${selectedUser === user ? "bg-accent" : ""}`}
              >
                <span className="flex min-w-0 items-center gap-2 text-sm font-medium">
                  <span
                    className="size-2.5 shrink-0 rounded-xs"
                    aria-hidden="true"
                    style={{ background: colors[index] }}
                  />
                  <span className="truncate">{userLabel(user)}</span>
                </span>
                <span className="col-start-2 row-span-2 row-start-1 flex flex-col items-end gap-1 number">
                  <span
                    className="text-base font-semibold"
                    title={exactMoney(user.cost_usd)}
                  >
                    {money(user.cost_usd)}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {user.cost_usd !== null &&
                    data.summary.cost_usd !== null &&
                    data.summary.cost_usd > 0
                      ? `${((user.cost_usd / data.summary.cost_usd) * 100).toFixed(1)}% of total`
                      : "Share unavailable"}
                  </span>
                </span>
                <span className="col-start-1 mt-1 block pl-4.5 text-xs text-muted-foreground number">
                  {number(user.calls)} calls ·{" "}
                  {user.unpriced_calls
                    ? `${number(user.unpriced_calls)} unpriced`
                    : "All calls priced"}
                </span>
              </button>
            ))}
          </div>
          {summary.unpriced_calls > 0 && (
            <p className="mt-3 text-xs text-muted-foreground">
              {number(summary.unpriced_calls)} calls have no price available.
              Their cost is excluded from bars, totals, and shares.
            </p>
          )}
        </>
      )}
    </PageSection>
  );
}

export function AgentCosts() {
  const { dateTime, timeZone } = useTimeZone();
  const { user } = useDashboard();
  const [range, setRange] = useState("30d");
  const [filters, setFilters] = useState(emptyFilters);
  const [pages, setPages] = useState(initialPages);
  const query = new URLSearchParams({ range });
  dimensions.forEach((key) => {
    if (filters[key]) query.set(key, filters[key]);
    query.set(`${key}_offset`, String(pages[key].offset));
    query.set(`${key}_sort`, pages[key].sort);
    query.set(`${key}_order`, pages[key].order);
  });
  const resource = useResource<CostData>(
    user ? `costs/agents/summary?${query}` : null,
    30000,
    true,
    { sourceCard: "agent-costs" },
  );
  const data = resource.data;
  const pendingAge = data?.processing?.pending_since
    ? Date.parse(data.until) - Date.parse(data.processing.pending_since)
    : NaN;
  const processingDelayed = !!data?.processing?.pending_exports &&
    (!Number.isFinite(pendingAge) || pendingAge >= 60_000);
  const filtered = dimensions.some((key) => filters[key]);
  const hookEstimates = useResource<{ range: string; items: HookEstimate[] }>(
    user && range !== "90d" && !filtered ? `costs/hook-estimates?range=${range}` : null,
    30000, false, { sourceCard: "hook-estimates" },
  );
  const resetPages = () =>
    setPages(
      (previous) =>
        Object.fromEntries(
          dimensions.map((key) => [key, { ...previous[key], offset: 0 }]),
        ) as Record<Dimension, PageState>,
    );
  const filter = (key: Dimension, value: string) => {
    resetPages();
    setFilters((previous) => ({ ...previous, [key]: value }));
  };
  const clearFilters = () => {
    resetPages();
    setFilters(emptyFilters);
  };
  return (
    <div className="@container/agent-costs min-w-0 space-y-3">
      <div className="flex flex-wrap items-start gap-2">
        <div
          role="group"
          aria-label="Cost time range"
          className="flex gap-1 rounded-md bg-muted"
        >
          {["24h", "30d", "90d"].map((value) => (
            <Button
              key={value}
              size="sm"
              variant={value === range ? "outline" : "ghost"}
              aria-pressed={value === range}
              onClick={() => {
                resetPages();
                setRange(value);
              }}
            >
              {value}
            </Button>
          ))}
        </div>
        <div className="contents" aria-label="Cost filters">
          {dimensions.map((key) => (
            <DimensionFilter
              key={key}
              dimension={key}
              range={range}
              value={filters[key]}
              options={data?.available_filters[key] || []}
              truncated={data?.filters_truncated[key] || false}
              onChange={(value) => filter(key, value)}
            />
          ))}
          {filtered && (
            <Button variant="ghost" size="sm" onClick={clearFilters}>
              <X aria-hidden="true" className="size-3.5" />
              Clear filters
            </Button>
          )}
        </div>
        <div className="ml-auto flex h-8 items-center gap-2">
          {resource.updated && (
            <span
              className="text-xs text-muted-foreground"
              title={dateTime(resource.updated.toISOString())}
            >
              Updated{" "}
              {resource.updated.toLocaleTimeString(undefined, {
                timeZone,
                hour: "numeric",
                minute: "2-digit",
              })}
            </span>
          )}
          <Button
            size="sm"
            variant="outline"
            disabled={resource.loading || hookEstimates.loading}
            onClick={() => { void resource.reload(); void hookEstimates.reload(); }}
          >
            <RefreshCw aria-hidden="true" className="size-3.5" />
            Refresh
          </Button>
        </div>
      </div>
      <section aria-label="Hook estimates">
        <Card className="min-w-0 space-y-3 p-4">
          <h2 className="text-sm font-semibold">Hook estimates</h2>
          <p className="text-xs text-muted-foreground">
            Approximate tokens and standard list-price cost for captured Copilot and Cursor text.
            Hidden and repeated context are unknown. Separate from reported usage below; not billed spend.
          </p>
          {filtered ? <p className="text-sm text-muted-foreground">Clear filters to see hook estimates across this organization.</p>
            : range === "90d" ? <p className="text-sm text-muted-foreground">Hook estimates are retained for 30 days. Select 24h or 30d.</p>
            : hookEstimates.error ? <ErrorState message={`Hook estimates unavailable: ${hookEstimates.error}`} onRetry={() => void hookEstimates.reload()} />
            : !hookEstimates.data || hookEstimates.data.range !== range ? <LoadingState label="Loading hook estimates…" />
            : !hookEstimates.data.items.length ? <p className="text-sm text-muted-foreground">No captured hook text in this period.</p>
            : <TableLayout>
              <Table aria-label="Hook estimates by agent and model">
                <TableHeader><TableRow>
                  <TableHead>Agent / model</TableHead><TableHead className="text-right">Est. input tokens</TableHead>
                  <TableHead className="text-right">Est. output tokens</TableHead><TableHead className="text-right">Est. text cost</TableHead>
                </TableRow></TableHeader>
                <TableBody>{hookEstimates.data.items.map((item) => <TableRow key={`${item.application}/${item.model}/${item.model_source}`}>
                  <TableCell>
                    <div className="font-medium">{item.application === "github-copilot" ? "GitHub Copilot" : "Cursor"}</div>
                    <div className="max-w-64 break-words text-xs text-muted-foreground">{item.model === "unknown" ? "Model unknown"
                      : `${item.model_source === "configured" ? "Assumed model: " : ""}${displayModel(item.model)}`}</div>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">~{number(item.estimated_input_tokens)}</TableCell>
                  <TableCell className="text-right tabular-nums">~{number(item.estimated_output_tokens)}</TableCell>
                  <TableCell className="text-right tabular-nums">{item.estimated_cost_usd === null ? "Cost unknown"
                    : `~${Number(item.estimated_cost_usd).toLocaleString("en-US", {style:"currency", currency:"USD", maximumFractionDigits:6})}`}
                    {item.estimated_cost_usd !== null && item.priced_observations < item.observations &&
                      <div className="text-xs text-muted-foreground">{item.priced_observations}/{item.observations} observations priced</div>}
                  </TableCell>
                </TableRow>)}</TableBody>
              </Table>
            </TableLayout>}
        </Card>
      </section>
      {resource.error && (
        <ErrorState
          message={
            data
              ? `Stale data. Unable to load data: ${resource.error}`
              : resource.error
          }
          onRetry={() => void resource.reload()}
        />
      )}
      {!data && !resource.error && (
        <LoadingState label="Loading agent costs…" />
      )}
      {data && (
        <>
          {processingDelayed && (
            <p
              role="status"
              className="border-l-4 border-status-warning bg-status-warning/5 px-3 py-2 text-sm"
            >
              Usage is still being processed. Totals may be incomplete and will
              update automatically.
            </p>
          )}
          {!!data.processing?.pending_project_sessions && (
            <p role="status" className="border-l-4 border-status-warning bg-status-warning/5 px-3 py-2 text-sm">
              Project attribution is updating. Project totals will update automatically.
            </p>
          )}
          <div className="grid grid-cols-2 gap-2 xl:grid-cols-4">
            {[
              {
                title: data.summary.unpriced_calls
                  ? "Known estimated cost"
                  : "Estimated cost",
                value: money(data.summary.cost_usd),
                detail: "USD · API-equivalent usage",
                exact: exactMoney(data.summary.cost_usd),
              },
              {
                title: "Model calls",
                value: number(data.summary.calls),
                detail: "Per-request usage records",
              },
              {
                title: "Reported tokens",
                value: number(data.summary.tokens),
                detail: "Input, output, and cache",
              },
              {
                title: "Price coverage",
                value: data.summary.calls
                  ? `${Math.round((data.summary.priced_calls / data.summary.calls) * 100)}%`
                  : "N/A",
                detail: `${number(data.summary.priced_calls)} of ${number(data.summary.calls)} calls priced`,
              },
            ].map((stat) => (
              <Card key={stat.title} className="min-w-0 gap-1 p-3">
                <p className="text-xs text-muted-foreground">{stat.title}</p>
                <p
                  className="figure number break-words text-display font-semibold"
                  title={stat.exact}
                >
                  {stat.value}
                </p>
                <p className="text-xs text-muted-foreground">{stat.detail}</p>
              </Card>
            ))}
          </div>
          {data.summary.unpriced_calls > 0 && (
            <p className="border-l-4 border-status-warning bg-status-warning/5 px-3 py-2 text-sm">
              {number(data.summary.unpriced_calls)} calls have no price
              available. Their tokens and calls are included; their cost is
              excluded from totals and shares.
            </p>
          )}
          {data.summary.demo_calls > 0 && (
            <p className="text-sm text-muted-foreground">
              Includes {number(data.summary.demo_calls)} synthetic demo calls.
            </p>
          )}
          {filtered && data.summary.calls === 0 ? (
            <PageSection title="No matching usage">
              <EmptyState
                title="No usage matches these filters"
                description="Clear the filters or choose a different time range."
                action={
                  <Button variant="outline" onClick={clearFilters}>
                    Clear filters
                  </Button>
                }
              />
            </PageSection>
          ) : (
            <>
              <CostChart
                key={JSON.stringify([range, filters])}
                data={data}
                stale={Boolean(resource.error)}
                loading={resource.loading}
              />
              <div className="grid min-w-0 grid-cols-1 items-start gap-3 @2xl/agent-costs:grid-cols-2 @7xl/agent-costs:grid-cols-4">
                {dimensions.filter((key) => key !== "user" || !data.user_series).map((key) => (
                  <Breakdown
                    key={key}
                    dimension={key}
                    rows={data[`by_${key}`]}
                    total={data.summary.cost_usd}
                    pagination={data.pagination[key]}
                    loading={resource.loading || Boolean(resource.error)}
                    onPage={(next) =>
                      setPages((previous) => ({ ...previous, [key]: next }))
                    }
                    onFilter={(value) => filter(key, value)}
                  />
                ))}
              </div>
            </>
          )}
          <PageNotice title="How cost estimates are calculated" collapsible>
            Estimates use agent-reported costs or published token rates (
            {data.price_dates?.join(", ") || data.price_date}). Subscription
            fees, discounts, and taxes are excluded. Activities are inferred
            from correlated tools; missing attribution is shown as Unattributed.
            Select a row to filter all views. Models can share the Guardrail
            label. Each filter selects one recorded model.
            {" "}Reasoning effort uses reported request settings. Missing or invalid
            settings are Unknown. Effort levels can mean different things across
            models; filter by model to compare them.
          </PageNotice>
        </>
      )}
    </div>
  );
}
