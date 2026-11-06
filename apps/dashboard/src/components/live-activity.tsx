"use client";

import { useTimeZone } from "@/components/time-zone-context";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type React from "react";
import Link from "next/link";
import {
  ArrowLeft,
  ArrowRight,
  Pause,
  Play,
  RefreshCw,
  TriangleAlert,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { CodeBlock, InlineCode } from "@/components/ui/code-block";
import { CopyButton } from "@/components/ui/copy-button";
import { Status } from "@/components/ui/status";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-layout";
import { EventSourceBadge } from "@/components/telemetry-panels";
import { KnowledgeEvidence } from "@/components/company-knowledge";
import { useLiveEvents } from "@/lib/use-live-events";
import {
  CATEGORIES,
  LEGEND,
  eventTime,
  groupActivity,
  nodeVisible,
  sessionState,
  type ActivityCategory,
  type LiveDevice,
  type LiveSession,
  type SessionState,
  type TimelineNode,
} from "@/lib/activity";
import {
  api,
  eventDetail,
  productLabel,
  relative,
  type AgentEvent,
  type DeviceStatus,
  type EventRisk,
} from "@/lib/api";
import { binaryContent, binaryFields, collectionNotes, contentLine, downloadRaw, firstLine, withoutBinary } from "@/lib/event-content";
import { DECISION_LABELS, DECISION_TONES, enforcedDecision, isGuardrailDecision } from "@/lib/guardrail";
import { cn } from "@/lib/utils";
import { SessionArchiveLink } from "@/components/session-links";
import { ActivityCategoryFilters, ActivitySessionButton, ActivityTimelineButton } from "@/components/activity-presentation";
import { isUuid } from "@/lib/session";

/** Session Active/Idle state and "last" times follow this clock. */
const CLOCK_MS = 15_000;
/** Lines an expanded excerpt shows before "Show all". */
const EXPANDED_LINES = 12;
const NO_DEVICES: DeviceStatus[] = [];

const STATE_LABELS: Record<SessionState, string> = {
  active: "Active",
  idle: "Idle",
  ended: "Ended",
};

function useClock(ms: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(timer);
  }, [ms]);
  return now;
}

/** The selected session lives in `?session=` so a link reopens it. */
function useSelectedSession() {
  const [key, setKey] = useState<string | null>(null);
  // False until the URL has been read, so a default never replaces a link.
  const [ready, setReady] = useState(false);
  useEffect(() => {
    setKey(new URLSearchParams(window.location.search).get("session"));
    setReady(true);
  }, []);
  const select = useCallback((next: string | null) => {
    setKey(next);
    const url = new URL(window.location.href);
    if (next) url.searchParams.set("session", next);
    else url.searchParams.delete("session");
    window.history.replaceState(window.history.state, "", url);
  }, []);
  return [key, select, ready] as const;
}

/**
 * Live agent activity as one master-detail card (apps/dashboard/DESIGN.md,
 * Activity views): sessions grouped by device on the left, the selected
 * session's timeline on the right. Each pane scrolls on its own, so the card
 * never grows with its data. A timeline is a list of turns headed by their
 * prompt; every event is one summary line that expands in place. Polls the
 * live endpoint every second while visible.
 */
export function LiveActivityFeed({
  limit = 100,
  query = "",
  devices = NO_DEVICES,
}: {
  /** Kept for callers; the card always fits one viewport. */
  compact?: boolean;
  limit?: number;
  /** Extra `events/live` filters, for example `product=codex-cli`. */
  query?: string;
  /** Known sensors, for online status in the device groups. */
  devices?: DeviceStatus[];
}) {
  const { clockTime } = useTimeZone();
  const feed = useLiveEvents(query, { limit, max: 300 });
  const now = useClock(CLOCK_MS);
  const [selectedKey, selectSession, urlRead] = useSelectedSession();
  const [detailOnPhone, setDetailOnPhone] = useState(false);
  // Chips select categories; with none selected every category shows.
  const [picked, setPicked] = useState<Set<ActivityCategory>>(() => new Set());
  const shown = useMemo(
    () => (picked.size ? picked : new Set(LEGEND)),
    [picked],
  );
  const [selected, setSelected] = useState<TimelineNode | null>(null);
  // The latest prompt seen per session, so a busy session keeps its summary
  // after the prompt leaves the bounded live window.
  const prompts = useRef(new Map<string, string>());
  // Every session seen since the page loaded, so one noisy session cannot
  // push another out of the list by filling the window.
  const roster = useRef(new Map<string, LiveSession>());
  const stored = useStoredPrompts();
  const grouped = useMemo(() => {
    const result = groupActivity(feed.items, devices, now, [...roster.current.values()]);
    for (const item of result.sessions) {
      if (item.lastPrompt) prompts.current.set(item.key, item.lastPrompt);
      else item.lastPrompt = prompts.current.get(item.key) ?? stored.prompts.get(item.key) ?? "";
    }
    roster.current = new Map(
      result.sessions.map((item) => [item.key, roster.current.get(item.key) && item.outside ? roster.current.get(item.key)! : item]),
    );
    return result;
  }, [feed.items, devices, now, stored.prompts]);
  const { load } = stored;
  useEffect(() => {
    for (const item of grouped.sessions) {
      if (item.lastPrompt) continue;
      // The server's session row, which stored prompts are filed under.
      const sessionId = item.nodes.map((node) => node.event.session_id).find(Boolean);
      if (typeof sessionId === "string") load(item.key, sessionId);
    }
  }, [grouped.sessions, load]);
  // The selected session, or the most recently active one. The default is
  // pinned (and written to the URL) once, so later activity elsewhere does
  // not switch the session being read.
  const session =
    grouped.sessions.find((item) => item.key === selectedKey) ?? grouped.sessions[0];
  const defaultKey = session?.key;
  useEffect(() => {
    if (urlRead && !selectedKey && defaultKey) selectSession(defaultKey);
  }, [urlRead, selectedKey, defaultKey, selectSession]);
  const selectedNode = selected
    ? grouped.sessions
        .flatMap((item) => item.nodes)
        .find((node) => node.event.id === selected.event.id) ?? {
          ...selected,
          // A late call can absorb a standalone result or native record. Keep
          // the selected record, updated from the feed before display grouping.
          event: feed.items.find((event) => event.id === selected.event.id) ?? selected.event,
        }
    : null;
  const toggleCategory = useCallback((category: ActivityCategory) => {
    setPicked((previous) => {
      const next = new Set(previous);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  }, []);
  const choose = useCallback(
    (key: string) => {
      selectSession(key);
      setDetailOnPhone(true);
    },
    [selectSession],
  );

  if (feed.accessDenied) return <ErrorState message={feed.error} onRetry={feed.reload} />;

  const status = feed.paused
    ? "Paused"
    : feed.error
      ? "Retrying"
      : feed.updated
        ? `Live · updated ${clockTime(feed.updated.toISOString())}`
        : "Connecting";
  return (
    <section id="live-activity" aria-label="Live agent activity" className="scroll-mt-4">
      <Card className="gap-0 overflow-hidden">
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div className="min-w-60 flex-1">
            <CardTitle>Live activity</CardTitle>
            <CardDescription>
              Agent sessions on your devices as activity arrives. Filters and pause apply only to this timeline.
            </CardDescription>
          </div>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Status
              tone={
                feed.paused
                  ? "neutral"
                  : feed.error
                    ? "warning"
                    : feed.updated
                      ? "ok"
                      : "neutral"
              }
              pulse={!feed.paused && !feed.error}
              className="font-normal text-muted-foreground"
            >
              {status}
            </Status>
            <Button
              variant="outline"
              aria-pressed={feed.paused}
              aria-label={
                feed.paused ? "Resume live updates" : "Pause live updates"
              }
              onClick={() => feed.setPaused(!feed.paused)}
            >
              {feed.paused ? <Play /> : <Pause />}
              {feed.paused ? "Resume" : "Pause"}
            </Button>
            <Button variant="ghost" asChild>
              <Link href="/evidence">
                Explore evidence
                <ArrowRight />
              </Link>
            </Button>
          </div>
        </CardHeader>
        {feed.riskError && (
          <p role="status" className="border-t px-4 py-2 text-xs text-muted-foreground">
            {feed.riskError}
          </p>
        )}
        {feed.loading && !feed.items.length ? (
          <CardContent>
            <LoadingState label="Loading live activity" />
          </CardContent>
        ) : feed.error && !feed.items.length ? (
          <CardContent>
            <ErrorState message={feed.error} onRetry={feed.reload} />
          </CardContent>
        ) : !session ? (
          <EmptyState
            title="No agent activity yet"
            description="Type a prompt in a connected coding agent to see activity here."
          />
        ) : (
          <>
            {feed.error && (
              <div
                role="alert"
                className="flex items-start gap-2 border-t border-l-4 border-l-status-warning bg-status-warning/10 px-4 py-2 text-xs leading-5 text-foreground"
              >
                <TriangleAlert
                  aria-hidden="true"
                  className="mt-0.5 size-3.5 text-status-warning"
                />
                <span>
                  Live updates interrupted: {feed.error} Retrying every second;
                  the activity below stays as last received.
                </span>
                <button
                  onClick={feed.reload}
                  className="ml-auto font-medium text-primary underline underline-offset-2"
                >
                  <RefreshCw aria-hidden="true" className="mr-1 inline size-3" />
                  Reload
                </button>
              </div>
            )}
            <div className="grid min-h-0 border-t lg:h-[calc(100dvh-18rem)] lg:min-h-112 lg:grid-cols-[320px_minmax(0,1fr)]">
              <SessionList
                className={cn("max-lg:max-h-[70vh]", detailOnPhone && "max-lg:hidden")}
                devices={grouped.devices}
                sessions={grouped.sessions}
                selected={session.key}
                now={now}
                recent={feed.recent}
                onSelect={choose}
              />
              <SessionDetail
                className={cn(!detailOnPhone && "max-lg:hidden")}
                session={session}
                state={sessionState(session, now)}
                recent={feed.recent}
                picked={picked}
                shown={shown}
                onToggle={toggleCategory}
                onReset={() => setPicked(new Set())}
                onBack={() => setDetailOnPhone(false)}
                onView={setSelected}
              />
            </div>
          </>
        )}
      </Card>
      <EventDialog node={selectedNode} onClose={() => setSelected(null)} />
    </section>
  );
}

function SessionStateBadge({ state }: { state: SessionState }) {
  return (
    <Status tone={state === "active" ? "ok" : "neutral"} pulse={state === "active"}>
      {STATE_LABELS[state]}
    </Status>
  );
}

function deviceTone(status: LiveDevice["status"]) {
  return status === "online" ? "ok" : status === "disabled" ? "warning" : "neutral";
}

const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The latest stored prompt of sessions whose prompts are older than the live
 * window, as on a fresh load during a long session. Each session is asked once.
 */
function useStoredPrompts() {
  const [prompts, setPrompts] = useState<Map<string, string>>(() => new Map());
  const asked = useRef(new Set<string>());
  const load = useCallback((key: string, sessionId: string) => {
    if (asked.current.has(key) || !SESSION_ID.test(sessionId)) return;
    asked.current.add(key);
    api<{ items: AgentEvent[] }>(
      `events?${new URLSearchParams({ kind: "prompt", session_id: sessionId, source: "collector", limit: "1" })}`,
    )
      .then(async (result) => {
        let prompt = typeof result.items[0]?.text === "string" ? result.items[0].text.trim() : "";
        if (!prompt) {
          const native = await api<{ items: AgentEvent[] }>(
            `events?${new URLSearchParams({ kind: "prompt", session_id: sessionId, source: "otlp", limit: "1" })}`,
          );
          prompt = typeof native.items[0]?.text === "string" ? native.items[0].text.trim() : "";
        }
        if (prompt) setPrompts((current) => new Map(current).set(key, prompt));
      })
      // The row keeps "No prompt text"; a later fresh load asks again.
      .catch(() => undefined);
  }, []);
  return useMemo(() => ({ prompts, load }), [prompts, load]);
}

/** Sessions grouped by device, most recently active first. */
function SessionList({
  devices,
  sessions,
  selected,
  now,
  recent,
  onSelect,
  className,
}: {
  devices: LiveDevice[];
  sessions: LiveSession[];
  selected: string;
  now: number;
  recent: Set<string>;
  onSelect: (key: string) => void;
  className?: string;
}) {
  return (
    <nav
      aria-label="Sessions"
      className={cn("min-h-0 overflow-y-auto border-b lg:border-r lg:border-b-0", className)}
    >
      {devices.map((device) => {
        const name = device.label || device.hostname;
        const items = sessions.filter(
          (session) => (session.sensorId || session.hostname || "unknown") === device.key,
        );
        return (
          <section key={device.key} aria-label={`Sessions on ${name}`}>
            <h3 className="sticky top-0 z-10 flex items-center gap-2 border-b bg-card px-4 py-2 text-xs font-semibold">
              <span className="min-w-0 flex-1 truncate" title={name}>
                {name}
              </span>
              {/* A sensor with no reported status shows none, rather than a label that crowds the name. */}
              {device.status !== "unknown" && (
                <Status tone={deviceTone(device.status)} className="shrink-0 font-normal">
                  {device.status === "online" ? "Online" : device.status === "offline" ? "Offline" : "Disabled"}
                </Status>
              )}
              <span className="number shrink-0 font-normal text-muted-foreground">
                {items.length} {items.length === 1 ? "session" : "sessions"}
              </span>
            </h3>
            <ul className="divide-y">
              {items.map((session) => {
                const state = sessionState(session, now);
                const current = session.key === selected;
                const fresh = session.nodes.some((node) => recent.has(node.id));
                return (
                  <li key={session.key}>
                    <ActivitySessionButton
                      product={session.product}
                      current={current}
                      recent={fresh}
                      onClick={() => onSelect(session.key)}
                      status={<SessionStateBadge state={state} />}
                      summary={session.lastPrompt}
                      metadata={<>
                        {relative(session.lastAt)} · {session.events}{" "}
                        {session.events === 1 ? "event" : "events"}
                      </>}
                    />
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
    </nav>
  );
}

type Turn = { key: string; prompt?: TimelineNode; items: TimelineNode[] };

/** Group a timeline into turns: each prompt heads the events that follow it. */
function turnsOf(nodes: TimelineNode[]) {
  const turns: Turn[] = [];
  for (const node of nodes) {
    if (node.category === "prompt") turns.push({ key: node.id, prompt: node, items: [] });
    else if (turns.length) turns[turns.length - 1].items.push(node);
    else turns.push({ key: `start-${node.id}`, items: [node] });
  }
  return turns;
}

function SessionDetail({
  session,
  state,
  recent,
  picked,
  shown,
  onToggle,
  onReset,
  onBack,
  onView,
  className,
}: {
  session: LiveSession;
  state: SessionState;
  recent: Set<string>;
  picked: Set<ActivityCategory>;
  shown: Set<ActivityCategory>;
  onToggle: (category: ActivityCategory) => void;
  onReset: () => void;
  onBack: () => void;
  onView: (node: TimelineNode) => void;
  className?: string;
}) {
  const { clockTime } = useTimeZone();
  const filtering = picked.size > 0;
  const [open, setOpen] = useState<string | null>(null);
  const scroller = useRef<HTMLDivElement | null>(null);
  const pinned = useRef(true);
  const visible = filtering
    ? session.nodes.filter((node) => nodeVisible(node, shown))
    : session.nodes;
  const turns = turnsOf(visible);
  const archiveId = session.nodes.map((node) => node.event.session_id).find(isUuid);
  // Open on the newest activity, and stay there while it arrives unless the
  // reader scrolled up.
  useEffect(() => {
    pinned.current = true;
    setOpen(null);
  }, [session.key]);
  useEffect(() => {
    const node = scroller.current;
    if (node && pinned.current) node.scrollTop = node.scrollHeight;
    // Folded results and merged records change the session without adding a row.
  }, [session.key, visible.length, session.events, session.lastAt]);
  return (
    <article
      aria-label={`${productLabel(session.product)} session, ${STATE_LABELS[state].toLowerCase()}`}
      className={cn("flex min-h-0 min-w-0 flex-col", className)}
    >
      <header className="border-b px-4 py-3">
        <Button variant="ghost" size="xs" className="mb-2 lg:hidden" onClick={onBack}>
          <ArrowLeft aria-hidden="true" />
          Sessions
        </Button>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <h3 className="text-sm font-semibold">{productLabel(session.product)}</h3>
          <SessionStateBadge state={state} />
          <SessionArchiveLink sessionId={archiveId} />
          <span className="text-xs text-muted-foreground">
            {[session.user, session.hostname].filter(Boolean).join(" @ ") ||
              "Host not reported"}
          </span>
          {session.cwd && (
            // Truncated from the start: the end of a path names the project.
            <InlineCode
              className="max-w-80 truncate [direction:rtl]"
              title={session.cwd}
            >
              {session.cwd}
            </InlineCode>
          )}
        </div>
        <p className="number mt-1 text-xs text-muted-foreground">
          Started {clockTime(session.startedAt)} · {session.events}{" "}
          {session.events === 1 ? "event" : "events"}
          {session.accepted > 0 &&
            ` · ${session.accepted} policy ${session.accepted === 1 ? "check" : "checks"} accepted`}
          {session.native > 0 &&
            ` · ${session.native} native ${session.native === 1 ? "record" : "records"} merged`}
          {filtering && ` · ${visible.length} shown`}
        </p>
        <ActivityCategoryFilters picked={picked} onToggle={onToggle} onReset={onReset} />
      </header>
      <div
        ref={scroller}
        onScroll={(event) => {
          const node = event.currentTarget;
          pinned.current = node.scrollHeight - node.scrollTop - node.clientHeight < 48;
        }}
        className="min-h-0 flex-1 overflow-y-auto px-4 py-2 max-lg:max-h-[70vh]"
      >
        {turns.length ? (
          <ol aria-label="Session timeline" className="space-y-3">
            {turns.map((turn) => (
              <li key={turn.key}>
                {turn.prompt && (
                  <TimelineRow
                    node={turn.prompt}
                    heading
                    open={open === turn.prompt.id}
                    recent={recent.has(turn.prompt.id)}
                    onToggle={() => setOpen((id) => (id === turn.prompt!.id ? null : turn.prompt!.id))}
                    onView={onView}
                  />
                )}
                {turn.items.length > 0 && (
                  <ol className={cn("timeline", turn.prompt && "ml-4")}>
                    {turn.items.map((node) => (
                      <TimelineRow
                        key={node.id}
                        node={node}
                        open={open === node.id}
                        recent={
                          recent.has(node.id) ||
                          (!!node.result && recent.has(node.result.id)) ||
                          (!!node.native && recent.has(node.native.id))
                        }
                        onToggle={() => setOpen((id) => (id === node.id ? null : node.id))}
                        onView={onView}
                      />
                    ))}
                  </ol>
                )}
              </li>
            ))}
          </ol>
        ) : (
          <p className="py-6 text-center text-sm text-muted-foreground">
            {session.outside
              ? "Its events are outside the live window."
              : "No events of the selected kinds in this session."}
          </p>
        )}
      </div>
    </article>
  );
}

/** Risk levels badged on a row, least severe first. */
const EXCEPTION_LEVELS = ["low", "medium", "high", "critical"];

/** A measured risk at Low or above; everything else stays off the row. */
function exceptional(risk?: EventRisk | null) {
  return (
    risk?.status === "scored" &&
    typeof risk.score === "number" &&
    !!risk.level &&
    EXCEPTION_LEVELS.includes(risk.level)
  );
}

function summaryOf(node: TimelineNode) {
  const detail = eventDetail(node.event);
  if (node.category === "prompt") return firstLine(detail).line || detail;
  return contentLine(detail, node.event.truncated === true);
}

/** One event: a single summary line that expands in place to its full content. */
function TimelineRow({
  node,
  heading = false,
  open,
  recent,
  onToggle,
  onView,
}: {
  node: TimelineNode;
  heading?: boolean;
  open: boolean;
  recent: boolean;
  onToggle: () => void;
  onView: (node: TimelineNode) => void;
}) {
  const { clockTime, dateTime } = useTimeZone();
  const { label, color } = CATEGORIES[node.category];
  const categoryStyle = { "--activity-color": color } as React.CSSProperties;
  const toolName =
    node.category === "tool" || node.category === "result"
      ? node.event.tool?.name
      : undefined;
  // The agent's own outcome for a tool call: from the native record joined
  // to a collector call, or from the event itself when it is the native record.
  const outcome = (node.native ?? node.event).tool;
  const duration =
    node.category === "tool" && typeof outcome?.duration_ms === "number"
      ? `${(outcome.duration_ms / 1000).toFixed(outcome.duration_ms >= 10000 ? 0 : 1)} s`
      : "";
  const exitCode = node.result?.command?.exit_code ?? node.event.command?.exit_code;
  const failed =
    (node.category === "tool" && outcome?.success === false) ||
    !!node.result?.tool?.is_error ||
    (typeof exitCode === "number" && exitCode !== 0);
  // A folded result or merged record keeps its own risk: the row shows the most severe.
  const flagged = [node.event, node.result, node.native]
    .map((event) => event?.risk)
    .filter(exceptional)
    .sort(
      (a, b) =>
        EXCEPTION_LEVELS.indexOf(b!.level!) - EXCEPTION_LEVELS.indexOf(a!.level!) ||
        (b!.score ?? 0) - (a!.score ?? 0),
    )[0];
  const decision = node.category === "decision" ? node.event.hook?.decision?.toLowerCase() : "";
  // What the sensor did: an `ask` rule on Codex is enforced as `deny`.
  // Native agent permission records (OTLP tool_decision) are not guardrail outcomes.
  const native = !!decision && !isGuardrailDecision(node.event);
  const enforced = decision && !native ? enforcedDecision(node.event) : null;
  const summary = summaryOf(node);
  const detail = eventDetail(node.event);
  // The visible outcome marks, spoken with the row since its label replaces them.
  const outcomeText = [
    duration,
    failed ? (typeof exitCode === "number" && exitCode !== 0 ? `exit ${exitCode}` : "failed") : "",
    native
      ? `Agent permission: ${node.event.hook?.decision}`
      : enforced && enforced !== "allow"
        ? decision === "ask" && enforced === "deny" ? "Denied, approval unavailable" : DECISION_LABELS[enforced]
        : !enforced && decision && !["accept", "allow", "allowed"].includes(decision) ? node.event.hook?.decision : "",
    flagged ? `Risk ${flagged.score}/100, ${RISK_LEVELS[flagged.level as keyof typeof RISK_LEVELS]}` : "",
  ].filter(Boolean).join(", ");
  const reveal = useRevealWhenOpen(open);
  if (heading)
    return (
      <div
        ref={reveal as React.RefObject<HTMLDivElement>}
        data-category="prompt"
        data-event-id={node.event.id}
        className={cn("rounded-md bg-muted", recent && "live-row-new")}
        style={categoryStyle}
      >
        {/* Each prompt is its turn's heading (below the session's h3). */}
        <h4 className="m-0 font-[inherit] text-[length:inherit]">
        <button
          type="button"
          aria-expanded={open}
          aria-label={`Prompt at ${clockTime(node.at)}: ${summary}${flagged ? `. Risk ${flagged.score}/100, ${RISK_LEVELS[flagged.level as keyof typeof RISK_LEVELS]}` : ""}`}
          onClick={onToggle}
          className="flex w-full items-baseline gap-3 rounded-md px-3 py-2 text-left focus-visible:outline-2 focus-visible:outline-ring"
        >
          <span className="number w-20 shrink-0 text-xs text-muted-foreground" title={dateTime(node.event.time)}>
            {clockTime(node.at)}
          </span>
          <Badge variant="activity">{label}</Badge>
          <span className="line-clamp-3 min-w-0 flex-1 whitespace-pre-wrap break-words text-sm font-medium">
            {detail}
          </span>
          {flagged && <RiskBadge risk={flagged} compact />}
        </button>
        </h4>
        {open && <Expanded node={node} onView={onView} className="px-3 pb-3" />}
      </div>
    );
  return (
    <li
      ref={reveal as React.RefObject<HTMLLIElement>}
      data-category={node.category}
      data-event-id={node.event.id}
      className={cn("timeline-item", recent && "live-row-new")}
      style={categoryStyle}
    >
      <span aria-hidden="true" className="timeline-dot" style={{ background: color }} />
      <ActivityTimelineButton
        category={node.category}
        at={node.at}
        toolName={toolName}
        summary={summary}
        monospace={(node.category === "tool" || node.category === "result") && !binaryContent(detail)}
        aria-expanded={open}
        aria-label={`${label}${toolName ? ` ${toolName}` : ""} at ${clockTime(node.at)}: ${summary}${outcomeText ? `. ${outcomeText}` : ""}`}
        onClick={onToggle}
      >
        {duration && <span className="number shrink-0 text-xs text-muted-foreground">{duration}</span>}
        {failed && (
          <span className="shrink-0 text-xs font-medium text-status-critical">
            {typeof exitCode === "number" && exitCode !== 0 ? `exit ${exitCode}` : "failed"}
          </span>
        )}
        {native ? (
          <span className="min-w-0 truncate text-xs text-muted-foreground">
            Agent permission: {node.event.hook?.decision}
          </span>
        ) : enforced && enforced !== "allow" ? (
          <Status tone={DECISION_TONES[enforced]} dotSize="lg" className="shrink-0">
            {decision === "ask" && enforced === "deny" ? "Denied · approval unavailable" : DECISION_LABELS[enforced]}
          </Status>
        ) : !enforced && decision && !["accept", "allow", "allowed"].includes(decision) && (
          <Status tone={decision.startsWith("den") || decision === "block" ? "critical" : "warning"} dotSize="lg" className="shrink-0">
            {node.event.hook?.decision}
          </Status>
        )}
        {flagged && <RiskBadge risk={flagged} compact />}
      </ActivityTimelineButton>
      {open && <Expanded node={node} onView={onView} className="mt-2" />}
    </li>
  );
}

/** Keep a row that was just expanded in view inside its scrolling pane. */
function useRevealWhenOpen(open: boolean) {
  const ref = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (open) ref.current?.scrollIntoView({ block: "nearest" });
  }, [open]);
  return ref;
}

/** A clamped excerpt with "Show all" and copy; binary content is described. */
function Excerpt({
  label,
  text,
  truncated,
}: {
  label: string;
  /** The stored value exactly as received; null when the field is absent. */
  text: string | null;
  truncated: boolean;
}) {
  const [all, setAll] = useState(false);
  if (text === null)
    return (
      <div className="min-w-0">
        <p className="mb-1 text-xs font-medium">{label}</p>
        <p className="text-xs text-muted-foreground">Not captured</p>
      </div>
    );
  const blank = !text.trim();
  const binary = blank ? null : binaryContent(text, truncated);
  const lines = blank ? 0 : text.replace(/\r\n?/g, "\n").trimEnd().split("\n").length;
  return (
    <div className="min-w-0">
      <p className="mb-1 flex items-center gap-2 text-xs font-medium">
        {label}
        {!binary && lines > 1 && (
          <span className="number font-normal text-muted-foreground">{lines} lines</span>
        )}
        {blank && <CopyButton className="ml-auto" text={text} label={`Copy ${label.toLowerCase()}`} />}
      </p>
      {blank ? (
        <p className="text-xs text-muted-foreground">
          {text.length ? `Empty (${text.length} whitespace ${text.length === 1 ? "character" : "characters"})` : "Empty"}
        </p>
      ) : binary ? (
        <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          {binary}
          <Button
            variant="ghost"
            size="xs"
            onClick={() => downloadRaw(text, `${label.toLowerCase()}.txt`)}
          >
            Download raw output
          </Button>
        </p>
      ) : (
        <>
          <CodeBlock copyText={text} copyLabel={`Copy ${label.toLowerCase()}`} lines={all || lines <= EXPANDED_LINES ? undefined : EXPANDED_LINES}>{excerpt(text)}</CodeBlock>
          {lines > EXPANDED_LINES && (
            <Button variant="ghost" size="xs" className="mt-1" onClick={() => setAll((value) => !value)}>
              {all ? "Show fewer lines" : `Show all ${lines} lines`}
            </Button>
          )}
        </>
      )}
    </div>
  );
}

function Assessment({ label, event }: { label: string; event?: AgentEvent }) {
  if (!event) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <RiskBadge risk={event.risk} />
      <RiskConfidence risk={event.risk} />
    </div>
  );
}

/** The full content of an event, its outcome, its assessments, and its record links. */
function Expanded({
  node,
  onView,
  className,
}: {
  node: TimelineNode;
  onView: (node: TimelineNode) => void;
  className?: string;
}) {
  const { dateTime } = useTimeZone();
  const detail = eventDetail(node.event);
  const tool = node.category === "tool" || node.category === "result";
  const assessed = ["prompt", "tool", "result", "response"].includes(node.category);
  // Collection changes are flagged per event, so they are noted once, not per excerpt.
  const notes = [...new Set([node.event, node.result, node.native].flatMap((event) => (event ? collectionNotes(event) : [])))];
  return (
    <div className={cn("space-y-3", className)}>
      {tool ? (
        <>
          <Excerpt
            label={node.category === "result" ? "Output" : "Input"}
            text={storedContent(node.event)}
            truncated={node.event.truncated === true}
          />
          {node.result && (
            <Excerpt label="Output" text={storedContent(node.result)} truncated={node.result.truncated === true} />
          )}
        </>
      ) : node.category === "prompt" || node.category === "response" ? (
        <Excerpt label="Text" text={storedContent(node.event)} truncated={node.event.truncated === true} />
      ) : (
        <p className="whitespace-pre-wrap break-words text-sm">{detail}</p>
      )}
      {notes.length > 0 && <p className="text-xs text-muted-foreground">{notes.join(" ")}</p>}
      {assessed && (
        <div className="space-y-1">
          <Assessment label={tool && node.category === "tool" ? "Call" : "Event"} event={node.event} />
          {node.result && <Assessment label="Result" event={node.result} />}
          {node.native && <Assessment label="Native record" event={node.native} />}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <EventSourceBadge event={node.event} />
        <span className="text-xs text-muted-foreground">
          Received {dateTime(node.event.received_at || null)}
        </span>
        <Button
          variant="outline"
          size="xs"
          className="ml-auto"
          onClick={() => onView(node)}
          aria-label={`View event ${node.event.id}`}
        >
          View details
        </Button>
      </div>
    </div>
  );
}

/** The exact stored payloads that the dialog's JSON describes instead of showing. */
function RawDownloads({ event }: { event: AgentEvent }) {
  const notes = collectionNotes(event);
  return (
    <>
      {notes.length > 0 && <p className="text-xs text-muted-foreground">{notes.join(" ")}</p>}
      {binaryFields(event).map(({ name, raw, binary }) => (
    <p key={name} className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      {name === "text" ? "Text" : "Output"}: {binary}
      <Button variant="outline" size="xs" onClick={() => downloadRaw(raw, `${event.id}-${name}.txt`)}>
        Download raw {name}
      </Button>
    </p>
      ))}
    </>
  );
}

/**
 * The stored value an excerpt shows, copies, and downloads, exactly as
 * received; `eventDetail` trims and summarizes it for the row instead.
 */
function storedContent(event: AgentEvent) {
  // Every stored string counts, including "" and "\n"; only an absent field is null.
  const exact = (value: unknown) => (typeof value === "string" ? value : null);
  switch (event.kind) {
    case "prompt":
    case "response":
      return exact(event.text);
    case "tool.result":
      return exact(event.tool?.output);
    case "command":
      return exact(event.command?.text);
    case "tool.call":
      return fullInput(event);
    default:
      // File, network, and MCP events show their stored path, URL, or target.
      return eventDetail(event);
  }
}

/**
 * A generic tool call's stored input, whole: the one-line summary
 * (`eventDetail`) shortens it to 400 characters. Commands keep their text.
 */
function fullInput(event: AgentEvent) {
  const input = event.tool?.input;
  if (event.kind !== "tool.call" || input === undefined || input === null) return null;
  return typeof input === "string" ? input : JSON.stringify(input, null, 2);
}

function EventDialog({ node, onClose }: { node: TimelineNode | null; onClose: () => void }) {
  const { dateTime } = useTimeZone();
  return (
    <Dialog
      open={!!node}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Event evidence</DialogTitle>
          <DialogDescription>Collected event data for this tenant.</DialogDescription>
        </DialogHeader>
        {node && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-muted-foreground">Source</span>
            <EventSourceBadge event={node.event} />
            <span className="text-muted-foreground">
              Received {dateTime(node.event.received_at || null)}
            </span>
          </div>
        )}
        {node && ["prompt", "tool", "result", "response"].includes(node.category) && (
          <div className="space-y-2 border-y py-3">
            <p className="text-xs font-semibold">Guardrail risk assessment</p>
            <RiskBadge risk={node.event.risk} />
            <RiskConfidence risk={node.event.risk} />
            <KnowledgeEvidence risk={node.event.risk} />
          </div>
        )}
        {node && <RawDownloads event={node.event} />}
        <CodeBlock className="max-h-[40vh]">
          {JSON.stringify(node && withoutBinary(node.event), null, 2)}
        </CodeBlock>
        {node?.native && (
          <>
            <p className="text-xs font-semibold">Native telemetry record</p>
            <RiskBadge risk={node.native.risk} />
            <RiskConfidence risk={node.native.risk} />
            <KnowledgeEvidence risk={node.native.risk} />
            <RawDownloads event={node.native} />
            <CodeBlock className="max-h-[30vh]">
              {JSON.stringify(withoutBinary(node.native), null, 2)}
            </CodeBlock>
          </>
        )}
        {node?.result && (
          <>
            <p className="text-xs font-semibold">Tool result</p>
            <RiskBadge risk={node.result.risk} />
            <RiskConfidence risk={node.result.risk} />
            <KnowledgeEvidence risk={node.result.risk} />
            <RawDownloads event={node.result} />
            <CodeBlock className="max-h-[30vh]">
              {JSON.stringify(withoutBinary(node.result), null, 2)}
            </CodeBlock>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function riskConfidence(risk?: EventRisk | null) {
  if (
    !risk || !["scored", "unscored"].includes(risk.status) ||
    typeof risk.confidence !== "number" || typeof risk.category_confidence !== "number" ||
    !Number.isFinite(risk.confidence) || risk.confidence < 0 || risk.confidence > 1 ||
    !Number.isFinite(risk.category_confidence) || risk.category_confidence < 0 || risk.category_confidence > 1
  ) return null;
  return `Score confidence ${Math.round(risk.confidence * 100)}% · Category confidence ${Math.round(risk.category_confidence * 100)}%`;
}

function RiskConfidence({ risk }: { risk?: EventRisk | null }) {
  const confidence = riskConfidence(risk);
  if (!confidence) return null;
  return (
    <p className="text-xs text-muted-foreground">
      {confidence}
      {" · "}Based on available session context
    </p>
  );
}

export const RISK_CATEGORIES = {
  secret_exfiltration: "Secret exfiltration",
  data_exfiltration: "Data exfiltration",
  supply_chain: "Supply chain",
  destructive_command: "Destructive commands",
  excessive_agency: "Excessive agency",
  hallucination: "Hallucination",
  none: "No identified risk",
  unknown: "Insufficient context",
};
export const RISK_LEVELS = {
  info: "Minimal",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};
export const RISK_VARIANTS = {
  info: "informational",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
} as const;

export function RiskBadge({
  risk,
  compact = false,
}: {
  risk?: EventRisk | null;
  /** Badge only, for a timeline row; the category is in the expanded row. */
  compact?: boolean;
}) {
  if (
    risk?.status !== "scored" ||
    typeof risk.score !== "number" ||
    !Number.isFinite(risk.score) || risk.score < 0 || risk.score > 100 ||
    !risk.level || !(risk.level in RISK_LEVELS) ||
    !risk.category || !(risk.category in RISK_CATEGORIES)
  ) {
    const label =
      !risk ? "Risk not assessed"
        : risk.status === "pending" ? "Risk assessing"
        : risk?.status === "error" ? "Risk unavailable"
          : risk?.reason === "evidence_too_large" ? "Risk unscored · Evidence too large"
          : risk?.status === "unscored" ? "Risk unknown · Insufficient context"
            : "Risk unavailable";
    return <span className="text-xs text-muted-foreground">{label}</span>;
  }
  const confidence = riskConfidence(risk);
  return (
    <span
      className={cn("inline-flex max-w-full items-center gap-x-1.5 gap-y-1", compact ? "min-w-0" : "flex-wrap")}
      title={`${confidence ? `Guardrail ${confidence}. ` : ""}Risk score measures severity, not certainty.`}
    >
      <Badge
        variant={RISK_VARIANTS[risk.level]}
        // In a timeline row the badge gives way (truncating) before it overflows.
        className={cn("number", compact && "min-w-0 shrink truncate")}
      >
        Risk {risk.score}/100 · {RISK_LEVELS[risk.level]}
      </Badge>
      {!compact && (
        <span className="text-xs text-muted-foreground">{RISK_CATEGORIES[risk.category]}</span>
      )}
    </span>
  );
}

/**
 * Remove the indentation every line of an excerpt shares, so output that
 * starts inside an indented block keeps its relative indentation but not the
 * common offset. Offsets under two columns are kept because they carry
 * meaning in formats such as `git status --short`.
 */
function excerpt(text: string) {
  const lines = text.replace(/\s+$/, "").split("\n");
  const indents = lines
    .filter((line) => line.trim())
    .map((line) => line.match(/^[ \t]*/)![0].length);
  const common = indents.length ? Math.min(...indents) : 0;
  return common >= 2
    ? lines.map((line) => line.slice(common)).join("\n")
    : lines.join("\n");
}
