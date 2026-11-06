"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  api,
  APIError,
  type AgentEvent,
  type EventRisk,
  type LiveEvents,
} from "@/lib/api";

export type LiveEventsOptions = {
  /** Events fetched on the first request. */
  limit?: number;
  /** Milliseconds between polls while the page is visible. */
  interval?: number;
  /** Rows kept in memory; older ones fall off the end. */
  max?: number;
};

/** How long a new row stays highlighted; matches the `live-row-new` animation. */
const HIGHLIGHT_MS = 2400;
const TERMINAL_RISK_ERRORS = new Set([
  "provider_rejected", "invalid_response", "response_too_large",
  "attempts_exhausted", "assessment_expired",
]);

/**
 * Follows `GET /api/v1/events/live`. The first request loads the newest
 * events; every later request asks for arrivals after the returned cursor
 * and puts the ones not seen before on top (the server also returns rows of
 * transactions that committed late, which are new). One request is in
 * flight at a time. Polling waits while the document is hidden or the feed
 * is paused and resumes from the same cursor, so nothing that arrived
 * meanwhile is skipped.
 */
export function useLiveEvents(
  query: string,
  { limit = 50, interval = 1000, max = 200 }: LiveEventsOptions = {},
) {
  const router = useRouter();
  const [items, setItems] = useState<AgentEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [accessDenied, setAccessDenied] = useState(false);
  const [riskError, setRiskError] = useState("");
  const [updated, setUpdated] = useState<Date | null>(null);
  const [recent, setRecent] = useState<Set<string>>(() => new Set());
  const [paused, setPausedState] = useState(false);
  const [restart, setRestart] = useState(0);
  const pausedRef = useRef(false);
  const kick = useRef<() => void>(() => {});

  useEffect(() => {
    let alive = true;
    let cursor = "";
    let inflight = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let clearRecent: ReturnType<typeof setTimeout> | null = null;
    let controller: AbortController | null = null;
    let riskController: AbortController | null = null;
    let riskRetryAt = 0;
    const deferredRisks = new Map<string, { at: number; delay: number }>();
    let current: AgentEvent[] = [];
    const seen = new Set<string>();
    setItems([]);
    setRecent(new Set());
    setLoading(true);
    setError("");
    setAccessDenied(false);
    setRiskError("");
    setUpdated(null);

    const denyAccess = (cause: unknown) => {
      if (!(cause instanceof APIError) || ![401, 403].includes(cause.status)) return false;
      alive = false;
      controller?.abort();
      riskController?.abort();
      if (timer) clearTimeout(timer);
      if (clearRecent) clearTimeout(clearRecent);
      current = [];
      setItems([]);
      setRecent(new Set());
      setUpdated(null);
      setLoading(false);
      setError(cause.message);
      setAccessDenied(true);
      if (cause.status === 401) router.replace("/login");
      else window.dispatchEvent(new Event("dashboard-access-denied"));
      return true;
    };

    // Assessments finish after arrival. Refresh retained events separately so
    // a slow risk endpoint cannot delay new activity or advance its cursor.
    const refreshRisks = async () => {
      if (riskController || !current.length || pausedRef.current || document.hidden || Date.now() < riskRetryAt)
        return;
      const retained = new Set(current.map((event) => event.id));
      for (const id of deferredRisks.keys()) {
        if (!retained.has(id)) deferredRisks.delete(id);
      }
      const pending = current.filter(
        (event) =>
          ["prompt", "response", "tool.call", "tool.result", "command", "file.read", "file.write", "network"].includes(event.kind) &&
          event.risk?.status !== "scored" && event.risk?.status !== "unscored" &&
          !(event.risk?.status === "error" && TERMINAL_RISK_ERRORS.has(event.risk.reason ?? "")) &&
          (deferredRisks.get(event.id)?.at ?? 0) <= Date.now(),
      );
      if (!pending.length) return;
      const request = new AbortController();
      riskController = request;
      try {
        for (let offset = 0; offset < pending.length; offset += 100) {
          const ids = pending
            .slice(offset, offset + 100)
            .map((event) => event.id)
            .join(",");
          const result = await api<{ items: { id: string; risk: EventRisk | null }[] }>(
            `events/risks?${new URLSearchParams({ ids })}`,
            { signal: AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]) },
          );
          if (!alive) return;
          const updates = new Map<string, EventRisk | null>();
          for (const item of result.items) {
            updates.set(item.id, item.risk);
            if (!item.risk || item.risk.status === "error") {
              const previousDelay = deferredRisks.get(item.id)?.delay ?? 0;
              const delay = Math.min(Math.max(previousDelay, item.risk ? 15_000 : 500) * 2, 300_000);
              deferredRisks.set(item.id, { at: Date.now() + delay, delay });
            } else {
              deferredRisks.delete(item.id);
            }
          }
          // Keep completed batches even if a later batch fails. Avoid rerendering
          // unchanged null/pending assessments while scoring is unavailable.
          let changed = false;
          current = current.map((event) => {
            const risk = updates.get(event.id);
            if (!updates.has(event.id) || JSON.stringify(event.risk ?? null) === JSON.stringify(risk))
              return event;
            changed = true;
            return { ...event, risk };
          });
          if (changed) setItems(current);
        }
        setRiskError("");
      } catch (cause) {
        if (!alive || request.signal.aborted) return;
        if (denyAccess(cause)) return;
        riskRetryAt = Date.now() + 5_000;
        setRiskError("Risk scores could not refresh. Retrying; activity continues to update.");
      } finally {
        if (riskController === request) riskController = null;
      }
    };

    const schedule = (delay: number) => {
      if (!alive) return;
      if (timer) clearTimeout(timer);
      timer = setTimeout(poll, delay);
    };

    const poll = async () => {
      timer = null;
      if (!alive || inflight) return;
      if (document.hidden || pausedRef.current) return;
      inflight = true;
      const request = new AbortController();
      controller = request;
      const params = new URLSearchParams(query);
      params.set("limit", String(cursor ? max : limit));
      if (cursor) params.set("after", cursor);
      let more = false;
      try {
        const result = await api<LiveEvents>(`events/live?${params}`, {
          signal: request.signal,
        });
        if (!alive) return;
        more = result.more;
        const fresh = result.items.filter((event) => !seen.has(event.id));
        for (const event of fresh) seen.add(event.id);
        if (cursor) {
          if (fresh.length) {
            // Later arrivals come oldest first; the newest belongs on top.
            const arrived = [...fresh].reverse();
            current = [...arrived, ...current].slice(0, max);
            setItems(current);
            setRecent(new Set(arrived.map((event) => event.id)));
            if (clearRecent) clearTimeout(clearRecent);
            clearRecent = setTimeout(() => {
              if (alive) setRecent(new Set());
            }, HIGHLIGHT_MS);
          }
        } else {
          current = fresh.slice(0, max);
          setItems(current);
        }
        if (seen.size > max * 4) {
          // Bound memory without forgetting anything that can come back:
          // every row on screen and every row of this response stay known.
          seen.clear();
          for (const event of current) seen.add(event.id);
          for (const event of result.items) seen.add(event.id);
        }
        if (result.cursor) cursor = result.cursor;
        setUpdated(new Date());
        setError("");
        setLoading(false);
        void refreshRisks();
      } catch (cause) {
        if (!alive || request.signal.aborted) return;
        if (denyAccess(cause)) return;
        setError(
          cause instanceof Error ? cause.message : "Unable to load activity.",
        );
        setLoading(false);
      } finally {
        inflight = false;
      }
      schedule(more ? 0 : interval);
    };

    kick.current = () => schedule(0);
    void poll();
    const onVisible = () => {
      if (!document.hidden) schedule(0);
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      alive = false;
      document.removeEventListener("visibilitychange", onVisible);
      if (timer) clearTimeout(timer);
      if (clearRecent) clearTimeout(clearRecent);
      controller?.abort();
      riskController?.abort();
    };
  }, [query, limit, interval, max, restart, router]);

  const setPaused = useCallback((value: boolean) => {
    pausedRef.current = value;
    setPausedState(value);
    if (!value) kick.current();
  }, []);

  /** Start over from the newest events, for example after an error. */
  const reload = useCallback(() => {
    pausedRef.current = false;
    setPausedState(false);
    setRestart((value) => value + 1);
  }, []);

  return { items, loading, error, accessDenied, riskError, updated, recent, paused, setPaused, reload };
}
