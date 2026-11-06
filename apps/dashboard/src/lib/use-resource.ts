"use client";

import { useCallback, useContext, useEffect, useRef, useState, type SetStateAction } from "react";
import { useRouter } from "next/navigation";
import { api, APIError } from "@/lib/api";
import { ResourceCacheContext, type ResourceCache } from "@/lib/resource-cache";

type Snapshot<T> = {
  path: string | null;
  cache: ResourceCache | null;
  generation: number;
  data: T | null;
  updated: Date | null;
};

export function useResource<T>(
  path: string | null,
  refreshInterval = 0,
  keepPrevious = false,
  cachePolicy?: { validate?: (data: T) => boolean; sourceCard?: string },
) {
  const router = useRouter();
  const sessionCache = useContext(ResourceCacheContext);
  const validate = cachePolicy?.validate;
  const sourceCard = cachePolicy?.sourceCard;
  const cache = validate ? sessionCache : null;
  const snapshot = useCallback((data: T | null, updated: Date | null): Snapshot<T> => ({
    path, cache, generation: cache?.generation ?? 0, data, updated,
  }), [path, cache]);
  const restore = useCallback(() => {
    const entry = path ? cache?.read(path) : null;
    return snapshot(entry ? entry.data as T : null, entry?.updated ?? null);
  }, [path, cache, snapshot]);
  const [state, setState] = useState<Snapshot<T>>(restore);
  const current = useRef(state);
  current.current = state;
  const [loading, setLoading] = useState(Boolean(path));
  const [error, setError] = useState("");
  const active = useRef<AbortController | null>(null);
  const generation = cache?.generation ?? 0;

  const setData = useCallback((value: SetStateAction<T | null>) => {
    if (!cache) {
      setState((previous) => ({
        ...previous,
        data: typeof value === "function"
          ? (value as (data: T | null) => T | null)(previous.data) : value,
      }));
      return;
    }
    // A completed approval may arrive after navigation or sign-out.
    if (cache && cache.generation !== generation) return;
    const entry = path ? cache?.peek(path) : null;
    const previous = entry ? entry.data as T : current.current.data;
    const data = typeof value === "function"
      ? (value as (previous: T | null) => T | null)(previous)
      : value;
    const updated = entry?.updated ?? current.current.updated;
    if (cache && path && data !== null && updated && validate?.(data)) {
      cache.write(path, data, updated);
    }
    setState(snapshot(data, updated));
  }, [cache, path, generation, validate, snapshot]);

  const reload = useCallback(async () => {
    active.current?.abort();
    if (!path) return;
    const controller = new AbortController();
    active.current = controller;
    const startedGeneration = cache?.generation;
    const revision = cache?.peek(path)?.revision;
    const obsolete = () => controller.signal.aborted ||
      (cache !== null && cache.generation !== startedGeneration);
    setLoading(true);
    setError("");
    try {
      const result = await api<T>(path, { signal: controller.signal, sourceCard });
      if (obsolete() || (cache && cache.peek(path)?.revision !== revision)) return;
      const updated = new Date();
      // Invalid responses still reach each component's existing error UI.
      if (cache && validate?.(result)) cache.write(path, result, updated);
      setState(snapshot(result, updated));
    } catch (cause) {
      if (obsolete()) return;
      if (cause instanceof APIError && [401, 403].includes(cause.status)) {
        sessionCache?.clear();
        setState(snapshot(null, null));
        if (cause.status === 403) window.dispatchEvent(new Event("dashboard-access-denied"));
        if (cause.status === 401) {
          router.replace("/login");
          return;
        }
      }
      setError(cause instanceof Error ? cause.message : "Unable to load data.");
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, [path, router, cache, sessionCache, validate, snapshot, sourceCard]);

  useEffect(() => {
    const unsubscribe = cache && path ? cache.subscribe(path, (entry) => {
      setState(snapshot(entry ? entry.data as T : null, entry?.updated ?? null));
      if (!entry) setError("");
    }) : null;
    if (cache || !keepPrevious || !path) setState(restore());
    setError("");
    setLoading(Boolean(path));
    void reload();
    const timer =
      refreshInterval > 0
        ? setInterval(() => {
            if (!document.hidden) void reload();
          }, refreshInterval)
        : null;
    return () => {
      unsubscribe?.();
      active.current?.abort();
      if (timer) clearInterval(timer);
    };
  }, [reload, refreshInterval, path, keepPrevious, cache, restore, snapshot]);

  // Never render another query or identity while its effect is still pending.
  const visible = cache && (state.path !== path || state.cache !== cache || state.generation !== generation)
    ? restore() : state;
  return { data: visible.data, setData, loading, error, reload, updated: visible.updated };
}

type Page<T> = { items: T[]; next_cursor: string };

export function usePagedResource<T>(path: string | null) {
  const router = useRouter();
  const sessionCache = useContext(ResourceCacheContext);
  const [items, setItems] = useState<T[]>([]);
  const [nextCursor, setNextCursor] = useState("");
  const [loading, setLoading] = useState(Boolean(path));
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState<Date | null>(null);
  const active = useRef<AbortController | null>(null);

  const load = useCallback(
    async (cursor = "") => {
      active.current?.abort();
      if (!path) return;
      const controller = new AbortController();
      active.current = controller;
      setLoading(!cursor);
      setLoadingMore(Boolean(cursor));
      setError("");
      try {
        const query = cursor
          ? `${path}${path.includes("?") ? "&" : "?"}cursor=${encodeURIComponent(cursor)}`
          : path;
        const result = await api<Page<T>>(query, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setItems((previous) =>
          cursor ? [...previous, ...result.items] : result.items,
        );
        setNextCursor(result.next_cursor);
        setUpdated(new Date());
      } catch (cause) {
        if (controller.signal.aborted) return;
        if (cause instanceof APIError && [401, 403].includes(cause.status)) {
          sessionCache?.clear();
          setItems([]);
          setNextCursor("");
          setUpdated(null);
          if (cause.status === 403) window.dispatchEvent(new Event("dashboard-access-denied"));
        }
        if (cause instanceof APIError && cause.status === 401) {
          setItems([]);
          router.replace("/login");
        } else {
          setError(
            cause instanceof Error ? cause.message : "Unable to load data.",
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
          setLoadingMore(false);
        }
      }
    },
    [path, router, sessionCache],
  );

  useEffect(() => {
    setItems([]);
    setNextCursor("");
    setLoadingMore(false);
    setUpdated(null);
    setError("");
    setLoading(Boolean(path));
    void load();
    return () => active.current?.abort();
  }, [load, path]);

  const reload = useCallback(() => {
    void load();
  }, [load]);
  const loadMore = useCallback(() => {
    if (nextCursor && !loading && !loadingMore) void load(nextCursor);
  }, [load, nextCursor, loading, loadingMore]);

  return {
    items,
    nextCursor,
    loading,
    loadingMore,
    error,
    loadMore,
    reload,
    updated,
  };
}
