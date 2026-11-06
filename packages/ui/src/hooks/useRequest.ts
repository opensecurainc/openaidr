import { useCallback, useEffect, useRef, useState } from "react";

export interface RequestState<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  /** True while a refetch is in flight and previous data is still shown. */
  stale: boolean;
  reload: () => void;
  setData: (updater: T | ((prev: T | undefined) => T)) => void;
}

/**
 * Runs an async request when deps change. Keeps the previous result while
 * reloading so tables and charts do not flash.
 */
export function useRequest<T>(fn: () => Promise<T>, deps: unknown[], opts: { enabled?: boolean } = {}): RequestState<T> {
  const enabled = opts.enabled ?? true;
  const [data, setDataState] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(enabled);
  const [stale, setStale] = useState(false);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    if (!enabled) { setLoading(false); return; }
    const id = ++seq.current;
    setStale(true);
    if (data === undefined) setLoading(true);
    fnRef.current().then(
      (res) => { if (id === seq.current) { setDataState(res); setError(null); setLoading(false); setStale(false); } },
      (err) => { if (id === seq.current) { setError(err); setLoading(false); setStale(false); } },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick, enabled]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const setData = useCallback((updater: T | ((prev: T | undefined) => T)) => {
    setDataState((prev) => (typeof updater === "function" ? (updater as (p: T | undefined) => T)(prev) : updater));
  }, []);
  return { data, error, loading, stale, reload, setData };
}
