import { useCallback } from "react";
import { useSearchParams } from "react-router";

/** Filter state stored in the URL query string. Empty values remove the key. */
export function useSearchState(): [Record<string, string>, (patch: Record<string, string | undefined>) => void] {
  const [params, setParams] = useSearchParams();
  const state: Record<string, string> = {};
  params.forEach((v, k) => { state[k] = v; });
  const update = useCallback((patch: Record<string, string | undefined>) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) {
        if (v === undefined || v === "") next.delete(k); else next.set(k, v);
      }
      if (!("cursor" in patch)) next.delete("cursor");
      return next;
    }, { replace: true });
  }, [setParams]);
  return [state, update];
}
