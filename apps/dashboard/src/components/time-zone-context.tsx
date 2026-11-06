/** @jsxImportSource react */
"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { clockTime, dateTime } from "@/lib/api";
import { chartTimeTick, chartTimestamp } from "@/lib/chart";

export type TimeZoneMode = "local" | "utc";
const STORAGE_KEY = "openaidr.time-zone";
const TimeZoneContext = createContext<{
  mode: TimeZoneMode;
  setMode: (mode: TimeZoneMode) => void;
  localZone: string;
} | null>(null);

export function TimeZoneProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<TimeZoneMode>("local");
  const [localZone, setLocalZone] = useState("");
  useEffect(() => {
    setLocalZone(Intl.DateTimeFormat().resolvedOptions().timeZone);
    const restore = () => {
      try {
        setMode(localStorage.getItem(STORAGE_KEY) === "utc" ? "utc" : "local");
      } catch {
        // The current tab still works when browser storage is unavailable.
      }
    };
    restore();
    const sync = (event: StorageEvent) => {
      if (event.key === STORAGE_KEY || event.key === null) restore();
    };
    window.addEventListener("storage", sync);
    return () => window.removeEventListener("storage", sync);
  }, []);
  const select = useCallback((value: TimeZoneMode) => {
    setMode(value);
    try {
      localStorage.setItem(STORAGE_KEY, value);
    } catch {
      // Persistence is optional; changing the display must still work.
    }
  }, []);
  const value = useMemo(
    () => ({ mode, setMode: select, localZone }),
    [mode, select, localZone],
  );
  return <TimeZoneContext.Provider value={value}>{children}</TimeZoneContext.Provider>;
}

export function useTimeZone() {
  const context = useContext(TimeZoneContext);
  if (!context) throw new Error("Time zone context missing");
  return useMemo(() => {
    const timeZone = context.mode === "utc" ? "UTC" : context.localZone || "UTC";
    return {
      ...context,
      timeZone,
      label: context.mode === "utc" ? "UTC" : "Local time",
      dateTime: (value: string | null | undefined) => dateTime(value, timeZone),
      clockTime: (value: string | null | undefined) => clockTime(value, timeZone),
      chartTimestamp: (value: string | number, daily = false) => chartTimestamp(value, daily, timeZone),
      chartTimeTick: (value: number, daily = false) => chartTimeTick(value, daily, timeZone),
    };
  }, [context]);
}
