"use client";

import { useId } from "react";
import type { TimeZoneMode } from "@/components/time-zone-context";
import { cn } from "@/lib/utils";

export function TimeZoneControl({
  value,
  onChange,
  localZone,
}: {
  value: TimeZoneMode;
  onChange: (value: TimeZoneMode) => void;
  localZone: string;
}) {
  const name = useId();
  return (
    <fieldset
      aria-label="Time zone"
      data-slot="time-zone-control"
      className="relative isolate grid h-10 w-32 shrink-0 grid-cols-2 text-sm font-medium sm:h-8"
    >
      <legend className="sr-only">Time zone</legend>
      <span aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10 rounded-md border border-input bg-card">
        <span className={cn(
          "absolute inset-y-[3px] left-[3px] w-[calc((100%-6px)/2)] rounded-sm bg-primary transition-transform motion-reduce:transition-none",
          value === "utc" && "translate-x-full",
        )} />
      </span>
      {(["local", "utc"] as const).map((mode) => (
        <label
          key={mode}
          title={mode === "local" ? `Local time${localZone ? `: ${localZone}` : ""}` : "Coordinated Universal Time"}
          className={cn(
            "relative flex cursor-pointer items-center justify-center rounded-md select-none has-focus-visible:outline-3 has-focus-visible:outline-offset-2 has-focus-visible:outline-ring",
            mode === value ? "text-primary-foreground" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <input
            className="absolute inset-0 size-full cursor-pointer opacity-0"
            type="radio"
            name={name}
            value={mode}
            checked={value === mode}
            onChange={() => onChange(mode)}
          />
          {mode === "local" ? "Local" : "UTC"}
        </label>
      ))}
    </fieldset>
  );
}
