"use client";

import { useId } from "react";
import { cn } from "@/lib/utils";

/** Uses the same sliding selection and native radios as TimeZoneControl. */
export function TimeRangeControl<T extends string>({
  value,
  onChange,
  options,
}: {
  value: T;
  onChange: (value: T) => void;
  options: readonly (readonly [T, string])[];
}) {
  const name = useId();
  return (
    <fieldset
      aria-label="Time range"
      className="relative isolate grid h-10 w-full min-w-0 text-xs font-medium sm:h-8 sm:w-[28rem] sm:text-sm"
      style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }}
    >
      <legend className="sr-only">Time range</legend>
      <span aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10 rounded-md border border-input bg-card">
        <span
          className="absolute inset-y-[3px] left-[3px] rounded-sm bg-primary transition-transform motion-reduce:transition-none"
          style={{
            width: `calc((100% - 6px) / ${options.length})`,
            transform: `translateX(${options.findIndex(([option]) => option === value) * 100}%)`,
          }}
        />
      </span>
      {options.map(([option, label]) => (
        <label
          key={option}
          className={cn(
            "relative flex cursor-pointer items-center justify-center rounded-md px-1 text-center select-none has-focus-visible:outline-3 has-focus-visible:outline-offset-2 has-focus-visible:outline-ring",
            option === value ? "text-primary-foreground" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <input
            className="absolute inset-0 size-full cursor-pointer opacity-0"
            type="radio"
            name={name}
            value={option}
            checked={value === option}
            onChange={() => onChange(option)}
          />
          {label}
        </label>
      ))}
    </fieldset>
  );
}
