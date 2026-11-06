"use client";

import { useTimeZone } from "@/components/time-zone-context";
import type { ReactNode } from "react";

export function TimeAxisTick({
  x = 0,
  y = 0,
  payload,
  start,
  end,
  daily = false,
  stacked = false,
}: {
  x?: number;
  y?: number;
  payload?: { value: number };
  start: number;
  end: number;
  daily?: boolean;
  stacked?: boolean;
}) {
  const { chartTimeTick, timeZone } = useTimeZone();
  if (!payload) return null;
  const date = new Date(payload.value);
  return (
    <text
      x={x}
      y={y + 12}
      textAnchor={
        payload.value === start
          ? "start"
          : payload.value === end
            ? "end"
            : "middle"
      }
      className="recharts-cartesian-axis-tick-value number"
    >
      {stacked && !daily ? (
        <>
          <tspan x={x}>
            {date.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone })}
          </tspan>
          <tspan x={x} dy={14}>
            {date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone })}
          </tspan>
        </>
      ) : chartTimeTick(payload.value, daily)}
    </text>
  );
}

export function ChartReadout({
  timestamp,
  rows,
  children,
}: {
  timestamp: string;
  rows: { label: string; value: string; color: string; dash?: string }[];
  children?: ReactNode;
}) {
  return (
    <div className="max-w-64 rounded-lg border border-border bg-popover px-3 py-2 text-xs shadow-overlay">
      <p className="mb-1 text-muted-foreground">{timestamp}</p>
      <ul className="space-y-1">
        {rows.map((row) => (
          <li
            key={row.label}
            className="flex items-center justify-between gap-3"
          >
            <span className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
              <svg
                aria-hidden="true"
                className="h-3 w-4 shrink-0"
                viewBox="0 0 16 12"
              >
                <line
                  x1="0"
                  x2="16"
                  y1="6"
                  y2="6"
                  stroke={row.color}
                  strokeWidth={2}
                  strokeDasharray={row.dash}
                />
              </svg>
              {row.label}
            </span>
            <span className="number text-sm font-medium">{row.value}</span>
          </li>
        ))}
      </ul>
      {children && <div className="mt-1 text-muted-foreground">{children}</div>}
    </div>
  );
}

export function SampleMarker({
  cx,
  cy,
  show,
  color,
}: {
  cx?: number;
  cy?: number;
  show: boolean;
  color: string;
}) {
  return show && cx != null && cy != null ? (
    <circle
      cx={cx}
      cy={cy}
      r={3}
      stroke={color}
      strokeWidth={2}
      fill="var(--card)"
    />
  ) : (
    <g />
  );
}
