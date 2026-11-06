import * as React from "react";
import { cn } from "@/lib/utils";

export const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

const MARKS: Record<Severity, { letter: string; label: string; className: string }> = {
  critical: {
    letter: "C",
    label: "Critical",
    className: "bg-severity-critical text-severity-critical-on",
  },
  high: {
    letter: "H",
    label: "High",
    className: "bg-severity-high text-severity-high-on",
  },
  medium: {
    letter: "M",
    label: "Medium",
    className: "bg-severity-medium text-severity-medium-on",
  },
  low: {
    letter: "L",
    label: "Low",
    className: "bg-severity-low text-severity-low-on",
  },
  info: {
    letter: "I",
    label: "Info",
    className: "bg-severity-info text-severity-info-on",
  },
};

export function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(value);
}

export function severityLabel(value: string) {
  return isSeverity(value) ? MARKS[value].label : value;
}

/**
 * A count with a one-letter severity mark, for dense rows: "2 (C)". The
 * accessible name spells the severity out, so the letter never stands alone.
 */
function SeverityMark({
  severity,
  count,
  className,
}: {
  severity: Severity;
  count?: number;
  className?: string;
}) {
  const mark = MARKS[severity];
  const name =
    count === undefined ? mark.label : `${count.toLocaleString()} ${mark.label.toLowerCase()}`;
  return (
    <span
      data-slot="severity-mark"
      role="img"
      aria-label={name}
      title={name}
      className={cn("inline-flex items-center gap-1 text-sm", className)}
    >
      {count !== undefined && (
        <span className="number font-medium">{count.toLocaleString()}</span>
      )}
      <span
        aria-hidden="true"
        className={cn(
          "inline-flex size-5 items-center justify-center rounded-sm text-xs font-semibold",
          mark.className,
        )}
      >
        {mark.letter}
      </span>
    </span>
  );
}

/** Nonzero severity counts, most severe first. Renders nothing when all are zero. */
function SeverityCounts({
  counts,
  className,
}: {
  counts: Partial<Record<Severity, number>>;
  className?: string;
}) {
  const shown = SEVERITY_ORDER.filter((severity) => (counts[severity] ?? 0) > 0);
  if (!shown.length) return null;
  return (
    <span
      className={cn("inline-flex flex-wrap items-center gap-x-3 gap-y-1", className)}
    >
      {shown.map((severity) => (
        <SeverityMark key={severity} severity={severity} count={counts[severity]} />
      ))}
    </span>
  );
}

export { SeverityMark, SeverityCounts };
