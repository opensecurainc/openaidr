"use client";

import {
  SEVERITY_ORDER,
  severityLabel,
  type Severity,
} from "@/components/ui/severity-mark";
import { cn } from "@/lib/utils";

/** Chart fills use the same severity tokens as badges and letter marks. */
export const SEVERITY_FILL: Record<Severity, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  info: "var(--severity-info)",
};

/**
 * A visible key for severity bars that have no counts of their own to label.
 * Pass `info` when any bar it explains has an informational segment.
 */
export function SeverityKey({
  className,
  info = false,
}: {
  className?: string;
  info?: boolean;
}) {
  return (
    <ul
      aria-label="Severity key"
      className={cn("flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground", className)}
    >
      {SEVERITY_ORDER.filter((severity) => info || severity !== "info").map((severity) => (
        <li key={severity} className="flex items-center gap-1.5">
          <span
            aria-hidden="true"
            className="size-2.5 rounded-sm"
            style={{ background: SEVERITY_FILL[severity] }}
          />
          {severityLabel(severity)}
        </li>
      ))}
    </ul>
  );
}
