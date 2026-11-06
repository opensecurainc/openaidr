import * as React from "react";
import { cn } from "@/lib/utils";

const TONES = {
  critical: "bg-status-critical",
  warning: "bg-status-warning",
  ok: "bg-status-ok",
  info: "bg-status-info",
  neutral: "bg-status-neutral",
} as const;

export type StatusTone = keyof typeof TONES;

/**
 * State as a dot and a text label, with no container: online, active,
 * connected, delayed. The label carries the meaning; the dot only reinforces it.
 */
function Status({
  tone,
  pulse = false,
  dotSize = "sm",
  className,
  children,
  ...props
}: React.ComponentProps<"span"> & { tone: StatusTone; pulse?: boolean; dotSize?: "sm" | "lg" }) {
  return (
    <span
      data-slot="status"
      data-tone={tone}
      className={cn(
        "inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap text-foreground",
        className,
      )}
      {...props}
    >
      <span
        aria-hidden="true"
        className={cn(
          "shrink-0 rounded-full",
          dotSize === "lg" ? "size-3" : "size-2",
          TONES[tone],
          pulse && "motion-safe:animate-pulse",
        )}
      />
      {children}
    </span>
  );
}

export { Status };
