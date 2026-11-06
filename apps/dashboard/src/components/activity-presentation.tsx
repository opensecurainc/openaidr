"use client";

import type { ComponentProps, CSSProperties, ReactNode } from "react";
import { Check } from "lucide-react";
import { AgentLogo } from "@/components/agent-logo";
import { useTimeZone } from "@/components/time-zone-context";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CATEGORIES, LEGEND, type ActivityCategory } from "@/lib/activity";
import { productLabel } from "@/lib/api";
import { cn } from "@/lib/utils";

export function ActivitySessionButton({
  product, summary, metadata, status, current, recent, className, ...props
}: Omit<ComponentProps<"button">, "children"> & {
  product: string;
  summary: string;
  metadata: ReactNode;
  status?: ReactNode;
  current: boolean;
  recent?: boolean;
}) {
  return <button type="button" aria-current={current || undefined} {...props}
    className={cn(
      "block w-full min-w-0 px-4 py-2.5 text-left hover:bg-muted/50 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring",
      current && "bg-primary/5 shadow-[inset_3px_0_0_0_var(--primary)]",
      recent && !current && "live-row-new", className,
    )}>
    <span className="flex items-center gap-2">
      <AgentLogo product={product} />
      <span className="text-sm font-medium">{productLabel(product)}</span>
      {status}
    </span>
    <span className={cn("mt-0.5 block truncate text-sm", !summary && "text-muted-foreground")} title={summary || undefined}>
      {summary || "No prompt text"}
    </span>
    <span className="number mt-0.5 block text-xs text-muted-foreground">{metadata}</span>
  </button>;
}

export function ActivityCategoryFilters({ picked, onToggle, onReset }: {
  picked: Set<ActivityCategory>;
  onToggle: (category: ActivityCategory) => void;
  onReset: () => void;
}) {
  const filtering = picked.size > 0;
  return <div className="mt-2 flex flex-wrap items-center gap-2">
    <ul aria-label="Filter timeline by category" className="flex flex-wrap items-center gap-1.5">
      {LEGEND.map(category => {
        const on = picked.has(category);
        const { label, color } = CATEGORIES[category];
        return <li key={category}>
          <button type="button" aria-pressed={on} onClick={() => onToggle(category)}
            title={on ? `Stop showing only ${label}` : `Show ${label}`}
            className={cn("legend-chip", on && "legend-chip-on")}
            style={{ "--activity-color": color } as CSSProperties}>
            <span aria-hidden="true" className="flex size-3 items-center justify-center">
              {on ? <Check className="size-3" /> : <span className="size-3 rounded-full bg-current" />}
            </span>
            {label}
          </button>
        </li>;
      })}
    </ul>
    <Button variant="ghost" size="xs" className={cn("text-muted-foreground", !filtering && "invisible")}
      aria-hidden={!filtering} tabIndex={filtering ? 0 : -1} onClick={onReset}>Show all kinds</Button>
  </div>;
}

export function ActivityTimelineButton({
  category, at, toolName, summary, monospace, children, className, ...props
}: ComponentProps<"button"> & {
  category: ActivityCategory;
  at: string;
  toolName?: string;
  summary: string;
  monospace?: boolean;
}) {
  const { clockTime, dateTime } = useTimeZone();
  const { label, color } = CATEGORIES[category];
  return <button type="button" {...props}
    className={cn("flex w-full min-w-0 items-baseline gap-2 rounded-sm text-left focus-visible:outline-2 focus-visible:outline-ring", className)}
    style={{ "--activity-color": color } as CSSProperties}>
    <time dateTime={at} className="number w-20 shrink-0 text-xs text-muted-foreground" title={dateTime(at)}>{clockTime(at)}</time>
    <Badge variant="activity">{label}</Badge>
    {toolName && <span className="min-w-12 max-w-40 truncate text-sm font-medium" title={toolName}>{toolName}</span>}
    <span className={cn("min-w-0 flex-1 truncate text-sm text-muted-foreground", monospace && "font-mono text-xs")}>{summary}</span>
    {children}
  </button>;
}
