"use client";

import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

// A review-board card: the header row is the solid status fill with white
// text, an icon, and a count pill; the border repeats the fill; the body is a
// capped, keyboard-focusable scroll region (DESIGN.md, Approval groups).
const tones = {
  critical: { header: "bg-status-critical", card: "border-status-critical" },
  warning: { header: "bg-status-warning", card: "border-status-warning" },
  ok: { header: "bg-status-ok", card: "border-status-ok" },
  info: { header: "bg-status-info", card: "border-status-info" },
  neutral: { header: "bg-status-neutral", card: "border-status-neutral" },
} as const;
export type ReviewTone = keyof typeof tones;

/** Sticky column headers inside a review card body. */
export const reviewTableHeader =
  "[&_th]:sticky [&_th]:top-0 [&_th]:z-10 [&_th]:bg-muted [&_th]:shadow-[inset_0_-1px_0_var(--border)]";
/** Edge-to-edge table whose first and last columns align with the card text. */
export const reviewTable =
  "[&_:is(th,td):first-child]:pl-4 [&_:is(th,td):last-child]:pr-4";

export function ReviewCard({
  tone,
  icon: Icon,
  title,
  count,
  label = title,
  stacked,
  subheader,
  className,
  children,
}: {
  tone: ReviewTone;
  icon: LucideIcon;
  title: string;
  /** Count pill text, such as "4 components". */
  count?: ReactNode;
  /** Accessible section name when the title alone is ambiguous. */
  label?: string;
  /** Stacked cards share one column beside the queue: the top card keeps a
   *  short list and the bottom card fills the remaining column height. */
  stacked?: "top" | "bottom";
  /** One compact line between the header and the body. */
  subheader?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section
      aria-label={label}
      className={cn(
        "flex min-w-0 flex-col",
        stacked === "top" && "shrink-0",
        stacked === "bottom" && "min-h-0 flex-1",
        className,
      )}
    >
      <Card
        className={cn("min-h-0 flex-1 overflow-hidden", tones[tone].card)}
      >
        <div
          data-slot="review-card-header"
          className={cn(
            "flex items-center justify-between gap-2 px-4 py-1.5 text-primary-foreground",
            tones[tone].header,
          )}
        >
          <h3 className="flex items-center gap-2 text-base font-semibold">
            <Icon aria-hidden="true" className="size-4" />
            {title}
          </h3>
          {count !== undefined && (
            <span className="number rounded-sm bg-primary-foreground/20 px-2 py-0.5 text-xs font-medium whitespace-nowrap">
              {count}
            </span>
          )}
        </div>
        {subheader && (
          <div className="border-b px-4 py-1.5 text-xs text-muted-foreground">
            {subheader}
          </div>
        )}
        <div
          data-slot="review-card-body"
          role="region"
          aria-label={`${label} list`}
          tabIndex={0}
          className={cn(
            "min-h-0 flex-1 overflow-auto overscroll-contain focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring",
            stacked === "top"
              ? "max-h-[min(28rem,60dvh)] md:max-h-[min(14rem,30dvh)]"
              : stacked === "bottom"
                ? "max-h-[min(28rem,60dvh)] md:max-h-none"
                : "max-h-[min(28rem,60dvh)]",
          )}
        >
          {children}
        </div>
      </Card>
    </section>
  );
}
