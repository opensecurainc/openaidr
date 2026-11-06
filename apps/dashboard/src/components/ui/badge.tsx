import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
import { Slot } from "radix-ui";

// Badges classify; they are never clickable. Neutral is the default. Tones are
// used for severity, verdicts, and activity categories, with a text label.
const badgeVariants = cva(
  "inline-flex h-5 w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-sm border border-transparent px-1.5 text-xs font-medium whitespace-nowrap focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring focus-visible:ring-offset-2 [&>svg]:pointer-events-none [&>svg]:size-3",
  {
    variants: {
      variant: {
        default: "bg-muted text-foreground",
        secondary: "bg-muted text-foreground",
        outline: "border-border text-foreground",
        activity:
          "bg-[color:var(--activity-color)] text-primary-foreground",
        // Severity of a finding: the severity palette (COLORS.md). A solid
        // swatch in the exact chart color leads the readable tinted label.
        critical:
          "bg-severity-critical/12 text-severity-critical-text before:size-2 before:rounded-xs before:bg-severity-critical before:content-['']",
        high: "bg-severity-high/12 text-severity-high-text before:size-2 before:rounded-xs before:bg-severity-high before:content-['']",
        medium:
          "bg-severity-medium/12 text-severity-medium-text before:size-2 before:rounded-xs before:bg-severity-medium before:content-['']",
        low: "bg-severity-low/12 text-severity-low-text before:size-2 before:rounded-xs before:bg-severity-low before:content-['']",
        // Informational severity; distinct from the status "info" tone below.
        informational:
          "bg-severity-info/12 text-severity-info-text before:size-2 before:rounded-xs before:bg-severity-info before:content-['']",
        // State of a thing: the status palette.
        destructive: "bg-status-critical/10 text-status-critical",
        warning: "bg-status-warning/10 text-status-warning",
        ok: "bg-status-ok/10 text-status-ok",
        info: "bg-status-info/10 text-status-info",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

function Badge({
  className,
  variant = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot.Root : "span";

  return (
    <Comp
      data-slot="badge"
      data-variant={variant}
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  );
}

export { Badge, badgeVariants };
