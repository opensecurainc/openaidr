import type { ComponentProps, ReactNode } from "react";
import { cn } from "@/lib/utils";

/** Interactive data marks in a flow diagram, not nested content cards. */
export function FlowNode({
  label,
  detail,
  count,
  selected = false,
  compact = false,
  className,
  ...props
}: Omit<ComponentProps<"button">, "children"> & {
  label: ReactNode;
  detail?: string;
  count?: number;
  selected?: boolean;
  compact?: boolean;
}) {
  return (
    <button
      type="button"
      title={typeof label === "string" ? label : undefined}
      aria-pressed={selected}
      data-slot="flow-node"
      className={cn(
        "flex w-full items-center justify-between gap-2 rounded-md border border-input bg-card px-3 text-left text-sm text-foreground outline-none hover:bg-accent focus-visible:ring-[3px] focus-visible:ring-ring focus-visible:ring-offset-2",
        compact ? "min-h-10 py-2" : "min-h-16 py-3",
        selected && "border-primary bg-accent ring-1 ring-primary",
        className,
      )}
      {...props}
    >
      <span className="min-w-0">
        <span className="block truncate font-medium">{label}</span>
        {detail && (
          <span
            className="mt-1 block truncate text-xs text-muted-foreground"
            title={detail}
          >
            {detail}
          </span>
        )}
      </span>
      {count !== undefined && (
        <span className="number shrink-0 font-semibold">
          {count.toLocaleString()}
        </span>
      )}
    </button>
  );
}

/** A neutral group and shared ports keep paths distinct from decision nodes. */
export function FlowGate({ children, ...props }: ComponentProps<"div">) {
  return (
    <div
      className="relative w-full space-y-3 rounded-md bg-muted p-3 text-sm"
      {...props}
    >
      <span
        aria-hidden="true"
        className="absolute top-1/2 -left-1 size-2 -translate-y-1/2 rounded-full bg-muted-foreground"
      />
      {children}
      <span
        aria-hidden="true"
        className="absolute top-1/2 -right-1 size-2 -translate-y-1/2 rounded-full bg-muted-foreground"
      />
    </div>
  );
}
