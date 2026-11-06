import type { ComponentProps } from "react";
import { ChevronDownIcon } from "lucide-react";
import { cn } from "@/lib/utils";

function NativeSelect({
  className,
  variant = "default",
  ...props
}: ComponentProps<"select"> & { variant?: "default" | "form" | "inline" }) {
  return (
    <span className={cn("relative inline-flex max-w-full min-w-0 items-center", className)}>
      <select
        data-slot="native-select"
        className={cn(
          "h-9 w-full min-w-0 appearance-none rounded-md border border-input bg-background pl-3 pr-9 text-sm outline-offset-2 focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-50",
          variant === "form" && "h-10",
          variant === "inline" && "border-0 bg-transparent pl-0 sm:h-7",
        )}
        {...props}
      />
      <ChevronDownIcon aria-hidden="true" className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground opacity-50" />
    </span>
  );
}

export { NativeSelect };
