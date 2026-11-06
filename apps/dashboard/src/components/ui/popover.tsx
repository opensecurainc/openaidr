"use client";

import * as React from "react";
import { Popover as PopoverPrimitive } from "radix-ui";
import { cn } from "@/lib/utils";

const Popover = PopoverPrimitive.Root;
const PopoverTrigger = PopoverPrimitive.Trigger;
const PopoverAnchor = PopoverPrimitive.Anchor;
const PopoverClose = PopoverPrimitive.Close;

function PopoverContent({
  className,
  align = "end",
  sideOffset = 8,
  variant = "default",
  ...props
}: React.ComponentProps<typeof PopoverPrimitive.Content> & {
  variant?: "default" | "readout";
}) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        data-slot="popover-content"
        align={align}
        sideOffset={sideOffset}
        collisionPadding={16}
        className={cn(
          "z-50 max-w-[calc(100vw-2rem)] outline-none",
          variant === "default" &&
            "max-h-[var(--radix-popover-content-available-height)] w-80 overflow-y-auto rounded-lg border border-border bg-popover p-4 text-sm text-popover-foreground shadow-overlay",
          className,
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  );
}

export { Popover, PopoverAnchor, PopoverTrigger, PopoverContent, PopoverClose };
