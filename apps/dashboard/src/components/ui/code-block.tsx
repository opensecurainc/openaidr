"use client";

import * as React from "react";
import { CopyButton } from "@/components/ui/copy-button";
import { cn } from "@/lib/utils";

/**
 * Commands, payloads, and file contents. The only place, with InlineCode,
 * where the monospace face appears. Overflow scrolls inside the block.
 */
function CodeBlock({
  className,
  lines,
  copyText,
  copyLabel,
  style,
  ...props
}: Omit<React.ComponentProps<"pre">, "ref"> & {
  /** Clamp to this many lines. The clamp sits inside the padding so no partial line shows. */
  lines?: number;
  /** The complete stored value when the displayed excerpt has been formatted or trimmed. */
  copyText?: string;
  copyLabel?: string;
}) {
  const content = React.useRef<HTMLPreElement>(null);
  return (
    <div
      data-slot="code-block"
      className={cn(
        "relative flex min-h-10 min-w-0 max-w-full flex-col rounded-md bg-muted py-2 pr-12 pl-3 font-mono text-xs leading-5 whitespace-pre-wrap break-words text-foreground",
        className,
      )}
    >
      <pre
        ref={content}
        tabIndex={0}
        className={cn(
          "min-h-0 font-[inherit] [white-space:inherit] [overflow-wrap:inherit] [word-break:inherit] focus-visible:outline-2 focus-visible:outline-ring",
          lines ? "overflow-hidden" : "overflow-auto",
        )}
        style={lines ? {
          display: "-webkit-box",
          WebkitBoxOrient: "vertical",
          WebkitLineClamp: lines,
          ...style,
        } : style}
        {...props}
      />
      <CopyButton
        className="absolute top-2 right-2"
        text={copyText ?? (() => content.current?.textContent ?? "")}
        label={copyLabel}
      />
    </div>
  );
}

/** Hashes, identifiers, and paths shown on their own, never inside a sentence of metadata. */
function InlineCode({ className, ...props }: React.ComponentProps<"code">) {
  return (
    <code
      data-slot="inline-code"
      className={cn(
        "rounded-sm bg-muted px-1 font-mono text-xs text-foreground",
        className,
      )}
      {...props}
    />
  );
}

export { CodeBlock, InlineCode };
