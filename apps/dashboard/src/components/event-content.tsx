"use client";

import { useId, useState } from "react";
import { ChevronRight } from "lucide-react";
import { CodeBlock } from "@/components/ui/code-block";
import { Button } from "@/components/ui/button";
import { binaryContent, contentLine, downloadRaw, firstLine } from "@/lib/event-content";
import { cn } from "@/lib/utils";

/** Lines an expanded excerpt shows before "Show all". */
const EXPANDED_LINES = 12;
/** A single line longer than this wraps when expanded instead of being cut off. */
const LONG_LINE = 120;

/**
 * A command, payload, or output as one summary line that expands in place to
 * a clamped code block, then to the full content. Binary or encoded content
 * is described ("PNG image, 18 KB"), never shown as text.
 */
export function EventContent({
  text,
  label,
  truncated = false,
  notes = [],
  className,
}: {
  text: string;
  /** What the content is, for the toggle's accessible name ("command", "output"). */
  label: string;
  /** The sensor kept only a prefix of some field of this event. */
  truncated?: boolean;
  /** Event-level collection notices, from `collectionNotes`. */
  notes?: string[];
  className?: string;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [all, setAll] = useState(false);
  const binary = binaryContent(text, truncated);
  const notice = notes.length > 0 && (
    <p className="mt-1 text-xs text-muted-foreground">{notes.join(" ")}</p>
  );
  if (binary)
    return (
      <div className={cn("min-w-0", className)}>
        <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          {binary}
          <Button variant="ghost" size="xs" onClick={() => downloadRaw(text, `${label}.txt`)}>
            Download raw output
          </Button>
        </p>
        {notice}
      </div>
    );
  const { line, more } = firstLine(text);
  // A short single line is shown whole, wrapping if it must, so nothing is hidden.
  if (!more && line.length <= LONG_LINE)
    return (
      <div className={cn("min-w-0", className)}>
        <CodeBlock copyText={text}>{text.trim()}</CodeBlock>
        {notice}
      </div>
    );
  const summary = contentLine(text, truncated);
  const total = more + 1;
  return (
    <div className={cn("min-w-0", className)}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        aria-label={`${open ? "Collapse" : "Expand"} ${label}: ${summary}${more ? `, ${total} lines` : ""}`}
        onClick={() => {
          setOpen((value) => !value);
          setAll(false);
        }}
        className="flex w-full min-w-0 items-center gap-1.5 rounded-md text-left focus-visible:outline-2 focus-visible:outline-ring"
      >
        <ChevronRight
          aria-hidden="true"
          className={cn("size-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
        />
        <span className="min-w-0 truncate font-mono text-xs">{summary}</span>
      </button>
      {open && (
        <div id={id} className="mt-1.5">
          <CodeBlock copyText={text} lines={all || total <= EXPANDED_LINES ? undefined : EXPANDED_LINES}>{text.replace(/^\s*\n/, "").trimEnd()}</CodeBlock>
          {total > EXPANDED_LINES && (
            <Button variant="ghost" size="xs" className="mt-1" onClick={() => setAll((value) => !value)}>
              {all ? "Show fewer lines" : `Show all ${total} lines`}
            </Button>
          )}
          {notice}
        </div>
      )}
    </div>
  );
}
