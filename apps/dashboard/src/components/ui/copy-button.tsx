"use client";

import { useEffect, useId, useRef, useState } from "react";
import { Check, Copy, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function CopyButton({ text, label = "Copy text", className }: {
  text: string | (() => string);
  label?: string;
  className?: string;
}) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const statusId = useId();
  useEffect(() => () => clearTimeout(timer.current), []);
  const message = status === "copied" ? "Copied" : status === "failed"
    ? "Copy failed. Select the text and copy it manually." : "";

  async function copy() {
    clearTimeout(timer.current);
    try {
      await navigator.clipboard.writeText(typeof text === "function" ? text() : text);
      setStatus("copied");
      timer.current = setTimeout(() => setStatus("idle"), 2000);
    } catch {
      setStatus("failed");
    }
  }

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-xs"
      className={cn("font-sans", status === "failed" && "text-destructive", className)}
      aria-label={label}
      aria-describedby={statusId}
      title={message || label}
      onClick={() => void copy()}
    >
      {status === "copied" ? <Check aria-hidden="true" /> : status === "failed"
        ? <TriangleAlert aria-hidden="true" /> : <Copy aria-hidden="true" />}
      <span id={statusId} role="status" className="sr-only">{message}</span>
    </Button>
  );
}
