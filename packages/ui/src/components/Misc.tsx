import { useEffect, useState } from "react";
import { useClipboard } from "../hooks/useClipboard";
import { formatDateTime, relative } from "../utils/format";
import { Button } from "./Form";
import { IconCheck, IconCopy } from "./icons";

export function RelativeTime({ value, tick = 30_000 }: { value: string | null | undefined; tick?: number }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const id = setInterval(() => setNow(Date.now()), tick); return () => clearInterval(id); }, [tick]);
  if (!value) return <span className="muted">never</span>;
  return <time dateTime={value} title={formatDateTime(value)}>{relative(value, now)}</time>;
}

export function DateTime({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="muted">none</span>;
  return <time dateTime={value} className="nowrap">{formatDateTime(value)}</time>;
}

export function JsonView({ value, small }: { value: unknown; small?: boolean }) {
  let text: string;
  if (typeof value === "string") { try { text = JSON.stringify(JSON.parse(value), null, 2); } catch { text = value; } }
  else text = JSON.stringify(value, null, 2) ?? "";
  return <pre className={`json${small ? " json--sm" : ""}`}><code>{text}</code></pre>;
}

export function CopyField({ value, label, mono = true }: { value: string; label?: string; mono?: boolean }) {
  const [copied, copy] = useClipboard();
  return (
    <div className="copy">
      <input className={`input${mono ? " input--mono" : ""}`} readOnly value={value} aria-label={label ?? "Value"} onFocus={(e) => e.currentTarget.select()} />
      <Button onClick={() => void copy(value)} icon={copied ? <IconCheck /> : <IconCopy />} aria-label={copied ? "Copied" : "Copy"}>{copied ? "Copied" : "Copy"}</Button>
    </div>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, copy] = useClipboard();
  return <Button size="sm" onClick={() => void copy(value)} icon={copied ? <IconCheck /> : <IconCopy />}>{copied ? "Copied" : label}</Button>;
}

export function Code({ children }: { children: string }) {
  return <pre className="code"><code>{children}</code></pre>;
}
