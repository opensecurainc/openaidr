/**
 * One-line summaries of agent event content, and recognition of content that
 * is not text. Lists show `contentLine`; the full content opens on demand
 * (apps/dashboard/DESIGN.md, Activity views).
 */

/** Binary or encoded payloads, by the leading characters of their base64. */
const SIGNATURES: [prefix: string, label: string][] = [
  ["iVBORw0KGgo", "PNG image"],
  ["/9j/", "JPEG image"],
  ["R0lGOD", "GIF image"],
  ["JVBERi0", "PDF document"],
  ["UEsDB", "ZIP archive"],
  ["H4sI", "gzip archive"],
];

const BASE64_RUN = /[A-Za-z0-9+/]{200,}={0,2}/;
/** One line of wrapped base64, as `base64` and PEM-style encoders write it (64 or 76 columns). */
const BASE64_LINE = /^[A-Za-z0-9+/]+={0,2}$/;
/** Line widths that encoders wrap at: PEM (64) and `base64` (76). */
const ENCODER_WIDTHS = [64, 76];
/** A whole payload of bare base64, which a known file signature identifies at any length. */
const BASE64_WHOLE = /^[A-Za-z0-9+/]{16,}={0,2}$/;
/** Serialized field keys around an encoded payload, as in `{"data": "..."}`: a quoted name followed by a colon. */
const QUOTED_NAME = /("[\w.-]*"|'[\w.-]*')\s*:/g;
/** What remains of a data envelope once its field names are removed: quotes, JSON punctuation, whitespace. */
const ENVELOPE = /^[\s"'{}[\]:,]{0,200}$/;
/** The last wrapped line, which can be as short as one 4-character group. */
const BASE64_LAST_LINE = /^[A-Za-z0-9+/]{2,}={0,2}$/;
// CSI parameter bytes are 0x30 to 0x3F, which includes colon-form colors (ESC[38:2::255:0:0m).
// eslint-disable-next-line no-control-regex
const ANSI = /\u001b\[[0-?]*[ -/]*[@-~]|\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g;

function sizeLabel(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** RIFF is a container for WebP, WAV, and AVI; only the format marker at bytes 8 to 11 tells them apart. */
function riffLabel(clean: string) {
  try {
    const format = atob(clean.slice(0, 16)).slice(8, 12);
    return format === "WEBP" ? "WebP image" : format === "WAVE" ? "WAV audio" : format === "AVI " ? "AVI video" : "RIFF data";
  } catch {
    return "RIFF data";
  }
}

/** "PNG image, 18 KB", or the captured size when the sensor truncated the event. */
function describe(label: string, bytes: number, truncated: boolean) {
  return `${label}, ${sizeLabel(bytes)}${truncated ? " captured" : ""}`;
}

function describeBase64(data: string, kind: string | undefined, truncated: boolean) {
  const clean = data.replace(/\s+/g, "");
  const signature = SIGNATURES.find(([prefix]) => clean.startsWith(prefix));
  const label = clean.startsWith("UklGR")
    ? riffLabel(clean)
    : signature?.[1] ?? (kind === "image" ? "Image" : "Binary data");
  const bytes = Math.floor((clean.replace(/=+$/, "").length * 3) / 4);
  return describe(label, bytes, truncated);
}

/**
 * A short description ("PNG image, 18 KB") when `text` is binary or encoded
 * content that must not be shown as text, else null. Recognizes agent image
 * results (`{"type":"image","file":{"base64":...}}`), data URIs, long base64
 * runs, and text with control characters. `truncated` is the event's
 * collection-time truncation flag.
 */
export function binaryContent(text: string | undefined | null, truncated = false): string | null {
  if (!text) return null;
  const trimmed = text.trim();
  if (trimmed.startsWith("{") && trimmed.includes("base64")) {
    try {
      const value = JSON.parse(trimmed) as {
        type?: string;
        file?: { base64?: string; type?: string };
        source?: { data?: string; media_type?: string };
      };
      const data = value.file?.base64 ?? value.source?.data;
      if (typeof data === "string" && data.length)
        return describeBase64(data, value.type, truncated);
    } catch {
      // The sensor clips oversized output at max_text_bytes, which leaves
      // invalid JSON; the wrapper's payload field is still recognizable.
      const data = /"(?:base64|data)"\s*:\s*"([A-Za-z0-9+/]{16,}={0,2})/.exec(trimmed)?.[1];
      if (data)
        return describeBase64(data, /"type"\s*:\s*"image"/.test(trimmed) ? "image" : undefined, truncated);
    }
  }
  // A small file returned as bare base64 is identified by its signature.
  if (BASE64_WHOLE.test(trimmed) && SIGNATURES.some(([prefix]) => trimmed.startsWith(prefix)))
    return describeBase64(trimmed, undefined, truncated);
  if (BASE64_WHOLE.test(trimmed) && trimmed.startsWith("UklGR") && riffLabel(trimmed) !== "RIFF data")
    return describeBase64(trimmed, undefined, truncated);
  // The media type is optional, and parameters may precede the encoding:
  // data:;base64,... and data:image/png;name=a.png;base64,...
  const uri = /^data:([\w./+-]*)(?:;[\w.+-]+=[^;,]*)*;base64,([A-Za-z0-9+/=\s]+)$/.exec(trimmed);
  if (uri) return describeBase64(uri[2], uri[1].startsWith("image/") ? "image" : undefined, truncated);
  // A base64 run is the whole payload only inside a data envelope (quotes,
  // JSON punctuation, field names). Shell syntax around it, as in
  // `printf ... | base64 -d | sh`, is evidence and stays readable.
  const run = BASE64_RUN.exec(trimmed);
  if (run && run[0].length > trimmed.length / 2 && ENVELOPE.test(trimmed.replace(run[0], "").replace(QUOTED_NAME, "")))
    return describeBase64(run[0], undefined, truncated);
  // Base64 wrapped at a fixed width: three or more lines that are all base64
  // and together long enough to be a payload rather than an identifier.
  const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (
    lines.length >= 3 &&
    // Every line but the last has the encoder's width, so lists of hashes or
    // identifiers of another fixed length stay text.
    ENCODER_WIDTHS.includes(lines[0].length) &&
    lines.slice(0, -1).every((line) => line.length === lines[0].length && BASE64_LINE.test(line)) &&
    lines[lines.length - 1].length <= lines[0].length &&
    BASE64_LAST_LINE.test(lines[lines.length - 1]) &&
    lines.reduce((total, line) => total + line.length, 0) >= 200
  )
    return describeBase64(lines.join(""), undefined, truncated);
  // Terminal colors are text formatting, not binary content.
  const plain = trimmed.replace(ANSI, "");
  // eslint-disable-next-line no-control-regex
  const control = plain.match(/[\u0000-\u0008\u000e-\u001f]/g)?.length ?? 0;
  if (control > 8 && control > plain.length / 100)
    return describe("Binary data", trimmed.length, truncated);
  return null;
}

/** The first non-empty line and how many more lines follow it. */
export function firstLine(text: string) {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const start = lines.findIndex((line) => line.trim());
  if (start < 0) return { line: "", more: 0 };
  const rest = lines.slice(start + 1);
  while (rest.length && !rest[rest.length - 1].trim()) rest.pop();
  return { line: lines[start].trim(), more: rest.length };
}

/** Characters of a first line kept in a summary, which also serves as a tooltip and accessible name. */
const SUMMARY_CHARS = 200;

/**
 * Everything a list row needs from one piece of content, computed once: the
 * binary description when it is not text, else the first line, bounded to
 * SUMMARY_CHARS, with a "+N lines" count.
 */
export function summarize(text: string | undefined | null, truncated = false) {
  if (!text) return { line: "", binary: null as string | null, more: 0 };
  const binary = binaryContent(text, truncated);
  if (binary) return { line: binary, binary, more: 0 };
  const first = firstLine(text);
  const more = first.more;
  const line = first.line.length > SUMMARY_CHARS ? `${first.line.slice(0, SUMMARY_CHARS)}…` : first.line;
  return {
    line: more ? `${line} +${more} ${more === 1 ? "line" : "lines"}` : line,
    binary: null as string | null,
    more,
  };
}

/** One line for a list row: a binary description, or the first line with "+N lines". */
export function contentLine(text: string | undefined | null, truncated = false) {
  return summarize(text, truncated).line;
}

/** Save stored content exactly as received, for binary output that is never shown as text. */
export function downloadRaw(text: string, name: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

type EventFields = { text?: unknown; truncated?: unknown; tool?: { output?: unknown } };

/** The event's binary or encoded text fields, with their descriptions, for detail views. */
export function binaryFields(event: EventFields) {
  const fields: { name: "text" | "output"; raw: string; binary: string }[] = [];
  for (const [name, raw] of [["text", event.text], ["output", event.tool?.output]] as const) {
    const binary = typeof raw === "string" ? binaryContent(raw, event.truncated === true) : null;
    if (binary) fields.push({ name, raw: raw as string, binary });
  }
  return fields;
}

/** A copy of an event with binary text and output replaced by their descriptions, for detail views. */
export function withoutBinary<T extends EventFields>(event: T): T {
  let copy = event;
  for (const { name, binary } of binaryFields(event))
    copy =
      name === "text"
        ? { ...copy, text: `[${binary}]` }
        : { ...copy, tool: { ...copy.tool, output: `[${binary}]` } };
  return copy;
}

/**
 * Event-level notices for what the sensor changed at collection. `truncated`
 * and `redacted` describe the event, not a particular field.
 */
export function collectionNotes(record: object) {
  const event = record as { truncated?: unknown; redacted?: unknown };
  const notes: string[] = [];
  if (event.truncated === true) notes.push("Truncated at collection: stored values may be a prefix.");
  if (event.redacted === true) notes.push("Redacted at collection: matching values were replaced.");
  return notes;
}
