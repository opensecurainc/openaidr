"use client";

import { useTimeZone } from "@/components/time-zone-context";
import { useEffect, useId, useRef, useState } from "react";
import { ChevronRight } from "lucide-react";
import { EventContent } from "@/components/event-content";
import { EventSourceBadge } from "@/components/telemetry-panels";
import { CollectionFooter, EmptyState, ErrorState, LoadingState, PageNotice, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { CodeBlock, InlineCode } from "@/components/ui/code-block";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { AgentEvent } from "@/lib/api";
import { displayText } from "@/lib/display";
import { collectionNotes } from "@/lib/event-content";
import { humanize, objectValue, storedCount, textValue, type JsonObject, type RetainedRead, type SessionSelection, type SnapshotItem, type SnapshotPage } from "@/lib/session";
import { useResource } from "@/lib/use-resource";
import { cn } from "@/lib/utils";

/** Safe text only. Metadata stays inspectable without making JSON the main UI. */
export function RetainedRecord({ body, label = "Retained record", metadata = body, projected = false }: { body: JsonObject; label?: string; metadata?: JsonObject; projected?: boolean }) {
  const { dateTime } = useTimeZone();
  const event = (objectValue(body.target_body) ?? body) as Partial<AgentEvent>;
  const value = event.text ?? event.command?.text ?? event.tool?.output ?? event.tool?.input ?? event.file?.path ?? event.network?.url;
  const content = typeof value === "string" ? value : value == null ? null : JSON.stringify(value, null, 2);
  return <div className="min-w-0 space-y-2" data-page-chat-exclude>
    <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      <span>{humanize(event.kind)}</span>
      {event.time && <span>{dateTime(event.time)}</span>}
      {event.kind && <EventSourceBadge event={event} />}
      {event.tool?.name && <span>{event.tool.name}</span>}
    </div>
    {content !== null ? <section aria-label={label}><EventContent text={content} label={label} truncated={event.truncated === true} notes={collectionNotes(event)} /></section> :
      <p className="text-sm text-muted-foreground">Content is not present in this retained record.</p>}
    <details className="text-sm">
      <summary className="w-fit cursor-pointer rounded-sm py-2 font-medium focus-visible:outline-2 focus-visible:outline-ring">{projected ? "Assessment view metadata" : "Full retained metadata"}</summary>
      <EventContent text={JSON.stringify(metadata, null, 2)} label={`${label} metadata`} />
    </details>
  </div>;
}

function SnapshotRow({ item, selection }: { item: SnapshotItem; selection: SessionSelection }) {
  const matched = selection.ordinal === item.ordinal;
  const [open, setOpen] = useState(matched);
  const id = useId();
  const ref = useRef<HTMLLIElement>(null);
  const scrolled = useRef(false);
  useEffect(() => {
    if (matched && !scrolled.current) {
      scrolled.current = true;
      setOpen(true);
      ref.current?.scrollIntoView({ block: "nearest", behavior: "instant" });
    }
  }, [matched]);
  const event = objectValue(item.body.target_body) ?? item.body;
  const projected = item.representation === "customer_service_metadata_v1";
  return <li ref={ref} id={`snapshot-record-${item.ordinal}`} aria-current={matched ? "true" : undefined}
    className={cn("min-w-0 py-3", matched && "border-l-[3px] border-primary bg-primary/5 pl-3")}
    data-page-chat-exclude>
    <button type="button" aria-expanded={open} aria-controls={id}
      aria-label={`${open ? "Collapse" : "Expand"} snapshot record ${item.ordinal}`}
      onClick={() => setOpen((value) => !value)}
      className="flex w-full flex-wrap items-center gap-2 rounded-sm py-1 text-left text-sm focus-visible:outline-2 focus-visible:outline-ring">
      <ChevronRight aria-hidden="true" className={cn("size-4 shrink-0", open && "rotate-90")} />
      <span className="font-medium">Record {item.ordinal} · {humanize(item.kind)}</span>
      <span className="text-muted-foreground">{displayText(textValue(event.kind) || textValue(item.body.status))}</span>
      {matched && <span className="text-xs font-medium">Matched record</span>}
    </button>
    {open && <div id={id} className="mt-2 space-y-2">
      {matched && selection.start !== undefined && <p className="text-sm">
        Citation: bytes {selection.start} to {selection.end}, end excluded, in the server&apos;s canonical UTF-8 target record.
        {projected ? "The assessment view below has separate bytes and a separate hash." : "The complete retained record is shown below; this display is not a reconstructed byte excerpt."}
      </p>}
      {projected && <PageNotice title="Assessment view">Internal service metadata is omitted. Captured content is unchanged. Citation byte ranges refer to the original stored record.</PageNotice>}
      <RetainedRecord body={item.body} metadata={{ ...item }} projected={projected} label={`Snapshot record ${item.ordinal}`} />
      <details className="text-sm"><summary className="w-fit cursor-pointer py-2 font-medium">Record identifiers</summary>
        <p className="text-xs text-muted-foreground">Source record</p><InlineCode className="break-all">{item.source_id}</InlineCode>
        {projected && <CodeBlock>{JSON.stringify({ retained_source_sha256: item.retained_source_sha256,
          representation_sha256: item.representation_sha256,
          representation_hash_fields: ["ordinal", "kind", "source_id", "body"] }, null, 2)}</CodeBlock>}
      </details>
    </div>}
  </li>;
}

/** Each continuation retains its exact server cursor and sealed snapshot ID. */
function SnapshotChunk({ snapshotId, sessionId, registrationId, cursor, before, afterOrdinal = 0, selection, seeking, first = false }: {
  snapshotId: string; sessionId: string; registrationId: string | null; cursor: string; before: number;
  selection: SessionSelection; seeking: boolean; first?: boolean; afterOrdinal?: number;
}) {
  const { dateTime } = useTimeZone();
  const [expanded, setExpanded] = useState(false);
  const query = new URLSearchParams({ limit: "100", ...(cursor ? { cursor } : {}) });
  const resource = useResource<SnapshotPage>(`session-snapshots/${encodeURIComponent(snapshotId)}?${query}`);
  const data = resource.data;
  if (data && (data.snapshot.id !== snapshotId || (registrationId ? data.snapshot.registration_id !== registrationId : data.snapshot.registration_id !== null || data.snapshot.session_id !== sessionId))) {
    return <ErrorState message="This snapshot does not belong to the selected session. The requested snapshot was not replaced." />;
  }
  const hasTarget = Boolean(data?.items.some((item) => item.ordinal === selection.ordinal));
  const needsTarget = selection.ordinal !== undefined && !hasTarget && Boolean(data?.items.length) &&
    data!.items[data!.items.length - 1].ordinal < selection.ordinal;
  const showNext = Boolean(data?.next_cursor) && (expanded || (seeking && needsTarget && !resource.error));
  const count = before + (data?.items.length ?? 0);
  return <>
    {resource.error && <ErrorState message={`${resource.error} The exact retained snapshot remains selected.`} onRetry={resource.reload} />}
    {!data && !resource.error && <LoadingState label={seeking ? `Locating record ${selection.ordinal}: ${before} records loaded…` : "Loading retained snapshot…"} />}
    {data && <>
      {first && <div className="mb-3 space-y-2 text-sm">
        <p>Revision {data.snapshot.revision} · sealed {dateTime(data.snapshot.sealed_at)} · {storedCount(data.snapshot.item_count)} retained records</p>
        <PageNotice title="Snapshot pagination and byte citations" collapsible>
          <p>Records are immutable and ordered by ordinal. Pages contain up to 100 records and 1 MiB of item JSON, with one larger record returned intact. Continue until the server cursor is exhausted.</p>
          <p>Byte citations refer to canonical target records retained by the server. Assessment views identify their own hashes separately and preserve captured content.</p>
          <p>Snapshot ID</p><InlineCode className="break-all">{snapshotId}</InlineCode>
        </PageNotice>
      </div>}
      {!data.items.length && first && <EmptyState title="No retained records" description="This sealed snapshot contains no records. An empty archive is not a finding or a coverage verdict." />}
      <ul aria-label="Retained snapshot records" className="divide-y">
        {data.items.map((item) => <SnapshotRow key={item.ordinal} item={item} selection={selection} />)}
      </ul>
      {selection.ordinal !== undefined && selection.ordinal > afterOrdinal && !hasTarget &&
        (!data.next_cursor || (data.items.length > 0 && selection.ordinal < data.items[data.items.length - 1].ordinal)) && <PageNotice title="Cited record is unavailable">
        Record {selection.ordinal} was not present after the final archive page. The citation and selected snapshot are unchanged.
      </PageNotice>}
      {showNext ? <SnapshotChunk snapshotId={snapshotId} sessionId={sessionId} registrationId={registrationId} cursor={data.next_cursor}
        before={count} afterOrdinal={data.items[data.items.length - 1]?.ordinal ?? afterOrdinal} selection={selection} seeking={seeking} /> : <div className="mt-3 border-t pt-3">
        <CollectionFooter count={count} hasMore={Boolean(data.next_cursor)} busy={resource.loading}
          onLoadMore={() => setExpanded(true)} label="snapshot records" />
      </div>}
    </>}
  </>;
}

export function RetainedSnapshot({ snapshotId, sessionId, registrationId, selection }: {
  snapshotId: string; sessionId: string; registrationId: string | null; selection: SessionSelection;
}) {
  const [seeking, setSeeking] = useState(false);
  return <div id="snapshot" className="scroll-mt-4" data-page-chat-exclude>
    <PageSection title="Retained snapshot" description="Retained evidence and assessment views, independent of live event retention."
      action={selection.ordinal !== undefined && <Button variant="outline" onClick={() => setSeeking((value) => !value)}>
        {seeking ? "Stop locating citation" : `Load through cited record ${selection.ordinal}`}
      </Button>}>
      <SnapshotChunk snapshotId={snapshotId} sessionId={sessionId} registrationId={registrationId} cursor="" before={0}
        selection={selection} seeking={seeking} first />
    </PageSection>
  </div>;
}

export function RetainedReadDialog({ readId, jobId, attemptId, item, onClose }: {
  readId: string | null; jobId: string; attemptId: string | null; item?: number; onClose: () => void;
}) {
  const { dateTime } = useTimeZone();
  const resource = useResource<RetainedRead>(readId ? `session-investigation-reads/${encodeURIComponent(readId)}` : null);
  const opener = useRef<HTMLElement | null>(null);
  const data = resource.data;
  const related = data?.id === readId && data?.job_id === jobId && data?.attempt_id === attemptId;
  const projected = data?.representation === "customer_service_metadata_v1";
  const parts = Array.isArray(data?.response.items) ? data.response.items : [];
  return <Dialog open={Boolean(readId)} onOpenChange={(open) => { if (!open) onClose(); }}>
    <DialogContent className="max-h-[85vh] grid-cols-[minmax(0,1fr)] overflow-y-auto sm:max-w-3xl" data-page-chat-exclude
      onOpenAutoFocus={() => {
        const active = document.activeElement;
        if (active instanceof HTMLElement && active.hasAttribute("data-retained-read-id")) opener.current = active;
      }}
      onCloseAutoFocus={(event) => {
        event.preventDefault();
        const target = opener.current?.isConnected ? opener.current :
          document.querySelector<HTMLElement>(`[data-retained-read-id="${CSS.escape(readId ?? "")}"]`) ?? document.getElementById("investigation");
        target?.focus({ preventScroll: true });
      }}>
      <DialogHeader><DialogTitle>Retained history read</DialogTitle>
        <DialogDescription>{projected ? "Assessment views preserve captured content and identify the original stored response separately." : "Exact response retained when this investigation read history. Current source availability does not replace it."}</DialogDescription>
      </DialogHeader>
      {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
      {!data && !resource.error && <LoadingState label="Loading retained history read…" />}
      {data && !related && <ErrorState message="This history read does not belong to the selected investigation attempt." />}
      {data && related && <div className="space-y-3 text-sm">
        <p>{humanize(data.tool_name)} · {humanize(data.status)} · {dateTime(data.created_at)}</p>
        {item !== undefined && <p>Cited response item {item} (zero based).</p>}
        {item !== undefined && item >= parts.length && <PageNotice title="Cited item is unavailable">The retained read does not contain response item {item}.</PageNotice>}
        {parts.length > 0 && <ul className="divide-y" aria-label="Retained history items">
          {parts.map((part, index) => {
            const value = objectValue(part);
            const itemProjected = value?.representation === "customer_service_metadata_v1";
            return <li key={index} aria-current={item === index ? "true" : undefined}
              className={cn("space-y-2 py-3", item === index && "border-l-[3px] border-primary bg-primary/5 pl-3")}>
              <p className="font-medium">Item {index}{item === index ? " · Matched record" : ""}</p>
              {typeof value?.text === "string" ? <>
                <p className="text-xs text-muted-foreground">{itemProjected ? "Assessment view UTF-8 bytes" : "Retained UTF-8 bytes"} {String(value.start)} to {String(value.end)}, end excluded, of {String(value.total_bytes)} bytes.</p>
                <section aria-label={`History item ${index}`}><EventContent text={value.text} label={`History item ${index}`} /></section>
              </> : value?.representation === "unavailable" ? <PageNotice title="Assessment view unavailable">The original source metadata could not be projected. Its retained reference remains available below.</PageNotice> :
                <section aria-label={`History item ${index}`}><EventContent text={JSON.stringify(part, null, 2)} label={`History item ${index}`} /></section>}
              {typeof value?.representation === "string" && <details><summary className="w-fit cursor-pointer py-2 font-medium">Original source range and view digest</summary>
                <CodeBlock>{JSON.stringify({ retained_source_range: value.retained_source_range, view_text_sha256: value.sha256 }, null, 2)}</CodeBlock>
              </details>}
            </li>;
          })}
        </ul>}
        <details><summary className="w-fit cursor-pointer py-2 font-medium">Read identifiers and digest</summary>
          <CodeBlock>{JSON.stringify({ id: data.id, job_id: data.job_id, attempt_id: data.attempt_id, step_id: data.step_id,
            session_id: data.session_id, source_snapshot_id: data.source_snapshot_id, response_sha256: data.response_sha256,
            ...(projected ? { representation: data.representation, retained_response_sha256: data.retained_response_sha256 } : {}) }, null, 2)}</CodeBlock>
        </details>
        <details><summary className="w-fit cursor-pointer py-2 font-medium">{projected ? "Full assessment view response" : "Full retained response"}</summary>
          <CodeBlock aria-label="Retained history response" className="max-h-96">{JSON.stringify(data.response, null, 2)}</CodeBlock>
        </details>
      </div>}
    </DialogContent>
  </Dialog>;
}
