"use client";

import { displayText } from "@/lib/display";
import { useTimeZone } from "@/components/time-zone-context";
import { useCallback, useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api, APIError, productLabel, type AgentEvent } from "@/lib/api";
import { binaryContent, collectionNotes } from "@/lib/event-content";
import { rememberSessionActionReturn } from "@/lib/session-action-return";
import { SessionActionPage } from "@/components/session-action-page";
import { ErrorState, LoadingState, PageNotice, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { CodeBlock } from "@/components/ui/code-block";
import { Status } from "@/components/ui/status";

type Approval = {
  id: string;
  status: "pending" | "approved" | "rejected" | "expired" | "revoked";
  expires_at: string;
  reason_code: string;
  tenant: { name: string };
  client: { product: string; version: string };
  device: { hostname: string; label: string };
  boundary: "prompt" | "tool_call" | "tool_output" | "assistant_response";
  preview: {
    target: AgentEvent;
    context: { latest_prompt: AgentEvent | null; matched_tool_call: AgentEvent | null; prior_events: AgentEvent[] };
  } | null;
  preview_withheld: boolean;
  assessment: { status: string; score: number | null; category: string };
  reason: string;
  warnings: string[];
  gaps: string[];
  release: { id: string; outcome: string | null; consumed_at: string } | null;
};

const BOUNDARIES = {
  prompt: "Send a prompt",
  tool_call: "Run a tool",
  tool_output: "Send tool output to the agent",
  assistant_response: "Show the agent response",
};

export default function ApprovalPage() {
  const { id } = useParams<{ id: string }>();
  return (
    <SessionActionPage title="Review this action" description="Your agent is waiting for a decision on one action." path={`/approvals/${id}`}>
      {(user) => <ApprovalReview key={`${user.id}:${id}`} id={id} />}
    </SessionActionPage>
  );
}

function ApprovalReview({ id }: { id: string }) {
  const { dateTime } = useTimeZone();
  const router = useRouter();
  const [data, setData] = useState<Approval | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const generation = useRef(0);
  const active = useRef<AbortController | null>(null);

  const handleError = useCallback((failure: unknown) => {
    if (failure instanceof APIError && failure.status === 401) {
      setData(null);
      rememberSessionActionReturn(`/approvals/${id}`);
      router.replace("/login");
    } else if (failure instanceof APIError && (failure.status === 403 || failure.status === 404)) {
      setData(null);
      setError("This action is unavailable for your account. Check the link or switch to the account that registered the session.");
    } else setError(failure instanceof Error ? failure.message : "Unable to load this action.");
  }, [id, router]);

  const reload = useCallback(async () => {
    if (inFlight.current) return;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    try {
      const result = await api<Approval>(`me/approvals/${encodeURIComponent(id)}`, { signal: controller.signal });
      if (generation.current === current) {
        setData(result);
        setError("");
      }
    } catch (failure) {
      if (!controller.signal.aborted && generation.current === current) handleError(failure);
    }
  }, [id, handleError]);

  useEffect(() => {
    void reload();
    const timer = setInterval(() => { if (!document.hidden) void reload(); }, 5000);
    return () => { clearInterval(timer); generation.current++; active.current?.abort(); };
  }, [reload]);

  async function decide(choice: "approve" | "reject" | "revoke") {
    if (inFlight.current) return;
    inFlight.current = true;
    active.current?.abort();
    generation.current++;
    setBusy(true);
    setError("");
    let refresh = false;
    try {
      const result = await api<Approval>(`me/approvals/${encodeURIComponent(id)}/${choice === "revoke" ? "revoke" : "decision"}`, {
        method: "POST", body: JSON.stringify(choice === "revoke" ? {} : { decision: choice }),
      });
      setData(result);
    } catch (failure) {
      handleError(failure);
      refresh = failure instanceof APIError && failure.status === 409;
    } finally {
      inFlight.current = false;
      setBusy(false);
      if (refresh) void reload();
    }
  }

  const consumed = !!data?.release;
  const status = consumed ? "Consumed by the client" : data?.status === "approved" ? "Approved, waiting for the client"
    : data?.status === "pending" ? "Waiting for your decision" : data?.status === "rejected" ? "Rejected"
    : data?.status === "expired" ? "Expired" : "Revoked";

  return (
    <div className="space-y-4">
      {error && <ErrorState message={error} onRetry={() => void reload()} />}
      {!data && !error && <LoadingState label="Loading the held action…" />}
      {data && <>
        <PageSection title={BOUNDARIES[data.boundary]}>
          <div className="space-y-4">
            <div aria-live="polite"><Status tone={consumed || data.status === "approved" ? "info" : data.status === "pending" ? "warning" : "critical"}>{status}</Status></div>
            <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div><dt className="text-muted-foreground">Organization</dt><dd>{data.tenant.name}</dd></div>
              <div><dt className="text-muted-foreground">Client</dt><dd>{productLabel(data.client.product)}{data.client.version && ` ${displayText(data.client.version)}`}</dd></div>
              <div><dt className="text-muted-foreground">Device</dt><dd className="break-words">{data.device.label || data.device.hostname || "Not reported"}</dd></div>
              <div><dt className="text-muted-foreground">Expires</dt><dd>{dateTime(data.expires_at)}</dd></div>
            </dl>
            <div><h3 className="font-semibold">Why approval is needed</h3><p className="mt-1 break-words">{data.reason}</p></div>
            <p>Risk assessment: {data.assessment.status === "scored" && data.assessment.score !== null
              ? `${data.assessment.score} / 100 · ${displayText(data.assessment.category.replaceAll("_", " "))}`
              : "Unavailable"}</p>
            {data.warnings.map((warning, index) => <p key={index}>{warning}</p>)}
            {data.gaps.length > 0 && <PageNotice title="Captured information is incomplete"><p>{displayText(data.gaps.map((gap) => gap.replaceAll("_", " ")).join("; "))}.</p></PageNotice>}
            {data.boundary === "assistant_response" || data.preview_withheld ? <p>The response is held until you approve.</p> : data.preview && <>
              <CapturedEvent event={data.preview.target} label="Captured action" />
              <details className="border-t pt-3">
                <summary className="cursor-pointer py-2 font-medium">Review captured context</summary>
                <div className="space-y-4 pt-2">
                  {data.preview.context.latest_prompt && <CapturedEvent event={data.preview.context.latest_prompt} label="Latest prompt" />}
                  {data.preview.context.matched_tool_call && <CapturedEvent event={data.preview.context.matched_tool_call} label="Related tool call" />}
                  {data.preview.context.prior_events.map((event, index) => <CapturedEvent key={`${event.id}:${index}`} event={event} label={`Earlier ${displayText(event.kind.replaceAll(".", " "))}`} />)}
                  {!data.preview.context.latest_prompt && !data.preview.context.matched_tool_call && !data.preview.context.prior_events.length && <p>No earlier context was captured.</p>}
                </div>
              </details>
            </>}
            {!consumed && data.status === "pending" && <div className="flex flex-wrap gap-3 border-t pt-4">
              <Button size="lg" disabled={busy || !!error} onClick={() => void decide("approve")}>{busy ? "Saving…" : "Approve once"}</Button>
              <Button variant="outline" size="lg" disabled={busy || !!error} onClick={() => void decide("reject")}>Reject</Button>
            </div>}
            {!consumed && data.status === "approved" && <div className="space-y-3 border-t pt-4">
              <p>The client can release this action once before approval expires.</p>
              <Button variant="outline" size="lg" disabled={busy || !!error} onClick={() => void decide("revoke")}>Revoke approval</Button>
            </div>}
            {data.release && <p role="status">Outcome: {data.release.outcome ? displayText(data.release.outcome.replaceAll("_", " ")) : "Not reported"}.</p>}
          </div>
        </PageSection>
      </>}
    </div>
  );
}

function CapturedEvent({ event, label }: { event: AgentEvent; label: string }) {
  const captured: unknown = event.command?.text ?? event.text ?? event.tool?.output ?? event.file?.path ?? event.network?.url;
  const raw = captured ?? event.tool?.input ?? "Content was not captured.";
  const value = typeof raw === "string" ? raw : JSON.stringify(raw, null, 2);
  const binary = binaryContent(value, event.truncated === true);
  const cwd = event.command?.cwd || event.session?.cwd;
  return (
    <div className="min-w-0 space-y-2">
      <h3 className="font-semibold">{label}{event.tool?.name && ` · ${event.tool.name}`}</h3>
      {cwd && <div><p className="mb-1 text-muted-foreground">Working directory</p><CodeBlock>{cwd}</CodeBlock></div>}
      {binary ? <p>{binary}</p> : <CodeBlock className="max-h-96" tabIndex={0} aria-label={label}>{value}</CodeBlock>}
      {captured !== undefined && event.tool?.input !== undefined && <div>
        <p className="mb-1 text-muted-foreground">Tool arguments</p>
        <CodeBlock className="max-h-96" tabIndex={0} aria-label={`${label} arguments`}>{JSON.stringify(event.tool.input, null, 2)}</CodeBlock>
      </div>}
      {collectionNotes(event).map((note) => <p key={note} className="text-xs text-muted-foreground">{note}</p>)}
    </div>
  );
}
