"use client";

import Link from "next/link";
import { hasRole } from "@/lib/roles";

import { useId, useState } from "react";
import { CircleAlert } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { useTimeZone } from "@/components/time-zone-context";
import { EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Status } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, eventSummary, productLabel } from "@/lib/api";
import { RiskBadge } from "@/components/live-activity";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { Decision } from "@/lib/guardrail";
import { checkDecision, checkKey, type FlowDecision, type GuardrailCheckPage, type LinkAssessment } from "@/lib/guardrail-flow";
import { gatewayOutcome } from "@/lib/gateways";
import { displayModel, displayText } from "@/lib/display";
import { useResource } from "@/lib/use-resource";

type HookMode = "shadow" | "enforce";
type HookSettings = { mode: HookMode; version: number; updated_at: string | null };
const DECISIONS: Record<Decision, string> = { allow: "Allow", warn: "Warn", ask: "Ask", deny: "Deny" };
const BOUNDARIES: Record<string, string> = {
  GatewayRequest: "Gateway request", UserPromptSubmit: "Prompt", PreToolUse: "Tool call",
  PostToolUse: "Tool result", PostToolUseFailure: "Failed tool result",
};
const FAILURES: Record<string, string> = {
  capture_disabled: "Content capture is disabled",
  unsupported_boundary: "This hook does not support the requested control",
  content_redacted: "Content was redacted before evaluation",
  content_truncated: "Content exceeded the capture limit",
  unsupported_content: "Content could not be evaluated",
  evaluation_unavailable: "Policy evaluation was unavailable",
  path_context_unavailable: "Source path information was unavailable",
  timeout: "Classification timed out",
  provider_unavailable: "Classification service unavailable",
  connection_failed: "Classification connection failed",
  invalid_response: "Invalid classification response",
  insufficient_evidence: "Insufficient evidence",
};
const INCONCLUSIVE_DETAIL = "Insufficient evidence: the model assessment was inconclusive. Displayed as Risk 0/100 · Minimal.";

function LinkCheck({ assessment }: { assessment: LinkAssessment }) {
  const labels = {
    matched: "Flagged link", not_listed: "No listed threats", partial: "Link check incomplete",
    unavailable: "Link check unavailable", no_urls: "No URLs captured",
  };
  const threats: Record<string, string> = {
    MALWARE: "Malware", SOCIAL_ENGINEERING: "Phishing or social engineering", UNWANTED_SOFTWARE: "Unwanted software",
  };
  const reasons: Record<string, string> = {
    urls_skipped: "Some URLs were excluded for privacy, unsupported format, or the check limit.",
    content_redacted: "Some captured content was redacted.", content_truncated: "Some captured content was truncated.",
    provider_unavailable: "The link reputation service was unavailable.", connection_failed: "The reputation connection failed.",
    timeout: "A reputation lookup timed out.", invalid_response: "The reputation service returned an invalid response.",
    unsupported_evidence: "Captured content could not be checked.",
  };
  return <details className="mt-2 max-w-xs whitespace-normal text-xs text-muted-foreground">
    <summary className="w-fit cursor-pointer rounded-sm py-1 focus-visible:outline-2 focus-visible:outline-ring">
      <Badge variant={assessment.matches.length ? "destructive" : ["partial", "unavailable"].includes(assessment.status) ? "warning" : "secondary"}>{labels[assessment.status]}</Badge>
    </summary>
    <p className="mt-1">Link reputation · {assessment.checked} checked · {assessment.skipped} skipped · {assessment.failed} unavailable</p>
    {assessment.matches.map((match) => <div key={match.url} className="mt-2">
      <p className="break-all">{match.url}</p>
      <p>{match.threat_types.map((type) => threats[type] || type).join(", ")}</p>
    </div>)}
    {assessment.reasons.map((reason) => <p key={reason} className="mt-1">{reasons[reason] || "Some URLs could not be checked."}</p>)}
    <p className="mt-1">Reputation at check time. An unlisted URL is not proof of safety. A match does not confirm access or blocking.</p>
  </details>;
}

export function ClassifiedActions({ history, page, cursor, onPage, decision, onDecision, boundary, onBoundary }: {
  history: ReturnType<typeof useResource<GuardrailCheckPage>>;
  page: GuardrailCheckPage | null;
  cursor: string;
  onPage: (cursor: string) => void;
  boundary: string;
  onBoundary: (value: string) => void;
  decision: FlowDecision;
  onDecision: (value: FlowDecision) => void;
}) {
  const { clockTime, dateTime } = useTimeZone();
  const records = page?.items ?? [];
  return (
    <PageSection title="Actions" description="Checks from the complete selected flow scope. Evaluated decisions, returned responses, and delivery evidence remain separate.">
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Select value={boundary} onValueChange={onBoundary}>
          <SelectTrigger aria-label="Action type" className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="all">All actions</SelectItem>{Object.entries(BOUNDARIES).map(([key, label]) => <SelectItem key={key} value={key}>{label}</SelectItem>)}</SelectContent>
        </Select>
        <Select value={decision} onValueChange={(value) => onDecision(value as FlowDecision)}>
          <SelectTrigger aria-label="Decision" className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All decisions</SelectItem>
            {Object.entries(DECISIONS).map(([key, label]) => <SelectItem key={key} value={key}>{label}</SelectItem>)}
            <SelectItem value="unavailable">Check failed</SelectItem>
            {(decision === "unknown" || records.some((record) => checkDecision(record) === "unknown")) && <SelectItem value="unknown">Unknown decision</SelectItem>}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">{cursor ? "Older checks · Fixed time window" : history.updated ? `Updated ${clockTime(history.updated.toISOString())}` : "Connecting"}</p>
        {cursor && <Button variant="outline" onClick={() => onPage("")} disabled={history.loading}>Latest checks</Button>}
      </div>
      {history.error && <ErrorState message={history.error} onRetry={history.reload} />}
      {history.loading && !records.length ? <LoadingState label="Loading actions" /> : !records.length ? (history.error && !records.length ? null : <EmptyState title="No matching checks" description="Change the flow filters or choose a wider time window." />) : (
        <TableLayout><Table>
          <TableHeader><TableRow><TableHead>Time</TableHead><TableHead>Action</TableHead><TableHead>Reported identity</TableHead><TableHead>Decision</TableHead><TableHead>Guardrail label</TableHead></TableRow></TableHeader>
          <TableBody>{records.map((record) => {
            if (record.source === "gateway") return <TableRow key={checkKey(record)}>
              <TableCell className="whitespace-nowrap">{clockTime(record.created_at)}</TableCell>
              <TableCell className="max-w-md"><div className="flex items-center gap-2"><Link className="font-medium text-primary hover:underline" href={`/gateways/requests/${encodeURIComponent(record.id)}`}>Gateway request</Link><Badge variant="outline">Gateway</Badge></div><p className="text-xs text-muted-foreground">{record.model ? displayModel(record.model) : "Model not reported"}</p><p className="truncate text-xs text-muted-foreground" title={record.route_id}>Route: {record.route_id || "Not reported"}</p></TableCell>
              <TableCell className="max-w-xs"><p className="truncate" title={record.consumer_id}>{record.consumer_id ? `Caller: ${record.consumer_name || record.consumer_id}` : "Unknown caller"}</p>{record.application_name && <p className="truncate text-xs text-muted-foreground" title={record.application_name}>Application: {record.application_name}</p>}<p className="truncate text-xs text-muted-foreground" title={record.gateway_name}>Gateway: {record.gateway_name}</p></TableCell>
              <TableCell>
                <p>{record.status === "unavailable" ? "Check failed" : record.evaluated_decision ? DECISIONS[record.evaluated_decision] : "Unknown decision"} · {record.mode === "shadow" ? "Shadow" : record.mode === "enforce" ? "Enforce" : "Mode unavailable"}</p>
                <p className="text-xs text-muted-foreground">Returned: {record.returned_decision ? DECISIONS[record.returned_decision] : "Unavailable"}</p>
                <p className="text-xs text-muted-foreground">Reported outcome: {gatewayOutcome(record.outcome)}</p>
                <details className="mt-1 max-w-xs text-xs text-muted-foreground"><summary className="w-fit cursor-pointer rounded-sm py-1 font-medium focus-visible:outline-2 focus-visible:outline-ring">Decision details</summary><p className="mt-1"><time dateTime={record.created_at}>{dateTime(record.created_at)}</time></p>{record.reason && <p className="mt-1 whitespace-pre-wrap break-words">{record.reason}</p>}{record.failure_reason && <p className="mt-1">{FAILURES[record.failure_reason] || record.failure_reason}</p>}<p className="mt-1">A returned decision does not confirm enforcement. Forwarding does not confirm model completion.</p></details>
              </TableCell>
              <TableCell>{record.assessment?.status === "scored" ? <RiskBadge risk={record.assessment} /> : <span className="text-xs text-muted-foreground">Assessment unavailable</span>}</TableCell>
            </TableRow>;
            const evidence = record.actions.map((action) => action.text ?? action.tool?.output ?? eventSummary(action)).join("\n");
            const failure = FAILURES[record.failure_reason] || record.failure_reason;
            const inconclusive = record.failure_reason === "insufficient_evidence";
            const detail = record.reason || (record.failure_reason === "evaluation_unavailable"
              ? "The cause of this policy evaluation failure was not recorded."
              : displayText(record.rule_name) || (inconclusive ? "" : failure));
            return <TableRow key={checkKey(record)}>
              <TableCell className="whitespace-nowrap">{clockTime(record.created_at)}</TableCell>
              <TableCell className="max-w-md"><p className="font-medium">{BOUNDARIES[record.hook_event] || record.hook_event}{record.actions[0]?.tool?.name ? ` · ${record.actions[0].tool.name}` : ""} <Badge variant="outline">Endpoint</Badge></p><p className="truncate text-xs text-muted-foreground" title={evidence}>{evidence || "Content not captured"}</p></TableCell>
              <TableCell><p>{record.sensor_username || "Unknown OS user"}</p><p className="text-xs text-muted-foreground">{record.sensor_hostname} · {productLabel(record.product)}</p></TableCell>
              <TableCell>
                <p>{record.status === "unavailable" ? "Check failed · allowed" : record.evaluated_decision ? `${DECISIONS[record.evaluated_decision]} · ${record.mode === "shadow" ? "Shadow" : "Enforce"}` : "Unknown decision"}</p>
                <p className="text-xs text-muted-foreground">{record.returned_decision ? `Returned: ${DECISIONS[record.returned_decision]}` : failure}</p>
                <p className="text-xs text-muted-foreground">{record.delivery_status === "delivered" ? `Response sent: ${(record.delivered_decision ? DECISIONS[record.delivered_decision] : "Unknown")}` : record.delivery_status === "unconfirmed" ? "Delivery not confirmed" : record.delivery_status === "timed_out" ? "Timed out · allowed" : "Delivery failed · allowed"}</p>
                <details className="mt-1 max-w-xs text-xs text-muted-foreground">
                  <summary className="w-fit cursor-pointer rounded-sm py-1 font-medium focus-visible:outline-2 focus-visible:outline-ring">Decision details</summary>
                  <p className="mt-1"><time dateTime={record.created_at}>{dateTime(record.created_at)}</time></p>
                  {detail && <p className="mt-1 whitespace-pre-wrap break-words">{detail}</p>}
                  {inconclusive && <p className="mt-1 whitespace-pre-wrap break-words">{INCONCLUSIVE_DETAIL}</p>}
                </details>
                {record.assessment?.links && <LinkCheck assessment={record.assessment.links} />}
              </TableCell>
              <TableCell>{record.assessment?.status === "scored" ? <RiskBadge risk={record.assessment} /> : inconclusive ? <Badge variant="informational" className="number" title={INCONCLUSIVE_DETAIL}>Risk 0/100 · Minimal</Badge> : <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">{record.failure_reason === "evaluation_unavailable" && <CircleAlert className="size-3.5 shrink-0 text-status-critical" aria-hidden="true" />}<span>{failure || "Assessment unavailable"}</span></span>}</TableCell>
            </TableRow>;
          })}</TableBody>
        </Table></TableLayout>
      )}
      <div className="mt-3 flex gap-2">
        {page?.next_cursor && <Button variant="outline" onClick={() => onPage(page!.next_cursor)} disabled={history.loading}>Older checks</Button>}
      </div>
    </PageSection>
  );
}

function validSettings(value: HookSettings | null): value is HookSettings {
  return !!value && ["shadow", "enforce"].includes(value.mode) &&
    Number.isSafeInteger(value.version) && value.version >= 0;
}

export function HookPolicy() {
  const { user } = useDashboard();
  return user ? <HookPolicySettings key={user.tenant.id} editable={hasRole(user, "security_analyst")} /> : null;
}

function HookPolicySettings({ editable }: { editable: boolean }) {
  const name = useId();
  const resource = useResource<HookSettings>("response/hook-settings", 10000);
  const [confirmed, setConfirmed] = useState<HookSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const loaded = resource.data;
  const data = confirmed && (!validSettings(loaded) || confirmed.version > loaded.version) ? confirmed : loaded;
  const valid = validSettings(data);
  const loadError = resource.error || (loaded && !validSettings(loaded) ? "The server returned unsupported hook settings." : "");

  async function changeMode(mode: HookMode) {
    if (!validSettings(data) || mode === data.mode || saving || !editable || loadError) return;
    setSaving(true);
    setSaveError("");
    try {
      const result = await api<HookSettings>("response/hook-settings", {
        method: "PUT",
        body: JSON.stringify({ mode, version: data.version }),
      });
      if (!validSettings(result)) throw new Error("The server did not confirm the hook mode. Refresh to check its current state.");
      setConfirmed(result);
      await resource.reload();
    } catch (cause) {
      setSaveError(cause instanceof Error ? cause.message : "Unable to change the hook mode.");
      await resource.reload();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      <PageSection
        title="Hook policy"
        description="The backend evaluates policy for connected ordinary hooks."
        action={valid && editable && (
          <fieldset aria-label="Hook policy mode" disabled={saving || !!loadError} className="flex gap-1 rounded-md border border-input p-1 text-sm disabled:opacity-50">
            <legend className="sr-only">Hook policy mode</legend>
            {(["shadow", "enforce"] as const).map((mode) => (
              <label key={mode} className={`relative flex h-8 cursor-pointer items-center rounded-sm px-3 font-medium has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-ring ${data.mode === mode ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}>
                <input type="radio" name={name} value={mode} checked={data.mode === mode} onChange={() => void changeMode(mode)} className="absolute inset-0 size-full cursor-pointer opacity-0 disabled:cursor-wait" />
                {mode === "shadow" ? "Shadow" : "Enforce"}
              </label>
            ))}
          </fieldset>
        )}
      >
        <div className="space-y-3 text-sm">
          {!data && resource.loading && <LoadingState label="Loading hook policy…" />}
          {loadError && <ErrorState message={loadError} onRetry={resource.reload} />}
          {saveError && <p role="alert" className="text-destructive">{saveError}</p>}
          {valid && (
            <>
              <div className="flex flex-wrap items-center gap-3" aria-live="polite">
                <Status tone={data.mode === "enforce" ? "info" : "neutral"}>
                  {data.mode === "enforce" ? "Enforce" : "Shadow"}{loadError ? " (last confirmed)" : ""}
                </Status>
                <span>{saving ? "Saving…" : data.mode === "shadow" ? "Record decisions and allow actions." : "Apply backend decisions at supported hooks."}</span>
                <Button variant="ghost" size="sm" disabled={resource.loading || saving} onClick={resource.reload}>Refresh mode</Button>
              </div>
              {!editable && <p className="text-muted-foreground">A Security Analyst can change the mode for this organization.</p>}
            </>
          )}
          <p>In both modes, a failed check silently allows the action. Hooks wait at most 2 seconds.</p>
          <PageNotice title="Hook scope and delivery" collapsible>
            <p>The mode applies to installed prompt, tool-call, and supported tool-result hooks that use backend policy checks across this organization. Keep sensors up to date to use this mode.</p>
            <p>Policy rules are evaluated by the backend. Local secret redaction is a separate module.</p>
            <p>Result hooks act after a tool has run. Supported result controls can withhold output from the model, but cannot undo the tool’s effects. Unsupported controls allow the action.</p>
            <p>The backend records evaluated and returned decisions separately. A returned decision does not prove that the hook delivered it or that the action ran. Checks that never reach the backend cannot appear in its decision history.</p>
          </PageNotice>
        </div>
      </PageSection>
    </div>
  );
}
