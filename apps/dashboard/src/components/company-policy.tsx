"use client";

import { useId, useState } from "react";
import { ArrowRight, Check, CircleHelp, Info, Regex, ShieldCheck, Terminal, X } from "lucide-react";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { Textarea } from "@/components/ui/textarea";
import { useTimeZone } from "@/components/time-zone-context";
import { api, APIError } from "@/lib/api";
import { useResource } from "@/lib/use-resource";

type Policy = { revision: number; prompt: string; updated_at: string | null };
const LIMIT = 10_000;
const EXAMPLE = "Treat unapproved changes to production data or infrastructure as high risk.\nFlag credentials, secrets, or customer data sent to unapproved destinations.\nUse company knowledge to identify production systems and approved workflows.\nTreat read-only investigation and local development as low risk when the evidence supports it.";

function validPolicy(value: Policy | null): value is Policy {
  return !!value && Number.isSafeInteger(value.revision) && value.revision >= 0 && typeof value.prompt === "string";
}

export function CompanyPolicy({ editable }: { editable: boolean }) {
  const id = useId();
  const { dateTime } = useTimeZone();
  const resource = useResource<Policy>("response/company-policy");
  const [draft, setDraft] = useState<{ prompt: string; revision: number } | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [notice, setNotice] = useState("");
  const data = resource.data;
  const valid = validPolicy(data);
  const error = resource.error || (data && !valid ? "The server returned an unsupported company policy." : "");
  const prompt = draft?.prompt ?? (valid ? data.prompt : "");
  const dirty = valid && prompt !== data.prompt;
  const disabled = saving || resource.loading || !!error;

  async function save() {
    if (!valid || !draft || !dirty || disabled || !editable) return;
    setSaving(true);
    setSaveError("");
    setNotice("");
    try {
      const result = await api<Policy>("response/company-policy", { method: "PUT", body: JSON.stringify(draft) });
      if (!validPolicy(result)) throw new Error("The server did not confirm the policy. Refresh to check its state.");
      resource.setData(result);
      setDraft(null);
      setNotice("Company policy saved. New Guardrail model assessments will use these instructions.");
    } catch (cause) {
      setSaveError(cause instanceof APIError && cause.status === 409
        ? "Company policy changed. Your draft was kept. Reset draft to load the saved policy before editing again."
        : cause instanceof Error ? cause.message : "Unable to save company policy.");
      await resource.reload();
    } finally {
      setSaving(false);
    }
  }

  return <PageSection title="Company policy"
    description="Describe the risks, boundaries, and approved behavior that matter to your organization."
    action={valid && <Status tone={dirty ? "warning" : data.prompt.trim() ? "info" : "neutral"}>
      {dirty ? "Unsaved changes" : data.prompt.trim() ? "Saved" : "Not configured"}
    </Status>}>
    <div className="space-y-3 text-sm">
      {!data && resource.loading && <LoadingState label="Loading company policy…" />}
      {error && <ErrorState message={error} onRetry={resource.reload} />}
      {saveError && <p role="alert" className="text-destructive">{saveError}</p>}
      {notice && <p role="status">{notice}</p>}
      {valid && <form onSubmit={(event) => { event.preventDefault(); void save(); }} className="space-y-3">
        <label className="block space-y-2" htmlFor={id}>
          <span className="font-medium">Policy instructions</span>
          <Textarea id={id} rows={5} maxLength={LIMIT} readOnly={!editable} disabled={disabled}
            aria-describedby={`${id}-hint`} placeholder={EXAMPLE} value={prompt}
            onChange={(event) => {
              setDraft({ prompt: event.target.value, revision: draft?.revision ?? data.revision });
              setNotice("");
            }} />
        </label>
        <div className="flex flex-wrap justify-between gap-2 text-xs text-muted-foreground">
          <p id={`${id}-hint`}>Included in Guardrail model instructions, even when company knowledge is disabled.</p>
          <span>{prompt.length.toLocaleString()} / {LIMIT.toLocaleString()} characters</span>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">{data.updated_at ? `Revision ${data.revision} · Saved ${dateTime(data.updated_at)}` : "No company policy has been saved."}</p>
          {editable ? <div className="flex flex-wrap gap-2">
            {!prompt && <Button type="button" variant="ghost" disabled={disabled}
              onClick={() => setDraft({ prompt: EXAMPLE, revision: data.revision })}>Use example</Button>}
            {draft && <Button type="button" variant="ghost" disabled={disabled}
              onClick={() => { setDraft(null); setSaveError(""); }}>Reset draft</Button>}
            <Button type="submit" disabled={disabled || !dirty}>{saving ? "Saving…" : "Save policy"}</Button>
          </div> : <p className="text-xs text-muted-foreground">An administrator can edit the company policy.</p>}
        </div>
      </form>}
    </div>
  </PageSection>;
}

export function CompanyPolicyFlow() {
  return <PageSection title="How it works" description="Installed hooks send activity to the backend for fixed rules, model assessment, and a combined policy decision.">
    <div className="space-y-5 text-sm" role="group" aria-label="Guardrail evaluation paths">
      <div className="grid items-center gap-3 xl:grid-cols-[minmax(0,0.8fr)_1rem_minmax(0,1fr)_1rem_minmax(0,1.3fr)_1rem_minmax(0,1.1fr)]"
        role="group" aria-label="Hook check sequence">
        <div className="rounded-md bg-muted px-3 py-4 text-center">
          <Terminal aria-hidden="true" className="mx-auto mb-2 size-6 text-muted-foreground" />
          <h3 className="font-semibold">Agent activity</h3>
          <p className="mt-1 text-xs text-muted-foreground">Prompt · tool call · tool result</p>
        </div>
        <ArrowRight aria-hidden="true" className="mx-auto size-4 rotate-90 text-muted-foreground xl:rotate-0" />
        <div className="rounded-md bg-muted px-3 py-4 text-center" role="group" aria-label="Fixed-rule evaluation">
          <Regex aria-hidden="true" className="mx-auto mb-2 size-6 text-muted-foreground" />
          <h3 className="font-semibold">Fixed rules</h3>
          <p className="mt-1 text-xs text-muted-foreground">Regex and other match conditions</p>
          <p className="mt-3 text-xs">Keep the rule decision and any warnings</p>
        </div>
        <ArrowRight aria-hidden="true" className="mx-auto size-4 rotate-90 text-muted-foreground xl:rotate-0" />
        <div className="rounded-md bg-primary/5 px-3 py-4 text-center" role="group" aria-label="Model assessment">
          <ShieldCheck aria-hidden="true" className="mx-auto mb-2 size-6 text-primary" />
          <h3 className="font-semibold text-primary">Guardrail model</h3>
          <p className="mt-1 text-xs text-muted-foreground">Assess prompts, tool calls, and results</p>
          <div className="my-3 space-y-2 text-left">
            {[
              { icon: ShieldCheck, title: "Company policy", detail: "Saved assessment instructions" },
            ].map(({ icon: Icon, title, detail }) => <div key={title} className="flex items-start gap-2">
              <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
              <div className="min-w-0"><p className="text-xs font-semibold">{title}</p><p className="text-xs text-muted-foreground">{detail}</p></div>
            </div>)}
          </div>
          <p className="text-xs font-medium">Per-action risk score</p>
          <div className="mx-auto my-2 flex max-w-24 gap-1" aria-hidden="true">
            <span className="h-1 flex-1 rounded-xs bg-chart-1/25" /><span className="h-1 flex-1 rounded-xs bg-chart-1/50" /><span className="h-1 flex-1 rounded-xs bg-chart-1/75" /><span className="h-1 flex-1 rounded-xs bg-chart-1" />
          </div>
        </div>
        <ArrowRight aria-hidden="true" className="mx-auto size-4 rotate-90 text-muted-foreground xl:rotate-0" />
        <div className="text-center">
          <h3 className="font-semibold">Combined decision</h3>
          <p className="mt-1 text-xs text-muted-foreground">Retained rule decision + enabled model thresholds</p>
          <div className="mt-3 flex flex-wrap justify-center gap-2 text-xs">
            <span className="flex items-center gap-1 rounded-sm bg-status-ok/10 px-2 py-1 text-status-ok"><Check aria-hidden="true" className="size-3" />Allow</span>
            <span className="flex items-center gap-1 rounded-sm bg-status-warning/10 px-2 py-1 text-status-warning"><CircleHelp aria-hidden="true" className="size-3" />Ask</span>
            <span className="flex items-center gap-1 rounded-sm bg-status-critical/10 px-2 py-1 text-status-critical"><X aria-hidden="true" className="size-3" />Deny</span>
          </div>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">The combined decision keeps the most restrictive result. A low model risk score cannot override a fixed-rule denial. Shadow records that decision and returns Allow; Enforce returns supported decisions.</p>
      <div className="grid gap-4 border-t pt-4 lg:grid-cols-2">
        <div role="group" aria-label="Installed hooks">
          <h3 className="font-semibold">Installed hooks</h3>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">The backend evaluates fixed rules and assesses activity with the Guardrail model. Enabled model thresholds can add Ask or Deny. Failed checks allow the action; an unavailable model adds no restriction to a valid rule decision. Local secret redaction is separate from policy evaluation.</p>
        </div>
        <div role="group" aria-label="Background assessment">
          <h3 className="font-semibold">Background assessment</h3>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">Model scores are recorded after activity is collected. They do not block the original action.</p>
        </div>
      </div>
    </div>
    <p className="mt-4 flex items-start gap-2 border-t pt-3 text-xs text-muted-foreground">
      <Info aria-hidden="true" className="mt-0.5 size-3 shrink-0" />
      Actions shows the evaluated decision, returned response, and delivery status separately. A returned response does not prove enforcement. Tool-call checks can prevent execution. Tool-result checks assess output after execution. Available controls depend on the agent and hook.
    </p>
  </PageSection>;
}
