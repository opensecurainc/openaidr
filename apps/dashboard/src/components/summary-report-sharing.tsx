"use client";

import { useState } from "react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { CodeBlock, InlineCode } from "@/components/ui/code-block";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useTimeZone } from "@/components/time-zone-context";
import { api, number } from "@/lib/api";
import { hasRole } from "@/lib/roles";
import { useResource } from "@/lib/use-resource";

type ReportSettings = {
  automatic: boolean;
  available: boolean;
  version: number;
  destination: string | null;
  next_report_at: string | null;
  delivery: { pending: number; failed: number; last_sent_at: string | null };
};
const DECISIONS = [["allow", "Allow"], ["warn", "Warn"], ["ask", "Ask"], ["deny", "Deny"]] as const;
const COUNT_GROUPS = [
  ["checks", "Guardrail checks", [["total", "Total"], ["pending", "Pending"], ["evaluated", "Evaluated"],
    ["unavailable", "Unavailable"], ["shadow", "Shadow mode"], ["enforce", "Enforce mode"]]],
  ["delivery", "Delivery status", [["delivered", "Delivered"], ["timed_out", "Timed out"],
    ["failed", "Failed"], ["unconfirmed", "Unconfirmed"]]],
  ["findings", "Findings", [["total", "Total"], ["info", "Informational"], ["low", "Low"],
    ["medium", "Medium"], ["high", "High"], ["critical", "Critical"], ["marked_false_positive", "Marked false positive"]]],
  ["evaluated_decisions", "Evaluated decisions", DECISIONS],
  ["returned_decisions", "Returned decisions", DECISIONS],
  ["delivered_decisions", "Confirmed delivered decisions", DECISIONS],
  ["investigations", "Investigations", [["total", "Total"], ["finding", "Finding"], ["no_finding", "No finding"],
    ["inconclusive", "Inconclusive"], ["unknown", "Unknown outcome"], ["source_complete", "Complete source coverage"],
    ["source_incomplete", "Incomplete source coverage"], ["source_unknown", "Unknown source coverage"]]],
] as const;
type SummaryReport = {
  schema_version: number;
  report_id: string;
  tenant_id: string;
  generated_at: string;
  window_start: string;
  window_end: string;
  backend_version: string | null;
  counts: Record<(typeof COUNT_GROUPS)[number][0] | "latency_samples", Record<string, number>>;
  latency_ms: Record<string, number | null>;
};
type Preview = { report: SummaryReport; expires_at: string };

function ReportPreview({ report }: { report: SummaryReport }) {
  const { dateTime } = useTimeZone();
  return <Tabs defaultValue="html" className="min-w-0">
    <TabsList aria-label="Report format">
      <TabsTrigger value="html">HTML</TabsTrigger>
      <TabsTrigger value="json">JSON</TabsTrigger>
    </TabsList>
    <TabsContent value="html">
      <div role="region" aria-label="Formatted report" tabIndex={0} className="max-h-[32rem] space-y-4 overflow-auto text-sm">
        <section aria-label="Report details" className="space-y-2">
          <h3 className="text-sm font-semibold">Report details</h3>
          <dl className="grid min-w-0 gap-x-6 gap-y-2 sm:grid-cols-2">
            {[["Report ID", report.report_id], ["Tenant ID", report.tenant_id],
              ["Window start", dateTime(report.window_start)], ["Window end", dateTime(report.window_end)],
              ["Generated at", dateTime(report.generated_at)], ["Backend version", report.backend_version ?? "Unavailable"],
              ["Schema version", String(report.schema_version)]].map(([label, value]) => <div key={label} className="min-w-0">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="break-all">{label.endsWith("ID")
                  ? <InlineCode className="text-sm font-normal">{value}</InlineCode> : value}</dd>
              </div>)}
          </dl>
        </section>
        <div className="grid min-w-0 gap-x-6 gap-y-4 sm:grid-cols-2 xl:grid-cols-3">
          {COUNT_GROUPS.map(([group, title, fields]) => <section key={group} aria-label={title} className="min-w-0 space-y-2 border-t pt-3">
            <h3 className="text-sm font-semibold">{title}</h3>
            <dl className="space-y-1">
              {fields.map(([key, label]) => <div key={key} className="flex items-baseline justify-between gap-3">
                <dt className="min-w-0 break-words text-muted-foreground">{label}</dt>
                <dd className="shrink-0 tabular-nums">{number(report.counts[group][key])}</dd>
              </div>)}
            </dl>
          </section>)}
          {[["policy", "Policy latency"], ["e2e", "End-to-end latency"]].map(([key, title]) => <section
            key={key} aria-label={title} className="min-w-0 space-y-2 border-t pt-3">
            <h3 className="text-sm font-semibold">{title}</h3>
            <dl className="space-y-1">
              <div className="flex items-baseline justify-between gap-3">
                <dt className="text-muted-foreground">Samples</dt>
                <dd className="tabular-nums">{number(report.counts.latency_samples[key])}</dd>
              </div>
              {[["p50", "Median (p50)"], ["p95", "p95"], ["p99", "p99"]].map(([percentile, label]) => {
                const value = report.latency_ms[`${key}_${percentile}`];
                return <div key={percentile} className="flex items-baseline justify-between gap-3">
                  <dt className="shrink-0 text-muted-foreground">{label}</dt>
                  <dd className="break-all text-right tabular-nums">{value == null ? "Unavailable" : `${value} ms`}</dd>
                </div>;
              })}
            </dl>
          </section>)}
        </div>
        <p className="text-muted-foreground">Counts use retained data from this 24-hour window. Missing records can make them incomplete.
          Delivered decisions do not prove enforcement. Marked false positives are counts, not a false-positive rate.</p>
      </div>
    </TabsContent>
    <TabsContent value="json">
      <CodeBlock aria-label="Report JSON" tabIndex={0} className="max-h-96 break-all text-sm font-normal">
        {JSON.stringify(report, null, 2)}
      </CodeBlock>
    </TabsContent>
  </Tabs>;
}

function ReportForm({ settings, saved, refresh }: {
  settings: ReportSettings; saved: (value: ReportSettings) => void; refresh: () => void;
}) {
  const { dateTime } = useTimeZone();
  const [automatic, setAutomatic] = useState(settings.automatic);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const dirty = automatic !== settings.automatic;

  async function act(action: "save" | "preview" | "send") {
    setBusy(true); setError(""); setNotice("");
    try {
      if (action === "save") {
        saved(await api<ReportSettings>("settings/summary-reports", { method: "PUT",
          body: JSON.stringify({ automatic, version: settings.version }) }));
      } else if (action === "preview") {
        setPreview(await api<Preview>("settings/summary-reports/preview", { method: "POST", body: "{}" }));
      } else if (preview) {
        await api("settings/summary-reports/send", { method: "POST",
          body: JSON.stringify({ report_id: preview.report.report_id }) });
        setPreview(null);
        setNotice("Report queued. Refresh to check delivery status.");
        refresh();
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to update report sharing.");
    } finally { setBusy(false); }
  }

  return <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void act("save"); }}>
    <p className="max-w-3xl text-sm text-muted-foreground">
      Share aggregate guardrail decisions, investigation outcomes, coverage and latency from the last 24 hours,
      plus your tenant ID and backend version. Reports exclude prompts, commands, code, user and device identities,
      customer URLs and policy text. Counts may still reveal activity levels.
    </p>
    <p className="text-sm">{settings.automatic ? "Automatic sharing is on." : "Automatic sharing is off."}</p>
    <p className="break-words text-sm text-muted-foreground">Destination: <InlineCode className="text-sm font-normal">{settings.destination}</InlineCode></p>
    <label className="flex items-center gap-2 text-sm font-medium">
      <input type="checkbox" checked={automatic} onChange={(event) => setAutomatic(event.target.checked)}
        disabled={busy} />
      Send automatically each day
    </label>
    <p className="max-w-3xl text-sm text-muted-foreground">
      Saving this setting authorizes daily reports with the fields shown in the preview. The first report is sent
      after 24 hours. Turning it off cancels pending automatic reports. Reports you send manually remain queued.
      Sharing does not grant dashboard or VM access and does not change your guardrails.
    </p>
    <div className="flex flex-wrap gap-2">
      <Button type="submit" disabled={busy || !dirty}>{busy ? "Working..." : "Save report settings"}</Button>
      <Button type="button" variant="outline" disabled={busy || dirty} onClick={() => void act("preview")}>Preview report</Button>
      <Button type="button" variant="outline" disabled={busy || dirty || !preview}
        onClick={() => void act("send")}>Send report</Button>
    </div>
    {preview && <div className="min-w-0 space-y-2">
      <p className="text-sm">This exact snapshot will be sent. Preview expires {dateTime(preview.expires_at)}.</p>
      <ReportPreview key={preview.report.report_id} report={preview.report} />
    </div>}
    <div className="space-y-1 text-sm text-muted-foreground">
      <p>Pending reports: {settings.delivery.pending}. Failed reports: {settings.delivery.failed}.</p>
      <p>{settings.delivery.last_sent_at ? `Last delivered: ${dateTime(settings.delivery.last_sent_at)}` : "No reports delivered yet."}</p>
      {settings.next_report_at && <p>Next automatic report: {dateTime(settings.next_report_at)}.</p>}
      {settings.delivery.failed > 0 && <p>Ask an operator to check the receiver and upload credential, then preview and send a new report.</p>}
    </div>
    {notice && <p role="status" className="text-sm">{notice}</p>}
    {error && <ErrorState message={error} />}
  </form>;
}

export function SummaryReportSharing() {
  const { user } = useDashboard();
  const resource = useResource<ReportSettings>(hasRole(user, "it_admin") ? "settings/summary-reports" : null);
  if (!hasRole(user, "it_admin") || (!resource.error && !resource.data?.available)) return null;
  return <PageSection title="Share reports with OpenSecura" description="Help improve guardrails and detections."
    action={<Button variant="outline" size="sm" disabled={resource.loading} onClick={() => void resource.reload()}>Refresh</Button>}>
    {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
    {resource.data && !resource.error &&
      <ReportForm key={resource.data.version} settings={resource.data} saved={resource.setData} refresh={resource.reload} />}
  </PageSection>;
}
