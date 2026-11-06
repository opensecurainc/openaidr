"use client";

import { useRef } from "react";
import { ArrowRight, RefreshCw } from "lucide-react";
import {
  ErrorState,
  LoadingState,
  PageNotice,
  PageSection,
} from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { useTimeZone } from "@/components/time-zone-context";
import { number } from "@/lib/api";
import { useResource } from "@/lib/use-resource";
import Link from "next/link";

type Pipeline = {
  range: string;
  since: string;
  until: string;
  actions_scored: number;
  sessions_scored: number;
  sessions_inspected: number;
  sessions_with_alerts: number;
  alerts: number;
  sessions_eligible: number;
  sessions_escalated: number;
  selection_policy?: string;
  investigation_percent?: string | null;
  history_days?: number | null;
  reports?: number;
  actionable_reports?: number;
  no_finding_reports?: number;
  inconclusive_reports?: number;
  pending_investigations?: number;
  sessions_selected?: number;
  criteria?: {
    action_risk_threshold: number | null; urgent_risk_threshold: number | null;
    session_high_risk_actions: number | null; user_high_risk_actions: number | null;
    idle_seconds: number | null; delivery_grace_seconds: number | null;
    risk_threshold: string | null; gap_policy: string | null; gap_wait_seconds: number | null;
    max_concurrent: number | null; hourly_attempts: number | null;
  };
  availability?: {
    tenant_enabled: boolean; scheduling_enabled: boolean | null; worker_ready: boolean | null;
    reason: string; checked_at: string | null;
  };
};

function StartCriteria({ data }: { data: Pipeline }) {
  const criteria = data.criteria;
  if (!criteria || !["risk_budget", "legacy"].includes(data.selection_policy ?? "")) return <p className="text-sm text-muted-foreground">Start criteria are not reported by this backend. View investigation settings for the current configuration.</p>;
  const setting = (value: string | number | null | undefined, unit = "") => value == null ? "Not configured" : `${value}${unit}`;
  return <div className="space-y-3 text-sm">
    <p>The scheduler runs independently of agent turns. Scoring an action does not automatically start an investigation.</p>
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="space-y-2"><h3 className="font-semibold">1. Enable and prepare</h3>
        <p>Tenant investigations and server scheduling must be on, with a ready investigation service for this tenant.</p>
        <p>Normally, the session must end or become idle, and pending assessments and evidence delivery must settle.</p>
        <p className="text-muted-foreground">Idle threshold: {setting(criteria.idle_seconds, " seconds")}. Delivery grace: {setting(criteria.delivery_grace_seconds, " seconds")}.</p>
        <p>The sensor must be active. Managed sessions need a verified, active owner. Ordinary sessions can use their own evidence without verified ownership.</p>
      </div>
      <div className="space-y-2"><h3 className="font-semibold">2. Select the session</h3>
        {data.selection_policy === "risk_budget" ? <>
          <p>Consider sessions active within the last {setting(data.history_days)} days. High-risk action score: at least {setting(criteria.action_risk_threshold)}.</p>
          <ul className="list-disc space-y-1 pl-5">
            <li><strong>Session risk:</strong> at least {setting(criteria.session_high_risk_actions)} distinct high-risk actions.</li>
            <li><strong>User pattern:</strong> at least {setting(criteria.user_high_risk_actions)} distinct high-risk actions across at least two verified user sessions. The latest high-risk session is the candidate.</li>
            <li><strong>Urgent risk:</strong> an action score of at least {setting(criteria.urgent_risk_threshold)} can trigger an investigation before the session ends and can exceed the percentage target.</li>
          </ul>
          <p>Non-urgent candidates that meet risk thresholds are ranked within a {setting(data.investigation_percent, "%")} investigation target. These thresholds do not guarantee selection. The target is not a required alert rate.</p>
        </> : <>
          <p>Legacy risk selection: accumulated session risk must be greater than {setting(criteria.risk_threshold)}. Percentage targets do not apply.</p>
          <p>Managed sessions with incomplete evidence can instead qualify under the missing-evidence policy, without exceeding the risk threshold.</p>
          <p className="text-muted-foreground">Missing-evidence policy: {criteria.gap_policy === "investigate" ? `Investigate after ${setting(criteria.gap_wait_seconds, " seconds")}` : criteria.gap_policy === "retain" ? "Retain evidence and wait" : "Not configured"}.</p>
        </>}
      </div>
      <div className="space-y-2"><h3 className="font-semibold">3. Admit and complete</h3>
        <p>The worker rechecks eligibility and must have capacity and enough budget for an attempt.{data.selection_policy === "risk_budget" && " Urgent cases still obey execution and spending limits."}</p>
        <p className="text-muted-foreground">Concurrent investigations: {setting(criteria.max_concurrent)}. Hourly limit: {setting(criteria.hourly_attempts)} attempts.</p>
        <p>Only one investigation runs at a time per verified user. Previously reviewed evidence is not a blanket clearance for future activity.</p>
        <p><strong>Sessions inspected</strong> counts distinct sessions started in the selected date range that have a completed investigation. Queued, running, and inconclusive investigations are excluded from this count.</p>
      </div>
    </div>
    <Link href="/detection-rules" className="inline-block font-medium underline underline-offset-4">View investigation settings</Link>
  </div>;
}

export function DetectionPipeline({ range, setRange }: { range: string; setRange: (range: string) => void }) {
  const criteriaRef = useRef<HTMLDetailsElement>(null);
  const { dateTime } = useTimeZone();
  const resource = useResource<Pipeline>(
    `detections/pipeline?range=${range}`,
    30_000,
  );
  const data = resource.data?.range === range ? resource.data : null;
  const zeroReason = data?.sessions_inspected === 0
    ? data.availability?.reason === "tenant_disabled" ? "Investigations are off for this tenant."
      : data.availability?.reason === "scheduling_disabled" ? "Server scheduling is off."
      : (data.pending_investigations ?? 0) > 0 ? "Investigations are awaiting reports; none have completed in this date range."
      : (data.inconclusive_reports ?? 0) > 0 ? "Inconclusive investigations do not count as completed inspections."
      : data.availability?.reason === "worker_unavailable" ? "No ready investigation worker is available."
      : data.availability?.reason !== "ready" ? "Investigation readiness has not been confirmed."
      : data.sessions_selected === 0 ? "No sessions have been selected in this date range."
      : "No investigation has completed for sessions in this date range."
    : null;
  const stages = data
    ? [
        {
          label: "Actions scored",
          count: data.actions_scored,
          model: "By Guardrail model",
          detail: `Across ${number(data.sessions_scored)} ${data.sessions_scored === 1 ? "session" : "sessions"}`,
        },
        {
          label: "Sessions inspected",
          count: data.sessions_inspected,
          model: "By detection model",
          detail: "Completed investigations",
        },
        {
          label: "Sessions with alerts",
          count: data.sessions_with_alerts,
          model: "From detection model",
          detail: `${number(data.alerts)} ${data.alerts === 1 ? "alert" : "alerts"} created`,
        },
      ]
    : [];
  const escalation =
    data && data.sessions_eligible > 0
      ? new Intl.NumberFormat(undefined, {
          style: "percent",
          maximumFractionDigits: 2,
        }).format(data.sessions_escalated / data.sessions_eligible)
      : null;

  return (
    <PageSection
      title="Detection pipeline"
      description={`Progress for captured sessions started in the last ${range.slice(0, -1)} days.`}
      action={
        <>
          <div
            role="group"
            aria-label="Pipeline date range"
            className="flex gap-1 rounded-md bg-muted p-1"
          >
            {["7d", "30d", "90d"].map((value) => (
              <Button
                key={value}
                size="responsive"
                variant={range === value ? "outline" : "ghost"}
                aria-pressed={range === value}
                onClick={() => setRange(value)}
              >
                {value.slice(0, -1)} days
              </Button>
            ))}
          </div>
          <Button
            variant="outline"
            size="header-icon"
            aria-label="Refresh detection pipeline"
            disabled={resource.loading}
            onClick={() => void resource.reload()}
          >
            <RefreshCw aria-hidden="true" />
          </Button>
        </>
      }
    >
      {resource.error && (
        <ErrorState
          title="Unable to load detection pipeline"
          message={`${resource.error}${data ? " Showing the last successful counts." : ""}`}
          onRetry={resource.reload}
        />
      )}
      {!data && !resource.error && (
        <LoadingState label="Loading detection pipeline…" />
      )}
      {data && (
        <>
          <div className="mb-4" aria-label="Investigation availability">
            <PageNotice title={data.availability?.reason === "ready" ? "Session investigations are enabled" : data.availability?.reason === "tenant_disabled" ? "Session investigations are off" : data.availability?.reason === "scheduling_disabled" ? "Investigation scheduling is off" : "Investigation readiness is not confirmed"}>
              <p>{data.availability?.reason === "tenant_disabled" ? "Enable tenant investigations and configure their execution limits to start selection. A configured percentage alone does not enable detection." : data.availability?.reason === "scheduling_disabled" ? "Server scheduling is disabled. An operator must enable it before selected sessions can be investigated." : data.availability?.reason === "ready" ? "The tenant is enabled and a recent worker heartbeat reports readiness. Selection, execution limits, and service allowance still apply." : "A recent, compatible detection worker has not confirmed readiness. Missing status does not mean sessions are safe."}</p>
              {data.availability && <p>Tenant detection: {data.availability.tenant_enabled ? "On" : "Off"} · Server scheduling: {data.availability.scheduling_enabled == null ? "Not reported" : data.availability.scheduling_enabled ? "On" : "Off"} · Worker: {data.availability.worker_ready == null ? "Not reported" : data.availability.worker_ready ? "Ready" : "Not ready"}</p>}
              <Link href="/detection-rules" className="font-medium underline underline-offset-4">View investigation settings</Link>
            </PageNotice>
          </div>
          <ol
            aria-label="Detection stages"
            className="grid grid-cols-1 gap-8 md:grid-cols-3"
          >
            {stages.map((stage, index) => (
              <li
                key={stage.label}
                className="relative min-w-0 rounded-lg border bg-card p-4"
              >
                <p className="text-sm font-medium">{stage.label}</p>
                <p
                  className="figure mt-2 text-display font-semibold"
                  title={String(stage.count)}
                >
                  {number(stage.count)}
                </p>
                <p className="mt-2 text-sm">{stage.model}</p>
                <p className="mt-1 text-xs text-muted-foreground">{stage.detail}</p>
                {index === 1 && <>
                  {zeroReason && <p className="mt-2 text-sm" role="status">{zeroReason}</p>}
                  <Button variant="link" size="responsive" className="mt-1 px-0" onClick={() => {
                    if (criteriaRef.current) { criteriaRef.current.open = true; criteriaRef.current.scrollIntoView({ block: "nearest" }); criteriaRef.current.querySelector("summary")?.focus(); }
                  }}>View detection start criteria</Button>
                </>}
                {index < stages.length - 1 && (
                  <ArrowRight
                    aria-hidden="true"
                    className="absolute -bottom-6 left-1/2 size-4 -translate-x-1/2 rotate-90 text-muted-foreground md:-right-6 md:bottom-auto md:left-auto md:top-1/2 md:translate-x-0 md:-translate-y-1/2 md:rotate-0"
                  />
                )}
              </li>
            ))}
          </ol>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t pt-3 text-xs text-muted-foreground">
            <p>
              {data.selection_policy === "risk_budget" ? (
                <>{number(data.sessions_selected ?? 0)} sessions selected for investigation</>
              ) : escalation === null ? (
                "No eligible sessions yet."
              ) : (
                <>
                  Risk-based escalation:{" "}
                  <span className="number font-medium text-foreground">{escalation}</span>
                  {` · ${number(data.sessions_escalated)} of ${number(data.sessions_eligible)} eligible sessions`}
                </>
              )}
              {data.selection_policy === "risk_budget" && data.investigation_percent != null && ` · Configured target: ${data.investigation_percent}%`}
            </p>
            <p>As of {dateTime(data.until)}</p>
          </div>
          {data.reports !== undefined && <dl className="mt-4 grid grid-cols-2 gap-4 text-sm sm:grid-cols-3 xl:grid-cols-5" aria-label="Investigation outcomes">
            {([
              ["Reports", data.reports], ["Actionable", data.actionable_reports],
              ["No actionable findings", data.no_finding_reports], ["Inconclusive", data.inconclusive_reports],
              ["Awaiting report", data.pending_investigations],
            ] as const).map(([label, count]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="number mt-1 font-semibold">{count == null ? "Unavailable" : number(count)}</dd></div>)}
          </dl>}
        </>
      )}
      <div className="mt-3">
        {data && <details ref={criteriaRef} className="mb-3 rounded-md border p-3">
          <summary className="min-h-10 cursor-pointer py-2 text-sm font-medium focus-visible:outline-2 focus-visible:outline-ring">When detection starts</summary>
          <div className="mt-2"><StartCriteria data={data} /></div>
        </details>}
        <PageNotice title="How pipeline counts work" collapsible>
          <p>
            All stages follow the same captured sessions, using their recorded start time.
            Actions include scored prompts, tool calls, tool outputs, and responses.
            Retries and duplicate observations do not add another action or session.
            Pending and inconclusive investigations are excluded from completed inspections.
            Alerts count published detection-model findings in any status.
          </p>
          <p>
            The background scheduler runs independently of agent turns. Its configured
            policy selects sessions using session risk and verified user history.
            Urgent activity can exceed the target and can trigger a
            review before a session ends. Legacy selection uses accumulated session risk.
            Missing delivery records remain evidence gaps. Individual policy findings are outside this pipeline.
          </p>
          <p>Report counts include negative and inconclusive outcomes. Multiple findings in one report do not add reports. Sessions retrieved only as context do not add selected sessions. Counts here follow the session start window, not the rolling admission budget.</p>
          {data?.selection_policy === "risk_budget" && <p>Recent history window: {data.history_days ?? "not reported"} days.</p>}
          {data && (
            <p>Session start window: {dateTime(data.since)} to {dateTime(data.until)}.</p>
          )}
        </PageNotice>
      </div>
    </PageSection>
  );
}
