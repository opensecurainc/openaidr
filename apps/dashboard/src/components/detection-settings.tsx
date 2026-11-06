"use client";

import { hasRole } from "@/lib/roles";

import { useState } from "react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { api } from "@/lib/api";
import { creditLimit } from "@/lib/credits";
import { useResource } from "@/lib/use-resource";

type Settings = { enabled: boolean; version: number; detector_config_version: number; selection_policy: string; [key: string]: unknown };
const selectionFields = [
  ["investigation_percent", "Target sessions investigated (%)", 0.001, 100, "any"],
  ["history_days", "Recent history window (days)", 1, 90, "1"],
  ["action_risk_threshold", "High-risk action threshold", 1, 100, "1"],
  ["urgent_risk_threshold", "Urgent action threshold", 1, 100, "1"],
  ["session_high_risk_actions", "Distinct high-risk actions per session", 1, undefined, "1"],
  ["user_high_risk_actions", "Distinct high-risk actions across user sessions", 1, undefined, "1"],
] as const;
const executionFields = [
  ["risk_threshold", "Legacy accumulated risk threshold", 0, undefined, "any"],
  ["idle_seconds", "Session idle time (seconds)", 1, undefined, "1"],
  ["delivery_grace_seconds", "Delivery grace (seconds)", 0, undefined, "1"],
  ["gap_wait_seconds", "Wait for missing evidence (seconds)", 0, undefined, "1"],
  ["max_runtime_seconds", "Runtime per attempt (seconds)", 1, undefined, "1"],
  ["max_attempts", "Maximum attempts per investigation", 1, undefined, "1"],
  ["max_concurrent", "Maximum concurrent investigations", 1, undefined, "1"],
  ["hourly_attempts", "Maximum attempts per hour", 1, undefined, "1"],
  ["retry_delay_seconds", "Retry delay (seconds)", 0, undefined, "1"],
] as const;

const creditFields = [["max_credits_per_attempt", "Maximum credits per attempt"], ["hourly_credits", "Maximum credits per hour"]] as const;
function validCreditLimits(attempt: unknown, hourly: unknown) {
  if (attempt === null && hourly === null) return true;
  const lower = creditLimit(attempt), upper = creditLimit(hourly);
  return lower !== null && upper !== null && upper >= lower;
}
function validWeeklyLimit(attempt: unknown, weekly: unknown) {
  if (weekly === null) return true;
  const limit = creditLimit(weekly), lower = creditLimit(attempt);
  return limit !== null && (attempt === null || lower !== null && limit >= lower);
}

export function DetectionSettings() {
  const { user } = useDashboard();
  const editable = hasRole(user, "security_analyst");
  const resource = useResource<Settings>(user ? "response/session-detection" : null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const data = resource.data;
  const valid = data && typeof data.enabled === "boolean";
  const weeklySupported = data && Object.hasOwn(data, "weekly_credits");
  const visibleCreditFields = weeklySupported ? [...creditFields, ["weekly_credits", "Maximum credits in seven days"]] : creditFields;
  const creditSupported = data && creditFields.every(([key]) => Object.hasOwn(data, key))
    && validCreditLimits(data.max_credits_per_attempt, data.hourly_credits)
    && (!weeklySupported || validWeeklyLimit(data.max_credits_per_attempt, data.weekly_credits));
  const creditUnavailable = data && creditFields.some(([key]) => Object.hasOwn(data, key)) && !creditSupported;
  const numericFields = (fields: typeof selectionFields | typeof executionFields) => <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
    {fields.map(([key, label, min, max, step]) => <label key={key} className="min-w-0 space-y-1 text-sm">
      <span className="block">{label}</span><Input name={key} type="number" min={min} max={max} step={step}
        defaultValue={data?.[key] == null ? "" : String(data[key])} aria-label={label} />
    </label>)}
  </div>;
  const save = async (form: HTMLFormElement) => {
    const values = new FormData(form);
    const payload: Record<string, unknown> = { enabled: values.get("enabled") === "on", selection_policy: values.get("selection_policy"), gap_policy: values.get("gap_policy") || null };
    for (const [key, , , , step] of [...selectionFields, ...executionFields]) {
      const value = String(values.get(key) ?? "");
      payload[key] = value === "" ? null : step === "any" ? value : Number(value);
    }
    if (creditSupported) {
      for (const [key] of visibleCreditFields) payload[key] = String(values.get(key) ?? "").trim() || null;
      if (!validCreditLimits(payload.max_credits_per_attempt, payload.hourly_credits)) {
        setSaved(false);
        setError("Enter both credit limits or leave both blank. Use nonnegative decimals with up to six decimal places, no more than 9007199254.740991 credits. The hourly limit must be at least the per-attempt limit.");
        return;
      }
      if (weeklySupported && !validWeeklyLimit(payload.max_credits_per_attempt, payload.weekly_credits)) {
        setSaved(false);
        setError("Enter a valid seven-day credit limit at least as large as the per-attempt limit, or leave it blank. Use nonnegative decimals with up to six decimal places, no more than 9007199254.740991 credits.");
        return;
      }
    }
    setSaving(true); setError(""); setSaved(false);
    try {
      resource.setData(await api<Settings>("response/session-detection", { method: "PUT", body: JSON.stringify(payload) }));
      setSaved(true);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to save investigation settings."); }
    finally { setSaving(false); }
  };
  return <PageSection title="Investigation settings" description="An independent scheduler selects sessions for detailed reports. The investigation target is a budget, not a required finding rate.">
    <div className="space-y-4">
      {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
      {!data && !resource.error && <LoadingState label="Loading investigation settings…" />}
      {data && !valid && <ErrorState message="Investigation settings are unavailable in this response." />}
      {valid && <form key={data.version} onSubmit={(event) => { event.preventDefault(); void save(event.currentTarget); }} className="space-y-4">
        {!editable && <p className="text-sm text-muted-foreground">A Security Analyst can change investigation settings.</p>}
        <fieldset disabled={!editable || saving} className="space-y-4 disabled:opacity-70">
          <label className="flex items-center gap-2 text-sm font-medium"><input name="enabled" type="checkbox" defaultChecked={data.enabled} />Enable session investigations</label>
          <label className="block max-w-md space-y-1 text-sm"><span>Selection policy</span>
            <NativeSelect name="selection_policy" aria-label="Selection policy" defaultValue={data.selection_policy} variant="form" className="w-full">
              <option value="risk_budget">Session and user risk with investigation budget</option>
              <option value="legacy">Legacy accumulated session risk</option>
            </NativeSelect>
          </label>
          <p className="max-w-3xl text-xs text-muted-foreground">Session and user risk selection requires the configured risk thresholds. Urgent activity can exceed the target. Investigations run within the service allowance and execution limits. Reusing live Guardrail scores makes no additional requests. User accumulation requires verified ownership. A negative report never grants a safe period.</p>
          {numericFields(selectionFields)}
          {creditUnavailable && <p className="text-sm text-muted-foreground">Credit limits are unavailable in this response.</p>}
          {creditSupported && <fieldset className="space-y-3">
            <legend className="text-sm font-medium">Customer credit limits</legend>
            <p className="max-w-3xl text-xs text-muted-foreground">Enter both per-attempt and hourly limits or leave both blank. The hourly limit must be at least the per-attempt limit. Limits do not add credits. $1 = 100 credits.</p>
            {weeklySupported && <p className="max-w-3xl text-xs text-muted-foreground">The optional seven-day limit covers a rolling seven days of confirmed charges plus all pending reservations. Pending reservations stay held until resolved. Leave this limit blank for no weekly cap.</p>}
            <div className="grid gap-4 sm:grid-cols-2">
              {visibleCreditFields.map(([key, label]) => <label key={key} className="min-w-0 space-y-1 text-sm">
                <span className="block">{label}</span><Input name={key} inputMode="decimal"
                  defaultValue={data[key] == null ? "" : String(data[key])} aria-label={label} />
              </label>)}
            </div>
          </fieldset>}
          <details><summary className="w-fit cursor-pointer py-2 text-sm font-medium">Runtime and evidence limits</summary>
            <div className="space-y-4 pt-3">
              <p className="text-xs text-muted-foreground">Execution limits must be set before enabling investigations. Service allowance is managed separately.</p>
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="space-y-1 text-sm"><span>Missing evidence policy</span><NativeSelect name="gap_policy" aria-label="Missing evidence policy" defaultValue={String(data.gap_policy ?? "")} variant="form" className="w-full">
                  <option value="">Select a policy</option><option value="retain">Retain without investigation</option><option value="investigate">Investigate with explicit gaps</option>
                </NativeSelect></label>
              </div>
              {numericFields(executionFields)}
            </div>
          </details>
        </fieldset>
        {error && <ErrorState message={error} />}
        {saved && <p role="status" className="text-sm">Investigation settings saved.</p>}
        {editable && <Button type="submit" disabled={saving}>{saving ? "Saving…" : "Save investigation settings"}</Button>}
      </form>}
    </div>
  </PageSection>;
}
