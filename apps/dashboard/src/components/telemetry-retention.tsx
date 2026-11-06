"use client";

import { hasRole } from "@/lib/roles";

import { useId, useState } from "react";
import { useDashboard } from "@/components/dashboard-context";
import { useTimeZone } from "@/components/time-zone-context";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { api } from "@/lib/api";
import { useResource } from "@/lib/use-resource";
import { cn } from "@/lib/utils";

type Retention = {
  mode: string | null;
  cleanup_threshold_percent: number | null;
  version: number;
  message: string;
  status: string;
  automatic_available: boolean;
  last_cleanup_at: string | null;
};
const choices = [
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "unlimited", label: "Unlimited" },
];
const thresholds = [
  ...[70, 80, 90].map((value) => ({ value: String(value), label: `${value}%` })),
  { value: "", label: "Turn off" },
];

function RetentionControl({ label, choices, value, onChange, disabled }: {
  label: string;
  choices: { value: string; label: string; disabled?: boolean }[];
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  const name = useId();
  const selected = choices.findIndex((choice) => choice.value === value);
  return (
    <fieldset disabled={disabled} className="min-w-0 space-y-2">
      <legend className="text-sm font-medium">{label}</legend>
      <div className={cn("relative isolate grid h-10 max-w-full text-sm font-medium sm:h-8", disabled && "opacity-50")}
        style={{ width: `${choices.length * 5}rem`, gridTemplateColumns: `repeat(${choices.length}, minmax(0, 1fr))` }}>
        <span aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10 rounded-md border border-input bg-card">
          {selected >= 0 && <span className="absolute inset-y-[3px] left-[3px] rounded-sm bg-primary transition-transform motion-reduce:transition-none"
            style={{ width: `calc((100% - 6px) / ${choices.length})`, transform: `translateX(${selected * 100}%)` }} />}
        </span>
        {choices.map((choice) => (
          <label key={choice.value} className={cn(
            "relative flex items-center justify-center rounded-md select-none focus-within:underline focus-within:decoration-2 focus-within:underline-offset-4",
            disabled || choice.disabled ? "cursor-default" : "cursor-pointer",
            choice.disabled && !disabled && "opacity-50",
            choice.value === value ? "text-primary-foreground" : "text-muted-foreground",
          )}>
            <input className="absolute inset-0 size-full cursor-pointer opacity-0 disabled:cursor-default"
              type="radio" name={name} value={choice.value} checked={value === choice.value} disabled={choice.disabled}
              onChange={() => onChange(choice.value)} />
            {choice.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function RetentionForm({ settings, saved }: { settings: Retention; saved: (value: Retention) => void }) {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const [mode, setMode] = useState(settings.mode === "automatic" ? "unlimited" : settings.mode ?? "");
  const [threshold, setThreshold] = useState<number | null>(settings.cleanup_threshold_percent ?? null);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const permitted = hasRole(user, "it_admin");
  const label = choices.find((choice) => choice.value === mode)?.label;

  async function save() {
    setBusy(true);
    setError("");
    try {
      const result = await api<Retention>("settings/telemetry-retention", {
        method: "PUT",
        body: JSON.stringify({ mode, cleanup_threshold_percent: threshold, version: settings.version }),
      });
      setConfirm(false);
      saved(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to save retention.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-x-8 gap-y-4">
        <RetentionControl label="Retention period" choices={choices} value={mode} onChange={setMode} disabled={!permitted || busy} />
        <RetentionControl label="Auto-clean when disk usage reaches"
          choices={thresholds.map((choice) => ({ ...choice, disabled: choice.value !== "" && !settings.automatic_available }))}
          value={threshold === null ? "" : String(threshold)}
          onChange={(value) => setThreshold(value === "" ? null : Number(value))} disabled={!permitted || busy} />
      </div>
      <p className="text-sm text-muted-foreground">
        {threshold === null
          ? "Select a threshold to enable automatic disk cleanup."
          : `Automatic cleanup removes the oldest eligible telemetry at ${threshold}% disk usage and stops below ${threshold - 5}%.`}
        {" "}Telemetry is removed when either limit is reached. Unlimited disables age expiry only.
        {" "}Cleanup preserves data needed by unfinished processing.
      </p>
      {!settings.automatic_available && (
        <p className="text-sm text-muted-foreground">Automatic is unavailable until fresh measurements of the database disk are configured.</p>
      )}
      <p className="text-sm text-muted-foreground">
        Applies to raw telemetry and event history. Saved investigation evidence, findings, cost summaries, audit records, and backups are retained separately.
        {" "}Cleanup removes whole days, so data can remain slightly longer than the selected period. Deleted telemetry cannot be restored by increasing retention.
      </p>
      <p className="text-sm" role="status">{settings.message}</p>
      {settings.last_cleanup_at && <p className="text-sm text-muted-foreground">Last cleanup: {dateTime(settings.last_cleanup_at)}</p>}
      {permitted ? (
        <Button disabled={!mode || busy || (threshold !== null && !settings.automatic_available)} onClick={() => setConfirm(true)}>
          Save retention
        </Button>
      ) : <p className="text-sm text-muted-foreground">An IT Admin can change this policy.</p>}
      <Dialog open={confirm} onOpenChange={(open) => { if (!busy) setConfirm(open); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Save telemetry retention?</DialogTitle>
            <DialogDescription>
              {mode === "unlimited"
                ? "Telemetry will have no age limit."
                : `Telemetry older than ${label} becomes eligible for permanent deletion.`}
              {threshold === null
                ? " Automatic disk cleanup will be disabled."
                : ` Automatic cleanup can permanently delete younger telemetry when disk usage reaches ${threshold}%, and stops below ${threshold - 5}%.`}
              {" "}This also applies to telemetry already stored. Saved evidence and findings are retained separately.
            </DialogDescription>
          </DialogHeader>
          {error && <ErrorState message={error} />}
          <DialogFooter>
            <Button variant="outline" disabled={busy} onClick={() => setConfirm(false)}>Cancel</Button>
            <Button disabled={busy} onClick={() => void save()}>{busy ? "Saving..." : "Confirm retention"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export function TelemetryRetention() {
  const resource = useResource<Retention>("settings/telemetry-retention", 30000);
  return (
    <PageSection title="Telemetry retention" description="Control how long raw telemetry and event history are kept."
      action={<Button variant="outline" size="sm" disabled={resource.loading} onClick={() => void resource.reload()}>Refresh</Button>}>
      {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
      {resource.data
        ? <RetentionForm key={resource.data.version} settings={resource.data} saved={resource.setData} />
        : !resource.error && <LoadingState label="Loading telemetry retention" />}
    </PageSection>
  );
}
