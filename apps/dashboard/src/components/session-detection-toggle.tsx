"use client";

import Link from "next/link";
import { useState } from "react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { hasRole } from "@/lib/roles";
import { useResource } from "@/lib/use-resource";

type Settings = {
  enabled: boolean; version: number;
  availability: { reason: string };
};
const reasons: Record<string, string> = {
  ready: "Investigations are enabled. Sessions are selected within the configured risk and spending limits.",
  tenant_disabled: "Investigations are off. Existing evidence and reports remain available.",
  scheduling_disabled: "Investigations are enabled, but server scheduling is off. Contact your administrator.",
  provider_unavailable: "Investigations are enabled, but the Intelligence service is unavailable. Contact your administrator.",
  worker_unavailable: "Investigations are enabled, but an investigation worker is not available. Contact your administrator.",
  readiness_unknown: "Investigations are enabled. Worker readiness has not yet been confirmed.",
};
function valid(value: Settings) {
  return Boolean(value && typeof value.enabled === "boolean" && Number.isInteger(value.version)
    && typeof value.availability?.reason === "string");
}

export function SessionDetectionToggle() {
  const { user } = useDashboard();
  const permitted = hasRole(user, "it_admin");
  const resource = useResource<Settings>(user && permitted ? "settings/session-detection" : null, 0, false, { validate: valid });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const data = resource.data;
  async function toggle() {
    if (!data || saving) return;
    setSaving(true); setError(""); setNotice("");
    try {
      const result = await api<Settings>("settings/session-detection", { method: "PUT",
        body: JSON.stringify({ enabled: !data.enabled, version: data.version }) });
      if (!valid(result)) throw new Error("The server did not confirm the investigation setting.");
      resource.setData(result);
      setNotice(result.enabled ? "Investigations turned on." : "Investigations turned off.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to save investigation settings.");
      await resource.reload();
    } finally { setSaving(false); }
  }
  if (!permitted) return null;
  return <PageSection title="Session investigations" description="Review selected sessions for risks and create investigation reports. Enabled by default for new or unconfigured tenants.">
    {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
    {!data && !resource.error && <LoadingState label="Loading investigation settings…" />}
    {data && <div className="space-y-3 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0 flex-1 basis-64">
          <p>{reasons[data.availability.reason] ?? "Investigation readiness is not confirmed."}</p>
        </div>
        <Button role="switch" aria-label="Session investigations" aria-checked={data.enabled}
          variant={data.enabled ? "default" : "outline"} disabled={saving || resource.loading || !!resource.error}
          onClick={() => void toggle()}>{saving ? "Saving…" : data.enabled ? "On" : "Off"}</Button>
      </div>
      <p className="text-xs text-muted-foreground">Turning this off stops new investigations and further service requests. Captured activity, risk rankings, and existing reports are retained.</p>
      {hasRole(user, "security_analyst") && <Link href="/detection-rules" className="inline-block underline underline-offset-4">Edit investigation selection and limits</Link>}
    </div>}
    {error && <div className="mt-3"><ErrorState message={error} onRetry={resource.reload} /></div>}
    {notice && <p role="status" className="mt-3 text-sm">{notice}</p>}
  </PageSection>;
}
