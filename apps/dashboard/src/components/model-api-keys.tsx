"use client";

import { hasRole } from "@/lib/roles";

import { useState } from "react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, dateTime } from "@/lib/api";
import { displayText } from "@/lib/display";
import { useResource } from "@/lib/use-resource";

type Routing = { mode: "intelligence"; origin: string; credential_configured: boolean;
  trust: "private_ca" | "system"; capability_status: "unverified" | "unavailable";
  version?: number; tenant_id?: string; credential_management?: boolean;
  environments?: { origin: string; label: string; credential_configured?: boolean; saved_key?: boolean }[] };
type Keys = { routing: Routing; verification?: CapabilityCheck };
const capabilityLabels = {
  url_reputation: "URL reputation", package_vulnerabilities: "Package vulnerabilities", guardrail: "Guardrail",
  application_research: "Application research", assistant: "OpenAIDR Assistant", rule_generation: "Detection rule generation",
  overview_summaries: "Overview summaries", session_summaries: "Session summaries", skill_assessment: "Skill assessment",
  investigations: "Investigations",
};
const capabilityStates = { configured: "Configured", provider_unconfigured: "Provider not configured", runtime_unavailable: "Runtime unavailable" };
type CapabilityCheck = { origin: string; build: string; checked_at: string;
  capabilities: Record<keyof typeof capabilityLabels, keyof typeof capabilityStates> };

function ServiceCapabilities({ origin, environment, disabled, verification }: { origin: string; environment?: string; disabled: boolean; verification?: CapabilityCheck }) {
  const [result, setResult] = useState<CapabilityCheck | null>(verification?.origin === origin ? verification : null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  async function check() {
    setChecking(true);
    setResult(null);
    setError("");
    try {
      const checked = await api<CapabilityCheck>("settings/intelligence/check", { method: "POST", body: "{}" });
      if (checked.origin !== origin) throw new Error("The service connection changed. Reload Settings before checking again.");
      setResult(checked);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to check the selected service.");
    } finally {
      setChecking(false);
    }
  }
  return <div className="space-y-3">
    <Button type="button" disabled={checking || disabled} onClick={() => void check()}>{checking ? "Checking connection..." : "Check connection"}</Button>
    {error && <ErrorState title={`Unable to check ${environment ? displayText(environment) : "service"}`} message={error} />}
    {result ? <>
      <p role="status" className="text-sm">Service authenticated{environment ? ` for ${displayText(environment)}` : ""}. Checked {dateTime(result.checked_at)}.</p>
      <details className="space-y-3">
      <summary className="cursor-pointer text-sm">Service details</summary>
      <p className="break-all text-sm text-muted-foreground">Service build: {displayText(result.build)}</p>
      <dl aria-label="Intelligence capability configuration" className="divide-y text-sm">
        {Object.entries(capabilityLabels).map(([name, label]) => <div key={name} className="grid grid-cols-2 gap-4 py-2">
          <dt className="min-w-0">{label}</dt>
          <dd className="min-w-0">{capabilityStates[result.capabilities[name as keyof typeof capabilityLabels]]}</dd>
        </div>)}
      </dl>
      </details>
    </> : !checking && !error && <p role="status" className="text-sm text-muted-foreground">Capability availability has not been verified.</p>}
    <p className="text-sm text-muted-foreground">This check verifies service configuration and installed runtimes without model requests. Provider access, quota and investigation worker liveness are not tested. Configured capabilities do not guarantee that requests can complete.</p>
  </div>;
}

export function ModelApiKeys() {
  const { user } = useDashboard();
  const permitted = hasRole(user, "it_admin");
  const resource = useResource<Keys>(permitted ? "settings/model-keys" : null);
  const routing = resource.data?.routing;
  const environment = routing?.environments?.find((item) => item.origin === routing.origin)?.label;
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<{ title: string; message: string } | null>(null);
  const [notice, setNotice] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [key, setKey] = useState("");

  async function select(origin: string) {
    if (!routing || saving || origin === routing.origin) return;
    setSaving(true); setError(null); setNotice("");
    try {
      const result = await api<Keys>("settings/intelligence", { method: "PUT",
        body: JSON.stringify({ origin, version: routing.version }) });
      if (result.routing?.origin !== origin || !result.routing.credential_configured)
        throw new Error("The server did not confirm the service selection. Reload Settings.");
      resource.setData(result);
      setEditing(null); setKey("");
      setNotice(`${displayText(routing.environments?.find((item) => item.origin === origin)?.label || "Service")} is active. New requests use this environment.`);
    } catch (cause) {
      setError({ title: `Unable to switch to ${displayText(routing.environments?.find((item) => item.origin === origin)?.label || origin)}`,
        message: cause instanceof Error ? cause.message : "Unable to switch the service." });
      await resource.reload();
    } finally { setSaving(false); }
  }

  async function saveKey(origin: string) {
    if (!routing || saving || !key.trim()) return;
    setSaving(true); setError(null); setNotice("");
    const apiKey = key.trim();
    try {
      const result = await api<Keys>("settings/intelligence/key", { method: "PUT",
        body: JSON.stringify({ origin, api_key: apiKey, version: routing.version, activate: true }) });
      if (result.routing?.origin !== origin || !result.routing.credential_configured)
        throw new Error("The server did not confirm the connection. Reload Settings before trying again.");
      resource.setData(result);
      setKey(""); setEditing(null);
      setNotice(`${displayText(routing.environments?.find((item) => item.origin === origin)?.label || "Service")} is active. New requests use this environment.`);
    } catch (cause) {
      setError({ title: `Unable to connect to ${displayText(routing.environments?.find((item) => item.origin === origin)?.label || origin)}`,
        message: cause instanceof Error ? cause.message : "Unable to save the service key." });
      await resource.reload();
    } finally { setSaving(false); }
  }

  if (!permitted) return null;
  return <PageSection title="Intelligence service" description="Service connection and capability availability for this workspace.">
    {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
    {routing ? <div className="space-y-3">
        {!!routing.environments?.length && <div className="space-y-2">
          {routing.environments.map((item) => {
            const active = routing.origin === item.origin;
            const label = displayText(item.label);
            const busy = saving || resource.loading || !!resource.error;
            return <div key={item.origin} role="group" aria-label={`${label} environment`} className="space-y-3 rounded-md border p-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div><p className="font-medium">{label}</p><p className="text-sm text-muted-foreground">
                  {item.credential_configured ? active ? "Active" : "Available" : "Not connected"}
                </p></div>
                <div className="flex flex-wrap gap-2">
                  {!active && item.credential_configured && <Button type="button" disabled={busy}
                    onClick={() => void select(item.origin)}>Use {label}</Button>}
                  {routing.credential_management && editing !== item.origin && <Button type="button" variant={item.credential_configured ? "outline" : "default"}
                    disabled={busy}
                    onClick={() => { setEditing(item.origin); setKey(""); setError(null); setNotice(""); }}>
                    {item.credential_configured ? `Replace ${label} key` : `Connect ${label}`}
                  </Button>}
                </div>
              </div>
              {editing === item.origin && <form className="space-y-3 border-t pt-3" onSubmit={(event) => { event.preventDefault(); void saveKey(item.origin); }}>
                <p className="text-sm">Use an existing {label} key or create one for this workspace.</p>
                <a className="block text-sm underline" href={`${item.origin}/admin/?tenant_id=${encodeURIComponent(routing.tenant_id || "")}`}
                  target="_blank" rel="noreferrer">Create {label} key (opens in a new tab)</a>
                <p className="break-all text-sm text-muted-foreground">Tenant ID: <span className="font-mono">{routing.tenant_id}</span></p>
                <label className="block text-sm" htmlFor={`key-${item.label}`}>{label} API key</label>
                <Input id={`key-${item.label}`} type="password" autoComplete="off" spellCheck={false} autoFocus
                  value={key} disabled={saving} onChange={(event) => { setKey(event.target.value); setError(null); }} placeholder="Paste the complete key" />
                <p className="text-sm text-muted-foreground">{active ? `The verified key will replace the current ${label} key.` : `After verification, new workspace requests will use ${label}.`} Active requests finish on their original service.</p>
                <div className="flex flex-wrap gap-2">
                  <Button type="submit" disabled={busy || !key.trim()}>{saving ? "Verifying connection..." : active ? "Verify and update key" : `Verify and use ${label}`}</Button>
                  <Button type="button" variant="outline" disabled={saving}
                    onClick={() => { setEditing(null); setKey(""); setError(null); }}>Cancel</Button>
                </div>
              </form>}
            </div>;
          })}
          {routing.credential_management === false && <p className="text-sm text-muted-foreground">Ask a deployment administrator to enable encrypted key storage before saving environment keys.</p>}
          {saving && <p role="status" className="text-sm">Verifying service...</p>}
        </div>}
        {error && <ErrorState title={error.title} message={error.message} />}
        {notice && <p role="status" className="text-sm">{notice}</p>}
        <p className="break-all font-mono text-sm" aria-label="Intelligence service origin">{routing.origin}</p>
        <p className="text-sm">Service connection {routing.credential_configured ? "configured" : "requires a key"}. {routing.trust === "private_ca" ? "Private certificate authority." : "System certificate authorities."}</p>
        {routing.credential_configured
          ? <ServiceCapabilities key={`${routing.origin}:${routing.version}`} origin={routing.origin} environment={environment} disabled={saving} verification={resource.data?.verification} />
          : <ErrorState message={routing.credential_management ? "Save a key for the selected environment to use the Intelligence service." : "The Intelligence service is unavailable for this workspace. Ask an administrator to configure its connection."} />}
      <p className="text-sm text-muted-foreground">{routing.environments?.length
        ? "Each key is encrypted on the server and used only for its environment. Saved keys are never displayed. The deployment key remains available for its original endpoint."
        : "An administrator manages this connection in deployment configuration."} The service manages provider credentials.</p>
    </div> : !resource.error && <LoadingState label="Loading Intelligence service" />}
  </PageSection>;
}
