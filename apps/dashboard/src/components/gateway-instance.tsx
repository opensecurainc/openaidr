"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, APIError } from "@/lib/api";
import { displayText } from "@/lib/display";
import { hasRole } from "@/lib/roles";
import { useResource } from "@/lib/use-resource";
import { type CreatedGatewayCredential, type Gateway, type GatewayDetail, type GatewayMode, gatewayMetric, gatewayPluginLabel } from "@/lib/gateways";
import { useDashboard } from "@/components/dashboard-context";
import { useTimeZone } from "@/components/time-zone-context";
import { type Policy } from "@/components/fixed-rules";
import { GatewayCoverageNotice, GatewayCredentialSecret, GatewayHealth } from "@/components/gateways";
import { LiteLLMSetup } from "@/components/gateway-litellm-setup";
import { EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { CodeBlock, InlineCode } from "@/components/ui/code-block";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Status } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export function GatewayInstance({ id }: { id: string }) {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const result = useResource<GatewayDetail>(`gateways/${encodeURIComponent(id)}`);
  const [feedback, setFeedback] = useState("");
  const admin = hasRole(user, "it_admin");
  const analyst = hasRole(user, "security_analyst");
  const detail = result.data;
  return <div className="space-y-4">
    <Button asChild variant="outline" size="sm"><Link href="/gateways/overview">Gateway overview</Link></Button>
    {result.error && <ErrorState message={result.error} onRetry={() => void result.reload()} />}
    {feedback && <p role="status" className="text-sm">{feedback}</p>}
    {!detail ? !result.error && <LoadingState /> : <>
      <PageSection title={detail.gateway.name} description={`${gatewayPluginLabel(detail.gateway.kind)} · ${detail.gateway.environment || "Environment not reported"}`} action={<><GatewayHealth status={detail.gateway.status} /><Button variant="outline" size="sm" onClick={() => void result.reload()} disabled={result.loading}>Refresh</Button>{analyst && <Button asChild variant="outline" size="sm"><Link href={`/guardrail/history?source=gateways&gateway_id=${encodeURIComponent(id)}`}>View requests</Link></Button>}</>}>
        <dl className="grid gap-4 text-sm sm:grid-cols-3"><div><dt className="text-xs text-muted-foreground">Policy mode</dt><dd className="mt-1">{detail.gateway.mode === "enforce" ? "Enforce" : "Shadow"}</dd></div><div><dt className="text-xs text-muted-foreground">Last heartbeat</dt><dd className="mt-1">{dateTime(detail.gateway.last_seen_at)}</dd></div><div><dt className="text-xs text-muted-foreground">Backend content permission</dt><dd className="mt-1">{detail.gateway.capture_content ? "Enabled; the plugin must also opt in" : "Off"}</dd></div></dl>
      </PageSection>
      <PageSection title="Nodes" description="Heartbeat health is independent of request volume. Dropped events are known collection losses, not a complete loss rate.">
        {!detail.nodes.length ? <EmptyState title="Awaiting a node heartbeat" description="Configure the plugin on each gateway node. No health conclusion is available before the first heartbeat." /> : <TableLayout><Table><TableHeader><TableRow><TableHead>Node</TableHead><TableHead>Plugin version</TableHead><TableHead>Gateway version</TableHead><TableHead>Heartbeat</TableHead><TableHead>Dropped events</TableHead><TableHead>Last seen</TableHead></TableRow></TableHeader><TableBody>{detail.nodes.map((node) => <TableRow key={node.node_id}><TableCell><InlineCode>{node.node_id}</InlineCode></TableCell><TableCell>{node.plugin_version || "Not reported"}</TableCell><TableCell>{(node.gateway_version ?? (detail.gateway.kind === "kong" ? node.kong_version : "")) || "Not reported"}</TableCell><TableCell><Status tone={node.status === "reporting" ? "ok" : "warning"}>{node.status === "reporting" ? "Reporting" : "Heartbeat delayed"}</Status></TableCell><TableCell>{gatewayMetric(node.dropped_events)}</TableCell><TableCell>{dateTime(node.last_seen_at)}</TableCell></TableRow>)}</TableBody></Table></TableLayout>}
      </PageSection>
      <Tabs defaultValue={detail.gateway.status === "never_seen" ? "setup" : "routes"} className="gap-4"><TabsList aria-label="Instance details"><TabsTrigger value="routes">Routes</TabsTrigger><TabsTrigger value="settings">Settings</TabsTrigger><TabsTrigger value="setup">Setup</TabsTrigger></TabsList>
        <TabsContent value="routes" className="space-y-4"><GatewayCoverageNotice /><PageSection title="Reported routes" description="These routes have been observed by the plugin. Other gateway routes may be unprotected.">
          {!detail.routes.length ? <EmptyState title="No reported routes" description="Routes appear after the plugin reports activity. An idle node may still have a current heartbeat." /> : <TableLayout><Table><TableHeader><TableRow><TableHead>Route</TableHead><TableHead>Service</TableHead><TableHead>Node</TableHead><TableHead>Protocol</TableHead><TableHead>Last seen</TableHead></TableRow></TableHeader><TableBody>{detail.routes.map((route) => <TableRow key={`${route.node_id}:${route.route_id}:${route.service_id}`}><TableCell><InlineCode>{route.route_id || "Not reported"}</InlineCode></TableCell><TableCell>{route.service_id || "Not reported"}</TableCell><TableCell><InlineCode>{route.node_id}</InlineCode></TableCell><TableCell>{route.protocol}</TableCell><TableCell>{dateTime(route.last_seen_at)}</TableCell></TableRow>)}</TableBody></Table></TableLayout>}
        </PageSection></TabsContent>
        <TabsContent value="settings" className="space-y-4"><ConnectionSettings key={`connection:${detail.gateway.version}`} gateway={detail.gateway} editable={admin} onSaved={() => { setFeedback("Connection saved."); void result.reload(); }} /><PolicySettings key={`policy:${detail.gateway.version}`} gateway={detail.gateway} editable={analyst} onSaved={() => { setFeedback("Gateway policy saved."); void result.reload(); }} /></TabsContent>
        <TabsContent value="setup"><GatewaySetup detail={detail} editable={admin} onChanged={() => void result.reload()} /></TabsContent>
      </Tabs>
    </>}
  </div>;
}

function ConnectionSettings({ gateway, editable, onSaved }: { gateway: Gateway; editable: boolean; onSaved: () => void }) {
  const [name, setName] = useState(gateway.name);
  const [environment, setEnvironment] = useState(gateway.environment);
  const [enabled, setEnabled] = useState(gateway.enabled);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const changed = name !== gateway.name || environment !== gateway.environment || enabled !== gateway.enabled;
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!editable) return; setBusy(true); setError(""); setSaved(false);
    try { await api<Gateway>(`gateways/${encodeURIComponent(gateway.id)}`, { method: "PATCH", body: JSON.stringify({ version: gateway.version, name: name.trim(), environment: environment.trim(), enabled }) }); setSaved(true); onSaved(); }
    catch (cause) { setError(cause instanceof APIError && cause.status === 409 ? "This connection changed. Refresh the instance and review the current settings before saving again." : cause instanceof Error ? cause.message : "Could not save connection settings."); }
    finally { setBusy(false); }
  }
  return <PageSection title="Connection settings" description={editable ? "IT admins manage connectivity and deployment identity." : "Only IT admins can change connection settings."}><form onSubmit={(event) => void save(event)} className="space-y-4">
    <div className="grid gap-4 sm:grid-cols-2"><div className="space-y-2"><Label htmlFor="connection-name">Name</Label><Input id="connection-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={120} disabled={!editable || busy} /></div><div className="space-y-2"><Label htmlFor="connection-environment">Environment</Label><Input id="connection-environment" value={environment} onChange={(event) => setEnvironment(event.target.value)} maxLength={120} disabled={!editable || busy} /></div></div>
    <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={enabled} disabled={!editable || busy} onChange={(event) => setEnabled(event.target.checked)} className="mt-1 accent-primary" /><span>Enable OpenAIDR collection and checks<p className="mt-1 text-xs text-muted-foreground">Turning this off does not stop model traffic. The plugin continues to fail open.</p></span></label>
    {error && <ErrorState message={error} />}{saved && <p role="status" className="text-sm">Connection saved.</p>}{editable && <Button type="submit" disabled={busy || !changed || !name.trim()}>{busy ? "Saving…" : "Save connection"}</Button>}
  </form></PageSection>;
}

function eligibleRule(rule: Policy["rules"][number], kind: string) {
  const match = rule.match ?? {};
  return rule.enabled && ["allow", "deny"].includes(rule.action)
    && Object.keys(match).length > 0
    && Object.keys(match).every((key) => ["kinds", "products"].includes(key))
    && (!match.kinds?.length || match.kinds.includes("prompt"))
    && (!match.products?.length || match.products.includes(kind));
}

function PolicySettings({ gateway, editable, onSaved }: { gateway: Gateway; editable: boolean; onSaved: () => void }) {
  const policy = useResource<Policy>(editable ? "response/policy" : null);
  const [mode, setMode] = useState<GatewayMode>(gateway.mode);
  const [capture, setCapture] = useState(gateway.capture_content);
  const [selected, setSelected] = useState(gateway.policy_rule_ids);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const rules = policy.data?.rules.filter((rule) => eligibleRule(rule, gateway.kind) || selected.includes(rule.id)) ?? [];
  const missing = selected.filter((id) => !rules.some((rule) => rule.id === id));
  const changed = mode !== gateway.mode || capture !== gateway.capture_content || JSON.stringify(selected) !== JSON.stringify(gateway.policy_rule_ids);
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!editable) return; setBusy(true); setError(""); setSaved(false);
    try { await api<Gateway>(`gateways/${encodeURIComponent(gateway.id)}/settings`, { method: "PUT", body: JSON.stringify({ version: gateway.version, mode, capture_content: capture, policy_rule_ids: selected }) }); setSaved(true); onSaved(); }
    catch (cause) { setError(cause instanceof APIError && cause.status === 409 ? "This policy changed. Refresh the instance and review the current settings before saving again." : cause instanceof Error ? cause.message : "Could not save policy settings."); }
    finally { setBusy(false); }
  }
  function toggle(id: string, checked: boolean) { setSelected(checked ? [...selected, id] : selected.filter((value) => value !== id)); }
  return <PageSection title="Gateway policy" description="Gateway mode is independent of endpoint mode. Only security analysts can change these settings."><form onSubmit={(event) => void save(event)} className="space-y-4">
    <div className="space-y-2"><Label htmlFor="gateway-mode">Policy mode</Label><Select value={mode} onValueChange={(value) => setMode(value as GatewayMode)} disabled={!editable || busy}><SelectTrigger id="gateway-mode"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="shadow">Shadow</SelectItem><SelectItem value="enforce">Enforce</SelectItem></SelectContent></Select><p className="text-sm text-muted-foreground">Shadow records the evaluated decision and returns allow. Enforce returns the backend decision. Evaluation failures allow traffic in both modes.</p></div>
    {mode === "enforce" && <PageNotice title="Enforce mode"><p>A valid, timely deny decision can block a model request. Confirm the selected policy before saving.</p></PageNotice>}
    <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={capture} disabled={!editable || busy} onChange={(event) => setCapture(event.target.checked)} className="mt-1 accent-primary" /><span>Permit prompt content capture<p className="mt-1 text-xs text-muted-foreground">The plugin must also enable local content capture. Both permissions are required before prompts are uploaded for assessment and retained evidence. When content is unavailable, a content assessment is unavailable, not a clean result.</p></span></label>
    <PageNotice title="Evaluation requires complete captured content"><p>Gateway checks require complete prompt content and a successful Guardrail assessment. Metadata-only, unsupported, redacted, or truncated content, missing model credentials, and assessment errors cause fail open. Selected static rules apply only after a successful assessment, including in Enforce mode.</p></PageNotice>
    <fieldset disabled={!editable || busy} className="space-y-3"><legend className="mb-2 text-sm font-medium">Assigned rules</legend><p className="text-sm text-muted-foreground">Only explicitly selected rules apply. Supported rules are enabled allow/deny rules with prompt action or matching gateway product selectors. Host, command, file, and tool selectors are not supported. Shared risk settings and company policy assessment apply when content capture is enabled.</p>
      {policy.error && <ErrorState message={policy.error} onRetry={() => void policy.reload()} />}{policy.loading && <LoadingState label="Loading eligible rules…" />}
      {rules.map((rule) => <label key={rule.id} className="flex items-start gap-2 rounded-md border p-3 text-sm"><input className="mt-1 accent-primary" type="checkbox" checked={selected.includes(rule.id)} disabled={!eligibleRule(rule, gateway.kind) && !selected.includes(rule.id)} onChange={(event) => toggle(rule.id, event.target.checked)} /><span className="min-w-0 flex-1"><span className="font-medium">{displayText(rule.name)}</span><span className="ml-2 text-xs text-muted-foreground">{rule.action}{!eligibleRule(rule, gateway.kind) && " · No longer eligible; remove to save"}</span>{rule.reason && <p className="mt-1 whitespace-pre-wrap break-words text-xs">{rule.reason}</p>}<CodeBlock className="mt-2">{JSON.stringify(rule.match ?? {}, null, 2)}</CodeBlock></span></label>)}
      {missing.map((id) => <label key={id} className="flex items-start gap-2 text-sm"><input type="checkbox" className="accent-primary" checked onChange={() => toggle(id, false)} /><span className="min-w-0 break-all">Assigned rule {id}{editable ? " (not available in the current rule list)" : ""}</span></label>)}
      {!selected.length && <p className="text-sm text-muted-foreground">No static rules assigned.</p>}
    </fieldset>
    {error && <ErrorState message={error} />}{saved && <p role="status" className="text-sm">Gateway policy saved.</p>}{editable && <Button type="submit" disabled={busy || !changed || policy.loading || Boolean(policy.error)}>{busy ? "Saving…" : "Save gateway policy"}</Button>}
  </form></PageSection>;
}

function GatewaySetup({ detail, editable, onChanged }: { detail: GatewayDetail; editable: boolean; onChanged: () => void }) {
  const { dateTime } = useTimeZone();
  const [origin, setOrigin] = useState("");
  const [secret, setSecret] = useState<CreatedGatewayCredential | null>(null);
  const [confirm, setConfirm] = useState<"rotate" | "revoke" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  useEffect(() => { setOrigin(window.location.protocol === "https:" ? window.location.origin : ""); }, []);
  const active = detail.credential && !detail.credential.revoked_at;
  async function changeCredential() {
    if (!editable || !confirm) return;
    setBusy(true); setError(""); setFeedback(""); setSecret(null);
    try {
      if (confirm === "rotate") {
        const credential = await api<CreatedGatewayCredential>(`gateways/${encodeURIComponent(detail.gateway.id)}/credentials`, { method: "POST", body: "{}" });
        setSecret(credential); setFeedback("New credential created. Update every gateway node using this connection.");
      } else if (detail.credential) {
        await api(`gateways/${encodeURIComponent(detail.gateway.id)}/credentials/${encodeURIComponent(detail.credential.id)}`, { method: "DELETE" });
        setFeedback("Credential revoked. Authenticated collection and checks stop. The plugin continues to allow traffic if OpenAIDR is unavailable.");
      }
      setConfirm(null); onChanged();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not update the credential."); }
    finally { setBusy(false); }
  }
  return <div className="space-y-4"><PageSection title="Integration credential" description="This credential is scoped to this gateway connection. It is not a dashboard or tenant administration token.">
    <div className="space-y-3"><p className="text-sm">{active ? `Active credential created ${dateTime(detail.credential?.created_at)}.` : "No active credential."} Only IT admins can create, rotate, or revoke it.</p>
      {feedback && <p role="status" className="text-sm">{feedback}</p>}{secret && <GatewayCredentialSecret credential={secret} onDismiss={() => setSecret(null)} />}
      {editable && <div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => { setError(""); setConfirm("rotate"); }}>{active ? "Rotate credential" : "Create credential"}</Button>{active && <Button variant="outline" onClick={() => { setError(""); setConfirm("revoke"); }}>Revoke credential</Button>}</div>}
    </div>
  </PageSection>
  {detail.gateway.kind === "kong" ? <PageSection title="Install on Kong" description="Pilot verified on self-hosted Kong 3.9.4. Install on each Kong data-plane node."><div className="space-y-4">
    <ol className="list-decimal space-y-3 pl-5 text-sm"><li>Extract the OpenAIDR Kong plugin package into /opt/openaidr on every data-plane node. The package contains kong/plugins/openaidr.</li><li>Store the connection credential in your secret manager and inject OPENAIDR_GATEWAY_TOKEN into each Kong node's environment. Add these settings, then restart or reload each node.<CodeBlock className="mt-2">{"KONG_LUA_PACKAGE_PATH='/opt/openaidr/?.lua;;'\nKONG_PLUGINS='bundled,openaidr'\nKONG_LUA_SSL_TRUSTED_CERTIFICATE='system'\nKONG_LUA_SSL_VERIFY_DEPTH=5\nKONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=64k\nKONG_NGINX_MAIN_ENV='OPENAIDR_GATEWAY_TOKEN'"}</CodeBlock><p className="mt-2">Keep existing plugin and environment entries. For an existing Nginx environment entry, use KONG_NGINX_MAIN_ENV='EXISTING_VARIABLE; env OPENAIDR_GATEWAY_TOKEN'.</p></li><li>If the backend uses a private CA, install its public certificate on each node and set KONG_LUA_SSL_TRUSTED_CERTIFICATE to 'system,/etc/openaidr/tenant-ca.pem' with the actual certificate path. Keep TLS certificate verification enabled.</li><li>Attach the plugin to each supported OpenAI-compatible chat completion route with the configuration below. The connection and node IDs are derived automatically.</li><li>For incremental streaming through an ordinary proxy route, set response_buffering to false on the Kong route. The plugin does not buffer or inspect model responses.</li></ol>
    <div className="space-y-2"><Label htmlFor="gateway-backend-url">OpenAIDR backend origin</Label><Input id="gateway-backend-url" type="url" value={origin} onChange={(event) => setOrigin(event.target.value)} /><p className="text-xs text-muted-foreground">Use the HTTPS origin reachable from Kong. This value only changes the example.</p></div>
    <CodeBlock>{`name: openaidr\nconfig:\n  backend_url: ${JSON.stringify(origin || "https://YOUR_OPENAIDR_HOST")}\n  credential: "{vault://env/openaidr-gateway-token}"\n  capture_content: false\n  timeout_ms: 1000`}</CodeBlock>
    <PageNotice title="Capture is opt-in in two places"><p>To send prompts for assessment, a security analyst must permit capture under Settings and the Kong administrator must set capture_content to true. An IT admin must also configure the backend Guardrail model credential. Start with Shadow and verify evaluated requests and heartbeats before enabling Enforce. Without complete captured content and a successful assessment, checks fail open and selected static rules are not applied.</p></PageNotice>
    <p className="text-sm text-muted-foreground">A heartbeat confirms connectivity, not protection of every route. The plugin allows traffic when OpenAIDR is unavailable. Disabling this connection or revoking its credential stops authenticated checks and collection; it does not stop provider requests.</p>
  </div></PageSection> : detail.gateway.kind === "litellm" ? <LiteLLMSetup origin={origin} onOriginChange={setOrigin} /> : <PageNotice title="Plugin setup unavailable"><p>This dashboard version does not include setup instructions for this plugin.</p></PageNotice>}
  <Dialog open={Boolean(confirm)} onOpenChange={(value) => { if (!value && !busy) setConfirm(null); }}><DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto"><DialogHeader><DialogTitle>{confirm === "revoke" ? "Revoke integration credential?" : active ? "Rotate integration credential?" : "Create integration credential?"}</DialogTitle><DialogDescription>{confirm === "revoke" ? "Authenticated collection and policy checks will stop immediately. The plugin still allows model traffic under fail-open. This does not disable the gateway." : "The previous credential becomes invalid immediately. Save the new credential once and update every gateway node for this connection."}</DialogDescription></DialogHeader>{error && <ErrorState message={error} />}<DialogFooter><Button variant="outline" disabled={busy} onClick={() => setConfirm(null)}>Cancel</Button><Button disabled={busy} onClick={() => void changeCredential()}>{busy ? "Updating…" : confirm === "revoke" ? "Confirm revoke" : "Confirm credential"}</Button></DialogFooter></DialogContent></Dialog>
  </div>;
}
