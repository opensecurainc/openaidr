"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api";
import { usePagedResource, useResource } from "@/lib/use-resource";
import { hasRole } from "@/lib/roles";
import { type CreatedGatewayCredential, type Gateway, type GatewayKind, type GatewayOverview, gatewayMetric, gatewayStatuses, gatewayPlugins, gatewayPluginLabel } from "@/lib/gateways";
import { useDashboard } from "@/components/dashboard-context";
import { useTimeZone } from "@/components/time-zone-context";
import { CollectionFooter, EmptyState, ErrorState, LoadingState, PageNotice, PageSection, TableLayout } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Status } from "@/components/ui/status";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function GatewayHealth({ status }: { status: Gateway["status"] }) {
  return <Status tone={status === "reporting" ? "ok" : status === "stale" ? "warning" : "neutral"}>{gatewayStatuses[status] ?? "Unknown"}</Status>;
}

export function GatewayCoverageNotice() {
  return <PageNotice title="Observed coverage"><p>Only routes reported by the plugin are shown. Reported routes do not prove full gateway coverage. Node health comes from heartbeats, so an idle gateway can still be reporting.</p></PageNotice>;
}

export function GatewayMetrics({ values }: { values: { label: string; value: string }[] }) {
  return <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3 xl:grid-cols-6">{values.map(({ label, value }) => <div key={label} className="min-w-0"><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 text-base font-semibold tabular-nums">{value}</dd></div>)}</dl>;
}

export function GatewaysOverview() {
  const { user } = useDashboard();
  const result = useResource<GatewayOverview>("gateways/overview", 30_000);
  const data = result.data;
  return <div className="space-y-4">
    <PageSection title="Gateway health" description="Gateway connections and node heartbeats." action={<Button variant="outline" size="sm" onClick={() => void result.reload()} disabled={result.loading}>Refresh</Button>}>
      {result.error && <ErrorState message={`${result.error}${data ? " Showing the last successful response; these metrics may be stale." : ""}`} onRetry={() => void result.reload()} />}
      {!data ? !result.error && <LoadingState /> : <GatewayMetrics values={[
        { label: "Instances", value: gatewayMetric(data.gateways.total) }, { label: "Reporting", value: gatewayMetric(data.gateways.reporting) },
        { label: "Heartbeat delayed", value: gatewayMetric(data.gateways.stale) }, { label: "Awaiting connection", value: gatewayMetric(data.gateways.never_seen) },
        { label: "Disabled", value: gatewayMetric(data.gateways.disabled) },
      ]} />}
    </PageSection>
    {(hasRole(user, "it_admin") || hasRole(user, "security_analyst")) && <GatewayInstances onCreated={() => void result.reload()} />}
    <GatewayCoverageNotice />
    <PageSection title="Model requests" description={data ? `Recorded in the past ${data.window_hours} hours. Counts describe separate stages and must not be added together.` : "Request metrics are unavailable until the server responds."} action={hasRole(user, "security_analyst") && <Button asChild variant="outline" size="sm"><Link href="/guardrail/history?source=gateways">View requests</Link></Button>}>
      {data && <div className="space-y-5"><GatewayMetrics values={[
        { label: "Requests", value: gatewayMetric(data.requests.total) }, { label: "Evaluated", value: gatewayMetric(data.requests.evaluated) },
        { label: "Evaluation unavailable", value: gatewayMetric(data.requests.unavailable) }, { label: "Would deny in Shadow", value: gatewayMetric(data.requests.would_deny) },
        { label: "Returned allow", value: gatewayMetric(data.requests.allowed) }, { label: "Returned deny", value: gatewayMetric(data.requests.denied) },
      ]} /><GatewayMetrics values={[
        { label: "Reported blocked", value: gatewayMetric(data.requests.blocked) }, { label: "Reported forwarded", value: gatewayMetric(data.requests.forwarded) },
        { label: "Reported fail open", value: gatewayMetric(data.requests.fail_open) }, { label: "Outcome unconfirmed", value: gatewayMetric(data.requests.unconfirmed) },
        { label: "Policy latency p50", value: gatewayMetric(data.policy_latency_ms.p50, " ms") }, { label: "Policy latency p95", value: gatewayMetric(data.policy_latency_ms.p95, " ms") },
      ]} /><p className="text-sm text-muted-foreground">An evaluated denial is not proof of a blocked request. Fail open means the policy path failed; it does not confirm provider completion. Usage and cost are unavailable in this gateway ledger.</p></div>}
    </PageSection>
  </div>;
}

export function GatewayCredentialSecret({ credential, onDismiss }: { credential: CreatedGatewayCredential; onDismiss: () => void }) {
  const [feedback, setFeedback] = useState("");
  async function copy() {
    try { await navigator.clipboard.writeText(credential.token); setFeedback("Credential copied."); }
    catch { setFeedback("Copy failed. Select the credential and copy it manually."); }
  }
  return <div className="space-y-3">
    <PageNotice title="Save this credential now"><p>This credential is shown once. Store it in your secret manager. Closing this view clears it from the dashboard.</p></PageNotice>
    <Label htmlFor="gateway-credential">Gateway credential</Label>
    <Input id="gateway-credential" value={credential.token} readOnly autoComplete="off" spellCheck={false} onFocus={(event) => event.target.select()} />
    <div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => void copy()}>Copy credential</Button><Button variant="outline" onClick={onDismiss}>Clear credential</Button></div>
    {feedback && <p role="status" className="text-sm">{feedback}</p>}
  </div>;
}

function GatewayInstances({ onCreated }: { onCreated: () => void }) {
  const { user } = useDashboard();
  const { dateTime } = useTimeZone();
  const result = usePagedResource<Gateway>("gateways?limit=50");
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<GatewayKind>("kong");
  const [environment, setEnvironment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<{ gateway: Gateway; credential: CreatedGatewayCredential | null } | null>(null);
  function changeOpen(value: boolean) {
    if (busy) return;
    setOpen(value); setCreated(null); setError(""); setName(""); setEnvironment(""); setKind("kong");
  }
  async function create(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const value = await api<{ gateway: Gateway; credential: CreatedGatewayCredential }>("gateways", { method: "POST", body: JSON.stringify({ name: name.trim(), environment: environment.trim(), kind }) });
      setCreated(value); result.reload(); onCreated();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not create the gateway."); }
    finally { setBusy(false); }
  }
  return <>
    <PageSection title="Instances" description="Each connection has its own scoped credential and policy mode. New connections start in Shadow." action={<><Button variant="outline" size="sm" onClick={result.reload} disabled={result.loading}>Refresh instances</Button>{hasRole(user, "it_admin") && <Button size="sm" onClick={() => changeOpen(true)}>Connect gateway</Button>}</>}>
      {result.error && <ErrorState message={result.error} onRetry={result.reload} />}
      {result.loading && !result.items.length ? <LoadingState /> : !result.items.length && !result.error ? <EmptyState title="No gateway connections" description="An IT admin can create a scoped connection, then install the OpenAIDR plugin on gateway nodes." /> : result.items.length > 0 && <TableLayout footer={<CollectionFooter count={result.items.length} hasMore={Boolean(result.nextCursor)} busy={result.loadingMore} onLoadMore={result.loadMore} label="instances" />}>
        <Table><TableHeader><TableRow><TableHead>Instance</TableHead><TableHead>Environment</TableHead><TableHead>Heartbeat</TableHead><TableHead>Mode</TableHead><TableHead>Nodes</TableHead><TableHead>Last seen</TableHead></TableRow></TableHeader><TableBody>{result.items.map((gateway) => <TableRow key={gateway.id}>
          <TableCell className="font-medium"><Link className="text-primary hover:underline" href={`/gateways/instances/${encodeURIComponent(gateway.id)}`}>{gateway.name}</Link><p className="text-xs text-muted-foreground">{gatewayPluginLabel(gateway.kind)}</p></TableCell>
          <TableCell>{gateway.environment || "Not reported"}</TableCell><TableCell><GatewayHealth status={gateway.status} /></TableCell><TableCell>{gateway.mode === "enforce" ? "Enforce" : "Shadow"}</TableCell><TableCell>{gatewayMetric(gateway.node_count)}</TableCell><TableCell>{dateTime(gateway.last_seen_at)}</TableCell>
        </TableRow>)}</TableBody></Table>
      </TableLayout>}
    </PageSection>
    <Dialog open={open} onOpenChange={changeOpen}><DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto"><DialogHeader><DialogTitle>{created ? "Gateway connection created" : "Connect gateway"}</DialogTitle><DialogDescription>{created ? "Install the plugin and configure it with this connection's credential." : "Create one connection for this gateway deployment. Policy mode starts in Shadow and content capture starts off."}</DialogDescription></DialogHeader>
      {error && <ErrorState message={error} />}
      {created ? <><p className="text-sm">{created.gateway.name} is awaiting its first heartbeat.</p>{created.credential && <GatewayCredentialSecret credential={created.credential} onDismiss={() => setCreated({ ...created, credential: null })} />}<DialogFooter><Button asChild><Link href={`/gateways/instances/${encodeURIComponent(created.gateway.id)}`}>Continue to setup</Link></Button></DialogFooter></> : <form onSubmit={(event) => void create(event)} className="space-y-4"><div className="space-y-2"><Label htmlFor="gateway-plugin">Gateway plugin</Label><Select value={kind} onValueChange={(value) => setKind(value as GatewayKind)} disabled={busy}><SelectTrigger id="gateway-plugin"><SelectValue /></SelectTrigger><SelectContent>{Object.entries(gatewayPlugins).map(([value, plugin]) => <SelectItem key={value} value={value}>{plugin.label}</SelectItem>)}</SelectContent></Select></div><div className="space-y-2"><Label htmlFor="gateway-name">Name</Label><Input id="gateway-name" required maxLength={120} value={name} onChange={(event) => setName(event.target.value)} placeholder={`Production ${gatewayPluginLabel(kind)}`} /></div><div className="space-y-2"><Label htmlFor="gateway-environment">Environment</Label><Input id="gateway-environment" maxLength={120} value={environment} onChange={(event) => setEnvironment(event.target.value)} placeholder="production" /></div><DialogFooter><Button type="button" variant="outline" disabled={busy} onClick={() => changeOpen(false)}>Cancel</Button><Button type="submit" disabled={busy || !name.trim()}>{busy ? "Creating…" : "Create connection"}</Button></DialogFooter></form>}
    </DialogContent></Dialog>
  </>;
}
