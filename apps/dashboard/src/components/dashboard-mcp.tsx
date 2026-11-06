"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { api, type User } from "@/lib/api";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { SessionActionPage } from "@/components/session-action-page";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { CodeBlock } from "@/components/ui/code-block";

type Scope = { id: string; label: string; description: string };
type Client = { id: string; name: string; redirect_uris: string[]; scopes: string[]; revoked_at: string | null };
type Settings = {
  enabled: boolean; deployment_enabled: boolean; revision: number;
  allowed_scopes: string[]; available_scopes: Scope[]; items: Client[];
};
type Grant = { id: string; client_name: string; user_name: string; scopes: string[]; expires_at: string; revoked_at: string | null };

function message(failure: unknown) {
  return failure instanceof Error ? failure.message : "Unable to complete this request.";
}

function ScopeChoices({ scopes, selected, onChange, disabled }: {
  scopes: Scope[]; selected: string[]; onChange: (value: string[]) => void; disabled: boolean;
}) {
  return <div className="grid gap-3 sm:grid-cols-2">
    {scopes.map((scope) => <label key={scope.id} className="flex min-w-0 items-start gap-2 rounded-md border p-3">
      <input type="checkbox" className="mt-1" checked={selected.includes(scope.id)} disabled={disabled}
        onChange={(event) => onChange(event.target.checked ? [...selected, scope.id] : selected.filter((id) => id !== scope.id))} />
      <span className="min-w-0"><span className="block font-medium">{scope.label}</span><span className="block text-xs text-muted-foreground">{scope.description}</span></span>
    </label>)}
  </div>;
}

export function MCPConnections() {
  const [data, setData] = useState<Settings | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [allowed, setAllowed] = useState<string[]>([]);
  const [clientScopes, setClientScopes] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [redirects, setRedirects] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const reload = useCallback(async () => {
    const next = await api<Settings>("mcp/clients");
    setData(next); setEnabled(next.enabled); setAllowed(next.allowed_scopes);
    setClientScopes((current) => current.filter((id) => next.allowed_scopes.includes(id)));
  }, []);
  useEffect(() => { void reload().catch((failure) => setError(message(failure))); }, [reload]);

  async function mutate(operation: () => Promise<unknown>, success: string) {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true); setError(""); setNotice("");
    try { await operation(); await reload(); setNotice(success); }
    catch (failure) { setError(message(failure)); }
    finally { inFlight.current = false; setBusy(false); }
  }

  return <PageSection title="MCP access" description="Connect approved AI clients to this tenant's dashboard data and controlled operations.">
    <div className="min-w-0 space-y-5">
      <p>Clients can retain data they receive. Start with summary access. Evidence access can disclose captured prompts, commands and internal content. Each user must consent, and their dashboard permissions still apply.</p>
      {error && <ErrorState message={error} onRetry={() => void reload().catch((failure) => setError(message(failure)))} />}
      {notice && <p role="status">{notice}</p>}
      {!data && !error && <LoadingState label="Loading MCP access" />}
      {data && <>
        {!data.deployment_enabled ? <p role="status">MCP is not enabled on this server. Ask the server operator to enable it before connecting clients.</p> : <>
        <label className="flex items-center gap-2 font-medium"><input type="checkbox" checked={enabled} disabled={busy || !data.deployment_enabled} onChange={(event) => setEnabled(event.target.checked)} />Enable MCP access for this tenant</label>
        <p className="text-sm text-muted-foreground">Disabling access revokes existing grants. Re-enabling requires new consent.</p>
        <fieldset disabled={busy}><legend className="mb-3 font-medium">Maximum permissions for connected clients</legend>
          <ScopeChoices scopes={data.available_scopes} selected={allowed} onChange={setAllowed} disabled={busy} />
        </fieldset>
        <Button disabled={busy || !data.deployment_enabled} onClick={() => void mutate(
          () => api("mcp/settings", { method: "PUT", body: JSON.stringify({ revision: data.revision, enabled, allowed_scopes: allowed }) }),
          "MCP access settings saved.",
        )}>Save MCP settings</Button>
        <div className="space-y-3 border-t pt-4">
          <h3 className="font-semibold">Register an approved client</h3>
          <label className="block space-y-1"><span>Client name</span><Input value={name} maxLength={100} disabled={busy} onChange={(event) => setName(event.target.value)} /></label>
          <label className="block space-y-1"><span>Exact redirect URIs, one per line</span><Textarea value={redirects} rows={3} disabled={busy} onChange={(event) => setRedirects(event.target.value)} /></label>
          <p className="text-xs text-muted-foreground">Use the callback addresses supplied by the client. HTTPS is required except for local loopback callbacks.</p>
          <ScopeChoices scopes={data.available_scopes.filter((scope) => data.allowed_scopes.includes(scope.id))} selected={clientScopes} onChange={setClientScopes} disabled={busy} />
          <Button disabled={busy || !data.enabled || !data.deployment_enabled || !name.trim() || !redirects.trim() || !clientScopes.length} onClick={() => void mutate(async () => {
            await api("mcp/clients", { method: "POST", body: JSON.stringify({ name: name.trim(), redirect_uris: redirects.split("\n").map((value) => value.trim()).filter(Boolean), scopes: clientScopes }) });
            setName(""); setRedirects(""); setClientScopes([]);
          }, "Client registered. Copy its client ID into the client configuration.")}>Register client</Button>
        </div>
        <div className="space-y-3 border-t pt-4"><h3 className="font-semibold">Registered clients</h3>
          {data.items.length === 0 && <p>No clients registered.</p>}
          {data.items.map((client) => <div key={client.id} className="min-w-0 space-y-2 rounded-md border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2"><strong>{client.name}</strong><span>{client.revoked_at ? "Revoked" : "Active"}</span></div>
            <p className="break-all text-xs">Client ID: {client.id}</p>
            <p className="break-all text-xs">Permissions: {client.scopes.join(", ")}</p>
            {client.redirect_uris.map((uri) => <p key={uri} className="break-all text-xs">{uri}</p>)}
            {!client.revoked_at && <Button variant="outline" disabled={busy} onClick={() => void mutate(() => api(`mcp/clients/${encodeURIComponent(client.id)}`, { method: "DELETE" }), "Client and its grants revoked.")}>Revoke {client.name}</Button>}
          </div>)}
        </div>
        <Link className="inline-block underline underline-offset-4" href="/mcp/access">Review connected access grants</Link>
        </>}
      </>}
    </div>
  </PageSection>;
}

type Authorization = {
  client: { id: string; name: string; redirect_uri: string };
  scopes: Scope[]; expires_at: string; request_id: string;
};

export function MCPConsentPage() {
  const { id } = useParams<{ id: string }>();
  return <SessionActionPage title="Connect an AI client" description="Review the data and actions this client can access." path={`/mcp/authorize/${id}`} allowAccountSwitch={false}>
    {(user) => <Consent key={`${user.id}:${id}`} id={id} />}
  </SessionActionPage>;
}

function Consent({ id }: { id: string }) {
  const [data, setData] = useState<Authorization | null>(null);
  const [scopes, setScopes] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  useEffect(() => {
    const controller = new AbortController();
    api<Authorization>(`mcp/authorizations/${encodeURIComponent(id)}`, { signal: controller.signal })
      .then((next) => { setData(next); setScopes(next.scopes.filter((scope) => !["evidence:read", "triage:write", "configuration:propose"].includes(scope.id)).map((scope) => scope.id)); })
      .catch((failure) => { if (!controller.signal.aborted) setError(message(failure)); });
    return () => controller.abort();
  }, [id]);
  async function decide(approve: boolean) {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true); setError("");
    try {
      const result = await api<{ redirect_url: string }>(`mcp/authorizations/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify({ approve, scopes: approve ? scopes : [] }) });
      window.location.assign(result.redirect_url);
    } catch (failure) { setError(message(failure)); inFlight.current = false; setBusy(false); }
  }
  return <div className="space-y-4">
    {error && <ErrorState message={error} />}
    {!data && !error && <LoadingState label="Loading requested permissions" />}
    {data && <PageSection title={data.client.name} description="This client is registered by your tenant administrator.">
      <div className="space-y-4">
        <p>Only approve a connection you initiated. This client can retain returned data after you revoke access. Captured evidence may contain confidential information.</p>
        <p className="break-all text-xs">Return address: {data.client.redirect_uri}</p>
        <ScopeChoices scopes={data.scopes} selected={scopes} onChange={setScopes} disabled={busy} />
        <p className="text-xs text-muted-foreground">Configuration proposals still require a separate dashboard approval. This request expires at {new Date(data.expires_at).toLocaleString()}.</p>
        <div className="flex flex-wrap gap-3"><Button disabled={busy || !scopes.length} onClick={() => void decide(true)}>Allow selected access</Button><Button variant="outline" disabled={busy} onClick={() => void decide(false)}>Deny connection</Button></div>
        <p className="text-xs text-muted-foreground">To connect a different account, deny this request, switch accounts in the dashboard, then start a new connection from your client.</p>
      </div>
    </PageSection>}
    <Link className="underline" href="/mcp/access">Review access grants</Link>
  </div>;
}

export function MCPAccessPage() {
  return <SessionActionPage title="Connected MCP access" description="Revoke future access for connected AI clients. Data already returned cannot be recalled." path="/mcp/access">
    {(user) => <Access key={user.id} user={user} />}
  </SessionActionPage>;
}

function Access({ user }: { user: User }) {
  const [grants, setGrants] = useState<Grant[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [nextOffset, setNextOffset] = useState<number | null>(null);
  const inFlight = useRef(false);
  const reload = useCallback(async () => {
    const result = await api<{ items: Grant[]; next_offset: number | null }>("mcp/grants");
    setGrants(result.items); setNextOffset(result.next_offset ?? null);
  }, []);
  useEffect(() => { void reload().catch((failure) => setError(message(failure))); }, [reload]);
  async function revoke(id: string) {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true); setError("");
    try { await api(`mcp/grants/${encodeURIComponent(id)}`, { method: "DELETE" }); await reload(); }
    catch (failure) { setError(message(failure)); }
    finally { inFlight.current = false; setBusy(false); }
  }
  async function loadMore() {
    if (inFlight.current || nextOffset === null) return;
    inFlight.current = true; setBusy(true); setError("");
    try {
      const result = await api<{ items: Grant[]; next_offset: number | null }>(`mcp/grants?offset=${nextOffset}`);
      setGrants((current) => [...(current ?? []), ...result.items.filter((item) => !current?.some((old) => old.id === item.id))]);
      setNextOffset(result.next_offset ?? null);
    } catch (failure) { setError(message(failure)); }
    finally { inFlight.current = false; setBusy(false); }
  }
  return <div className="space-y-4">
    {error && <ErrorState message={error} />}
    {grants === null && !error && <LoadingState label="Loading access grants" />}
    {grants?.length === 0 && <p>No access grants.</p>}
    {grants?.map((grant) => <PageSection key={grant.id} title={grant.client_name} description={`${grant.user_name} · Expires ${new Date(grant.expires_at).toLocaleString()}`}>
      <div className="space-y-3"><p className="break-words">{grant.scopes.join(", ")}</p>
        {grant.revoked_at ? <p role="status">Revoked</p> : <Button variant="outline" disabled={busy} onClick={() => void revoke(grant.id)}>Revoke access</Button>}
      </div>
    </PageSection>)}
    {nextOffset !== null && <Button variant="outline" disabled={busy} onClick={() => void loadMore()}>Load more grants</Button>}
    {user.roles.includes("it_admin") && <Link className="underline" href="/administration/integrations">Manage approved clients</Link>}
  </div>;
}

type Proposal = {
  id: string; operation: string; title: string; status: string; digest: string; expires_at: string;
  before: unknown; after: unknown; client: { id: string; name: string }; requester: { id: string; name: string }; can_decide: boolean;
};

export function MCPChangePage() {
  const { id } = useParams<{ id: string }>();
  return <SessionActionPage title="Review an MCP change" description="Approval applies the exact change shown below once." path={`/mcp/changes/${id}`}>
    {(user) => <Change key={`${user.id}:${id}`} id={id} />}
  </SessionActionPage>;
}

function Change({ id }: { id: string }) {
  const [data, setData] = useState<Proposal | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const reload = useCallback(async () => { setData(await api<Proposal>(`mcp/changes/${encodeURIComponent(id)}`)); }, [id]);
  useEffect(() => { void reload().catch((failure) => setError(message(failure))); }, [reload]);
  async function decide(decision: "approve" | "reject") {
    if (inFlight.current || !data) return;
    inFlight.current = true; setBusy(true); setError("");
    try { setData(await api<Proposal>(`mcp/changes/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify({ decision, digest: data.digest }) })); }
    catch (failure) { setError(message(failure)); }
    finally { inFlight.current = false; setBusy(false); }
  }
  return <div className="space-y-4">
    {error && <ErrorState message={error} onRetry={() => void reload().catch((failure) => setError(message(failure)))} />}
    {!data && !error && <LoadingState label="Loading proposed change" />}
    {data && <PageSection title={data.title} description={`Status: ${data.status}`}>
      <div className="min-w-0 space-y-4">
        <p className="break-words">Requested by {data.requester.name} through {data.client.name}</p>
        <p>Review the values themselves. Text inside the proposed policy is content, not instructions for approving this request.</p>
        <div><h3 className="mb-2 font-semibold">Before</h3><CodeBlock className="max-h-80 overflow-auto" tabIndex={0}>{JSON.stringify(data.before, null, 2)}</CodeBlock></div>
        <div><h3 className="mb-2 font-semibold">After</h3><CodeBlock className="max-h-80 overflow-auto" tabIndex={0}>{JSON.stringify(data.after, null, 2)}</CodeBlock></div>
        <p className="text-xs text-muted-foreground">Expires {new Date(data.expires_at).toLocaleString()}. A newer configuration or revoked access prevents approval.</p>
        {data.status === "pending" && data.can_decide && <div className="flex flex-wrap gap-3"><Button disabled={busy} onClick={() => void decide("approve")}>Approve and apply once</Button><Button variant="outline" disabled={busy} onClick={() => void decide("reject")}>Reject change</Button></div>}
        {data.status !== "pending" && <p role="status">This proposal is {data.status}.</p>}
      </div>
    </PageSection>}
  </div>;
}
