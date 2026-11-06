"use client";

import { useState, type FormEvent } from "react";
import { Info } from "lucide-react";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { MCPContentPicker, savedImports, type MCPConnection as Connection, type MCPCatalog, type MCPImport } from "@/components/company-knowledge-mcp-content";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { api } from "@/lib/api";
import { useResource } from "@/lib/use-resource";
import { useTimeZone } from "@/components/time-zone-context";

type Props = {
  revision: number;
  editable: boolean;
  busy: boolean;
  blocked: boolean;
  saveError: string;
  run: (operation: () => Promise<void>) => Promise<void>;
  onChange: () => Promise<void>;
};

export function CompanyKnowledgeMCP({ revision, editable, busy, blocked, saveError, run, onChange }: Props) {
  const { dateTime } = useTimeZone();
  const { data, loading, error, reload } = useResource<{ connections: Connection[] }>(`knowledge/mcp?revision=${revision}`, 0, true);
  const [selection, setSelection] = useState<({ connection: Connection } & MCPCatalog) | null>(null);
  const [authType, setAuthType] = useState("none");
  const [preset, setPreset] = useState("custom");
  const [serverUrl, setServerUrl] = useState("");
  const [removing, setRemoving] = useState<Connection | null>(null);
  const [notice, setNotice] = useState("");
  const disabled = busy || blocked || loading || !!error;

  async function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    await run(async () => {
      setNotice("");
      const auth = authType === "basic" ? { type: authType, username: fields.get("mcp-username"), password: fields.get("mcp-secret") }
        : authType === "bearer" ? { type: authType, token: fields.get("mcp-secret") }
        : authType === "header" ? { type: authType, name: fields.get("mcp-header"), value: fields.get("mcp-secret") }
        : { type: "none" };
      const result = await api<{ connection: Connection } & MCPCatalog>("knowledge/mcp", {
        method: "POST", body: JSON.stringify({ revision, name: fields.get("name"), endpoint: serverUrl, auth }),
      });
      form.reset();
      setServerUrl("");
      setAuthType("none");
      setPreset("custom");
      setSelection({ ...result, templates: result.templates ?? [], tools: result.tools ?? [] });
      await onChange();
    });
  }

  async function sync(connection: Connection, imports: MCPImport[]) {
    const result = await api<{ imported: number }>(`knowledge/mcp/${connection.connection_id}/sync`, {
      method: "POST", body: JSON.stringify({ revision, imports }),
    });
    setNotice(`${result.imported} ${result.imported === 1 ? "document" : "documents"} indexed from ${connection.name}.`);
    setSelection(null);
    await onChange();
  }

  return <>
    <PageSection title="MCP servers" description="Connect a company knowledge server and select documents to index."
      className="h-full [&>[data-slot=card]]:h-full [&_[data-slot=section-body]]:flex [&_[data-slot=section-body]]:flex-1"
      action={<Popover>
        <PopoverTrigger asChild>
          <Button type="button" variant="ghost" size="header-icon" aria-label="MCP server support details" className="text-muted-foreground">
            <Info aria-hidden="true" />
          </Button>
        </PopoverTrigger>
        <PopoverContent aria-label="MCP server support details" className="space-y-2">
          <p>Streamable HTTP servers with text resources, resource templates, and retrieval tools are supported.</p>
          <p>Refresh imported resources at least every 24 hours to keep them available for new assessments.</p>
          <p>OAuth, local stdio servers, and legacy SSE endpoints are not supported. Tool previews and refreshes execute the selected tools.</p>
        </PopoverContent>
      </Popover>}>
      <div className="flex flex-1 flex-col gap-4 text-sm">
        {saveError && !selection && !removing && <p role="alert" className="text-destructive">{saveError}</p>}
        {error && <ErrorState message={error} onRetry={reload} />}
        {loading && !data && <LoadingState label="Loading MCP servers…" />}
        {notice && <p role="status">{notice}</p>}
        {editable && <form onSubmit={(event) => void connect(event)} autoComplete="off" className="flex flex-1 flex-col items-start gap-3">
          <div className="grid w-full gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <span id="mcp-preset-label">Server</span>
              <Select value={preset} disabled={disabled} onValueChange={(value) => {
                setPreset(value);
                setServerUrl(value === "confluence" ? "https://mcp.atlassian.com/v2/mcp?tools=all" : "");
                setAuthType(value === "confluence" ? "basic" : "none");
              }}>
                <SelectTrigger aria-labelledby="mcp-preset-label" className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="custom">Custom MCP server</SelectItem><SelectItem value="confluence">Confluence Cloud</SelectItem></SelectContent>
              </Select>
            </div>
            <label className="space-y-1"><span>Connection name</span><Input name="name" required maxLength={160} placeholder="Company wiki" disabled={disabled} /></label>
          </div>
          {preset === "confluence" && <p className="text-xs text-muted-foreground">Use your Atlassian email and API token. Your organization must enable API-token access to its MCP server. A service account API key uses Bearer authentication.</p>}
          <div className="grid w-full gap-3">
            <label className="space-y-1"><span>MCP server URL</span><Input name="mcp-endpoint" type="url" autoComplete="off" required maxLength={1024} placeholder="https://knowledge.example.com/mcp" value={serverUrl} onChange={(event) => setServerUrl(event.target.value)} disabled={disabled} /></label>
          </div>
          <div className="w-full space-y-1">
            <span id="mcp-auth-label">Authentication</span>
            <Select value={authType} onValueChange={setAuthType} disabled={disabled}>
              <SelectTrigger aria-labelledby="mcp-auth-label" className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value="none">None</SelectItem><SelectItem value="bearer">Bearer token</SelectItem><SelectItem value="basic">Basic (username and password)</SelectItem><SelectItem value="header">Custom header</SelectItem></SelectContent>
            </Select>
          </div>
          {authType !== "none" && <div className={authType === "bearer" ? "grid w-full gap-3" : "grid w-full gap-3 sm:grid-cols-2"}>
            {authType === "basic" && <label className="block space-y-1"><span>{preset === "confluence" ? "Atlassian email" : "Username"}</span><Input key={preset} name="mcp-username" autoComplete="off" required maxLength={4096} disabled={disabled} /></label>}
            {authType === "header" && <label className="block space-y-1"><span>Header name</span><Input name="mcp-header" placeholder="X-API-Key" autoComplete="off" required maxLength={80} disabled={disabled} /></label>}
            {authType !== "none" && <label className="block space-y-1"><span>{authType === "basic" ? preset === "confluence" ? "Atlassian API token" : "Password or API token" : authType === "header" ? "Header value" : "Bearer token"}</span><Input key={`${preset}:${authType}`} name="mcp-secret" type="password" autoComplete="new-password" required maxLength={4096} disabled={disabled} /></label>}
          </div>}
          <p className="mt-auto text-xs text-muted-foreground">Credentials stay on the server and are encrypted when stored. Selected documents are shared with your organization.</p>
          <Button type="submit" variant="outline" disabled={disabled}>{busy ? "Working…" : "Connect MCP server"}</Button>
        </form>}
        {data?.connections?.map((connection) => <div key={connection.connection_id} className="space-y-2 border-t pt-4">
          <h3 className="font-semibold break-words">{connection.name}</h3>
          <p className="break-all text-xs text-muted-foreground">{connection.endpoint}</p>
          <p className="text-xs text-muted-foreground">{connection.resource_uris.length} {connection.resource_uris.length === 1 ? "document" : "documents"} indexed · {{ none: "No authentication", bearer: "Bearer token", basic: "Basic authentication", header: "Custom header" }[connection.auth_type ?? (connection.has_token ? "bearer" : "none")]} · {connection.synced_at ? `Last imported ${dateTime(connection.synced_at)}` : "Not imported yet"}</p>
          {editable && <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" disabled={disabled} onClick={() => void run(async () => {
              setNotice("");
              const result = await api<MCPCatalog>(`knowledge/mcp/${connection.connection_id}/resources`, { method: "POST", body: "{}" });
              setSelection({ connection, ...result, templates: result.templates ?? [], tools: result.tools ?? [] });
            })}>Select content</Button>
            <Button size="sm" variant="outline" disabled={disabled || !savedImports(connection).length} onClick={() => void run(() => sync(connection, savedImports(connection)))}>Refresh imports</Button>
            <Button size="sm" variant="ghost" disabled={disabled} onClick={() => setRemoving(connection)}>Disconnect</Button>
          </div>}
        </div>)}
        {!editable && <p className="text-muted-foreground">A Security Analyst can connect servers and select content.</p>}
      </div>
    </PageSection>
    {selection && <MCPContentPicker connection={selection.connection} catalog={selection} busy={busy} blocked={blocked} saveError={saveError}
      run={run} onSave={(sources) => sync(selection.connection, sources)} onClose={() => setSelection(null)} />}
    <Dialog open={!!removing} onOpenChange={(open) => { if (!open && !busy) setRemoving(null); }}>
      <DialogContent><DialogHeader><DialogTitle>Disconnect MCP server</DialogTitle><DialogDescription>Disconnect {removing?.name} and remove its documents from new assessments? Stored credentials will be deleted. Historical evidence is retained.</DialogDescription></DialogHeader>
        {saveError && <p role="alert" className="text-sm text-destructive">{saveError}</p>}
        <Button disabled={busy || blocked} onClick={() => void run(async () => {
          if (!removing) return;
          await api(`knowledge/mcp/${removing.connection_id}/disconnect`, { method: "POST", body: JSON.stringify({ revision }) });
          setRemoving(null);
          setNotice("MCP server disconnected.");
          await onChange();
        })}>Disconnect server</Button>
      </DialogContent>
    </Dialog>
  </>;
}
