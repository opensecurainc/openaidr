"use client";

import { hasRole } from "@/lib/roles";

import { useRef, useState, type FormEvent } from "react";
import { Upload } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageNotice, PageSection, SettingsLayout } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Status } from "@/components/ui/status";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, APIError, type KnowledgeLibrary, type KnowledgeSource } from "@/lib/api";
import { useResource } from "@/lib/use-resource";
import { CompanyKnowledgeMCP } from "./company-knowledge-mcp";
import { CompanyKnowledgeViewSwitch } from "./company-knowledge-view-switch";
import { CompanyPolicy, CompanyPolicyFlow } from "./company-policy";
import { FixedRules } from "./fixed-rules";

export function CompanyKnowledge() {
  const { user } = useDashboard();
  const { data: loaded, loading, error, reload } = useResource<KnowledgeLibrary>(user ? "knowledge/library" : null);
  const [confirmed, setConfirmed] = useState<KnowledgeLibrary | null>(null);
  const data = confirmed && (!loaded || confirmed.revision > loaded.revision) ? confirmed : loaded;
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [errorSection, setErrorSection] = useState<"library" | "mcp">("library");
  const [notice, setNotice] = useState("");
  const [selected, setSelected] = useState<KnowledgeSource | null>(null);
  const [removing, setRemoving] = useState<KnowledgeSource | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const editable = hasRole(user, "security_analyst");
  const valid = data && typeof data.enabled === "boolean" && Number.isSafeInteger(data.revision) &&
    Array.isArray(data.documents) && Array.isArray(data.sources);
  const loadError = error || (data && !valid ? "The server returned an unsupported knowledge configuration." : "");
  const sources = valid ? data.sources.filter((source) => source.status !== "revoked") : [];
  const indexed = sources.filter((source) => source.status === "current" && source.fresh);
  const canEnable = valid && (data.retrieval_mode === "postgres" ? indexed.length > 0 : data.documents.length > 0);

  async function save(operation: () => Promise<void>, section: "library" | "mcp" = "library") {
    if (saving) return;
    setSaving(true);
    setSaveError("");
    setErrorSection(section);
    setNotice("");
    try {
      await operation();
    } catch (cause) {
      setSaveError(cause instanceof Error ? cause.message : "Unable to save knowledge settings.");
      if (cause instanceof APIError && [401, 409].includes(cause.status)) await reload();
    } finally {
      setSaving(false);
    }
  }

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!data || !uploadFile) return;
    const file = uploadFile;
    const form = new FormData(event.currentTarget);
    await save(async () => {
      if (!file.size || file.size > 5 * 1024 * 1024) throw new Error("Upload a nonempty file no larger than 5 MiB.");
      const content = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(",")[1]);
        reader.onerror = () => reject(new Error("Unable to read the selected file."));
        reader.readAsDataURL(file);
      });
      await api("knowledge/uploads", { method: "POST", body: JSON.stringify({
        revision: data.revision, filename: file.name, content,
        keywords: String(form.get("keywords") || "").split(",").map((term) => term.trim()).filter(Boolean),
      }) });
      if (fileInput.current) fileInput.current.value = "";
      setUploadFile(null);
      await reload();
      setNotice(`${file.name} was indexed.${data.enabled ? "" : " Enable company knowledge to use it in new assessments."}`);
    });
  }

  return (
    <div className="space-y-6">
      <CompanyKnowledgeViewSwitch view="current" />
      <CompanyPolicyFlow />
      <div id="fixed-rules" className="scroll-mt-4">
        {user && <FixedRules key={user.tenant.id} />}
      </div>
      {user && <CompanyPolicy key={user.tenant.id} editable={editable} />}
      <section aria-label="Company knowledge" className="space-y-3 text-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div><h2 className="font-semibold">Company knowledge</h2><p className="text-xs text-muted-foreground">Add relevant documents and MCP resources to model assessments.</p></div>
        {valid && editable && (
          <Button role="switch" aria-label="Use company knowledge" aria-checked={data.enabled}
            variant={data.enabled ? "outline" : "default"}
            disabled={saving || loading || !!loadError || (!data.enabled && !canEnable)}
            onClick={() => void save(async () => {
              setConfirmed(await api<KnowledgeLibrary>("knowledge/library", { method: "PUT",
                body: JSON.stringify({ enabled: !data.enabled, revision: data.revision }) }));
            })}>
            {saving ? "Saving…" : data.enabled ? "Disable knowledge" : "Enable knowledge"}
          </Button>
        )}
        </div>
        <div className="space-y-4 text-sm">
          {!data && loading && <LoadingState label="Loading company knowledge…" />}
          {loadError && <ErrorState message={loadError} onRetry={reload} />}
          {saveError && errorSection === "library" && <p role="alert" className="text-destructive">{saveError}</p>}
          {notice && <p role="status">{notice}</p>}
          {valid && <>
            <div className="flex flex-wrap items-center gap-3" aria-live="polite">
              <Status tone={data.enabled ? "info" : "neutral"}>
                {data.enabled ? "Enabled" : "Disabled"}{loadError ? " (last confirmed)" : ""}
              </Status>
              <span className="text-xs text-muted-foreground">
                {data.retrieval_mode === "postgres" ? indexed.length : data.documents.length} documents indexed · Revision {data.revision}
              </span>
              <Button variant="ghost" size="sm" disabled={loading || saving} onClick={reload}>Refresh knowledge</Button>
            </div>
            {!editable && <p className="text-muted-foreground">A Security Analyst can change this setting.</p>}
            {!canEnable && !sources.length && !data.documents.length && (
              <p>No documents indexed. Upload a document or import MCP content to enable company knowledge.</p>
            )}
          </>}
        </div>
      </section>
      {valid && <>
        <SettingsLayout>
          {editable && <PageSection title="Upload documents"
            className="min-w-0 self-stretch [&>[data-slot=card]]:h-full [&_[data-slot=section-body]]:flex [&_[data-slot=section-body]]:flex-1"
            description="Add reference material about your systems, data, and internal workflows.">
            <form onSubmit={(event) => void upload(event)} className="flex min-w-0 flex-1 flex-col gap-3 text-sm">
              <div className="grid gap-3">
                <label className="relative flex min-h-24 items-center justify-center gap-3 rounded-md border border-dashed border-input bg-muted/30 p-4 has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-ring"
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={(event) => {
                    event.preventDefault();
                    if (!saving && !loading && !loadError) setUploadFile(event.dataTransfer.files[0] ?? null);
                  }}>
                  <Upload aria-hidden="true" className="size-5 shrink-0 text-primary" />
                  <span className="min-w-0"><span className="block break-all font-medium text-primary">{uploadFile?.name || "Choose a document"}</span>
                    <span className="block text-xs text-muted-foreground">{uploadFile ? "Ready to upload" : "or drop it here · up to 5 MiB"}</span>
                  </span>
                  <Input ref={fileInput} type="file" aria-label="Document" className="absolute inset-0 h-full cursor-pointer opacity-0"
                    accept=".md,.markdown,.txt,.pdf,.docx" required={!uploadFile} disabled={saving || loading || !!loadError}
                    onChange={(event) => setUploadFile(event.target.files?.[0] ?? null)} />
                </label>
                <p className="text-xs text-muted-foreground">Markdown, text, PDF, or Word (.docx). PDF files must contain text. Uploading the same filename replaces its indexed content.</p>
                <label className="space-y-1"><span>Keywords (optional)</span>
                  <Input name="keywords" placeholder="deploy, routing, production" disabled={saving} />
                </label>
              </div>
              <div className="mt-auto space-y-3">
                <p className="text-xs text-muted-foreground">Documents are shared with your organization. Original files are not retained; extracted text is indexed for reference.</p>
                <Button type="submit" variant="outline" disabled={saving || loading || !!loadError}>Upload document</Button>
              </div>
            </form>
          </PageSection>}
          <div className={editable ? "min-w-0 self-stretch" : "min-w-0 xl:col-span-2"}>
            <CompanyKnowledgeMCP revision={data.revision} editable={editable} busy={saving} blocked={loading || !!loadError}
              saveError={errorSection === "mcp" ? saveError : ""} run={(operation) => save(operation, "mcp")} onChange={reload} />
          </div>
        </SettingsLayout>
        {(!!sources.length || !!data.documents.length) && <PageSection title="Documents">
          <div className="space-y-4 text-sm">
            {!!sources.length && <Table>
              <TableHeader><TableRow><TableHead>Document</TableHead><TableHead>Source</TableHead><TableHead>Status</TableHead><TableHead>Actions</TableHead></TableRow></TableHeader>
              <TableBody>{sources.map((source) => <TableRow key={source.source_id}>
                <TableCell className="font-medium">{source.title}</TableCell>
                <TableCell>{source.source_type === "upload" ? "Upload" : source.source_type === "mcp" ? "MCP" : source.source_type === "manual" ? "Manual" : "Markdown"}</TableCell>
                <TableCell><Status tone={source.fresh ? "ok" : "warning"}>
                  {source.status === "pending" ? "Indexing" : source.fresh ? "Indexed" : "Expired"}
                </Status></TableCell>
                <TableCell><div className="flex gap-2">
                  <Button variant="ghost" size="xs" onClick={() => setSelected(source)}>Inspect</Button>
                  {editable && !["manual", "mcp"].includes(source.source_type) && <Button variant="ghost" size="xs" disabled={saving || loading || !!loadError} onClick={() => { setSaveError(""); setRemoving(source); }}>Remove</Button>}
                </div></TableCell>
              </TableRow>)}</TableBody>
            </Table>}
            {!!data.documents.length && !sources.some((source) => source.source_type === "manual") && <PageNotice title="Indexed documents" collapsible>
              {data.documents.map((document) => <div key={document.id} className="break-words">
                <p className="font-medium">{document.title}</p>
                <p className="text-xs text-muted-foreground">{document.kind === "command" ? "Command" : "Resource"} · Keywords: {document.keywords.join(", ")}</p>
              </div>)}
            </PageNotice>}
          </div>
        </PageSection>}
      </>}
      <Dialog open={!!selected} onOpenChange={(open) => { if (!open) setSelected(null); }}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader><DialogTitle>{selected?.title}</DialogTitle><DialogDescription>Indexed reference passages. Historical assessments keep their original evidence.</DialogDescription></DialogHeader>
          {selected && <SourcePreview source={selected} />}
        </DialogContent>
      </Dialog>
      <Dialog open={!!removing} onOpenChange={(open) => { if (!open && !saving) setRemoving(null); }}>
        <DialogContent><DialogHeader><DialogTitle>Remove document</DialogTitle><DialogDescription>Remove {removing?.title} from new assessments? Historical evidence is retained.</DialogDescription></DialogHeader>
          {saveError && errorSection === "library" && <p role="alert" className="text-destructive">{saveError}</p>}
          <Button disabled={saving} onClick={() => void save(async () => {
            if (!data || !removing) return;
            await api(`knowledge/sources/${encodeURIComponent(removing.source_id)}/revoke`, { method: "POST", body: JSON.stringify({ revision: data.revision }) });
            setRemoving(null);
            await reload();
          })}>Remove document</Button>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function SourcePreview({ source }: { source: KnowledgeSource }) {
  const { data, loading, error, reload } = useResource<{ passages: { passage_id: string; section_path: string; body: string }[] }>(
    `knowledge/sources/${encodeURIComponent(source.source_id)}`,
  );
  return <div className="space-y-3 text-sm">
    {loading && <LoadingState label="Loading passages…" />}
    {error && <ErrorState message={error} onRetry={reload} />}
    {data && !data.passages.length && <p>No current passages. Reimport this source to update it.</p>}
    {data?.passages.map((passage) => <div key={passage.passage_id} className="space-y-1 border-t pt-3">
      <h3 className="font-medium">{passage.section_path}</h3><p className="whitespace-pre-wrap break-words">{passage.body}</p>
    </div>)}
  </div>;
}
