"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { CodeBlock } from "@/components/ui/code-block";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { api } from "@/lib/api";

export type MCPImport =
  | { kind: "resource"; uri: string }
  | { kind: "template"; uri_template: string; parameters: Record<string, unknown> }
  | { kind: "tool"; name: string; arguments: Record<string, unknown>; schema_hash: string };
export type MCPCatalog = {
  resources: { uri: string; name: string; mime_type: string }[];
  templates: { uri_template: string; name: string; description: string; parameters: string[] }[];
  tools: { name: string; title: string; description: string; input_schema: Record<string, unknown>; schema_hash: string; can_import: boolean }[];
};
export type MCPConnection = {
  connection_id: string; name: string; endpoint: string; has_token: boolean;
  auth_type?: string; imports?: MCPImport[]; resource_uris: string[]; synced_at: string | null;
};

export function savedImports(connection: MCPConnection): MCPImport[] {
  return connection.imports ?? connection.resource_uris.map((uri) => ({ kind: "resource", uri }));
}

function label(source: MCPImport) {
  return source.kind === "resource" ? source.uri : source.kind === "template" ? source.uri_template : source.name;
}

export function MCPContentPicker({ connection, catalog, busy, blocked, saveError, run, onSave, onClose }: {
  connection: MCPConnection; catalog: MCPCatalog; busy: boolean; blocked: boolean; saveError: string;
  run: (operation: () => Promise<void>) => Promise<void>;
  onSave: (sources: MCPImport[]) => Promise<void>; onClose: () => void;
}) {
  const [selected, setSelected] = useState<MCPImport[]>(() => savedImports(connection));
  const [toolName, setToolName] = useState("");
  const [templateUri, setTemplateUri] = useState("");
  const [argumentsText, setArgumentsText] = useState("{}");
  const [parametersText, setParametersText] = useState("{}");
  const [preview, setPreview] = useState<{ source: MCPImport; text: string } | null>(null);
  const tool = catalog.tools.find((item) => item.name === toolName);
  const template = catalog.templates.find((item) => item.uri_template === templateUri);
  const disabled = busy || blocked;

  function add(source: MCPImport) {
    setSelected((items) => items.some((item) => JSON.stringify(item) === JSON.stringify(source)) ? items : [...items, source]);
    setPreview(null);
  }

  async function read(kind: "template" | "tool") {
    setPreview(null);
    let values: Record<string, unknown>;
    try {
      values = JSON.parse(kind === "tool" ? argumentsText : parametersText);
      if (!values || Array.isArray(values) || typeof values !== "object") throw new Error();
    } catch {
      throw new Error("Enter a valid JSON object for the parameters.");
    }
    const source: MCPImport = kind === "tool"
      ? { kind, name: tool!.name, arguments: values, schema_hash: tool!.schema_hash }
      : { kind, uri_template: template!.uri_template, parameters: values };
    const result = await api<{ document: { text: string } }>(`knowledge/mcp/${connection.connection_id}/preview`, {
      method: "POST", body: JSON.stringify({ source }),
    });
    setPreview({ source, text: result.document.text });
  }

  return <Dialog open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>Select MCP content</DialogTitle>
        <DialogDescription>Choose up to 20 imports from {connection.name}. Saving replaces this connection’s selection. Removed documents are excluded from new assessments.</DialogDescription>
      </DialogHeader>
      {saveError && <p role="alert" className="text-sm text-destructive">{saveError}</p>}
      <Tabs defaultValue={catalog.resources.length ? "resources" : catalog.tools.length ? "tools" : "templates"} onValueChange={() => setPreview(null)}>
        <TabsList aria-label="MCP content types">
          <TabsTrigger value="resources">Resources ({catalog.resources.length})</TabsTrigger>
          <TabsTrigger value="templates">Templates ({catalog.templates.length})</TabsTrigger>
          <TabsTrigger value="tools">Tools ({catalog.tools.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="resources" className="space-y-2">
          {!catalog.resources.length && <p className="text-sm text-muted-foreground">This server lists no resources. Check its tools and templates.</p>}
          {catalog.resources.map((resource) => {
            const checked = selected.some((item) => item.kind === "resource" && item.uri === resource.uri);
            return <label key={resource.uri} className="flex items-start gap-3 rounded-md border p-3 text-sm">
              <input type="checkbox" className="mt-1" checked={checked} disabled={disabled || (!checked && selected.length >= 20)}
                onChange={(event) => event.target.checked ? add({ kind: "resource", uri: resource.uri }) : setSelected(selected.filter((item) => item.kind !== "resource" || item.uri !== resource.uri))} />
              <span className="min-w-0"><span className="block font-medium break-words">{resource.name}</span><span className="block break-all text-xs text-muted-foreground">{resource.uri}</span></span>
            </label>;
          })}
        </TabsContent>
        <TabsContent value="templates" className="space-y-3 text-sm">
          {!catalog.templates.length ? <p className="text-muted-foreground">This server lists no resource templates.</p> : <>
            <Select value={templateUri} onValueChange={(value) => { setTemplateUri(value); setPreview(null); setParametersText("{}"); }} disabled={disabled}>
              <SelectTrigger aria-label="Resource template" className="w-full"><SelectValue placeholder="Choose a resource template" /></SelectTrigger>
              <SelectContent>{catalog.templates.map((item) => <SelectItem key={item.uri_template} value={item.uri_template}>{item.name}</SelectItem>)}</SelectContent>
            </Select>
            {template && <>
              <p className="break-words text-muted-foreground">{template.description}</p>
              <p className="break-all font-mono text-xs">{template.uri_template}</p>
              <p className="break-words text-xs">Parameters: {template.parameters.join(", ") || "None"}</p>
              <label className="block space-y-1"><span>Template parameters (JSON)</span><Textarea value={parametersText} onChange={(event) => { setParametersText(event.target.value); setPreview(null); }} disabled={disabled} maxLength={32768} className="font-mono" /></label>
              <Button variant="outline" disabled={disabled} onClick={() => void run(() => read("template"))}>Preview resource</Button>
            </>}
          </>}
        </TabsContent>
        <TabsContent value="tools" className="space-y-3 text-sm">
          {!catalog.tools.length ? <p className="text-muted-foreground">This server lists no tools.</p> : <>
            <p className="text-muted-foreground">Choose a retrieval tool you trust. Preview runs it on the server. Saving and refreshing run it again with the same arguments.</p>
            <Select value={toolName} onValueChange={(value) => { setToolName(value); setPreview(null); setArgumentsText("{}"); }} disabled={disabled}>
              <SelectTrigger aria-label="MCP tool" className="w-full"><SelectValue placeholder="Choose a tool" /></SelectTrigger>
              <SelectContent>{catalog.tools.map((item) => <SelectItem key={item.name} value={item.name} disabled={!item.can_import}>{item.title}{!item.can_import ? " (modifies data)" : ""}</SelectItem>)}</SelectContent>
            </Select>
            {tool && <>
              <p className="break-words text-muted-foreground">{tool.description}</p>
              <details><summary className="cursor-pointer">Tool input schema</summary><CodeBlock className="max-h-48 break-all">{JSON.stringify(tool.input_schema, null, 2)}</CodeBlock></details>
              <label className="block space-y-1"><span>Tool arguments (JSON)</span><Textarea value={argumentsText} onChange={(event) => { setArgumentsText(event.target.value); setPreview(null); }} disabled={disabled} maxLength={32768} className="font-mono" /></label>
              <Button variant="outline" disabled={disabled || !tool.can_import} onClick={() => void run(() => read("tool"))}>Run tool and preview</Button>
            </>}
          </>}
        </TabsContent>
      </Tabs>
      {preview && <div className="space-y-2">
        <h3 className="text-sm font-semibold">Preview</h3>
        <CodeBlock className="max-h-64 break-all">{preview.text}</CodeBlock>
        <Button variant="outline" disabled={disabled || selected.length >= 20} onClick={() => add(preview.source)}>Add to selection</Button>
      </div>}
      <div className="space-y-2 border-t pt-3 text-sm">
        <h3 className="font-semibold">Selected imports ({selected.length}/20)</h3>
        {selected.map((source, index) => <div key={index} className="flex items-start justify-between gap-2">
          <div className="min-w-0"><p className="break-all">{label(source)}</p>{source.kind !== "resource" && <p className="break-all text-xs text-muted-foreground">{JSON.stringify(source.kind === "tool" ? source.arguments : source.parameters)}</p>}</div>
          <Button variant="ghost" size="sm" disabled={disabled} aria-label={`Remove ${label(source)}`} onClick={() => setSelected(selected.filter((_, i) => i !== index))}>Remove</Button>
        </div>)}
        <Button disabled={disabled} onClick={() => void run(() => onSave(selected))}>{busy ? "Working…" : "Save import selection"}</Button>
      </div>
    </DialogContent>
  </Dialog>;
}
