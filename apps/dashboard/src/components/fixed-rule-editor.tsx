"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, APIError } from "@/lib/api";
import { displayText } from "@/lib/display";
import type { Policy } from "./fixed-rules";

export type RuleDraft = {
  intent: string;
  explanation: string;
  limitations: string[];
  rule: {
    name: string;
    action: "deny" | "ask" | "warn";
    reason: string;
    match: { kinds: string[]; products: string[]; tool_name: string; command_regex: string; path_glob: string; host_glob: string };
  };
  examples: {
    label: string; kind: string; value: string; product: string; tool_name: string;
    os: string; path_home: string; expected_match: boolean;
  }[];
};
type Preview = {
  version: number;
  passed: boolean;
  results: { label: string; matched: boolean | null; expected_match: boolean; shadowed: boolean;
    action: string | null; rule_name: string; passed: boolean; error: string }[];
};
type Generation = { status: "draft"; draft: RuleDraft } | { status: "clarify" | "unsupported"; explanation: string };
type Saved = { policy: Policy; rule_id: string };
const KINDS = ["command", "file.read", "file.write", "network", "tool.call"];

export function FixedRuleEditor({ policy, existing, onSaved, onReload, onClose }: {
  policy: Policy;
  existing?: Policy["rules"][number];
  onSaved: (policy: Policy) => void;
  onReload: () => Promise<void>;
  onClose: () => void;
}) {
  const [intent, setIntent] = useState(existing?.authoring?.intent || "");
  const [draft, setDraft] = useState<RuleDraft | null>(existing?.authoring || null);
  const [savedId, setSavedId] = useState(existing?.id || "");
  const [lists, setLists] = useState({ kinds: existing?.authoring?.rule.match.kinds.join(", ") || "",
    products: existing?.authoring?.rule.match.products.join(", ") || "" });
  const [preview, setPreview] = useState<Preview | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const tested = preview?.passed && preview.version === policy.version;

  async function run(label: string, operation: () => Promise<void>) {
    if (busy) return;
    setBusy(label);
    setError("");
    setMessage("");
    try {
      await operation();
    } catch (cause) {
      setPreview(null);
      setError(cause instanceof Error ? cause.message : "Unable to complete the rule request.");
      if (cause instanceof APIError && cause.status === 409) await onReload();
    } finally {
      setBusy("");
    }
  }

  function change(next: RuleDraft) {
    setDraft(next);
    setPreview(null);
    setMessage("");
    setError("");
  }

  async function generate() {
    await run("Generating", async () => {
      setDraft(null);
      setPreview(null);
      const result = await api<Generation>("response/policy/rules/generate", {
        method: "POST", body: JSON.stringify({ intent }),
      });
      if (result.status === "draft") {
        setDraft(result.draft);
        setLists({ kinds: result.draft.rule.match.kinds.join(", "), products: result.draft.rule.match.products.join(", ") });
      }
      else setMessage(result.explanation);
    });
  }

  async function testDraft() {
    await run("Testing", async () => {
      setPreview(await api<Preview>("response/policy/rules/preview", {
        method: "POST", body: JSON.stringify({ version: policy.version, draft, rule_id: savedId }),
      }));
    });
  }

  async function save() {
    if (!tested || !draft) return;
    await run(savedId ? "Enabling" : "Saving", async () => {
      const result = await api<Saved>(savedId ? `response/policy/rules/${savedId}` : "response/policy/rules/drafts", {
        method: savedId ? "PATCH" : "POST",
        body: JSON.stringify(savedId ? { version: policy.version, enabled: true } : { version: policy.version, draft }),
      });
      onSaved(result.policy);
      if (savedId) onClose();
      else {
        setSavedId(result.rule_id);
        setPreview(null);
        setMessage("Rule saved disabled. Test the saved rule, then enable it when you are satisfied.");
      }
    });
  }

  return <Dialog open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <DialogContent variant="drawer" showCloseButton={!busy} className="sm:max-w-3xl">
      <DialogHeader className="shrink-0 border-b p-5 pr-12 text-left">
        <DialogTitle>{savedId ? "Review saved rule" : "Create rule from description"}</DialogTitle>
        <DialogDescription>Describe intent, review the draft, and test its effect before enabling it.</DialogDescription>
      </DialogHeader>
      <div className="min-h-0 flex-1 space-y-5 overflow-y-auto p-5 text-sm">
        {error && <p role="alert" className="text-destructive">{error}</p>}
        {message && <p role="status">{message}</p>}
        <div className="space-y-2">
          <label className="block space-y-1">
            <span className="font-medium">Describe your intent</span>
            <Textarea value={intent} maxLength={4000} rows={3} disabled={!!busy || !!savedId}
              placeholder="Block agents from reading files under /srv/payroll/"
              onChange={(event) => { setIntent(event.target.value); setDraft(null); setPreview(null); setMessage(""); }} />
          </label>
          {!savedId && <>
            <p className="text-xs text-muted-foreground">Your description is sent to the configured AI provider. Use example values for secrets.</p>
            <Button disabled={!!busy || !intent.trim()} onClick={() => void generate()}>
              {busy === "Generating" ? "Generating draft…" : "Generate draft"}
            </Button>
          </>}
        </div>
        {draft && <>
          <div className="space-y-2 rounded-md bg-muted p-3">
            <p className="font-medium">Generated explanation</p>
            <p>{draft.explanation}</p>
            {draft.limitations.length > 0 && <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              {draft.limitations.map((item, index) => <li key={index}>{item}</li>)}
            </ul>}
          </div>
          <fieldset disabled={!!busy || !!savedId} className="min-w-0 space-y-3">
            <legend className="mb-2 font-semibold">Rule conditions</legend>
            <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
              <label className="min-w-0 space-y-1"><span>Rule name</span>
                <Input value={draft.rule.name} maxLength={120} onChange={(e) => change({ ...draft, rule: { ...draft.rule, name: e.target.value } })} />
              </label>
              <div className="space-y-1"><span id="rule-action-label">Action</span>
                <Select value={draft.rule.action} disabled={!!busy || !!savedId}
                  onValueChange={(action: RuleDraft["rule"]["action"]) => change({ ...draft, rule: { ...draft.rule, action } })}>
                  <SelectTrigger aria-labelledby="rule-action-label"><SelectValue /></SelectTrigger>
                  <SelectContent>{["deny", "ask", "warn"].map((action) => <SelectItem key={action} value={action}>{action}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>
            <label className="block space-y-1"><span>Reason shown to the agent</span>
              <Input value={draft.rule.reason} maxLength={500} onChange={(e) => change({ ...draft, rule: { ...draft.rule, reason: e.target.value } })} />
            </label>
            <div className="grid gap-3 sm:grid-cols-2">
              {([
                ["kinds", "Event kinds (comma separated)"], ["products", "Agent products (empty means all)"],
                ["path_glob", "File path pattern"], ["host_glob", "Host pattern"], ["tool_name", "Tool name or prefix"],
              ] as const).map(([key, label]) => <label key={key} className="min-w-0 space-y-1"><span>{label}</span>
                <Input className="font-mono text-sm font-normal" value={key === "kinds" || key === "products" ? lists[key] : draft.rule.match[key]}
                  onChange={(e) => {
                    if (key === "kinds" || key === "products") setLists({ ...lists, [key]: e.target.value });
                    change({ ...draft, rule: { ...draft.rule, match: { ...draft.rule.match,
                    [key]: key === "kinds" || key === "products" ? e.target.value.split(",").map((v) => v.trim()).filter(Boolean) : e.target.value,
                  } } }); }} />
              </label>)}
            </div>
            <details open={!!draft.rule.match.command_regex} className="space-y-2">
              <summary className="cursor-pointer font-medium">Advanced command matching</summary>
              <label className="block space-y-1"><span>Command regex</span>
                <Textarea value={draft.rule.match.command_regex} maxLength={2000} rows={2} className="font-mono text-sm font-normal"
                  onChange={(e) => change({ ...draft, rule: { ...draft.rule, match: { ...draft.rule.match, command_regex: e.target.value } } })} />
              </label>
            </details>
          </fieldset>
          <fieldset disabled={!!busy || !!savedId} className="min-w-0 space-y-3">
            <legend className="mb-2 font-semibold">Test cases</legend>
            <p className="text-xs text-muted-foreground">Examples are synthetic. Edit them to check your intended coverage. Tests do not execute commands.</p>
            {draft.examples.map((example, index) => <div key={index} className="space-y-2 border-t py-3">
              <p className="font-medium">{example.label}</p>
              <label className="block space-y-1"><span>Test input {index + 1}</span>
                <Input className="font-mono text-sm font-normal" value={example.value} maxLength={2000} onChange={(e) => change({ ...draft, examples: draft.examples.map((row, i) => i === index ? { ...row, value: e.target.value } : row) })} />
              </label>
              <div className="flex flex-wrap gap-2">
                <Select value={example.kind} disabled={!!busy || !!savedId} onValueChange={(kind) => change({ ...draft, examples: draft.examples.map((row, i) => i === index ? { ...row, kind } : row) })}>
                  <SelectTrigger aria-label={`Event kind ${index + 1}`}><SelectValue /></SelectTrigger>
                  <SelectContent>{KINDS.map((kind) => <SelectItem key={kind} value={kind}>{kind}</SelectItem>)}</SelectContent>
                </Select>
                <Select value={String(example.expected_match)} disabled={!!busy || !!savedId} onValueChange={(value) => change({ ...draft, examples: draft.examples.map((row, i) => i === index ? { ...row, expected_match: value === "true" } : row) })}>
                  <SelectTrigger aria-label={`Expected match ${index + 1}`}><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="true">Should match</SelectItem><SelectItem value="false">Should not match</SelectItem></SelectContent>
                </Select>
              </div>
              <details className="space-y-2"><summary className="cursor-pointer text-xs text-muted-foreground">Test context: {example.os}{example.product ? ` · ${example.product}` : ""}</summary>
                <div className="grid gap-2 sm:grid-cols-2">
                  {([ ["product", "Agent product"], ["tool_name", "Tool name"], ["os", "Platform (linux, darwin, windows)"], ["path_home", "Home directory"] ] as const).map(([key, label]) => <label key={key} className="min-w-0 space-y-1 text-xs"><span>{label} for test {index + 1}</span>
                    <Input className="font-mono text-sm font-normal" value={example[key]} onChange={(e) => change({ ...draft, examples: draft.examples.map((row, i) => i === index ? { ...row, [key]: e.target.value } : row) })} />
                  </label>)}
                </div>
              </details>
              {preview?.results[index] && <div className="space-y-1 text-xs" role="status">
                <p className={preview.results[index].passed ? "text-status-ok" : "text-destructive"}>
                  {preview.results[index].passed ? "Passed" : "Needs attention"}: {preview.results[index].error ||
                    `Draft ${preview.results[index].matched ? "matches" : "does not match"}. Fixed-rule decision: ${preview.results[index].action}.`}
                </p>
                {preview.results[index].shadowed && <p className="text-destructive">Earlier rule “{displayText(preview.results[index].rule_name)}” takes precedence. Refine this draft or review the existing policy.</p>}
              </div>}
            </div>)}
          </fieldset>
          <p className="text-xs text-muted-foreground">New rules are appended. The first matching rule wins. Tests cover these examples only. Enabled model thresholds may add restrictions. Shadow records decisions and allows actions; Enforce returns supported decisions. Hook failures allow actions.</p>
        </>}
      </div>
      <div className="flex shrink-0 flex-wrap items-center justify-end gap-2 border-t p-4">
        <Button variant="ghost" disabled={!!busy} onClick={onClose}>Close</Button>
        {draft && <>
          <Button variant="outline" disabled={!!busy} onClick={() => void testDraft()}>{busy === "Testing" ? "Testing…" : "Test against current rules"}</Button>
          <Button disabled={!!busy || !tested} onClick={() => void save()}>{busy === "Saving" || busy === "Enabling" ? `${busy}…` : savedId ? "Enable rule" : "Save disabled rule"}</Button>
        </>}
      </div>
    </DialogContent>
  </Dialog>;
}
