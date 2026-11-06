"use client";

import { useState } from "react";
import { Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { useResource } from "@/lib/use-resource";
import { useDashboard } from "@/components/dashboard-context";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { ErrorState, LoadingState, PageNotice } from "@/components/page-layout";

type Settings = {
  mode: "off" | "pilot" | "automatic"; pilot_size: number;
  pending: number; running: number; completed: number; failed: number;
  worker_available: boolean; key_configured: boolean; budget_blocked: boolean;
};
const modes = { off: "Paused", pilot: "Pilot", automatic: "New and changed skills" };

export function SkillLlmControls({ onChanged }: { onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const { user } = useDashboard();
  const admin = user?.roles.includes("it_admin");
  const resource = useResource<Settings>(open ? "inventory/skills/llm" : null, 15_000);
  const data = resource.data;
  const allowed = data?.worker_available && data?.key_configured;
  async function save(mode: Settings["mode"]) {
    setSaving(true); setError("");
    try {
      await api("inventory/skills/llm", { method: "PUT", body: JSON.stringify({ mode }) });
      await resource.reload();
      onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to update skill analysis.");
    } finally { setSaving(false); }
  }
  return <Dialog open={open} onOpenChange={setOpen}>
    <DialogTrigger asChild><Button variant="outline" size="responsive" onClick={() => { setOpen(true); setError(""); }}>
      <Sparkles className="size-3.5" />AI scan
    </Button></DialogTrigger>
      <DialogContent className="max-h-[85dvh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>AI skill analysis</DialogTitle>
          <DialogDescription>Use OpenAIDR to review skill instructions and code.</DialogDescription>
        </DialogHeader>
        {resource.loading && !data && <LoadingState />}
        {(error || resource.error) && <ErrorState message={error || resource.error} onRetry={resource.reload} />}
        {data && <div className="space-y-4 text-sm">
          <dl className="grid grid-cols-2 gap-3 border-b pb-4">
            <div><dt className="text-xs text-muted-foreground">Mode</dt><dd className="font-medium">{modes[data.mode]}</dd></div>
            <div><dt className="text-xs text-muted-foreground">Scans</dt><dd>{data.completed} complete · {data.failed} incomplete or failed</dd></div>
            <div><dt className="text-xs text-muted-foreground">Queue</dt><dd>{data.running} running · {data.pending} queued</dd></div>
          </dl>
          {!data.key_configured && <PageNotice title="Intelligence service required">An administrator must configure the tenant Intelligence service connection.</PageNotice>}
          {!data.worker_available && <PageNotice title="Scanner unavailable">Start or update the skill scanner to enable model analysis.</PageNotice>}
          {data.budget_blocked && <PageNotice title="Service allowance reached">Contact your administrator to review the allowance. Unstarted scans remain queued.</PageNotice>}
          <p className="text-muted-foreground">The pilot scans up to {data.pilot_size} collected bundles. Automatic mode scans new or changed bundles and reuses results for the same SHA-256 and scanner version. Scans begin after the next sensor upload. Failed attempts are not retried automatically.</p>
          <p className="text-muted-foreground">Selected skill contents are sent to the OpenAIDR Intelligence service for analysis. Your backend retains collected skill content and assessment results.</p>
          {admin ? <div className="space-y-3 border-t pt-4">
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => void save("pilot")} disabled={saving || !allowed}>Run {data.pilot_size}-bundle pilot</Button>
              <Button variant="outline" onClick={() => void save("automatic")} disabled={saving || !allowed}>Scan new and changed</Button>
              <Button variant="outline" onClick={() => void save("off")} disabled={saving || data.mode === "off"}>Pause</Button>
            </div>
            <p className="text-xs text-muted-foreground">Pause stops new analysis requests. Requests already sent may finish.</p>
          </div> : <p className="text-muted-foreground">An IT admin can change scan settings.</p>}
        </div>}
      </DialogContent>
  </Dialog>;
}
