"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { ExternalLink, Headset, Slack, X } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverClose, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { api, APIError } from "@/lib/api";
import { hasRole } from "@/lib/roles";
import { useResource } from "@/lib/use-resource";

type Settings = { slack_channel_url: string; version: number; updated_at: string | null };
const channelLink = /^https:\/\/(?:app\.slack\.com\/client\/[TE][A-Z0-9]+\/[CG][A-Z0-9]+|[a-z0-9][a-z0-9-]*\.slack\.com\/archives\/[CG][A-Z0-9]+|slack\.com\/app_redirect\?team=[TE][A-Z0-9]+&channel=[CG][A-Z0-9]+)$/;

function validSettings(value: Settings) {
  return Boolean(value && typeof value.slack_channel_url === "string" && value.slack_channel_url.length <= 2048
    && (!value.slack_channel_url || channelLink.test(value.slack_channel_url))
    && Number.isSafeInteger(value.version) && value.version >= 0
    && (value.updated_at === null || typeof value.updated_at === "string"));
}

export function ContactSupport() {
  const { user } = useDashboard();
  const [open, setOpen] = useState(false);
  const titleId = useId();
  const resource = useResource<Settings>(open && user ? "settings/support" : null, 0, false, { validate: validSettings });
  const data = resource.data && validSettings(resource.data) ? resource.data : null;
  return <Popover open={open} onOpenChange={setOpen}>
    <PopoverTrigger asChild>
      <Button variant="outline" size="responsive" aria-label="Contact support" title="Contact support"
        className="w-10 px-0 text-primary data-[state=open]:border-primary data-[state=open]:bg-accent sm:w-auto sm:px-2.5">
        <Headset aria-hidden="true" /><span className="hidden sm:inline">Support</span>
      </Button>
    </PopoverTrigger>
    <PopoverContent className="w-80" aria-labelledby={titleId}>
      <div className="flex items-center justify-between gap-3">
        <h2 id={titleId} className="text-base font-semibold">Contact support</h2>
        <PopoverClose asChild><Button variant="ghost" size="icon-xs" aria-label="Close support"><X /></Button></PopoverClose>
      </div>
      <p className="mt-2 text-sm text-muted-foreground">Ask a question or report an issue to the OpenSecura team.</p>
      <div className="mt-4">
        {resource.loading ? <LoadingState label="Loading support channel" />
          : resource.error || !data ? <ErrorState message="Support is unavailable right now." onRetry={resource.reload} />
          : data.slack_channel_url ? <>
            <div className="mb-3 flex items-center gap-3 rounded-md border bg-muted/30 p-3">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-md border bg-card text-primary"><Slack aria-hidden="true" className="size-5" /></span>
              <div className="min-w-0"><p className="font-medium">Slack support</p><p className="break-words text-xs text-muted-foreground">{user?.tenant.name}</p></div>
            </div>
            <Button asChild className="w-full"><a href={data.slack_channel_url} target="_blank" rel="noopener noreferrer">Open Slack<ExternalLink aria-hidden="true" /></a></Button>
            <p className="mt-2 text-center text-xs text-muted-foreground">Opens in a new tab</p>
          </> : <>
            <p className="text-sm text-muted-foreground">{hasRole(user, "it_admin")
              ? "Add your workspace's Slack support channel in Settings."
              : "Slack support has not been set up for this workspace. Contact your IT admin for help."}</p>
            {hasRole(user, "it_admin") && <Button asChild className="mt-3 w-full"><Link href="/administration/settings#support" onClick={() => setOpen(false)}>Set up support</Link></Button>}
          </>}
      </div>
    </PopoverContent>
  </Popover>;
}

function SupportForm({ settings, saved, refresh, unverified }: {
  settings: Settings; saved: (value: Settings) => void; refresh: () => Promise<void>; unverified: boolean;
}) {
  const [draft, setDraft] = useState<{ settings: Settings; url: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const hintId = useId();
  const conflict = draft !== null && draft.settings.version !== settings.version;
  async function save() {
    if (!draft || saving || unverified || conflict) return;
    setSaving(true); setError(""); setNotice("");
    try {
      const result = await api<Settings>("settings/support", { method: "PUT",
        body: JSON.stringify({ slack_channel_url: draft.url, version: draft.settings.version }) });
      if (!validSettings(result)) throw new Error("The server did not confirm the support channel.");
      saved(result);
      setDraft(null);
      setNotice(result.slack_channel_url ? "Support channel saved." : "Support channel removed.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to save the support channel.");
      if (cause instanceof APIError && cause.status === 409) await refresh();
    } finally { setSaving(false); }
  }
  return <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void save(); }}>
    <label className="block max-w-2xl space-y-1 text-sm">
      <span>Slack channel link</span>
      <Input type="url" autoComplete="off" spellCheck={false} maxLength={2048} aria-describedby={hintId}
        value={draft?.url ?? settings.slack_channel_url} disabled={saving}
        placeholder="https://your-workspace.slack.com/archives/C0123456789"
        onChange={(event) => {
          const url = event.target.value;
          setError(""); setNotice("");
          setDraft((previous) => {
            const original = previous?.settings ?? settings;
            return url === original.slack_channel_url ? null : { settings: original, url };
          });
        }} />
    </label>
    <p id={hintId} className="max-w-3xl text-sm text-muted-foreground">Copy the channel link from Slack and paste it here. Workspace members must already have access to the channel. Leave blank to remove the link.</p>
    <div className="flex flex-wrap gap-2">
      <Button type="submit" disabled={!draft || saving || unverified || conflict}>{saving ? "Saving…" : "Save support channel"}</Button>
      {draft && <Button type="button" variant="outline" disabled={saving} onClick={() => { setDraft(null); setError(""); setNotice(""); }}>Discard changes</Button>}
    </div>
    {notice && <p role="status" className="text-sm">{notice}</p>}
    {conflict ? <ErrorState title="Settings changed" message="The support channel changed while you were editing. Your unsaved changes are retained. Discard changes to use the latest setting." />
      : error && <ErrorState message={error} />}
  </form>;
}

export function SupportSettings() {
  const { user } = useDashboard();
  const permitted = hasRole(user, "it_admin");
  const resource = useResource<Settings>(permitted ? "settings/support" : null, 0, false, { validate: validSettings });
  const data = resource.data && validSettings(resource.data) ? resource.data : null;
  if (!permitted) return null;
  return <div id="support" className="scroll-mt-20"><PageSection title="Support" description="Set the Slack channel opened by Support on every dashboard page."
    action={<Button variant="outline" size="sm" disabled={resource.loading} onClick={() => void resource.reload()}>Refresh</Button>}>
    {(resource.error || (!resource.loading && !data)) && <div className="mb-3"><ErrorState message="Unable to load the support setting." onRetry={resource.reload} /></div>}
    {!data && resource.loading && <LoadingState label="Loading support settings" />}
    {data && <SupportForm settings={data} saved={resource.setData} refresh={resource.reload} unverified={resource.loading || Boolean(resource.error)} />}
  </PageSection></div>;
}
