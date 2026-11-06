"use client";

import { useLayoutEffect, useState } from "react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { hasRole } from "@/lib/roles";
import { useResource } from "@/lib/use-resource";
import { useTimeZone } from "@/components/time-zone-context";

type SlackSettings = {
  enabled: boolean;
  configured: boolean;
  available: boolean;
  version: number;
  delivery: { pending: number; failed: number; last_sent_at: string | null };
};

function SlackForm({ settings, saved, refresh, unverified }: {
  settings: SlackSettings; saved: (value: SlackSettings) => void; refresh: () => void;
  unverified: boolean;
}) {
  const { dateTime } = useTimeZone();
  const [draft, setDraft] = useState<{ settings: SlackSettings; enabled: boolean; webhook: string } | null>(null);
  const { enabled, webhook } = draft ?? { enabled: settings.enabled, webhook: "" };
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const dirty = draft !== null;
  const conflict = draft !== null && draft.settings.version !== settings.version;
  function edit(changes: { enabled?: boolean; webhook?: string }) {
    setDraft((previous) => {
      const next = { ...(previous ?? { settings, enabled: settings.enabled, webhook: "" }), ...changes };
      return next.enabled === next.settings.enabled && next.webhook === "" ? null : next;
    });
  }
  useLayoutEffect(() => {
    if (dirty || busy) return;
    const check = () => { if (!document.hidden) void refresh(); };
    const timer = setInterval(check, 15_000);
    window.addEventListener("focus", check);
    document.addEventListener("visibilitychange", check);
    return () => {
      clearInterval(timer);
      window.removeEventListener("focus", check);
      document.removeEventListener("visibilitychange", check);
    };
  }, [dirty, busy, refresh]);

  async function save(disconnect = false) {
    if (conflict) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await api<SlackSettings>("settings/slack", {
        method: "PUT", body: JSON.stringify({ version: draft?.settings.version ?? settings.version, enabled: disconnect ? false : enabled,
          ...(disconnect ? { webhook_url: "" } : webhook ? { webhook_url: webhook } : {}) }),
      });
      setDraft(null);
      saved(result);
      void refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to save Slack settings.");
    } finally { setBusy(false); }
  }

  async function testMessage() {
    setBusy(true); setError(""); setNotice("");
    try {
      await api("settings/slack/test", { method: "POST", body: JSON.stringify({ version: settings.version }) });
      setNotice("Test message queued. Delivery status updates automatically.");
      refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to queue a test message.");
    } finally { setBusy(false); }
  }

  return <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void save(); }}>
    <p className="text-sm" role="status">{unverified && "Last known status: "}{!settings.configured ? "No webhook saved."
      : !settings.available ? "Webhook saved. Delivery unavailable."
      : settings.enabled ? "Webhook saved. Notifications enabled." : "Webhook saved. Notifications disabled."}</p>
    {!settings.available && <p className="text-sm text-muted-foreground">{settings.configured
      ? "Server setup is incomplete. Your saved webhook is retained. Contact an operator to restore delivery."
      : "An operator must complete server setup before Slack can be enabled."}</p>}
    <label className="block max-w-xl space-y-1 text-sm">
      <span>{settings.configured ? "Replace webhook URL" : "Webhook URL"}</span>
      <Input type="password" autoComplete="new-password" spellCheck={false} maxLength={512}
        aria-label={settings.configured ? "Replace webhook URL" : "Webhook URL"}
        value={webhook} onChange={(event) => edit({ webhook: event.target.value })} disabled={busy || unverified || !settings.available}
        placeholder={settings.configured ? "Leave blank to keep the saved webhook" : "Paste the incoming webhook URL from Slack"} />
    </label>
    <p className="max-w-3xl text-sm text-muted-foreground">
      Create an incoming webhook in Slack and select the shared channel there. The saved URL is kept private.
      {" "}<a className="underline underline-offset-4" href="https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/" target="_blank" rel="noreferrer">Slack setup instructions</a>
    </p>
    <label className="flex items-center gap-2 text-sm font-medium">
      <input type="checkbox" checked={enabled} onChange={(event) => edit({ enabled: event.target.checked })} disabled={busy || unverified || (!settings.available && !enabled)} />
      Enable Slack notifications
    </label>
    <p className="max-w-3xl text-sm text-muted-foreground">
      Sends one alert when a completed investigation detects an incident, and warns when server disk usage reaches 95%.
      Disk warnings reset after usage falls below 90%. Server disk alerts require host monitoring on a dedicated tenant server.
      Policy findings and routine investigation summaries stay in the dashboard.
      Messages contain counts and dashboard links. Full evidence requires dashboard access.
      Enabling or replacing the webhook starts with new activity. Disabling or replacing it cancels pending messages.
    </p>
    <div className="flex flex-wrap gap-2">
      <Button type="submit" disabled={busy || unverified || conflict || !dirty || (enabled && (!settings.available || (!settings.configured && !webhook)))}>{busy ? "Working..." : "Save Slack settings"}</Button>
      <Button type="button" variant="outline" disabled={busy || unverified || dirty || !settings.enabled || !settings.available} onClick={() => void testMessage()}>Send test message</Button>
      {settings.configured && <Button type="button" variant="outline" disabled={busy || unverified || conflict} onClick={() => void save(true)}>Disconnect Slack</Button>}
      {conflict && <Button type="button" variant="outline" disabled={busy} onClick={() => { setDraft(null); setError(""); setNotice(""); }}>Discard changes</Button>}
    </div>
    <div className="space-y-1 text-sm text-muted-foreground">
      <p>Pending deliveries: {settings.delivery.pending}. Failed deliveries: {settings.delivery.failed}.</p>
      <p>{settings.delivery.last_sent_at ? `Last successful delivery: ${dateTime(settings.delivery.last_sent_at)}` : "No messages delivered yet."}</p>
      {settings.delivery.failed > 0 && <p>Check the webhook and channel permissions, replace the URL if needed, then send a test message. Failed messages are not replayed.</p>}
    </div>
    {notice && <p role="status" className="text-sm">{notice}</p>}
    {conflict ? <ErrorState title="Settings changed" message="Slack settings changed while you were editing. Your unsaved changes are retained. Discard changes to use the latest settings." />
      : error && <ErrorState message={error} />}
  </form>;
}

export function SlackNotifications() {
  const { user } = useDashboard();
  const permitted = hasRole(user, "it_admin");
  const resource = useResource<SlackSettings>(permitted ? "settings/slack" : null);
  if (!permitted) return null;
  return <PageSection title="Slack notifications" description="Send incident and low disk space alerts to one shared channel."
    action={<Button variant="outline" size="sm" disabled={resource.loading} onClick={() => void resource.reload()}>Refresh</Button>}>
    {resource.error && <ErrorState message={`Unable to verify Slack status.${resource.data ? " Showing the last known settings." : ""} Try Refresh.`} onRetry={resource.reload} />}
    {resource.loading && resource.data && <p className="text-sm text-muted-foreground" role="status">Checking Slack status…</p>}
    {resource.data
      ? <SlackForm settings={resource.data} saved={resource.setData} refresh={resource.reload}
        unverified={Boolean(resource.error)} />
      : !resource.error && <LoadingState label="Loading Slack settings" />}
  </PageSection>;
}
