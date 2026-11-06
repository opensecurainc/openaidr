"use client";

import { useEffect, useId, useRef, useState } from "react";
import { ArrowRight, Bell } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { CodeBlock } from "@/components/ui/code-block";
import { api, APIError } from "@/lib/api";
import { hasRole } from "@/lib/roles";
import { useResource } from "@/lib/use-resource";

type Recipient = { id: string; name: string; versions?: string[] };
type Content = { title: string; message: string; command: string; installed_version: string; required_version: string };
type Alert = Content & { id: string; sender_name: string; created_at: string; expires_at: string; expired: boolean;
  device_count: number; received_count: number; acknowledged_count: number };
type Detail = Alert & { recipients: { sensor_id: string; hostname: string; received_at: string | null;
  acknowledged_at: string | null; disabled: boolean; deleted_at: string | null }[] };
type Props = { applicationId: string; name: string; recipients: Recipient[] | ((signal: AbortSignal) => Promise<Recipient[]>); scopeNote?: string;
  notification?: Pick<Content, "title" | "message"> };
const empty: Content = { title: "", message: "", command: "", installed_version: "", required_version: "" };

export function EndpointAlerts(props: Props) {
  const { user } = useDashboard();
  return <AlertDialog key={`${user?.tenant.id}:${user?.id}:${user?.roles.join(",")}:${props.applicationId}`} {...props} />;
}

function AlertDialog(props: Props) {
  const { user } = useDashboard();
  const canSend = hasRole(user, "it_admin") || hasRole(user, "security_analyst");
  const [open, setOpen] = useState(false);
  const { recipients, ...contentProps } = props;
  const label = props.notification ? canSend ? "Notify users" : "View alerts" : "Alerts";
  return <Dialog open={open} onOpenChange={setOpen}>
    <DialogTrigger asChild><Button variant="outline" size={props.notification ? "xs" : "default"}
      className={props.notification ? "min-h-10 sm:min-h-6" : undefined}
      aria-label={props.notification ? `${label} for ${props.name}` : undefined}><Bell className="size-3.5" />{label}</Button></DialogTrigger>
    {open && (typeof recipients === "function"
      ? <RecipientAlerts {...contentProps} loadRecipients={recipients} />
      : <AlertContent {...contentProps} recipients={recipients} />)}
  </Dialog>;
}

function RecipientAlerts({ loadRecipients, ...props }: Omit<Props, "recipients"> & { loadRecipients: (signal: AbortSignal) => Promise<Recipient[]> }) {
  const { user, refreshUser } = useDashboard();
  const [load] = useState(() => loadRecipients);
  const [recipients, setRecipients] = useState<Recipient[] | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal).then(items => {
      if (!controller.signal.aborted) setRecipients(items);
    }).catch(failure => {
      if (controller.signal.aborted) return;
      if (failure instanceof APIError && [401, 403].includes(failure.status)) void refreshUser().catch(() => {});
      setError(failure instanceof Error ? failure.message : "Unable to load recipient devices.");
    });
    return () => controller.abort();
  }, [load, attempt, refreshUser]);
  if (recipients) return <AlertContent {...props} recipients={recipients} />;
  return <DialogContent>
    <DialogHeader>
      <DialogTitle>{props.notification && (hasRole(user, "it_admin") || hasRole(user, "security_analyst")) ? "Notify users" : "Alerts"}</DialogTitle>
      <DialogDescription className="break-words">{props.name}</DialogDescription>
    </DialogHeader>
    {error ? <>
      <p role="alert" className="text-sm text-destructive">Could not load recipient devices: {error}</p>
      <Button variant="outline" onClick={() => { setError(""); setAttempt(value => value + 1); }}>Retry</Button>
    </> : <p role="status" className="text-sm text-muted-foreground">Loading recipient devices…</p>}
  </DialogContent>;
}

function AlertContent({ applicationId, name, recipients, scopeNote, notification }: Omit<Props, "recipients"> & { recipients: Recipient[] }) {
  const { user, refreshUser } = useDashboard();
  const { dateTime } = useTimeZone();
  const fieldId = useId();
  const canSend = hasRole(user, "it_admin") || hasRole(user, "security_analyst");
  const [targets] = useState(() => {
    const devices = new Map<string, Recipient>();
    for (const item of recipients) devices.set(item.id, {...item,
      versions:[...new Set([...(devices.get(item.id)?.versions || []), ...(item.versions || [])])]});
    return [...devices.values()];
  });
  const [context, setContext] = useState(applicationId.length <= 256 ? applicationId : "");
  const [view, setView] = useState<"history" | "compose" | "preview" | "detail">(notification && canSend ? "compose" : "history");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string[]>(() => notification && canSend && targets.length <= 100 ? targets.map(item => item.id) : []);
  const [content, setContent] = useState<Content>(() => ({ ...empty, ...notification }));
  const [detailId, setDetailId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const attempt = useRef<{ body: string; id: string } | null>(null);
  const mounted = useRef(true);
  const inFlight = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    if (applicationId.length <= 256) return;
    let active = true;
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(applicationId)).then(digest => {
      if (active) setContext(`component-sha256:${Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("")}`);
    }).catch(() => { if (active) setError("Cannot identify this component. Close and try again."); });
    return () => { active = false; };
  }, [applicationId]);
  const history = useResource<{ items: Alert[]; has_more: boolean }>(context
    ? `endpoint-alerts?${new URLSearchParams({ application_id: context, offset: String(offset) })}` : null);
  const detail = useResource<Detail>(detailId ? `endpoint-alerts/${encodeURIComponent(detailId)}` : null);
  const rows = history.data?.items;
  const supported = Array.isArray(rows) && typeof history.data?.has_more === "boolean" && !history.error;
  const payload = Object.fromEntries(Object.entries(content).map(([key, value]) => [key, value.trim()])) as Content;
  const valid = Boolean(canSend && supported && context && payload.title && payload.message && selected.length && selected.length <= 100
    && Boolean(payload.installed_version) === Boolean(payload.required_version));
  function start() {
    setContent({ ...empty, ...notification }); setSelected(notification && targets.length <= 100 ? targets.map(item => item.id) : []);
    attempt.current = null; setError(""); setNotice(""); setView("compose");
  }
  async function send() {
    if (!canSend || !valid || !context || inFlight.current) return;
    const body = JSON.stringify({ ...payload, application_id: context, sensor_ids: [...selected].sort() });
    if (attempt.current?.body !== body) attempt.current = { body, id: crypto.randomUUID() };
    inFlight.current = true; setBusy(true); setError("");
    try {
      const sent = await api<Alert>("endpoint-alerts", { method: "POST", signal: AbortSignal.timeout(20_000),
        body: JSON.stringify({ ...JSON.parse(body), request_id: attempt.current.id }) });
      if (!sent?.id) throw new Error("Invalid send response");
      if (!mounted.current) return;
      setNotice(`Alert sent to ${selected.length} ${selected.length === 1 ? "device" : "devices"}. Delivery is pending until each app receives it.`);
      setDetailId(sent.id); setView("detail"); setOffset(0); void history.reload();
    } catch (failure) {
      if (!mounted.current) return;
      if (failure instanceof APIError && [401, 403].includes(failure.status)) void refreshUser();
      setError(failure instanceof APIError
        ? failure.status === 404 ? "Alerts are unavailable, or a selected device is no longer available. Refresh the inventory and check the backend version." : failure.message
        : "Send was not confirmed. Retry without changes to avoid sending a duplicate alert.");
    } finally { inFlight.current = false; if (mounted.current) setBusy(false); }
  }
  const title = view === "compose" ? notification ? "Notify users" : "New alert" : view === "preview" ? "Preview alert" : view === "detail" ? "Alert details" : "Alerts";
  return <DialogContent className="flex max-h-[calc(100dvh-2rem)] flex-col sm:max-w-xl"
    showCloseButton={!busy} onEscapeKeyDown={event => { if (busy) event.preventDefault(); }}
    onInteractOutside={event => event.preventDefault()}>
    <DialogHeader className="shrink-0 pr-6 text-left">
      <DialogTitle>{title}</DialogTitle>
      <DialogDescription className="break-words">{name}</DialogDescription>
    </DialogHeader>
    <div className="min-h-0 min-w-0 space-y-4 overflow-y-auto text-sm" data-testid="endpoint-alert-scroll" tabIndex={0}>
      {notice && <p role="status">{notice}</p>}
      {error && <p role="alert" className="text-destructive">{error}</p>}
      {view !== "detail" && <>
        {history.error && <p role="alert" className="text-destructive">Could not load alerts: {history.error}. If this backend is older, deploy the endpoint alerts API first.</p>}
        {history.loading && <p role="status">Loading alert history…</p>}
        {history.data && (!Array.isArray(rows) || typeof history.data.has_more !== "boolean") && <p role="alert">The alert response is incompatible. Update the backend and try again.</p>}
      </>}
      {view === "history" && <>
        <p className="text-muted-foreground">Send instructions to the OpenAIDR app on selected devices. Delivery requires an updated app to be running. Alerts expire after 30 days.</p>
        <div className="flex flex-wrap gap-2">
          {canSend && <Button onClick={start} disabled={!supported || !targets.length}>New alert</Button>}
          <Button variant="outline" onClick={() => void history.reload()} disabled={history.loading}>Refresh history</Button>
        </div>
        {!canSend && <p className="text-xs text-muted-foreground">IT Admins and Security Analysts can send alerts.</p>}
        {rows?.length === 0 && <p>No alerts have been sent for this software.</p>}
        {rows && rows.length > 0 && <ul className="divide-y" aria-label="Alert history">{rows.map(row => <li key={row.id} className="py-3">
          <Button variant="link" className="h-auto max-w-full whitespace-normal break-words p-0 text-left" onClick={() => { setDetailId(row.id); setView("detail"); setNotice(""); }}>{row.title}</Button>
          <p className="mt-1 text-xs text-muted-foreground">{dateTime(row.created_at)} · {row.sender_name}</p>
          <p className="mt-1">{row.device_count} sent · {row.received_count} received by app · {row.acknowledged_count} acknowledged{row.expired ? " · Expired" : ""}</p>
        </li>)}</ul>}
        <div className="flex items-center justify-between gap-2">
          <Button variant="outline" disabled={offset === 0 || history.loading} onClick={() => setOffset(value => Math.max(0, value - 50))}>Previous</Button>
          <span className="text-xs text-muted-foreground">Page {offset / 50 + 1}</span>
          <Button variant="outline" disabled={!history.data?.has_more || history.loading || Boolean(history.error)} onClick={() => setOffset(value => value + 50)}>Next</Button>
        </div>
      </>}
      {view === "compose" && <>
        {notification && <div className="space-y-2 border-b pb-3">
          <p className="font-medium">OpenAIDR app notification</p>
          <p className="text-xs text-muted-foreground">The alert appears when an updated OpenAIDR app is running on the selected device. Alerts expire after 30 days.</p>
          <Button variant="link" className="h-auto p-0" onClick={() => { setView("history"); setError(""); }}>View history</Button>
        </div>}
        <fieldset className="space-y-2">
          <legend className="font-semibold">Recipients ({selected.length} selected)</legend>
          <p className="text-xs text-muted-foreground">{scopeNote || "Choose devices with a reported installation."} Select up to 100 devices. Receipt identifies the device, not a particular user.</p>
          <div className="max-h-48 overflow-y-auto divide-y" aria-label="Recipient devices" tabIndex={0}>{targets.map(item => <label key={item.id} className="flex cursor-pointer items-start gap-2 py-2">
            <input type="checkbox" className="mt-1 accent-primary" checked={selected.includes(item.id)}
              disabled={!selected.includes(item.id) && selected.length >= 100}
              onChange={event => setSelected(ids => event.target.checked ? [...ids, item.id] : ids.filter(id => id !== item.id))} />
            <span className="min-w-0 break-words">{item.name || item.id}{item.versions?.length ? <span className="block font-mono text-sm font-normal text-muted-foreground">{item.versions.join(", ")}</span> : null}</span>
          </label>)}</div>
        </fieldset>
        {(Object.keys(empty) as (keyof Content)[]).filter(key => !notification || key === "title" || key === "message").map(key => {
          const label = {title: "Title", message: "Instructions", command: "Command (optional)", installed_version: "Installed version (optional)", required_version: "Required version (optional)"}[key];
          const common = {id:`${fieldId}-${key}`, value:content[key], maxLength:key === "title" ? 160 : key.endsWith("version") ? 100 : 2000,
            onChange:(event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setContent(value => ({...value, [key]:event.target.value})),
            className:key === "command" || key.endsWith("version") ? "font-mono text-sm font-normal" : undefined};
          return <div key={key} className="space-y-1"><label htmlFor={common.id} className="font-medium">{label}</label>
            {key === "message" || key === "command" ? <Textarea {...common} rows={key === "message" ? 4 : 2} /> : <Input {...common} />}
          </div>;
        })}
        {!notification && <p className="text-xs text-muted-foreground">Provide both versions or leave both blank. Commands and versions must apply to every selected device. The app displays the command for copying; it does not run it.</p>}
      </>}
      {view === "preview" && <>
        <p className="text-muted-foreground">Review what recipients will see before sending.</p>
        <AlertMessage content={payload} />
        <p className="border-t pt-3 text-xs text-muted-foreground">From {user?.name} · {selected.length} {selected.length === 1 ? "device" : "devices"}</p>
        <ul aria-label="Selected devices" className="list-inside list-disc break-words">{targets.filter(item => selected.includes(item.id)).map(item => <li key={item.id}>{item.name || item.id}</li>)}</ul>
        <p className="text-xs text-muted-foreground">Acknowledgement confirms receipt only. It does not confirm that an upgrade or other remediation is complete.</p>
      </>}
      {view === "detail" && <>
        <Button variant="outline" disabled={detail.loading} onClick={() => void detail.reload()}>Refresh status</Button>
        {detail.loading && <p role="status">Loading recipient status…</p>}
        {detail.error && <p role="alert" className="text-destructive">{detail.error}</p>}
        {detail.data && <>
          <AlertMessage content={detail.data} />
          <p className="text-xs text-muted-foreground">Sent by {detail.data.sender_name} · {dateTime(detail.data.created_at)}<br />Expires {dateTime(detail.data.expires_at)}</p>
          <ul className="divide-y" aria-label="Delivery status">{detail.data.recipients.map(item => <li key={item.sensor_id} className="py-3">
            <p className="break-words font-medium">{item.hostname || item.sensor_id}</p>
            <p>{item.acknowledged_at ? `Acknowledged ${dateTime(item.acknowledged_at)}` : item.received_at ? `Received by app ${dateTime(item.received_at)}`
              : new Date(detail.data!.expires_at).getTime() <= Date.now() ? "Expired without receipt" : "Pending receipt"}</p>
            {(item.disabled || item.deleted_at) && <p className="text-xs text-muted-foreground">Device {item.deleted_at ? "deleted" : "disabled"}</p>}
          </li>)}</ul>
          <p className="text-xs text-muted-foreground">Received means the app loaded the alert. Acknowledged confirms receipt, not remediation. Offline, older, or closed apps may remain pending until expiration.</p>
        </>}
      </>}
    </div>
    <DialogFooter className="shrink-0 border-t pt-4" showCloseButton={view === "history"}>
      {view === "compose" && <>{notification
        ? <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
        : <Button variant="outline" onClick={() => { setView("history"); setError(""); }}>Cancel</Button>}
        <Button disabled={!valid} onClick={() => { setError(""); setView("preview"); }}>Preview alert</Button></>}
      {view === "preview" && <><Button variant="outline" disabled={busy} onClick={() => setView("compose")}>Edit</Button><Button disabled={busy || !valid || !canSend} onClick={() => void send()}>{busy ? "Sending…" : `Send to ${selected.length} ${selected.length === 1 ? "device" : "devices"}`}</Button></>}
      {view === "detail" && <Button variant="outline" onClick={() => { setView("history"); setDetailId(""); setNotice(""); void history.reload(); }}>Back to history</Button>}
    </DialogFooter>
  </DialogContent>;
}

function AlertMessage({ content }: { content: Content }) {
  return <section aria-label="Alert message" className="min-w-0 space-y-4">
    <h3 className="break-words text-base font-semibold">{content.title}</h3>
    <p className="whitespace-pre-wrap break-words">{content.message}</p>
    {content.installed_version && content.required_version && <div className="flex items-center gap-4 border-y py-3">
      <dl className="min-w-0 flex-1"><dt className="text-xs text-muted-foreground">Installed</dt><dd className="break-all font-mono text-sm font-normal">{content.installed_version}</dd></dl>
      <ArrowRight className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <dl className="min-w-0 flex-1"><dt className="text-xs text-muted-foreground">Required</dt><dd className="break-all font-mono text-sm font-normal">{content.required_version}</dd></dl>
    </div>}
    {content.command && <div className="min-w-0 space-y-2"><h4 className="text-sm font-medium">{content.required_version ? "Upgrade command" : "Command"}</h4><CodeBlock className="text-sm font-normal" tabIndex={0}>{content.command}</CodeBlock></div>}
  </section>;
}
