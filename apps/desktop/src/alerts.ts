import { isTauri } from '@tauri-apps/api/core';
import { isPermissionGranted, requestPermission, sendNotification, onAction } from '@tauri-apps/plugin-notification';
import './alerts.css';

type Alert = {
  id: string; title: string; message: string; command: string; installed_version: string;
  required_version: string; sender_name: string; created_at: string; expires_at: string;
  received_at: string | null; acknowledged_at: string | null;
};
type Inbox = {supported: boolean; scope: string; sensor_id: string; server_url: string; items: Alert[]};
type Receipt = {items: {alert_id: string; received_at: string; acknowledged_at: string | null}[]};
type Status = {enrolled?: boolean; disabled?: boolean; sensor_id?: string; server_url?: string; desktop_removal?: unknown};
type Request = (action: string, params?: Record<string, unknown>) => Promise<unknown>;
const icon = (path: string) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
const close = icon('<path d="m6 6 12 12M6 18 18 6"/>');

export function initAlerts(request: Request, fit: () => void) {
  const trigger = document.createElement('button');
  trigger.className = 'button button-secondary'; trigger.id = 'open-alerts'; trigger.hidden = true;
  trigger.innerHTML = `${icon('<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 20a2 2 0 0 0 4 0"/>')}<span>Alerts</span>`;
  trigger.setAttribute('aria-haspopup', 'dialog');
  document.getElementById('header-actions')!.prepend(trigger);
  document.getElementById('app')!.insertAdjacentHTML('beforeend', `
    <dialog class="endpoint-alert-dialog" id="alerts-inbox" aria-labelledby="alerts-title">
      <div class="endpoint-alert-layout">
        <div class="endpoint-alert-header"><h2 id="alerts-title" tabindex="-1">Alerts</h2><button class="button alert-close" aria-label="Close alerts">${close}</button></div>
        <div class="endpoint-alert-scroll" tabindex="0">
          <p class="alert-description">Messages from your organization’s security team.</p>
          <p id="alerts-error" class="alert-error" role="alert" hidden></p>
          <p id="alerts-notification-status" class="alert-metadata" role="status" hidden></p>
          <div id="alerts-list"></div>
          <p id="alerts-empty" class="alert-description">No active alerts.</p>
        </div>
        <div class="endpoint-alert-footer"><button class="button button-secondary" id="refresh-alerts">Refresh</button><button class="button button-secondary alert-close">Close</button></div>
      </div>
    </dialog>
    <dialog class="endpoint-alert-dialog" id="endpoint-alert" aria-labelledby="endpoint-alert-title" aria-describedby="endpoint-alert-message">
      <div class="endpoint-alert-layout">
        <div class="endpoint-alert-header"><h2 id="endpoint-alert-title" tabindex="-1"></h2><button class="button alert-close" aria-label="Close alert">${close}</button></div>
        <div class="endpoint-alert-scroll" tabindex="0">
          <p id="endpoint-alert-message" class="alert-description"></p>
          <div class="alert-versions" id="alert-versions"><dl><dt>Installed</dt><dd id="alert-installed"></dd></dl>${icon('<path d="M4 12h16m-6-6 6 6-6 6"/>')}<dl><dt>Required</dt><dd id="alert-required"></dd></dl></div>
          <section id="alert-command-section">
            <div class="alert-command-heading"><h3 id="alert-command-heading">Command</h3><button class="button alert-copy" id="copy-alert-command">${icon('<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>')}<span>Copy command</span></button></div>
            <pre id="alert-command" tabindex="0"></pre><p id="alert-copy-status" class="alert-metadata" role="status" hidden></p>
          </section>
          <p id="alert-action-error" class="alert-error" role="alert" hidden></p>
          <div class="alert-source"><span id="alert-sender"></span><time id="alert-created"></time></div>
        </div>
        <div class="endpoint-alert-footer">
          <p class="alert-metadata" id="alert-receipt-note"></p>
          <div class="alert-actions"><button class="button button-secondary alert-close">Close</button><button class="button" id="acknowledge-alert">Acknowledge</button></div>
        </div>
      </div>
    </dialog>`);
  const el = (id: string) => document.getElementById(id)!;
  const inbox = el('alerts-inbox') as HTMLDialogElement;
  const popup = el('endpoint-alert') as HTMLDialogElement;
  const ack = el('acknowledge-alert') as HTMLButtonElement;
  const refreshButton = el('refresh-alerts') as HTMLButtonElement;
  let identity = '', scope = '', items: Alert[] = [], selected = '', pending = '', revision = 0;
  let fetching = false, acknowledging = false, timer: ReturnType<typeof setTimeout> | undefined;
  let seen = new Set<string>(), listener: Promise<unknown> | undefined;
  let returnToInbox = false;
  const stamp = (value: string) => new Date(value).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'});
  const active = () => items.filter(item => new Date(item.expires_at).getTime() > Date.now());
  const current = () => active().find(item => item.id === selected);
  const message = (id: string, value: string) => { el(id).textContent = value; el(id).hidden = !value; };
  const resize = () => requestAnimationFrame(fit);

  function render() {
    const rows = active(), unread = rows.filter(item => !item.acknowledged_at).length;
    trigger.hidden = rows.length === 0 && el('alerts-error').hidden;
    trigger.classList.toggle('button-danger', unread > 0);
    trigger.classList.toggle('button-secondary', unread === 0);
    trigger.querySelector('span')!.textContent = unread ? `Alerts (${unread})` : 'Alerts';
    trigger.setAttribute('aria-label', unread ? `Alerts, ${unread} awaiting acknowledgment` : 'Alerts');
    const focused = (document.activeElement as HTMLElement)?.dataset.alertId;
    el('alerts-list').replaceChildren(...rows.map(item => {
      const button = document.createElement('button'); button.className = 'alert-inbox-row'; button.dataset.alertId = item.id;
      const title = document.createElement('strong'); title.textContent = item.title;
      const meta = document.createElement('span'); meta.className = 'alert-metadata';
      meta.textContent = `${stamp(item.created_at)} · ${item.acknowledged_at ? 'Acknowledged' : 'Not acknowledged'}`;
      button.append(title, meta); button.addEventListener('click', () => open(item.id, true)); return button;
    }));
    if (focused && inbox.open) Array.from(el('alerts-list').querySelectorAll('button')).find(button => button.dataset.alertId === focused)?.focus({preventScroll: true});
    el('alerts-empty').hidden = rows.length > 0 || !el('alerts-error').hidden;
    const item = current();
    if (popup.open && !item) popup.close();
    if (item) {
      el('endpoint-alert-title').textContent = item.title;
      el('endpoint-alert-message').textContent = item.message;
      el('alert-versions').hidden = !item.installed_version || !item.required_version;
      el('alert-installed').textContent = item.installed_version; el('alert-required').textContent = item.required_version;
      el('alert-command-section').hidden = !item.command;
      el('alert-command-heading').textContent = item.required_version ? 'Upgrade command' : 'Command';
      el('alert-command').textContent = item.command;
      el('alert-sender').textContent = item.sender_name;
      el('alert-created').textContent = stamp(item.created_at);
      el('alert-created').setAttribute('datetime', item.created_at);
      el('alert-receipt-note').textContent = item.acknowledged_at
        ? 'Receipt acknowledged. Follow the instructions above.'
        : 'Confirms receipt only. Follow the instructions above.';
      ack.textContent = item.acknowledged_at ? 'Done' : 'Acknowledge';
      ack.disabled = acknowledging;
    }
    resize();
  }

  function open(id: string, fromInbox = false) {
    if (!active().some(item => item.id === id)) return;
    returnToInbox = fromInbox; selected = id;
    if (inbox.open) inbox.close();
    if (document.querySelector('dialog[open]') && !popup.open) { pending = id; return; }
    pending = ''; message('alert-action-error', ''); message('alert-copy-status', '');
    el('copy-alert-command').querySelector('span')!.textContent = 'Copy command';
    render();
    if (!popup.open) popup.showModal();
    popup.querySelector('.endpoint-alert-scroll')!.scrollTop = 0;
    el('endpoint-alert-title').focus({preventScroll: true}); resize();
  }
  function openPending() {
    if (pending && !document.hidden && !document.querySelector('dialog[open]')) open(pending);
  }
  for (const dialog of [inbox, popup]) {
    dialog.querySelectorAll('.alert-close').forEach(button => button.addEventListener('click', () => dialog.close()));
    dialog.addEventListener('close', () => {
      if (dialog === popup && returnToInbox && identity) {
        returnToInbox = false; inbox.showModal(); el('alerts-title').focus({preventScroll: true});
      } else if (!document.querySelector('dialog[open]') && !trigger.hidden) trigger.focus({preventScroll: true});
      resize();
    });
  }
  document.addEventListener('close', () => queueMicrotask(openPending), true);
  document.addEventListener('visibilitychange', openPending);
  trigger.addEventListener('click', () => { render(); inbox.showModal(); el('alerts-title').focus({preventScroll: true}); resize(); void refresh(); });
  refreshButton.addEventListener('click', () => void refresh());

  async function notify(rows: Alert[], expected: number) {
    if (!isTauri() || !rows.length) return;
    try {
      listener ??= onAction(async event => {
        const extra = event.notification?.extra;
        if (!extra || extra.scope !== scope || !active().some(item => item.id === extra.alert_id)) return;
        await request('alerts.focus'); open(String(extra.alert_id));
      });
      await listener;
      const allowed = await isPermissionGranted() || await requestPermission() === 'granted';
      if (expected !== revision) return;
      if (!allowed) { message('alerts-notification-status', 'System notifications are off. Alerts remain available here.'); return; }
      sendNotification({title: rows.length === 1 ? rows[0].title : `${rows.length} new security alerts`,
        body: 'Your security team sent instructions. Open OpenAIDR to review them.',
        extra: {scope, alert_id: rows[0].id}});
    } catch { if (expected === revision) message('alerts-notification-status', 'System notifications are unavailable. Alerts remain available here.'); }
  }

  async function refresh() {
    if (!identity || fetching) return;
    fetching = true; refreshButton.disabled = true; clearTimeout(timer);
    const expected = revision;
    try {
      const data = await request('alerts.list') as Inbox;
      if (expected !== revision) return;
      if (data.supported === false) { items = []; message('alerts-error', ''); render(); return; }
      if (!Array.isArray(data.items) || `${data.server_url}|${data.sensor_id}` !== identity) throw new Error('Could not read alerts. Try again.');
      scope = data.scope;
      items = data.items.map(item => {
        const confirmed = items.find(previous => previous.id === item.id);
        return {...item, received_at: item.received_at || confirmed?.received_at || null,
          acknowledged_at: item.acknowledged_at || confirmed?.acknowledged_at || null};
      });
      message('alerts-error', '');
      const incoming = active().filter(item => !item.received_at && !item.acknowledged_at && !seen.has(item.id));
      incoming.forEach(item => seen.add(item.id));
      render();
      if (incoming.length) { pending = incoming[0].id; openPending(); void notify(incoming, expected); }
      const received = active().filter(item => !item.received_at).map(item => item.id);
      if (received.length) {
        const result = await request('alerts.received', {ids: received, scope}) as Receipt;
        if (expected !== revision) return;
        for (const receipt of result.items) {
          const row = items.find(item => item.id === receipt.alert_id);
          if (row) row.received_at = receipt.received_at;
        }
      }
    } catch (error) {
      if (expected === revision) { message('alerts-error', String(error instanceof Error ? error.message : error)); render(); }
    } finally {
      fetching = false; refreshButton.disabled = false;
      if (identity) timer = setTimeout(() => void refresh(), expected === revision ? 60000 : 0);
    }
  }
  ack.addEventListener('click', async () => {
    const item = current(); if (!item || acknowledging) return;
    if (item.acknowledged_at) { popup.close(); return; }
    acknowledging = true; ack.disabled = true; message('alert-action-error', '');
    const expected = revision;
    try {
      const result = await request('alerts.acknowledge', {id: item.id, scope}) as Receipt;
      if (expected !== revision) return;
      const receipt = result.items.find(row => row.alert_id === item.id && row.acknowledged_at);
      if (!receipt) throw new Error('Acknowledgement was not confirmed. Try again.');
      const latest = items.find(row => row.id === item.id);
      if (latest) { latest.acknowledged_at = receipt.acknowledged_at; latest.received_at = receipt.received_at; }
    } catch (error) {
      if (expected === revision) message('alert-action-error', error instanceof Error ? error.message : String(error));
    } finally { acknowledging = false; render(); }
  });
  el('copy-alert-command').addEventListener('click', async () => {
    const item = current(); if (!item) return;
    try {
      await navigator.clipboard.writeText(item.command);
      if (selected === item.id) el('copy-alert-command').querySelector('span')!.textContent = 'Copied';
    } catch {
      if (selected !== item.id) return;
      const range = document.createRange(); range.selectNodeContents(el('alert-command'));
      const selection = getSelection(); selection?.removeAllRanges(); selection?.addRange(range); el('alert-command').focus();
      message('alert-copy-status', 'Command selected. Press Command+C or Ctrl+C to copy.'); resize();
    }
  });
  return {
    setStatus(status: Status) {
      const next = status.enrolled && !status.disabled && !status.desktop_removal && status.sensor_id && status.server_url
        ? `${status.server_url.replace(/\/$/, '')}|${status.sensor_id}` : '';
      if (identity === next) return;
      revision++; identity = next; scope = ''; items = []; seen = new Set(); pending = ''; selected = ''; returnToInbox = false;
      trigger.hidden = true; popup.close(); inbox.close(); message('alerts-error', ''); message('alerts-notification-status', '');
      clearTimeout(timer); render();
      if (next) void refresh();
    },
    preferredHeight() {
      const dialog = popup.open ? popup : inbox.open ? inbox : null;
      return dialog ? Array.from(dialog.querySelector('.endpoint-alert-layout')!.children)
        .reduce((height, child) => height + child.scrollHeight, 34) : 0;
    },
  };
}
