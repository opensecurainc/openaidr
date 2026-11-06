import { Channel, invoke, isTauri } from '@tauri-apps/api/core';
import './style.css';
import { initSimulation } from './simulation';
import { initUsage } from './usage';
import { initCredits } from './credits';
import { initPosture } from './posture';
import { initGuardrails, agentEntries, AGENT_NAMES, type Agent, type HookState } from './guardrails';
import { initUpdates, updateWarningDeferred, type DesktopUpdate } from './updates';
import { initAbout } from './about';
import { initAlerts } from './alerts';
import { initCloudCredit, type CloudProtection } from './cloud-credit';
import { initMenuBar } from './menu-bar';
import { initLocalRuntime } from './local-runtime';

type TelemetryAgent = 'codex' | 'claude';
type TelemetryClient = {pid:number; process_name:string; started_at:string; last_failed_at:string; signals:string[]};
type SensorStatus = {
  connection_mode?: 'free' | 'api_key' | 'organization';
  cloud_protection?: CloudProtection | null;
  sensor_id?: string; server_url?: string; tenant_name?: string;
  desktop_removal?: {state: 'pending' | 'complete'; errors?: string[]; retained_data?: string; data_deletion_started?: boolean; data_deleted?: boolean};
  enrolled?: boolean; running?: boolean; disabled?: boolean; foreground?: boolean; service_downgrade?: boolean; recorded_service_version?: string; version?: string; service_version?: string; service_outdated?: boolean; service_newer?: boolean; settings_stale?: boolean;
  service?: string | { status?: string; installed?: boolean; running?: boolean };
  hooks?: Partial<Record<Agent, HookState>>;
  heartbeat?: {last_success_at?: string | null; error?: string} | null;
  activity?: {queue_depth?: number | null; last_error?: string} | null;
  telemetry?: { queue_depth?: number | null; enabled?: boolean; codex_installed?: boolean; claude_installed?: boolean; codex_current?: boolean; claude_current?: boolean; codex_opted_out?: boolean; claude_opted_out?: boolean; codex_available?: boolean; claude_available?: boolean; forwarded?: number; processed_locally?: number; received?: number; last_error?: string | null; authentication_failed?: boolean; authentication_failures?:number; authentication_last_failed_at?:string | null; authentication_unidentified?:boolean; authentication_clients?:TelemetryClient[] };
  live?: Record<string, unknown>; status?: Record<string, unknown>;
  desktop_update?: DesktopUpdate & { status_cached?: boolean };
};
type SetupStep = { step: string; ok: boolean; error?: string; agents?: string[]; after?: string; running?: string; installed?: string; reason?: string };
type SetupResult = SensorStatus & { steps?: SetupStep[]; restart_required?: boolean };
type EnrollmentPreview = {server_url:string; tenant:{id:string; name:string}; auth_mode:'bearer' | 'mtls'; expires_at:string};
type WindowView = 'status' | 'link';

const TELEMETRY_AGENTS: TelemetryAgent[] = ['codex', 'claude'];
const AGENTS: Agent[] = [...TELEMETRY_AGENTS, 'copilot', 'cursor', 'antigravity', 'opencode', 'hermes', 'workbuddy'];
const BUILD_TIME: string = import.meta.env.VITE_BUILD_TIME;
const BUILD_COMMIT: string = import.meta.env.VITE_BUILD_COMMIT;
const BUILD_VERSION: string = import.meta.env.VITE_BUILD_VERSION;
const STEP_NAMES: Record<string, string> = {
  'service.status': 'Checking the sensor',
  'service.install': 'Installing the sensor',
  'service.start': 'Starting the sensor',
  'service.restart': 'Restarting the sensor',
  'telemetry.install': 'Connecting coding agents',
  'hooks.install': 'Installing agent guardrails',
};
// One automatic setup per drift, plus one extra pass for a service that is still starting.
const MAX_AUTOMATIC_ATTEMPTS = 2;
// Give the receiver time to start, independent of automatic or manual refresh frequency.
const UNREACHABLE_GRACE_MS = 15000;
const CONNECTION_GRACE_MS = 15 * 60 * 1000;
const CLOUD_CONNECTION_GRACE_MS = 15000;
const RECENT_CLOUD_CONTACT_MS = 180000;
const MAX_UPDATE_BYTES = 1024 * 1024 * 1024;
// Native operation locks return this message while an update or sensor operation owns the lock.
const OPERATION_BUSY = 'A desktop update or sensor operation is in progress. Try again shortly.';
const CONNECTED_DESCRIPTION = 'The sensor is running and connected to ';

let current: SensorStatus | null = null;
let connectionFailure: {sensorId?: string; serverUrl?: string; mode?: string; since: number} | null = null;
let busy = false;
let settingUp = false;
let fetching = false;
let statusFailed = false;
let statusBusy = false;
let editingConnection = false;
let choosingOrganization = false;
let freeRateLimited = false;
let setupAttempts = 0;
let setupFailed = '';
let unreachableSince: number | null = null;
let connectionStartupUntil = 0;
let refreshTimer: ReturnType<typeof setTimeout> | undefined;
let noticeTimer: ReturnType<typeof setTimeout> | undefined;
let connectionView: WindowView = 'status';
let enrollmentPreview: EnrollmentPreview | null = null;
let previewRevision = 0;
let previewPending = false;
let previewTimer: ReturnType<typeof setTimeout> | undefined;
let previewInvalidation: Promise<void> = Promise.resolve();
let enrollmentCA: {pem:string; origin:string} | null = null;
let removalSupported = false;
let nativeUninstaller = false;
let desktopUpdate: DesktopUpdate | null | undefined;
let updateFetching = false;
let updateRevision = 0;
let updateTimer: ReturnType<typeof setTimeout> | undefined;
const pages = ['usage','guardrails','posture'] as const;
let selectedPage:typeof pages[number] = 'usage';

type HealthTone = 'idle' | 'online' | 'loading' | 'busy' | 'warning' | 'error';
const healthIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path class="status-check" d="m6 12 4 4 8-9"/><path class="status-idle" d="M12 6v6l4 2"/><path class="status-alert" d="M12 5v8m0 5v.1"/><path class="status-error" d="m6 6 12 12m0-12L6 18"/></svg>`;
const app = document.querySelector<HTMLDivElement>('#app')!;
app.innerHTML = `
  <main>
  <header>
    <div class="brand"><img src="/icon.svg" alt=""><div>OpenAIDR</div></div>
    <nav id="page-navigation" class="app-pages" role="tablist" aria-label="App pages" hidden>
      <button type="button" role="tab" id="usage-tab" aria-controls="usage-panel" aria-selected="true" tabindex="0">Usage</button>
      <button type="button" role="tab" id="guardrails-tab" aria-controls="guardrails-page" aria-selected="false" tabindex="-1">Guardrails</button>
      <button type="button" role="tab" id="posture-tab" aria-controls="posture-page" aria-selected="false" tabindex="-1">Posture</button>
    </nav>
    <div id="header-actions" class="buttons">
      <span id="update-notice" class="update-notice" role="status" hidden></span>
      <button id="sensor-status" tabindex="0" class="status-button loading" type="button" aria-haspopup="dialog" aria-controls="health-card" aria-expanded="false" hidden><span class="status-icon" aria-hidden="true">${healthIcon}</span><span id="status-label" role="status" aria-live="polite">Checking</span><svg class="status-chevron" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="m4 6 4 4 4-4"/></svg></button>
    </div>
  </header>
  <p id="update-guidance" role="region" aria-label="Update details" aria-live="polite" tabindex="0" hidden></p>
  <div id="notice" role="status" aria-live="polite" hidden><span id="notice-message"></span></div>
  <section id="health-card" class="health-card" aria-labelledby="health-title">
    <button id="close-status" tabindex="0" class="button icon-button close-button close-status" type="button" aria-label="Close sensor status" hidden>×</button>
    <div class="health-summary">
      <span id="health-dot" class="health-dot loading" aria-hidden="true">${healthIcon}</span>
      <div class="health-copy" role="status" aria-live="polite" aria-atomic="true"><h1 id="health-title">Checking sensor…</h1><p id="health-description">Reading sensor status.</p></div>
    </div>
    <section id="telemetry-auth" aria-label="Rejected local reports" hidden><p id="telemetry-auth-summary"></p><h2 id="telemetry-clients-title">Affected running sessions</h2><ul id="telemetry-clients" aria-labelledby="telemetry-clients-title"></ul></section>
    <p id="dashboard-error" role="alert" hidden></p>
    <p id="collection-guidance" hidden></p>
    <pre id="health-error" tabindex="0" hidden></pre>
    <details id="sensor-details" hidden><summary>Sensor details</summary>
    <div id="sensor-facts" hidden><dl><div><dt>Sensor</dt><dd id="sensor-state">Unknown</dd></div><div><dt>Server</dt><dd id="server-state">Unknown</dd></div><div><dt>Configured agents</dt><dd id="connected-agents">Unknown</dd></div></dl></div>
    <dl id="stats" class="stats" aria-label="Sensor counters" hidden>
      <div><dt title="Records received since the sensor last started">Records received</dt><dd id="delivery">N/A</dd></div>
      <div><dt id="processed-label" title="Records forwarded since the sensor last started">Records forwarded</dt><dd id="sent">N/A</dd></div>
      <div><dt title="OpenTelemetry export batches waiting to be sent">Queued exports</dt><dd id="queued">N/A</dd></div>
      <div><dt title="Guardrail and transcript activity records waiting to be sent">Queued activity</dt><dd id="activity-queued">N/A</dd></div>
    </dl>
    <p id="counter-note" hidden></p>
    </details>
    <div id="retry-row" hidden><button tabindex="0" id="retry" class="button">Retry setup</button></div>
    <div id="removal-details" role="region" aria-label="Removal errors" tabindex="0" hidden></div>
    <div id="removal-data" hidden><label id="delete-data-label" hidden><input id="delete-data" type="checkbox">Delete local data</label><details id="retained-data-details" hidden><summary><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 4 4 4-4 4"/></svg>View files</summary><div id="retained-data" role="region" aria-label="Retained data" tabindex="0"></div></details></div>
    <p id="removal-data-note" hidden>Uploaded data is kept.</p>
    <div id="removal-actions" class="buttons" hidden><button id="resume-app" class="button button-secondary" hidden>Reinstall</button><button id="trash-app" class="button button-danger" hidden>Move app to Trash</button></div>
  </section>
  <section id="setup-choices" aria-label="Choose how to get started" hidden>
    <div class="setup-options">
      <section class="card setup-choice" aria-labelledby="free-title">
        <div class="setup-choice-heading"><span class="setup-choice-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="13" rx="2"/><path d="m9 16-1 5m7-5 1 5M2 21h20"/></svg></span><h2 id="free-title">Use OpenAIDR<br>for free</h2></div>
        <p>Cloud guardrails with a free usage allowance.<br>No account required.</p>
        <div class="setup-choice-actions"><button id="continue-free" class="button" type="button">Continue for free</button><button id="use-api-key" class="setup-data-link" type="button" aria-haspopup="dialog" aria-controls="api-key-dialog" hidden>Use an API key</button><button id="data-use" class="setup-data-link" type="button" aria-haspopup="dialog" aria-controls="data-use-dialog">How your data is used</button></div>
      </section>
      <section class="card setup-choice organization-choice" aria-labelledby="organization-title">
        <div class="setup-choice-heading"><span class="setup-choice-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 21V3h12v18m0-12h6v12M1 21h22M7 7h4M7 11h4M7 15h4M18 13v1m0 3v1"/></svg></span><h2 id="organization-title">Connect to your<br>organization</h2></div>
        <p>Use an enrollment link, or set up a local runtime on this computer.</p>
        <div class="setup-choice-actions"><button id="choose-organization" class="button button-secondary" type="button">Connect organization</button></div>
      </section>
    </div>
    <p class="setup-later">You can connect to an organization later in Settings.</p>
  </section>
  <section id="connect-card" class="card" aria-labelledby="connection-title" hidden>
    <div id="connection-heading" class="section-heading"><h2 id="connection-title">Connect your organization</h2><button id="back-to-choices" class="button button-secondary" type="button" hidden>Back</button></div>
    <p class="connection-intro">Use an enrollment link, or get started on this computer.</p>
    <div id="connection-options">
    <section class="card connection-option"><h3>I have an enrollment link</h3><p>Join an existing organization.</p>
    <form id="link-enrollment">
      <label for="enrollment-link">Enrollment link</label>
      <div class="enrollment-link-entry"><input id="enrollment-link" type="password" placeholder="Paste your enrollment link" maxlength="8192" required autocomplete="off" spellcheck="false" aria-describedby="link-feedback"></div>
      <p id="link-feedback" class="form-hint" role="status" aria-live="polite">Use the enrollment link from your administrator.</p>
      <div class="connection-option-actions"><button id="connect-link" class="button" type="submit" disabled>Connect</button>
      <details id="certificate-options" class="certificate-options">
        <summary>Private server certificate (optional)</summary>
        <p id="certificate-help" class="form-hint">Choose the public CA certificate from your administrator. Only OpenAIDR uses it, and it is saved only after you connect.</p>
        <label>Organization CA certificate<input id="enrollment-ca" type="file" accept=".pem,.crt,.cer" aria-describedby="certificate-help certificate-feedback"></label>
        <div class="certificate-selection"><p id="certificate-feedback" class="form-hint" role="status">Paste your link first. PEM files only, up to 32 KiB.</p><button id="remove-certificate" class="button button-secondary" type="button" hidden>Remove file</button></div>
      </details>
      </div>
      <div id="link-preview" class="connection-preview" hidden>
        <dl><div><dt>Organization</dt><dd id="link-organization"></dd></div><div><dt>Server</dt><dd id="link-server"></dd></div></dl>
      </div>
    </form>
    </section>
    <section class="card connection-option"><h3>Set up on this computer</h3><p>Your own local runtime and dashboard.</p><p class="local-option-copy">OpenAIDR creates the runtime and connects this device automatically. No enrollment link needed.</p><div class="connection-option-actions"><button id="choose-local-runtime" class="button button-secondary" type="button">Set up local runtime →</button><p class="form-hint">Requires Docker with Compose.<br>AI checks use the cloud.</p></div></section>
    </div>
  </section>
  <footer id="status-footer"><button tabindex="0" id="change-connection" class="button button-secondary" aria-haspopup="dialog" aria-controls="connection-dialog" aria-expanded="false"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true"><path d="M4 7h3m4 0h9M4 17h9m4 0h3"/><circle cx="9" cy="7" r="2"/><circle cx="15" cy="17" r="2"/></svg>Settings</button><button id="check-update" class="button button-secondary" type="button">Check updates</button><button id="show-about" tabindex="0" class="button button-secondary" type="button" aria-haspopup="dialog" aria-controls="about-dialog" aria-expanded="false"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.01"/></svg>About</button><span id="build-info"></span></footer>
  </main>
  <dialog id="api-key-dialog" class="simulation-dialog" aria-labelledby="api-key-title">
    <form id="api-key-form">
      <h2 id="api-key-title">Connect with an API key</h2>
      <p>Enter an OpenSecura API key to use cloud guardrails. Usage stays on this device, and checks run in Shadow mode.</p>
      <label for="api-key">OpenSecura API key</label>
      <input id="api-key" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="256" required>
      <p id="api-key-error" role="alert" hidden></p>
      <div class="simulation-actions"><button id="cancel-api-key" class="button button-secondary" type="button">Cancel</button><button id="connect-api-key" class="button" type="submit">Connect</button></div>
    </form>
  </dialog>
  <dialog id="data-use-dialog" class="simulation-dialog" aria-labelledby="data-use-title">
    <h2 id="data-use-title">How your data is used</h2>
    <p>Usage totals and guardrail activity stay on this device. Redacted prompts and tool details needed for a guardrail check are sent to the OpenSecura cloud service.</p>
    <p>The service processes request content without retaining it. It keeps metadata such as installation identity, IP address, usage, and cost for accounting and abuse prevention.</p>
    <p>Free guardrails start in Shadow mode. Checks are recorded and actions continue. If the service is unavailable or the allowance is exhausted, actions still continue and the app shows that protection is inactive.</p>
    <div class="simulation-actions"><button id="close-data-use" class="button" type="button">Done</button></div>
  </dialog>
  <dialog id="connection-dialog" class="simulation-dialog connection-dialog" aria-labelledby="settings-title">
    <div class="section-heading"><h2 id="settings-title">Settings</h2><button id="close-connection" tabindex="0" class="button icon-button close-button" type="button" aria-label="Close Settings">×</button></div>
    <div id="settings-actions" class="settings-actions"><button id="cancel-change" class="button button-secondary" type="button">Done</button></div>
  </dialog>
  <dialog id="remove-dialog" class="simulation-dialog" aria-labelledby="remove-title">
    <h2 id="remove-title">Uninstall OpenAIDR?</h2>
    <p id="remove-description"></p>
    <p id="removal-retention"></p>
    <div id="removal-progress" hidden><p id="removal-stage" role="status"></p><p id="removal-elapsed" role="timer"></p></div>
    <p id="remove-error" role="alert" hidden></p>
    <div class="simulation-actions"><button id="cancel-remove" class="button button-secondary">Cancel</button><button id="confirm-remove" class="button button-danger">Uninstall OpenAIDR</button></div>
  </dialog>`;

const el = (id: string) => document.getElementById(id)!;
const usage = initUsage(request, () => selectedPage === 'usage' && !menuBar.hidden());
const guardrails = initGuardrails(request, configureGuardrails, () => !menuBar.hidden());
const posture = initPosture(request, () => !menuBar.hidden());
el('usage-panel').setAttribute('role', 'tabpanel');
el('usage-panel').setAttribute('aria-labelledby', 'usage-tab');
const pageTabs = pages.map(page => el(`${page}-tab`)) as HTMLButtonElement[];
function selectPage(page:typeof pages[number]) {
  selectedPage = page;
  pageTabs.forEach(tab => { const active = tab.id === `${page}-tab`; tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1; });
  usage.setVisible(page === 'usage');
  guardrails.setVisible(page === 'guardrails');
  posture.setVisible(page === 'posture');
}
pageTabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectPage(pages[index]));
  tab.addEventListener('keydown', event => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? pages.length-1 : (index+(event.key === 'ArrowRight' ? 1 : -1)+pages.length)%pages.length;
    selectPage(pages[next]); pageTabs[next].focus();
  });
});
const alerts = initAlerts(request, fitWindow);
const cloudCredit = initCloudCredit();
initAbout(request);
const menuBar = initMenuBar(() => { void refresh(false); if (!menuBar.hidden()) void refreshUpdate(); }, fitWindow);
const healthCard = el('health-card');
const credits = initCredits(healthCard, request, () => !document.hidden && !menuBar.hidden());
const dashboardLink = document.createElement('a');
dashboardLink.id = 'dashboard-link';
dashboardLink.tabIndex = 0;
dashboardLink.target = '_blank';
dashboardLink.rel = 'noopener noreferrer';
dashboardLink.title = 'Open dashboard in your browser';
dashboardLink.textContent = 'Open dashboard';
dashboardLink.addEventListener('click', async event => {
  if (!isTauri()) return;
  event.preventDefault();
  const serverUrl = dashboardLink.href;
  const error = el('dashboard-error');
  error.hidden = true;
  try { await request('desktop.dashboard', {server_url:serverUrl}); }
  catch {
    if (!dashboardLink.isConnected || dashboardLink.href !== serverUrl) return;
    error.textContent = `Could not open your browser. Open ${serverUrl} to view the dashboard.`;
    error.hidden = false;
  }
});
function placeDashboard() {
  const card = el('free-plan');
  const container = card.hidden ? healthCard : card;
  if (el('dashboard-row').parentElement !== container) container.insertBefore(el('dashboard-row'), el(card.hidden ? 'health-error' : 'free-plan-message'));
}
const statusButton = el('sensor-status');
const connectionDialog = el('connection-dialog') as HTMLDialogElement;
let statusOpen = false;
function positionStatus() {
  const bounds = statusButton.getBoundingClientRect();
  healthCard.style.setProperty('--health-top', `${bounds.bottom + 8}px`);
  healthCard.style.right = `${Math.max(12, innerWidth - bounds.right)}px`;
}
function presentHealth(tone: HealthTone, label: string, popover: boolean) {
  const menuLabel = statusFailed && !statusBusy ? 'Status unavailable' : popover ? label === 'Running' ? 'Sensor running' : label
    : el('health-title').textContent || label;
  menuBar.update(menuLabel, tone === 'warning' || tone === 'error');
  statusButton.hidden = !popover;
  el('close-status').hidden = !popover;
  statusButton.className = `status-button ${tone}`;
  statusButton.setAttribute('aria-label', `Sensor status: ${label}`);
  text('status-label', label);
  el('health-dot').className = `health-dot ${tone}`;
  el('health-description').hidden = tone === 'busy';
  healthCard.dataset.tone = tone;
  const compact = popover && tone === 'online' && label === 'Connected' && !TELEMETRY_AGENTS.some(agent => current?.telemetry?.[`${agent}_opted_out`]);
  healthCard.classList.toggle('compact-status', compact);
  healthCard.setAttribute('aria-labelledby', compact ? 'credit-title' : 'health-title');
  healthCard.classList.toggle('status-popover', popover);
  if (popover) el('health-description').removeAttribute('title');
  else el('health-description').title = el('health-description').textContent || '';
  if (!popover) statusOpen = false;
  healthCard.hidden = popover && !statusOpen;
  credits.setVisible(popover && statusOpen);
  statusButton.setAttribute('aria-expanded', String(statusOpen));
  if (popover) healthCard.setAttribute('role', 'dialog');
  else healthCard.removeAttribute('role');
}
// Use ordinary positioned content so the minimum supported WebKit can show it.
function setStatusOpen(open: boolean, focus = true) {
  statusOpen = open;
  credits.setVisible(open);
  healthCard.hidden = !open;
  statusButton.setAttribute('aria-expanded', String(open));
  if (open) positionStatus();
  if (focus) el(open ? 'close-status' : 'sensor-status').focus({preventScroll:true});
  fitWindow();
}
statusButton.addEventListener('click', () => setStatusOpen(!statusOpen));
el('close-status').addEventListener('click', () => setStatusOpen(false));
document.addEventListener('pointerdown', event => {
  if (statusOpen && !healthCard.contains(event.target as Node) && !statusButton.contains(event.target as Node)) setStatusOpen(false, false);
});
document.addEventListener('keydown', event => {
  if (statusOpen && event.key === 'Escape') { event.preventDefault(); setStatusOpen(false); }
});
document.addEventListener('focusin', event => {
  if (statusOpen && !healthCard.contains(event.target as Node) && !statusButton.contains(event.target as Node)) setStatusOpen(false, false);
});
window.addEventListener('resize', positionStatus);
el('app').addEventListener('scroll', () => { if (statusOpen) setStatusOpen(false, false); });
el('change-connection').insertAdjacentHTML('afterend', '<button id="remove-app" class="button button-secondary" hidden><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M9 6V4h6v2M5 6l1 14h12l1-14M10 10v6m4-6v6"/></svg><span id="remove-app-label">Uninstall</span></button>');
const numberFormat = new Intl.NumberFormat();
const text = (id: string, value: unknown) => {
  const content = value == null || value === '' ? 'N/A' : typeof value === 'number' ? numberFormat.format(value) : String(value);
  if (el(id).textContent !== content) el(id).textContent = content;
  if (['queued', 'sent', 'delivery', 'activity-queued'].includes(id)) el(id).classList.toggle('long-count', content.length > 10);
  if (id === 'health-description' && healthCard.classList.contains('status-popover')) el(id).removeAttribute('title');
  else if (['health-description', 'link-organization', 'link-server', 'link-feedback'].includes(id)) el(id).title = content;
};
const built = new Date(BUILD_TIME);
const buildDate = Number.isNaN(built.getTime()) ? BUILD_TIME : `${built.toLocaleDateString(undefined, {dateStyle:'medium'})}, ${built.toLocaleTimeString(undefined, {timeStyle:'long'})}`;
text('build-info', `Ver. ${BUILD_VERSION}`);
el('build-info').title = [buildDate && `Built ${buildDate}`, BUILD_COMMIT && `commit ${BUILD_COMMIT}`].filter(Boolean).join(', ');

// The window keeps a fixed width; its height follows the rendered content.
// Open modal dialogs sit outside <main>, so the window fits whichever is taller,
// including the rendered borders and the viewport space reserved by CSS max-height.
let fittedHeight = 0;
function fitWindow() {
  if (menuBar.hidden()) return;
  const dialogs = Array.from(document.querySelectorAll('dialog[open]'), dialog => {
    const style = getComputedStyle(dialog);
    const maxHeight = parseFloat(style.maxHeight);
    const viewportGap = Number.isFinite(maxHeight) ? Math.max(0, innerHeight - maxHeight) : 0;
    return dialog.scrollHeight + parseFloat(style.borderTopWidth) + parseFloat(style.borderBottomWidth) + viewportGap;
  });
  const popoverHeight = statusOpen ? healthCard.getBoundingClientRect().top + healthCard.scrollHeight + 14 : 0;
  const height = Math.ceil(Math.max(document.querySelector('main')!.getBoundingClientRect().height, popoverHeight, alerts.preferredHeight(), ...dialogs));
  if (!isTauri() || height === fittedHeight) return;
  fittedHeight = height;
  invoke('fit_window', {height}).catch(() => { fittedHeight = 0; });
}
// Fit after status, an error, or visible update progress renders, never just the loading placeholder.
let fitObserver: ResizeObserver | null = null;
function startFitting() {
  if (fitObserver) return;
  const observer = fitObserver = new ResizeObserver(fitWindow);
  observer.observe(document.querySelector('main')!);
  observer.observe(healthCard);
  observer.observe(el('connect-card'));
  healthCard.querySelectorAll(':scope > *').forEach(element => observer.observe(element));
  // Opening or closing a dialog changes its size. A dialog at its maximum height
  // scrolls instead of growing, so its children are observed as well.
  const observeDialogs = () => document.querySelectorAll('dialog, dialog > *').forEach(element => observer.observe(element));
  observeDialogs();
  new MutationObserver(observeDialogs).observe(document.body, {childList: true});
}

// Reuse the enrollment form in Settings, alongside the desktop preference.
function showConnectionView(open: boolean) {
  const card = el('connect-card');
  card.hidden = !open;
  el('back-to-choices').hidden = !open || editingConnection || !!current?.enrolled;
  el('change-connection').setAttribute('aria-expanded', String(editingConnection));
  text('connection-title', editingConnection ? 'Connection' : 'Connect your organization');
  if (editingConnection) {
    if (!connectionDialog.open) {
      connectionDialog.insertBefore(card, el('settings-actions'));
      el('connection-heading').after(el('notice'));
      connectionDialog.showModal();
      el(!el('menu-bar-setting').hidden ? 'show-menu-bar' : open ? 'enrollment-link' : 'close-connection').focus({preventScroll: true});
    }
  } else if (connectionDialog.open) {
    connectionDialog.close();
    healthCard.before(el('notice'));
    el('status-footer').before(card);
  }
  const view: WindowView = open ? 'link' : 'status';
  if (connectionView === view) return;
  connectionView = view;
  if (!editingConnection) el(open ? 'enrollment-link' : 'change-connection').focus({preventScroll: true});
}
function notice(message: string, tone: 'success' | 'error' | 'pending' = 'success', timeoutMs = 0) {
  clearTimeout(noticeTimer);
  const node = el('notice'); node.hidden = !message; el('notice-message').textContent = message; node.title = message; node.className = tone === 'error' ? 'error' : `${tone}-notice`;
  if (message && timeoutMs > 0) noticeTimer = setTimeout(() => notice(''), timeoutMs);
}
async function request(action: string, params: Record<string, unknown> = {}, onProgress?: Channel<{stage:string;event:string}>) {
  if (!isTauri()) throw new Error('Open the OpenAIDR desktop app to connect to your sensor.');
  return invoke<unknown>('sensor_request', {request: {action, ...params}, ...(onProgress ? {onProgress} : {})});
}
async function configureGuardrails(action:string, params:Record<string, unknown> = {}) {
  if (busy) throw new Error(OPERATION_BUSY);
  busy = true; availability();
  try {
    const result = await request(action, params) as SensorStatus;
    render(result);
    return result;
  } finally { busy = false; availability(); await refresh(false); }
}
const updates = initUpdates(request, BUILD_VERSION, update => {
  updateRevision += 1;
  desktopUpdate = update;
  renderUpdate();
  startFitting();
  clearTimeout(updateTimer);
  updateTimer = setTimeout(() => void refreshUpdate(), 1000);
});
const localRuntime = initLocalRuntime(request, async operation => {
  if (busy) throw new Error(OPERATION_BUSY);
  busy = true; availability();
  try { await operation(); }
  finally { busy = false; availability(); }
}, connected => {
  if (connected) { choosingOrganization = false; editingConnection = false; setupAttempts = 0; setupFailed = ''; }
  if (current) render(current);
  void refresh(false);
});
function availability() {
  const tauri = isTauri();
  (el('enrollment-link') as HTMLInputElement).disabled = busy;
  (el('api-key') as HTMLInputElement).disabled = busy;
  (el('enrollment-ca') as HTMLInputElement).disabled = busy || !tauri;
  document.querySelectorAll<HTMLButtonElement>('main button, #connection-dialog button, #api-key-dialog button').forEach(button => { button.disabled = busy || !tauri; });
  usage.setAvailability(!tauri || (busy && !settingUp) ? 'disabled'
    : busy || awaitingSensor() || current?.desktop_update?.status_cached ? 'cached' : 'enabled');
  credits.setAvailability(tauri && !busy && !awaitingSensor() && !current?.desktop_update?.status_cached);
  guardrails.setAvailability(tauri && !busy && !awaitingSensor() && !current?.desktop_update?.status_cached);
  posture.setAvailability(tauri && !busy && !awaitingSensor() && !current?.desktop_update?.status_cached);
  for (const id of ['sensor-status', 'close-status', 'show-about']) (el(id) as HTMLButtonElement).disabled = false;
  updates.availability(tauri);
  (el('connect-link') as HTMLButtonElement).disabled ||= !enrollmentPreview || previewPending;
  (el('connect-api-key') as HTMLButtonElement).disabled ||= !(el('api-key') as HTMLInputElement).value.trim();
  (el('change-connection') as HTMLButtonElement).disabled = busy || !tauri || localRuntime.isOpen();
  (el('retry') as HTMLButtonElement).disabled ||= fetching;
  el('retry').setAttribute('aria-busy', String(fetching));
  for (const id of ['cancel-remove', 'confirm-remove']) (el(id) as HTMLButtonElement).disabled = busy;
  (el('delete-data') as HTMLInputElement).disabled = busy || !tauri;
  if (current?.desktop_removal?.data_deletion_started && !current.desktop_removal.data_deleted) (el('resume-app') as HTMLButtonElement).disabled = true;
  localRuntime.availability();
}
function serviceState(status: SensorStatus) {
  const service = status.service;
  const label = (typeof service === 'string' ? service : service?.status || (service?.running ? 'running' : service?.installed ? 'stopped' : 'not installed')) || 'unknown';
  return { running: /^(running|active)$/i.test(label) };
}
// Drift is what automatic setup repairs: a service that is not running or
// still runs a previous version, or a detected agent whose settings do not
// point at the local receiver. A sensor with telemetry disabled has no
// receiver, so its agents are never counted as drift.
// An agent is connected only while its settings still match the desired
// values; older sensors without that field fall back to the installed flag.
function connected(telemetry: NonNullable<SensorStatus['telemetry']>, agent: TelemetryAgent) {
  return telemetry[`${agent}_current`] ?? telemetry[`${agent}_installed`];
}
function agentAvailable(status: SensorStatus, agent: Agent) {
  return status.hooks?.[agent]?.available ?? ((agent === 'codex' || agent === 'claude') && status.telemetry?.[`${agent}_available`]);
}
// Agents are never drift while the receiver is disabled, while the server
// disabled this sensor, or when they were disconnected on purpose from the CLI.
function drift(status: SensorStatus) {
  const telemetry = status.telemetry || {};
  // A sensor started by hand with `openaidr run` answers locally without a service; it is left alone.
  const foreground = !!status.foreground && status.running === true;
  // A manually started receiver on previous settings holds its agents for the operator.
  const held = holdsAgents(status);
  const managed = serviceState(status).running;
  const connectionStarting = Date.now() < connectionStartupUntil;
  // While a just-started service has not answered yet, nothing that needs the receiver runs, so the grace period is not defeated by agent setup.
  const starting = managed && status.running === false && (connectionStarting || unreachableSince === null || Date.now() - unreachableSince < UNREACHABLE_GRACE_MS);
  const agents = telemetry.enabled === false || status.disabled || held || starting ? [] : TELEMETRY_AGENTS.filter(agent => telemetry[`${agent}_available`] && !telemetry[`${agent}_opted_out`] && !connected(telemetry, agent));
  // Hooks have their own opt-out and can remain enabled without native telemetry.
  // Older sensors without hook status keep their existing setup behavior.
  const hooks = status.disabled || starting ? [] : AGENTS.filter(agent => {
    return agentEntries(status.hooks).some(entry => entry.agent === agent && entry.state
      && (entry.state.available || agentAvailable(status, agent)) && !entry.state.opted_out && !entry.state.disabled && !entry.state.approval_pending
      && !(entry.state.current ?? (entry.state.installed && (agent !== 'codex' || entry.state.trusted))));
  });
  const service = !managed && !foreground;
  const version = managed && status.running === true && versionMismatch(status);
  const settings = managed && !!status.settings_stale;
  // Running per launchd but not answering locally, for longer than a start takes.
  const unreachable = managed && status.running === false && !starting;
  return { service, version, settings, unreachable, agents, hooks, any: service || version || settings || unreachable || agents.length > 0 || hooks.length > 0 };
}
function versionMismatch(status: SensorStatus) {
  return !!status.version && status.service_version !== status.version;
}
function holdsAgents(status: SensorStatus) {
  const foreground = !!status.foreground && status.running === true;
  return !!status.settings_stale && foreground;
}
function describeDrift(gap: ReturnType<typeof drift>, status: SensorStatus) {
  const parts: string[] = [];
  if (gap.service) parts.push('the sensor is not running');
  if (gap.version) parts.push(`the sensor still runs version ${status.service_version}`);
  if (gap.settings) parts.push('the sensor settings have not updated');
  if (gap.unreachable) parts.push('the sensor is not responding');
  if (gap.agents.length) parts.push(`${gap.agents.map(agent => AGENT_NAMES[agent]).join(' and ')} telemetry is disconnected`);
  if (gap.hooks.length) parts.push(`${gap.hooks.map(agent => AGENT_NAMES[agent]).join(' and ')} guardrails are not connected`);
  return `Setup incomplete: ${parts.join('; ')}. Retry setup or contact your administrator.`;
}
function stepName(step: SetupStep) {
  if (step.step === 'telemetry.install' && step.agents?.length) return `Connecting ${step.agents.map(agent => AGENT_NAMES[agent as Agent] || agent).join(' and ')}`;
  if (step.step === 'hooks.install' && step.agents?.length) return `Installing ${step.agents.map(agent => AGENT_NAMES[agent as Agent] || agent).join(' and ')} guardrails`;
  return STEP_NAMES[step.step] || step.step;
}
function renderUpdate(fallback?: DesktopUpdate) {
  // Once read independently, even an unavailable updater is newer than sensor snapshots.
  const update = current?.desktop_removal ? null : desktopUpdate === undefined ? fallback : desktopUpdate;
  updates.render(update);
  const labels = {idle:'', available:'Update available', checking:'Checking updates…', downloading:'Downloading update…', installing:'Installing update…', restarting:'Restarting after update…', updated:'', error:'Update needs attention', unavailable:'In-app updates unavailable'};
  let label = update ? labels[update.state] || '' : '';
  if (update?.setup) label = update.state === 'error' ? 'App setup needs attention' : 'Setting up automatic updates…';
  if (updateWarningDeferred(update)) label = '';
  if (update?.state === 'downloading') {
    const received = update.downloaded_bytes;
    const total = update.total_bytes;
    if (typeof received === 'number' && Number.isSafeInteger(received) && received >= 0 && received <= MAX_UPDATE_BYTES) {
      label = typeof total === 'number' && Number.isSafeInteger(total) && total > 0 && total >= received && total <= MAX_UPDATE_BYTES
        ? `Downloading update ${Math.floor(received / total * 100)}%`
        : `Downloading update ${(received / 1048576).toFixed(1)} MiB`;
    }
  }
  const node = el('update-notice');
  node.hidden = !label;
  if (node.textContent !== label) node.textContent = label;
  const description = label ? [label, update?.latest && `Version ${update.latest}.`, update?.error].filter(Boolean).join(' ') : '';
  if (node.title !== description) {
    node.title = description;
    node.setAttribute('aria-label', description);
  }
  const guidance = el('update-guidance');
  const needsHelp = (update?.state === 'error' && !updateWarningDeferred(update)) || update?.state === 'unavailable';
  guidance.hidden = !needsHelp;
  const message = needsHelp ? [update.error, update.state === 'error'
    ? 'Contact your administrator if the problem continues.'
    : 'Reopen the app after fixing the installation. Contact your administrator for help.'].filter(Boolean).join(' ') : '';
  if (guidance.textContent !== message) guidance.textContent = message;
}
async function refreshUpdate() {
  if (menuBar.hidden() || updateFetching) return;
  clearTimeout(updateTimer);
  updateFetching = true;
  let interval = 15000;
  const revision = updateRevision;
  try {
    const snapshot = await request('desktop.update.status') as DesktopUpdate | null;
    if (revision !== updateRevision) return;
    desktopUpdate = snapshot;
    renderUpdate();
    if (!el('update-notice').hidden) startFitting();
    if (desktopUpdate && ['checking', 'downloading', 'installing', 'restarting'].includes(desktopUpdate.state)) interval = 1000;
  } catch {
    // Keep the last snapshot and use the idle interval after a failed read.
  } finally {
    updateFetching = false;
    if (!menuBar.hidden()) updateTimer = setTimeout(() => void refreshUpdate(), interval);
  }
}
function render(status: SensorStatus) {
  const standalone = status.connection_mode === 'free' || status.connection_mode === 'api_key';
  if (!!current?.desktop_removal !== !!status.desktop_removal) {
    (el('delete-data') as HTMLInputElement).checked = false;
    desktopUpdate = null;
    updateRevision += 1;
    updates.reset();
  }
  current = status;
  credits.setStatus(status);
  placeDashboard();
  if (localRuntime.isOpen()) {
    if (status.desktop_removal) localRuntime.dismiss();
    else availability();
    return;
  }
  const telemetry = status.telemetry || {};
  const live = status.live || status.status || {};
  const gap = drift(status);
  const cached = status.desktop_update?.status_cached;
  const manualGuidance = 'Stop the manually started sensor, then return to this window to run it in the background.';
  const restartGuidance = `The manually started sensor is using old settings. ${manualGuidance}`;
  let title: string, description: string;
  let tone: HealthTone = 'warning';
  const lastContact = status.heartbeat?.last_success_at ? new Date(status.heartbeat.last_success_at) : null;
  const hasContact = !!lastContact && Number.isFinite(lastContact.getTime());
  const checkedAt = Date.now();
  const contactAgeMs = hasContact ? checkedAt - lastContact!.getTime() : Infinity;
  const contactAge = hasContact ? Math.max(0, Math.floor(contactAgeMs / 60000)) : 0;
  const contactDescription = contactAge < 1 ? 'just now' : `${contactAge} ${contactAge === 1 ? 'min' : 'mins'} ago`;
  const errors = [status.heartbeat?.error, status.activity?.last_error, telemetry.last_error || live.last_error || live.last_send_error].filter(Boolean);
  // Older sensors expose error text only. Keep unknown, HTTP rejection, and TLS errors visible.
  const connectionError = /^(?:\[(?:Errno|WinError) -?\d+\] )?(?:connection (?:refused|reset|aborted)|(?:network|host) is (?:unreachable|down)|no route to host|temporary failure in name resolution|name or service not known|nodename nor servname provided|(?:the )?(?:(?:read|write|connect) )?operation timed out|timed out|all connection attempts failed|server disconnected)|^Server error '50[234]\b/i;
  const connectionErrors = errors.filter(error => typeof error === 'string' && (connectionError.test(error)
    || (standalone && error === 'Intelligence service unavailable')));
  if (!cached) {
    if (!connectionErrors.length) connectionFailure = null;
    else if (!connectionFailure || connectionFailure.sensorId !== status.sensor_id || connectionFailure.serverUrl !== status.server_url || connectionFailure.mode !== status.connection_mode) {
      connectionFailure = {sensorId:status.sensor_id,serverUrl:status.server_url,mode:status.connection_mode,
        since:!standalone && hasContact && contactAgeMs >= 0 ? lastContact!.getTime() : checkedAt};
    }
  }
  const failureAgeMs = connectionFailure ? checkedAt - connectionFailure.since : Infinity;
  // Cloud warnings share one short grace period, bounded independently of successful heartbeat timestamps.
  const connectionGrace = status.running && !status.disabled && connectionErrors.length > 0 && connectionErrors.length === errors.length
    && contactAgeMs >= 0 && contactAgeMs < (standalone ? RECENT_CLOUD_CONTACT_MS : CONNECTION_GRACE_MS)
    && failureAgeMs >= 0 && failureAgeMs < (standalone ? CLOUD_CONNECTION_GRACE_MS : CONNECTION_GRACE_MS);
  const deferCloudWarning = standalone && !!connectionGrace;
  const connectionLost = status.running && (status.heartbeat?.error || connectionErrors.length > 0) && !connectionGrace;
  const connectedLabel = connectionGrace && !standalone ? `Connected (${contactDescription})` : 'Connected';
  if (status.desktop_removal) {
    const complete = status.desktop_removal.state === 'complete';
    title = complete ? 'Background services stopped.' : 'Removal needs attention';
    description = complete ? 'Restart Codex and Claude Code to finish removal.' : 'Fix the issues below and retry removal. Setup and updates are paused.';
    tone = complete ? 'online' : 'error';
  }
  else if (cached) { title = 'Updating sensor'; description = 'Showing status from before the update.'; tone = 'loading'; }
  else if (!status.enrolled) { title = 'Welcome to OpenAIDR'; description = 'Choose how to get started on this device.'; tone = 'idle'; }
  else if (setupFailed) {
    title = 'Setup needs attention'; description = setupFailed; tone = 'error';
    const recovery = holdsAgents(status) ? restartGuidance : status.foreground && status.running ? manualGuidance : '';
    if (recovery) description += ` ${recovery}`;
  }
  else if (editingConnection && gap.any) { title = 'Setup paused'; description = 'Connect or close Settings to resume setup.'; }
  else if (gap.any) { title = 'Setting up this device…'; description = gap.version ? `Updating the sensor to version ${status.version}.` : gap.settings || gap.unreachable ? 'Restarting the sensor.' : 'Starting the sensor and connecting your coding agents.'; tone = 'loading'; }
  else if (status.running && versionMismatch(status)) { title = 'Sensor version mismatch'; description = `OpenAIDR requires sensor ${status.version}; the running sensor reports ${status.service_version || 'an unknown version'}. ${status.foreground ? manualGuidance : 'Retry setup to finish replacing the background sensor.'}`; }
  else if (status.disabled) { title = 'Sensor disabled by your organization'; description = 'Activity collection is off. Contact your administrator to enable it.'; tone = 'idle'; }
  else if (holdsAgents(status)) { title = 'Sensor needs a restart'; description = restartGuidance; }
  else if (status.foreground && status.running) { title = 'Sensor is running manually'; description = manualGuidance; tone = 'warning'; }
  else if (status.running && status.heartbeat && !status.heartbeat.last_success_at) { title = standalone ? status.connection_mode === 'api_key' ? 'Connecting with your API key' : 'Connecting to the free service' : 'Waiting for your organization'; description = 'The sensor is making its first connection.'; tone = 'loading'; }
  else if (status.running && telemetry.enabled === false) { title = 'Telemetry is disabled'; description = 'Agent telemetry is disabled in sensor settings. Guardrails can still collect activity.'; }
  else if (status.running && telemetry.authentication_failed) {
    if (telemetry.authentication_clients?.length) {
      title = 'Agent sessions need a restart';
      description = 'Save your work, then fully quit and reopen the affected agents listed below. Starting a new chat may keep the same agent process. Saved usage remains available.';
    } else {
      title = 'Usage collection needs attention';
      description = 'Some local reports were rejected. Restart running coding-agent sessions to reload their connection settings. Saved usage remains available.';
    }
  }
  else if (status.running) {
    title = hasContact ? 'Sensor connected' : 'Sensor is running';
    const organization = status.tenant_name?.trim() || 'your organization';
    description = connectionGrace ? `Last connected ${contactDescription}. Retrying automatically.` : hasContact ? `${CONNECTED_DESCRIPTION}${organization}.` : 'The sensor is running on this device.';
    if (standalone && hasContact && !connectionGrace) description = status.connection_mode === 'api_key' ? 'Connected with your API key. Usage stays on this device.' : 'Connected to the free service. Usage stays on this device.';
    tone = 'online';
    const disconnected = TELEMETRY_AGENTS.filter(agent => telemetry[`${agent}_opted_out`]).map(agent => AGENT_NAMES[agent]);
    if (disconnected.length) description += ` ${disconnected.join(' and ')} telemetry is disconnected.`;
  }
  else { title = 'Sensor is starting'; description = 'Waiting for the sensor to respond.'; tone = 'loading'; }
  const errorSources = new Map<string, string[]>();
  for (const [source, error] of [
    [standalone ? 'Cloud service connection' : 'Organization connection', status.heartbeat?.error],
    ['Activity upload', status.activity?.last_error],
    ['Telemetry upload', telemetry.last_error || live.last_error || live.last_send_error],
  ] as const) {
    if (error) {
      const message = String(error);
      errorSources.set(message, [...(errorSources.get(message) || []), source]);
    }
  }
  const lastError = [...errorSources].map(([message, sources]) => `${sources.join(', ')}: ${message}`).join('\n');
  if (lastError && !connectionGrace && status.enrolled && !setupFailed && !gap.any && !cached && !status.desktop_removal) {
    const preserveGuidance = status.disabled || versionMismatch(status) || status.foreground || holdsAgents(status) || telemetry.enabled === false || telemetry.authentication_failed;
    if (!preserveGuidance) {
      title = connectionLost ? 'Server connection lost' : 'Sensor needs attention';
      description = connectionLost ? standalone ? 'Usage stays on this device. Cloud guardrails are unavailable; actions continue.' : 'The sensor is running. Uploads are waiting for a connection.' : 'The sensor reported an error. See the details below.';
    }
    tone = 'warning';
  }
  if (status.running && !status.disabled && !setupFailed && !gap.any && !cached && !status.desktop_removal) {
    const unprotected = agentEntries(status.hooks).filter(entry => (entry.state?.available || agentAvailable(status, entry.agent)) && entry.state?.opted_out).map(entry => AGENT_NAMES[entry.agent] + (entry.profile ? ` (${entry.state?.name})` : ''));
    if (unprotected.length) { description += ` ${unprotected.join(' and ')} guardrails are disconnected.`; tone = 'warning'; }
    if (status.hooks?.hermes?.approval_pending && !status.hooks.hermes.opted_out) { description += ' Hermes Agent guardrails need approval. Start Hermes chat and approve the OpenAIDR hooks.'; tone = 'warning'; }
    const disabled = agentEntries(status.hooks).filter(entry => (entry.state?.available || agentAvailable(status, entry.agent)) && entry.state?.disabled).map(entry => AGENT_NAMES[entry.agent] + (entry.profile ? ` (${entry.state?.name})` : ''));
    if (disabled.length) { description += ` ${disabled.join(' and ')} guardrails are disabled in agent settings. Enable hooks there, then return to this window.`; tone = 'warning'; }
  }
  app.classList.toggle('removal-complete', status.desktop_removal?.state === 'complete');
  text('health-title', title);
  text('health-description', description);
  const showFacts = !!status.enrolled && !status.desktop_removal;
  let dashboardUrl = '';
  if (showFacts && !standalone && status.server_url) {
    try {
      const url = new URL(status.server_url);
      if (['https:', 'http:'].includes(url.protocol) && url.href === `${url.origin}/`) dashboardUrl = url.href;
    } catch { /* Hide the dashboard link when no valid address is available. */ }
  }
  if (dashboardLink.getAttribute('href') !== dashboardUrl) el('dashboard-error').hidden = true;
  el('dashboard-row').hidden = !dashboardUrl;
  if (dashboardUrl) {
    dashboardLink.href = dashboardUrl;
    if (!dashboardLink.isConnected) el('dashboard-address').append(dashboardLink);
  } else {
    dashboardLink.remove();
    dashboardLink.removeAttribute('href');
  }
  el('sensor-facts').hidden = !showFacts;
  text('sensor-state', cached ? 'Updating' : status.disabled ? 'Disabled' : status.running ? 'Running' : tone === 'loading' ? 'Starting' : serviceState(status).running ? 'Not responding' : 'Stopped');
  text('server-state', cached ? 'Not checked' : !status.running ? 'Not checked' : connectionGrace ? connectedLabel : status.heartbeat?.error ? 'Unreachable' : hasContact ? 'Connected' : status.heartbeat ? 'Connecting' : 'Unknown');
  const connectedAgents = status.disabled ? [] : AGENTS.filter(agent => {
    const hook = status.hooks?.[agent];
    const hasTelemetry = (agent === 'claude' || agent === 'codex') && telemetry.enabled !== false && !telemetry[`${agent}_opted_out`] && connected(telemetry, agent);
    const hasHooks = hook && !hook.opted_out && !hook.disabled && !hook.approval_pending
      && (hook.current ?? (hook.installed && (agent !== 'codex' || hook.trusted)));
    return agentAvailable(status, agent) && (hasTelemetry || hasHooks);
  });
  text('connected-agents', cached || !status.running ? 'Not checked' : connectedAgents.map(agent => AGENT_NAMES[agent]).join(', ') || 'None');
  el('sensor-state').className = !cached && !status.disabled && status.running === false && tone !== 'loading' ? 'error' : '';
  el('server-state').className = cached || !status.running ? '' : status.heartbeat?.error && !connectionGrace ? 'warning' : hasContact ? 'online' : '';
  el('collection-guidance').hidden = !showFacts || !!cached || !!status.disabled || (telemetry.enabled === false && !connectedAgents.length);
  const rejectedClients = telemetry.authentication_clients || [];
  const unidentified = telemetry.authentication_unidentified ?? !rejectedClients.length;
  const rejectionGuidance = [
    rejectedClients.length ? 'The listed processes sent reports with invalid local credentials. Their warnings stay visible until those processes exit or reconnect successfully.' : '',
    unidentified ? `${rejectedClients.length ? 'An additional client' : 'The client'} could not be identified. Its warning clears after five minutes without another rejection. Each rejection restarts that timer.` : '',
  ].filter(Boolean).join(' ');
  text('collection-guidance', telemetry.authentication_failed ? rejectionGuidance : `${status.running ? 'Collecting activity in the background.' : 'Activity collection is stopped.'} Restart coding-agent sessions after setup or an app update.`);
  el('telemetry-auth').hidden = !showFacts || !!cached || !!status.disabled || !status.running || !telemetry.authentication_failed;
  const failedAt = telemetry.authentication_last_failed_at ? new Date(telemetry.authentication_last_failed_at) : null;
  const count = telemetry.authentication_failures;
  const summary = [
    count !== undefined ? `${count.toLocaleString()} rejected local ${count === 1 ? 'report' : 'reports'} since the sensor started.` : '',
    failedAt && Number.isFinite(failedAt.getTime()) ? `Last rejection: ${failedAt.toLocaleString(undefined, {dateStyle:'short',timeStyle:'medium'})}.` : '',
  ].filter(Boolean).join(' ');
  text('telemetry-auth-summary', summary);
  el('telemetry-auth-summary').hidden = !summary;
  el('telemetry-clients-title').hidden = !rejectedClients.length;
  el('telemetry-clients').hidden = !rejectedClients.length;
  el('telemetry-clients').replaceChildren(...rejectedClients.map(client => {
    const row = document.createElement('li'), name = document.createElement('strong'), started = document.createElement('span');
    const agent = client.process_name.toLowerCase().replace(/\.exe$/, '');
    name.textContent = `${AGENT_NAMES[agent as Agent] || client.process_name} · PID ${client.pid}`;
    const when = new Date(client.started_at);
    started.textContent = Number.isFinite(when.getTime()) ? `Started ${when.toLocaleString(undefined, {dateStyle:'short',timeStyle:'medium'})}` : 'Start time unavailable';
    row.append(name, started);
    return row;
  }));
  el('health-error').hidden = !lastError || deferCloudWarning || !!cached || !!status.desktop_removal;
  el('health-error').textContent = lastError;
  el('counter-note').hidden = !showFacts;
  text('counter-note', cached ? 'Last known counters before the update.' : status.running ? 'Record counters are from the current sensor session.' : 'Last known counters before the sensor stopped.');
  let label = tone === 'online' ? hasContact ? connectedLabel : 'Running' : tone === 'error' ? status.running ? 'Setup failed' : 'Offline' : tone === 'loading' ? cached ? 'Updating' : 'Connecting' : status.disabled ? 'Disabled' : 'Attention';
  if (tone === 'warning' && connectionLost && !status.disabled) label = 'Connection lost';
  presentHealth(tone, label, showFacts);
  el('sensor-details').hidden = !showFacts;
  if (healthCard.classList.contains('compact-status')) el('collection-guidance').hidden = true;
  const removalErrors = status.desktop_removal?.errors || [];
  el('removal-details').hidden = !removalErrors.length;
  el('removal-details').replaceChildren(...removalErrors.map(message => {
    const paragraph = document.createElement('p'); paragraph.textContent = message; return paragraph;
  }));
  const retainedData = status.desktop_removal?.retained_data;
  el('removal-data').hidden = !status.desktop_removal || !!status.desktop_removal.data_deleted;
  el('delete-data-label').hidden = !removalSupported || status.desktop_removal?.state !== 'complete';
  el('removal-data-note').hidden = !status.desktop_removal;
  text('removal-data-note', status.desktop_removal?.data_deleted ? 'Local data deleted. Uploaded data is kept.'
    : status.desktop_removal?.data_deletion_started ? 'Some local data may remain. Retry deletion. Uploaded data is kept.' : 'Uploaded data is kept.');
  if (status.desktop_removal?.data_deleted) (el('delete-data') as HTMLInputElement).checked = false;
  el('retained-data-details').hidden = !retainedData;
  const retainedText = retainedData ? `Sensor data: ${retainedData}\nEnrollment and recovery files: ~/Library/Application Support/OpenAIDR\nQuit the app after removal completes before deleting these files.` : '';
  if (el('retained-data').textContent !== retainedText) {
    el('retained-data').replaceChildren();
    if (retainedData) {
      const dataPath = document.createElement('code'); dataPath.textContent = retainedData;
      const recoveryPath = document.createElement('code'); recoveryPath.textContent = '~/Library/Application Support/OpenAIDR';
      el('retained-data').append('Sensor data: ', dataPath, '\nEnrollment and recovery files: ', recoveryPath,
        '\nQuit the app after removal completes before deleting these files.');
    }
  }
  usage.setStatus(status);
  guardrails.setStatus(status);
  posture.setStatus(status);
  el('page-navigation').hidden = !status.enrolled || !!status.disabled || !!status.desktop_removal;
  alerts.setStatus(status);
  cloudCredit.setStatus(status, deferCloudWarning);
  // Setup is paused while the connection form is open, so a retry would do nothing.
  text('retry', setupFailed ? 'Retry setup' : 'Check again');
  el('retry-row').hidden = !(setupFailed || tone === 'warning') || !!cached || editingConnection || !!status.desktop_removal;
  el('stats').hidden = !status.enrolled || !!status.desktop_removal;
  text('queued', telemetry.queue_depth === undefined ? live.queue_depth : telemetry.queue_depth);
  text('activity-queued', status.activity?.queue_depth);
  text('sent', standalone ? telemetry.processed_locally : telemetry.forwarded);
  text('processed-label', standalone ? 'Processed locally' : 'Records forwarded');
  el('processed-label').title = standalone ? 'Records processed on this device since the sensor last started' : 'Records forwarded since the sensor last started';
  text('delivery', telemetry.received);
  renderRemovalControls();
  el('use-api-key').hidden = !freeRateLimited;
  const choices = !status.enrolled && !status.desktop_removal && !editingConnection && !choosingOrganization;
  el('setup-choices').hidden = !choices;
  healthCard.classList.toggle('setup-welcome', choices);
  if (!status.enrolled && choosingOrganization && !editingConnection && !status.desktop_removal) healthCard.hidden = true;
  showConnectionView(!status.desktop_removal && ((!status.enrolled && choosingOrganization) || editingConnection));
  renderUpdate(status.desktop_update);
  availability();
}

function awaitingSensor() {
  return current?.enrolled && serviceState(current).running && current.running === false
    && !current.desktop_removal && !current.desktop_update?.status_cached && !setupFailed;
}
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  const connecting = current?.enrolled && current.running && current.heartbeat
    && !current.heartbeat.last_success_at && !current.heartbeat.error && !current.disabled
    && !current.desktop_removal && !current.desktop_update?.status_cached && !setupFailed;
  refreshTimer = setTimeout(() => {
    if (menuBar.hidden() || busy || fetching) scheduleRefresh();
    else void refresh(false);
  }, menuBar.hidden() ? 15000 : statusBusy ? 3000 : awaitingSensor() || connecting ? 1000 : 15000);
}
async function refresh(showError = true) {
  if (fetching || busy) return;
  clearTimeout(refreshTimer);
  fetching = true;
  availability();
  let status: SensorStatus | null = null;
  try {
    status = await request('status') as SensorStatus;
    statusBusy = false;
    if (statusFailed) { statusFailed = false; notice(''); }
    if (!status.desktop_update?.status_cached) {
      if (status.running) connectionStartupUntil = 0;
      unreachableSince = status.enrolled && serviceState(status).running && status.running === false ? unreachableSince ?? Date.now() : null;
    }
    render(status);
  }
  catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    statusBusy = message === OPERATION_BUSY;
    statusFailed = true;
    current = null;
    el('setup-choices').hidden = true;
    healthCard.classList.remove('setup-welcome');
    app.classList.remove('removal-complete');
    usage.setStatus({});
    guardrails.setStatus({});
    posture.setStatus({});
    el('page-navigation').hidden = true;
    alerts.setStatus({});
    cloudCredit.setStatus({});
    credits.setStatus({});
    placeDashboard();
    renderUpdate(undefined);
    for (const id of ['queued','sent','delivery','activity-queued']) text(id, null);
    text('health-title', statusBusy ? 'OpenAIDR is updating.' : 'Status unavailable');
    presentHealth(statusBusy ? 'busy' : 'error', statusBusy ? 'Updating' : 'Offline', healthCard.classList.contains('status-popover'));
    if (statusBusy) {
      el('health-description').textContent = '';
      el('health-description').removeAttribute('title');
    } else text('health-description', 'Could not reach the local sensor.');
    for (const id of ['sensor-state', 'server-state', 'connected-agents']) text(id, 'Unknown');
    el('sensor-state').className = ''; el('server-state').className = '';
    el('sensor-facts').hidden = statusBusy || !healthCard.classList.contains('status-popover');
    el('stats').hidden = statusBusy || !healthCard.classList.contains('status-popover');
    el('sensor-details').hidden = statusBusy || !healthCard.classList.contains('status-popover');
    el('collection-guidance').hidden = true; el('telemetry-auth').hidden = true; el('counter-note').hidden = true;
    el('health-error').hidden = statusBusy;
    el('health-error').textContent = statusBusy ? '' : message;
    text('retry', statusBusy ? 'Check again' : 'Retry status'); el('retry-row').hidden = false;
    availability();
    if (statusBusy) notice('');
    else if (showError && !healthCard.classList.contains('status-popover')) notice(message, 'error');
  }
  finally { fetching = false; availability(); startFitting(); }
  if (status && !menuBar.hidden()) {
    await reconcile(status);
    if (!status.desktop_update?.status_cached && !awaitingSensor()) {
      void usage.refresh(showError);
      void credits.refresh();
      void guardrails.refresh();
      void posture.refresh();
    }
  }
  scheduleRefresh();
}
// Runs after every status read. Nothing here needs a click: enrolled devices
// converge on a running service and connected agents, and stop after a failure
// until Retry clears it.
async function reconcile(status: SensorStatus) {
  // Re-enrollment needs a stopped, drained sensor, so convergence pauses while the connection form is open.
  if (!status.enrolled || busy || editingConnection || localRuntime.isOpen() || removalDialog.open || status.desktop_removal || status.desktop_update?.status_cached) return;
  const gap = drift(status);
  if (!gap.any) {
    // A restart gets a new grace period, but only a receiver response clears the retry limit.
    if (serviceState(status).running && status.running === false) return;
    setupAttempts = 0;
    if (setupFailed) { setupFailed = ''; notice(''); render(status); }
    return;
  }
  if (setupFailed) return;
  if (setupAttempts >= MAX_AUTOMATIC_ATTEMPTS) { setupFailed = describeDrift(gap, status); render(status); return; }
  setupAttempts += 1;
  await runSetup();
}
async function runSetup() {
  if (busy) return;
  busy = true; settingUp = true; availability(); notice('Setting up this device…', 'pending');
  try {
    const result = await request('setup') as SetupResult;
    const steps = result.steps || [];
    if (steps.some(step => step.ok && ['service.install', 'service.start', 'service.restart'].includes(step.step))) unreachableSince = Date.now();
    const failed = steps.filter(step => !step.ok);
    const connected = steps.filter(step => step.ok && step.step === 'telemetry.install').flatMap(step => step.agents || []) as Agent[];
    const hooked = steps.filter(step => step.ok && step.step === 'hooks.install').flatMap(step => step.agents || []) as Agent[];
    const changes = [
      connected.length ? `${connected.map(agent => AGENT_NAMES[agent]).join(' and ')} telemetry connected` : '',
      hooked.length ? `${hooked.map(agent => AGENT_NAMES[agent]).join(' and ')} guardrails updated` : '',
    ].filter(Boolean);
    const connectedNote = changes.length ? ` ${changes.join('; ')}. Restart these agents to apply changes.` : '';
    if (failed.length) {
      setupFailed = failed.map(step => `${stepName(step)} failed: ${(step.error || 'unknown error').replace(/\.$/, '')}.`).join(' ') + connectedNote;
    }
    const restartAgents = [...new Set([...connected, ...hooked])].map(agent => AGENT_NAMES[agent]);
    notice(!failed.length && (result.restart_required || restartAgents.length)
      ? `Restart ${restartAgents.length === 1 ? restartAgents[0] : 'coding-agent'} sessions to apply the new settings.` : '', 'success', 60000);
    render({desktop_update: current?.desktop_update, ...result});
  } catch (error) {
    setupFailed = error instanceof Error ? error.message : String(error);
    if (current) { notice(''); render(current); }
    else notice(setupFailed, 'error');
  } finally { busy = false; settingUp = false; availability(); }
}
async function perform(action: string, params: Record<string, unknown>) {
  if (busy) return;
  busy = true; availability(); notice('Connecting…', 'pending');
  try {
    const result = await request(action, params);
    if (action === 'enrollment.connect' || action === 'free.connect' || action === 'api-key.connect') {
      freeRateLimited = false;
      apiKeyDialog.close();
      choosingOrganization = false;
      el('setup-choices').hidden = true;
      editingConnection = false; setupAttempts = 0; setupFailed = (result as {service_error?:string}).service_error || '';
      showConnectionView(false);
      text('health-title', 'Checking sensor…'); text('health-description', 'Device connected.');
      presentHealth('loading', 'Connecting', healthCard.classList.contains('status-popover'));
      el('sensor-facts').hidden = true; el('collection-guidance').hidden = true; el('telemetry-auth').hidden = true; el('counter-note').hidden = true; el('health-error').hidden = true;
      el('stats').hidden = true; el('retry-row').hidden = true;
    }
    notice('');
  }
  catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (action === 'free.connect' && message.startsWith('Free setup is rate limited.')) freeRateLimited = true;
    if (action === 'api-key.connect') { text('api-key-error', message); el('api-key-error').hidden = false; notice(''); }
    else notice(message, 'error');
  }
  finally {
    // Packaged sensors unpack their runtime before answering. Give a restarted
    // connection two minutes before automatic setup treats it as unreachable.
    connectionStartupUntil = Date.now() + 120000;
    unreachableSince = null;
    busy = false; availability(); await refresh(false);
    if (apiKeyDialog.open) el('api-key').focus();
    else if (connectionView === 'status') el(current?.enrolled ? 'change-connection' : !el('setup-choices').hidden ? 'continue-free' : healthCard.classList.contains('status-popover') ? 'sensor-status' : 'retry').focus({preventScroll: true});
  }
}
el('retry').addEventListener('click', () => {
  if (!statusFailed) { setupFailed = ''; setupAttempts = 0; }
  notice(''); void refresh();
});
el('continue-free').addEventListener('click', () => { void perform('free.connect', {}); });
const apiKeyDialog = el('api-key-dialog') as HTMLDialogElement;
const apiKeyInput = el('api-key') as HTMLInputElement;
el('use-api-key').addEventListener('click', () => {
  el('api-key-error').hidden = true; apiKeyInput.value = ''; availability(); apiKeyDialog.showModal(); apiKeyInput.focus();
});
apiKeyInput.addEventListener('input', availability);
el('api-key-form').addEventListener('submit', event => {
  event.preventDefault();
  if (busy || !apiKeyInput.value.trim()) return;
  const api_key = apiKeyInput.value.trim(); apiKeyInput.value = ''; el('api-key-error').hidden = true;
  void perform('api-key.connect', {api_key});
});
el('cancel-api-key').addEventListener('click', () => { if (!busy) apiKeyDialog.close(); });
apiKeyDialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
apiKeyDialog.addEventListener('close', () => { apiKeyInput.value = ''; if (!el('use-api-key').hidden) el('use-api-key').focus(); });

el('choose-organization').addEventListener('click', () => {
  choosingOrganization = true; notice('');
  if (current) render(current);
  el('enrollment-link').focus();
});
el('back-to-choices').addEventListener('click', () => {
  choosingOrganization = false; resetLink(); notice('');
  if (current) render(current);
  el('choose-organization').focus();
});
const dataUseDialog = el('data-use-dialog') as HTMLDialogElement;
el('data-use').addEventListener('click', () => { dataUseDialog.showModal(); });
el('close-data-use').addEventListener('click', () => { dataUseDialog.close(); });
dataUseDialog.addEventListener('close', () => { el('data-use').focus(); });
el('change-connection').addEventListener('click', () => {
  editingConnection = true; notice('');
  if (current) render(current);
  else showConnectionView(false);
  fitWindow();
});
function cancelConnection() {
  if (busy) return;
  localRuntime.dismiss();
  editingConnection = false;
  resetLink(); notice(''); showConnectionView(!!current && !current.enrolled && choosingOrganization && !current.desktop_removal);
  el('change-connection').focus({preventScroll: true});
  void refresh();
}
el('cancel-change').addEventListener('click', cancelConnection);
el('close-connection').addEventListener('click', cancelConnection);
connectionDialog.addEventListener('cancel', event => { event.preventDefault(); cancelConnection(); });
function resetLink(clear = true) {
  previewRevision++;
  // Keep invalidations in order without waiting for a slow preview request.
  const generation = previewInvalidation.then(async () => {
    const result = await request('enrollment.preview.invalidate') as {generation:number};
    if (!Number.isSafeInteger(result.generation) || result.generation < 0) throw new Error('Could not reset the enrollment preview. Edit the link to try again.');
    return result.generation;
  });
  previewInvalidation = generation.then(() => {}, () => {});
  clearTimeout(previewTimer);
  enrollmentPreview = null;
  previewPending = false;
  el('link-preview').hidden = true;
  el('link-feedback').classList.remove('error-text');
  text('link-feedback', 'Use the enrollment link from your administrator.');
  if (clear) {
    (el('enrollment-link') as HTMLInputElement).value = '';
    clearCertificate();
    (el('certificate-options') as HTMLDetailsElement).open = false;
  }
  availability();
  return generation;
}
function linkOrigin() {
  try { return new URL((el('enrollment-link') as HTMLInputElement).value.trim()).origin; }
  catch { return ''; }
}
function clearCertificate(clearFile = true) {
  enrollmentCA = null;
  if (clearFile) (el('enrollment-ca') as HTMLInputElement).value = '';
  el('remove-certificate').hidden = true;
  el('certificate-feedback').classList.remove('error-text');
  text('certificate-feedback', 'Paste your link first. PEM files only, up to 32 KiB.');
}
function previewLink() {
  const invalidation = resetLink(false);
  const link = (el('enrollment-link') as HTMLInputElement).value.trim();
  if (!link) return;
  const ca_certificate = enrollmentCA?.pem;
  const revision = previewRevision;
  previewPending = true;
  text('link-feedback', 'Checking enrollment link…');
  previewTimer = setTimeout(async () => {
    try {
      const generation = await invalidation;
      if (revision !== previewRevision) return;
      const preview = await request('enrollment.preview', {link, generation, ...(ca_certificate ? {ca_certificate} : {})}) as EnrollmentPreview;
      if (revision !== previewRevision) return;
      enrollmentPreview = preview;
      text('link-organization', preview.tenant.name);
      text('link-server', preview.server_url);
      text('link-feedback', `Expires ${new Date(preview.expires_at).toLocaleString([], {dateStyle:'medium',timeStyle:'short'})}.`);
      el('link-preview').hidden = false;
    } catch (error) {
      if (revision !== previewRevision) return;
      text('link-feedback', error instanceof Error ? error.message : String(error));
      el('link-feedback').classList.add('error-text');
    } finally {
      if (revision === previewRevision) { previewPending = false; availability(); }
    }
  }, 300);
}
el('enrollment-link').addEventListener('input', () => {
  // Selected trust belongs to one origin, never to a subsequently pasted server.
  if (!enrollmentCA || enrollmentCA.origin !== linkOrigin()) clearCertificate();
  previewLink();
});
el('enrollment-ca').addEventListener('change', async () => {
  const file = (el('enrollment-ca') as HTMLInputElement).files?.[0];
  resetLink(false);
  clearCertificate(false);
  if (!file) { previewLink(); return; }
  const revision = previewRevision;
  previewPending = true;
  availability();
  try {
    const origin = linkOrigin();
    if (!origin.startsWith('https://')) throw new Error('Paste an HTTPS enrollment link before choosing its certificate.');
    if (!file.size || file.size > 32 * 1024) throw new Error('Choose a PEM certificate file of at most 32 KiB.');
    const pem = await file.text();
    if (revision !== previewRevision) return;
    if (/[^\x00-\x7f]/.test(pem)) throw new Error('Choose an ASCII PEM certificate file.');
    enrollmentCA = {pem, origin};
    text('certificate-feedback', `${file.name} selected for ${origin}.`);
    el('remove-certificate').hidden = false;
    previewLink();
  } catch (error) {
    if (revision !== previewRevision) return;
    clearCertificate();
    text('certificate-feedback', error instanceof Error ? error.message : String(error));
    el('certificate-feedback').classList.add('error-text');
    text('link-feedback', 'Choose a valid certificate or edit the enrollment link to try again.');
    previewPending = false;
    availability();
  }
});
el('remove-certificate').addEventListener('click', () => {
  clearCertificate();
  previewLink();
});
el('link-enrollment').addEventListener('submit', event => {
  event.preventDefault();
  if (!enrollmentPreview || previewPending || busy) return;
  const params = {link:(el('enrollment-link') as HTMLInputElement).value.trim(), tenant_id:enrollmentPreview.tenant.id, ...(enrollmentCA ? {ca_certificate:enrollmentCA.pem} : {})};
  resetLink();
  void perform('enrollment.connect', params);
});
const removalDialog = el('remove-dialog') as HTMLDialogElement;
let removalAction = 'desktop.remove';
let resumeCompleted = false;
function deletionProgress() {
  const stages: Record<string, string> = {
    waiting:'Waiting for other operations…', locks:'Checking uninstall locks…', usage_shutdown:'Stopping activity reads…',
    preparation:'Preparing uninstall…', helper_startup:'Starting local cleanup…', validation:'Checking the local folder…',
    configuration_lock:'Waiting for local settings…', scan:'Checking local files…', services:'Checking background services are stopped…',
    integrations:'Removing remaining agent connections…', deletion:'Deleting local data and the app-created runtime…', record:'Saving cleanup status…',
    trash:'Local data deleted. Moving OpenAIDR to Trash…',
  };
  const started = performance.now();
  let active = true;
  const channel = new Channel<{stage:string;event:string}>(event => {
    if (active && event.event === 'start' && Object.hasOwn(stages, event.stage)) text('removal-stage', stages[event.stage]);
  });
  text('removal-stage', stages.waiting);
  const tick = () => text('removal-elapsed', `Elapsed ${Math.floor((performance.now() - started) / 1000)}s. Large folders can take several minutes.`);
  tick();
  el('removal-progress').hidden = false;
  const timer = window.setInterval(tick, 1000);
  fitWindow();
  return {channel, stop:() => { active = false; clearInterval(timer); el('removal-progress').hidden = true; }};
}
function renderRemovalControls() {
  el('remove-app').hidden = !removalSupported || current?.desktop_removal?.state === 'complete';
  text('remove-app-label', current?.desktop_removal ? 'Retry uninstall' : 'Uninstall');
  el('resume-app').hidden = !removalSupported || !current?.desktop_removal;
  el('removal-actions').hidden = el('resume-app').hidden;
  el('trash-app').hidden = !removalSupported || current?.desktop_removal?.state !== 'complete';
  el('delete-data-label').hidden = !removalSupported || current?.desktop_removal?.state !== 'complete';
  text('trash-app', (el('delete-data') as HTMLInputElement).checked ? 'Delete data and move to Trash' : 'Move app to Trash');
}
function openRemoval() {
  if (busy || !removalSupported) return;
  removalAction = 'desktop.remove';
  resumeCompleted = false;
  text('remove-title', 'Uninstall OpenAIDR?');
  text('remove-description', nativeUninstaller
    ? 'OpenAIDR will close and open the Windows uninstaller. Follow its steps to remove the app and stop background services.'
    : 'Uninstalling stops the background sensor and any local runtime created by this app, and removes OpenAIDR’s hooks.');
  text('removal-retention', 'Local and uploaded data are kept. Restart Codex and Claude Code after uninstalling.');
  text('confirm-remove', nativeUninstaller ? 'Open uninstaller' : 'Uninstall OpenAIDR');
  el('confirm-remove').classList.add('button-danger');
  el('remove-error').hidden = true;
  removalDialog.showModal();
  fitWindow();
  el('cancel-remove').focus();
}
el('remove-app').addEventListener('click', openRemoval);
el('resume-app').addEventListener('click', () => {
  if (busy || !removalSupported) return;
  removalAction = 'desktop.resume';
  void performRemoval();
});
el('delete-data').addEventListener('change', renderRemovalControls);
el('trash-app').addEventListener('click', async () => {
  if (busy || current?.desktop_removal?.state !== 'complete') return;
  if ((el('delete-data') as HTMLInputElement).checked) {
    removalAction = 'desktop.trash';
    text('remove-title', 'Delete local data?');
    text('remove-description', 'Permanently delete local activity, sensor logs, connection settings, recovery files, and the dashboard runtime and database created by this app. Then move OpenAIDR to Trash.');
    text('removal-retention', 'This cannot be undone. Uploaded data is kept. Separately installed runtimes are kept. Desktop diagnostic logs outside this folder are kept.');
    text('confirm-remove', 'Delete data and move to Trash');
    el('confirm-remove').classList.add('button-danger');
    el('remove-error').hidden = true;
    removalDialog.showModal(); fitWindow(); el('cancel-remove').focus();
    return;
  }
  busy = true; availability(); notice('');
  text('trash-app', 'Moving to Trash…');
  try {
    await request('desktop.trash');
    // The native app quits after the bundle reaches Trash.
  } catch (error) {
    notice(error instanceof Error ? error.message : String(error), 'error');
    busy = false; availability();
    renderRemovalControls();
  }
});
el('cancel-remove').addEventListener('click', () => removalDialog.close());
removalDialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
removalDialog.addEventListener('close', () => { fitWindow(); if (removalAction === 'desktop.trash' && !busy) el('trash-app').focus(); });
el('confirm-remove').addEventListener('click', () => void performRemoval());
async function performRemoval() {
  if (busy) return;
  const resume = removalAction === 'desktop.resume';
  const button = resume ? 'resume-app' : 'confirm-remove';
  const label = el(button).textContent;
  let closing = false;
  let progress: ReturnType<typeof deletionProgress> | undefined;
  busy = true; availability();
  text(button, removalAction === 'desktop.trash' ? current?.desktop_removal?.data_deleted ? 'Moving to Trash…' : 'Deleting local data…' : resume ? 'Installing…' : nativeUninstaller ? 'Opening uninstaller…' : 'Uninstalling…');
  el(button).setAttribute('aria-busy', 'true');
  if (resume) notice('');
  el('remove-error').hidden = true;
  resetLink();
  try {
    if (removalAction === 'desktop.trash') {
      progress = deletionProgress();
      await request('desktop.trash', current?.desktop_removal?.data_deleted ? {} : {delete_data:true}, progress.channel);
      closing = true;
      return;
    }
    const result = resumeCompleted ? null : await request(removalAction) as SensorStatus;
    if (nativeUninstaller && removalAction === 'desktop.remove') {
      closing = true;
      return;
    }
    if (removalAction === 'desktop.resume') resumeCompleted = true;
    setupFailed = ''; setupAttempts = 0; editingConnection = false;
    notice('');
    if (resumeCompleted) {
      // Resume only acknowledges restored settings. Keep progress visible until
      // a status read replaces the removal screen; retries need only that read.
      const status = await request('status') as SensorStatus;
      if (status.desktop_removal) throw new Error('Installation is still finishing. Try again shortly.');
      render(status);
      resumeCompleted = false;
    } else if (result?.desktop_removal) render(result);
    if (!resume) removalDialog.close();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (resume) notice(message, 'error');
    else {
      text('remove-error', message);
      el('remove-error').hidden = false;
    }
  } finally {
    progress?.stop();
    if (!closing) {
      text(button, label);
      el(button).setAttribute('aria-busy', 'false');
      busy = false; availability(); await refresh(false);
      if (removalAction === 'desktop.trash' && current?.desktop_removal?.data_deleted) {
        text('remove-title', 'Local data deleted');
        text('remove-description', 'Local cleanup finished. Retry moving OpenAIDR to Trash.');
        text('confirm-remove', 'Move app to Trash');
      }
    }
  }
}
resetLink(); void refresh(); void refreshUpdate();
void request('desktop.capabilities').then(result => {
  removalSupported = (result as {removal_supported?: boolean}).removal_supported === true;
  nativeUninstaller = (result as {native_uninstaller?: boolean}).native_uninstaller === true;
  renderRemovalControls(); if (current) fitWindow();
}).catch(() => {});
void initSimulation(request);
function refreshOnReturn() {
  if (menuBar.hidden()) clearTimeout(updateTimer);
  else {
    // Content can finish rendering while the native window is hidden.
    if (fitObserver) fitWindow();
    void refresh(false); void refreshUpdate();
  }
}
window.addEventListener('focus', refreshOnReturn);
document.addEventListener('visibilitychange', refreshOnReturn);
