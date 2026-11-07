import { test, expect, type Page, type Locator } from './fixtures';
import config from '../src-tauri/tauri.conf.json' with {type:'json'};
import {NativeUI} from '../e2e/native-ui';
import {exerciseAppControls} from '../e2e/native-flows';
import {execFileSync, spawn} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:http';
import {readFileSync} from 'node:fs';

const link = 'https://tenant.example/enroll#token=oaet_' + 'a'.repeat(43);
const preview = {server_url:'https://tenant.example',tenant:{id:'01000000-0000-7000-8000-000000000001',name:'Example organization'},auth_mode:'bearer',expires_at:'2099-01-01T00:00:00Z'};
const unenrolled = {enrolled:false, service:'not installed', running:false, telemetry:{}};
const enrolled = {service_version:'0.1.0', enrolled:true, sensor_id:'sensor-1', server_url:'https://192.168.1.50', version:'0.1.0'};
const converged = {...enrolled, service:'running', running:true, telemetry:{listen:'127.0.0.1:4318', codex_available:false, claude_available:true, claude_installed:true, claude_current:true}};
// Transport fixture only; certificate verification is covered by real TLS tests.
const certificate = '-----BEGIN CERTIFICATE-----\nY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n';

type AlertFixture = {id:string;title:string;message:string;command:string;installed_version:string;required_version:string;sender_name:string;created_at:string;expires_at:string;received_at:string|null;acknowledged_at:string|null};
type Mock = {
  localRuntime?: {docker_ready:boolean;docker_action?:'install'|'start'|'manual';existing:boolean;managed:boolean;connected:boolean;server_url:string};
  localDockerError?: string;
  localRuntimeError?: string;
  setupChoices?: boolean;
  freeError?: string;
  freeUsage?: Record<string, unknown>;
  freeUsageError?: string;
  creditPlan?: 'free'|'paid';
  creditIdentity?: {sensor_id:string;server_url:string};
  apiKeyError?: string;
  guardrails?: Record<string, unknown>;
  posture?: Record<string, unknown>;
  postureConfigureError?: string;
  postureError?: string;
  guardrailsError?: string;
  guardrailSetupError?: string;
  askPages?: Record<string, Record<string, unknown>>;
  denialPages?: Record<string, Record<string, unknown>>;
  denialDetails?: Record<string, Record<string, unknown>>;
  denialError?: string;
  reviewError?: string;
  reviewLoseResponse?: boolean;
  reviewReceipts?: Record<string, Record<string, unknown>>;
  menuBar?: {supported:boolean;enabled:boolean;label?:string;available?:boolean};
  menuBarError?: string;
  alerts?: AlertFixture[];
  alertsError?: string;
  acknowledgeError?: string;
  notificationPermission?: 'granted' | 'denied';

  usage?: Record<string, unknown>;
  usageByDays?: Record<number, Record<string, unknown>>;
  usageError?: string;
  usageErrorsByDays?: Record<number, string>;
  legacyUsage?: boolean;
  usagePeriods?: Record<string, unknown>;
  usageUntil?: string;
  pendingUsageDays?: number;
  maxWindowHeight?: number;
  removalSupported?: boolean | null;
  nativeUninstaller?: boolean;
  simulation?: Record<string, unknown>;
  simulationError?: string;
  status: Record<string, unknown>;
  afterEnroll?: Record<string, unknown>;
  afterSetup?: Record<string, unknown>;
  setup?: Record<string, unknown>;
  setupError?: string;
  statusError?: string;
  updateStatus?: Record<string, unknown> | null;
  updateStatusError?: string;
  updateError?: string;
  updateCheck?: Record<string, unknown>;
  updateInstall?: Record<string, unknown>;
  pendingUpdateStatus?: boolean;
  pendingAction?: string;
  preview?: Record<string, unknown>;
  previewError?: string;
  previewGeneration?: number;
  invalidationError?: string;
  enrollError?: string;
  enrollResult?: Record<string, unknown>;
  afterRemove?: Record<string, unknown>;
  removeError?: string;
  trashError?: string;
  afterResume?: Record<string, unknown>;
  resumeError?: string;
  supportError?: string;
  dashboardError?: string;
  dashboardHandoff?: string;
};
type Requests = {action:string;automatic?:boolean;decision?:'ask'|'deny';delete_data?:boolean;days?:number;generation?:number;id?:string;ids?:string[];scope?:string;server_url?:string;agent?:string;profile?:string;enabled?:boolean;until?:string;cursor?:string;label?:string;note?:string;review_version?:number;evidence_sha256?:string;expected_revision?:number;request_id?:string}[];

// The isolated IPC mock records every request; it never touches local settings.
async function boot(page: Page, mock: Mock) {
  // Match window_fit.rs: 160–720 logical pixels, further limited by the work area.
  await page.exposeFunction('fitWindow', (height:number) => page.setViewportSize({
    width:config.app.windows[0].width,
    height:Math.min(Math.max(160, Math.ceil(height)), 720, mock.maxWindowHeight ?? 720),
  }));
  await page.addInitScript((mock: Mock) => {
    const win = window as unknown as {isTauri:boolean; requests:Requests; mock:Mock; completeRequest?:() => void; completeInvalidation?:() => void; completeUpdateStatus?:() => void; __TAURI_INTERNALS__:unknown; ipcCommands:string[]; notifications:unknown[]; notificationAction?:(extra:Record<string,unknown>) => void};
    win.isTauri = true;
    win.requests = [];
    win.ipcCommands = [];
    win.mock = mock;
    win.notifications = [];
    Object.defineProperty(window, 'Notification', {value: class {
      static permission = mock.notificationPermission ?? 'granted';
      static requestPermission = async () => mock.notificationPermission ?? 'granted';
      constructor(title:string, options:unknown) { win.notifications.push({title,options}); }
    }});
    let previewGeneration = mock.previewGeneration ?? 0;
    win.__TAURI_INTERNALS__ = {transformCallback:() => 1, metadata:{currentWindow:{label:'main'}}, invoke: async (command:string, args:{request:Requests[number]}) => {
      win.ipcCommands.push(command);
      if (command === 'fit_window') return (window as unknown as {fitWindow:(height:number) => Promise<void>}).fitWindow((args as unknown as {height:number}).height);
      if (command === 'menu_bar_settings') {
        const enabled = (args as unknown as {enabled?:boolean} | undefined)?.enabled;
        if (enabled !== undefined) {
          if (win.mock.menuBarError) throw new Error(win.mock.menuBarError);
          win.mock.menuBar = {supported:true,enabled};
        }
        return win.mock.menuBar ?? {supported:false,enabled:false};
      }
      if (command === 'menu_bar_health') {
        (window as unknown as {menuHealth:unknown}).menuHealth = args;
        return;
      }
      if (command === 'plugin:notification|register_listener') {
        const handler = (args as unknown as {handler:{onmessage:(event:unknown) => void}}).handler;
        win.notificationAction = extra => handler.onmessage({actionId:'tap',notification:{extra}});
        return;
      }
      if (command !== 'sensor_request') throw new Error(`Unexpected IPC command: ${command}`);
      win.requests.push(args.request);
      const action = args.request.action;
      if (action === 'desktop.trash') {
        const channel = (args as unknown as {onProgress?:{onmessage:(event:unknown) => void}}).onProgress;
        (window as unknown as {removalProgress?:(stage:string) => void}).removalProgress = stage => channel?.onmessage({stage,event:'start'});
      }
      if (action === 'alerts.focus') return;
      if (action === 'alerts.list') {
        if (win.mock.alertsError) throw new Error(win.mock.alertsError);
        return {supported:win.mock.alerts !== undefined,scope:'a'.repeat(64),sensor_id:win.mock.status.sensor_id,server_url:win.mock.status.server_url,items:structuredClone(win.mock.alerts ?? [])};
      }
      if (action === 'alerts.received' || action === 'alerts.acknowledge') {
        if (action === 'alerts.acknowledge' && win.mock.acknowledgeError) throw new Error(win.mock.acknowledgeError);
        return {items:(win.mock.alerts ?? []).filter(row => row.id === args.request.id || args.request.ids?.includes(row.id)).map(row => {
          row.received_at ??= '2026-10-22T12:00:00Z';
          if (action === 'alerts.acknowledge') row.acknowledged_at ??= '2026-10-22T12:01:00Z';
          return {alert_id:row.id,received_at:row.received_at,acknowledged_at:row.acknowledged_at};
        })};
      }
      if (action === 'desktop.support') {
        if (win.mock.supportError) throw new Error(win.mock.supportError);
        return null;
      }
      if (action === 'desktop.dashboard') {
        if (win.mock.dashboardError) throw new Error(win.mock.dashboardError);
        if (win.mock.dashboardHandoff) await (window as unknown as {openNativeDashboard:(url:string) => Promise<void>}).openNativeDashboard(win.mock.dashboardHandoff);
        return null;
      }
      if (action === 'desktop.update.status') {
        const update = structuredClone(win.mock.updateStatus === undefined ? win.mock.status.desktop_update ?? null : win.mock.updateStatus);
        if (win.mock.pendingUpdateStatus) await new Promise<void>(resolve => { win.completeUpdateStatus = resolve; });
        if (win.mock.updateStatusError) throw new Error(win.mock.updateStatusError);
        return update;
      }
      if (action === 'enrollment.preview.invalidate') {
        const generation = ++previewGeneration;
        if (win.mock.pendingAction === action) await new Promise<void>(resolve => { win.completeInvalidation = resolve; });
        if (win.mock.invalidationError) throw new Error(win.mock.invalidationError);
        return {generation};
      }
      if (action === 'enrollment.preview' && args.request.generation !== previewGeneration) throw new Error('The enrollment preview was cancelled.');
      const enrollmentPreview = structuredClone(win.mock.preview);
      if (action === 'desktop.capabilities') return win.mock.removalSupported === null ? {} : {removal_supported:win.mock.removalSupported ?? true,native_uninstaller:win.mock.nativeUninstaller ?? false};
      const simulationStatus = {...(win.mock.simulation || {enabled:false})};
      const usageByDays = structuredClone(win.mock.usageByDays);
      const usage = structuredClone(win.mock.usage);
      const usageError = win.mock.usageErrorsByDays?.[args.request.days ?? 30] ?? win.mock.usageError;
      const guardrails = {...structuredClone(win.mock.guardrails ?? {supported:false}),days:args.request.days,sensor_id:win.mock.status.sensor_id,server_url:win.mock.status.server_url};
      const posture = {sensor_id:win.mock.status.sensor_id,server_url:win.mock.status.server_url,scope:'a'.repeat(64),...structuredClone(win.mock.posture ?? {supported:false,reason:'server_unavailable'})};
      const creditSnapshot = {sensor_id:win.mock.status.sensor_id,server_url:win.mock.status.server_url,...win.mock.creditIdentity,plan:win.mock.creditPlan ?? (win.mock.status.connection_mode === 'free' ? 'free' : 'paid'),usage:structuredClone(win.mock.freeUsage ?? null)};
      if (win.mock.pendingAction === action || (action === 'usage.summary' && win.mock.pendingUsageDays === args.request.days)) await new Promise<void>(resolve => { win.completeRequest = resolve; });
      if (action === 'credits.summary') {
        if (win.mock.freeUsageError) throw new Error(win.mock.freeUsageError);
        return creditSnapshot;
      }
      if (action === 'guardrails.summary') {
        if (win.mock.guardrailsError) throw new Error(win.mock.guardrailsError);
        return guardrails;
      }
      if (action === 'posture.summary') {
        if (win.mock.postureError) throw new Error(win.mock.postureError);
        return posture;
      }
      if (action === 'posture.configure') {
        if (win.mock.postureConfigureError) throw new Error(win.mock.postureConfigureError);
        if (args.request.scope === (win.mock.posture?.scope ?? 'a'.repeat(64))) {
          const value = win.mock.posture!.assessments as Record<string,unknown>;
          value.enabled = args.request.automatic; value.state = args.request.automatic ? 'waiting' : 'disabled';
        }
        return {enabled:args.request.automatic,scope:args.request.scope};
      }
      if (['guardrails.denials','guardrails.check','guardrails.review'].includes(action)) {
        if (win.mock.denialError) throw new Error(win.mock.denialError);
        const envelope = {supported:true,sensor_id:win.mock.status.sensor_id,server_url:win.mock.status.server_url,scope:'a'.repeat(64)};
        if (action === 'guardrails.denials') return {...envelope,...structuredClone((args.request.decision === 'ask' ? win.mock.askPages : win.mock.denialPages)?.[args.request.cursor || ''] ?? {items:[],next_cursor:''})};
        if (action === 'guardrails.review') {
          if (win.mock.reviewError) throw new Error(win.mock.reviewError);
          const detail = win.mock.denialDetails![args.request.id!];
          if (args.request.request_id && win.mock.reviewReceipts?.[args.request.request_id]) return {...envelope,...structuredClone(win.mock.reviewReceipts[args.request.request_id])};
          if (args.request.review_version && args.request.expected_revision !== detail.review_revision) throw new Error('Review changed. Reopen the check.');
          Object.assign(detail, {label:args.request.label,note:args.request.note,reviewed_at:'2026-10-29T12:00:00Z',
            ...(args.request.review_version ? {review_version:1,review_revision:args.request.expected_revision! + 1} : {})});
          if (args.request.request_id) (win.mock.reviewReceipts ??= {})[args.request.request_id] = structuredClone(detail);
          if (win.mock.reviewLoseResponse) { win.mock.reviewLoseResponse = false; throw new Error('Could not confirm the saved label.'); }
        }
        return {...envelope,...structuredClone(win.mock.denialDetails?.[args.request.id!])};
      }
      if (action === 'guardrails.configuration') return {};
      if (action === 'guardrails.configure') {
        if (win.mock.guardrailSetupError) throw new Error(win.mock.guardrailSetupError);
        const hooks = win.mock.status.hooks as Record<string, Record<string, unknown>>;
        const state = args.request.profile
          ? (hooks.codex.profiles as Record<string, unknown>[]).find(row => row.config_path === args.request.profile)!
          : hooks[args.request.agent!];
        Object.assign(state, {installed:args.request.enabled,current:args.request.enabled,opted_out:!args.request.enabled});
        return structuredClone(win.mock.status);
      }
      if (action === 'desktop.update.check' || action === 'desktop.update.install') {
        if (win.mock.updateError) throw new Error(win.mock.updateError);
        return win.mock.updateStatus = (action === 'desktop.update.check' ? win.mock.updateCheck : win.mock.updateInstall) ?? {state:'idle',latest:''};
      }
      if (action === 'desktop.update.cancel') {
        win.mock.updateCheck = win.mock.updateInstall = win.mock.updateStatus = {state:'idle',latest:''};
        win.completeRequest?.();
        return null;
      }
      if (action === 'simulation.status') return simulationStatus;
      if (action === 'simulation.start' || action === 'simulation.stop') {
        if (win.mock.simulationError) throw new Error(win.mock.simulationError);
        win.mock.simulation = {...win.mock.simulation, state:action === 'simulation.start' ? 'running' : 'stopped'};
        return win.mock.simulation;
      }
      if (action === 'status') { if (win.mock.statusError) throw new Error(win.mock.statusError); return win.mock.status; }
      if (action === 'usage.summary') {
        if (usageError) throw usageError;
        const makeUsage = (days:number) => {
          const counts = {tokens:0,calls:0,priced_calls:0,cost_usd:null};
          const data = usageByDays?.[days] ?? usage ?? {summary:counts,by_model:[],by_reasoning_effort:[],baseline:{status:'insufficient_data'},pending_exports:0};
          const series = data.series as {date:string}[] | undefined;
          const points = series?.slice(-(days === 1 ? 25 : days));
          return {...data,days,granularity:days === 1 ? 'hour' : 'day',timezone:'local',until:win.mock.usageUntil ?? '2026-10-07T12:30:00Z',
            series:days === 1 ? Array.from({length:25},(_,i) => ({...counts,...points?.[i],date:points?.[i]?.date.includes('T') ? points[i].date : new Date(Date.UTC(2026,9,6,12+i)).toISOString()}))
              : points ?? Array.from({length:days},(_,i) => ({...counts,date:new Date(Date.UTC(2026,9,7-days+1+i)).toISOString().slice(0,10)}))};
        };
        const data = makeUsage(args.request.days ?? 30);
        return win.mock.legacyUsage ? data : {...data,periods:win.mock.usagePeriods ?? {1:makeUsage(1),30:makeUsage(30)}};
      }
      if (action === 'desktop.remove') {
        if (win.mock.removeError) throw new Error(win.mock.removeError);
        if (win.mock.nativeUninstaller) return {};
        win.mock.status = win.mock.afterRemove || {desktop_removal:{state:'complete'}};
        return win.mock.status;
      }
      if (action === 'desktop.resume') {
        if (win.mock.resumeError) throw new Error(win.mock.resumeError);
        win.mock.status = win.mock.afterResume || {};
        return {resumed:true};
      }
      if (action === 'desktop.trash') {
        if (win.mock.trashError) throw new Error(win.mock.trashError);
        return {};
      }
      if (action === 'enrollment.preview') { if (win.mock.previewError) throw new Error(win.mock.previewError); return enrollmentPreview; }
      if (action === 'local-runtime.check') return win.mock.localRuntime ?? {docker_ready:true,existing:false,managed:false,connected:false,server_url:'http://localhost:8080'};
      if (action === 'local-runtime.docker-setup') {
        if (win.mock.localDockerError) throw new Error(win.mock.localDockerError);
        return win.mock.localRuntime = {...win.mock.localRuntime!,docker_ready:true};
      }
      if (action === 'local-runtime.prepare' || action === 'local-runtime.start') {
        if (win.mock.localRuntimeError) throw new Error(win.mock.localRuntimeError);
        return {};
      }
      if (action === 'local-runtime.connect') {
        if (win.mock.localRuntimeError) throw new Error(win.mock.localRuntimeError);
        win.mock.status = win.mock.afterEnroll ?? win.mock.status;
        win.mock.localRuntime = {docker_ready:true,existing:true,managed:true,connected:true,server_url:'http://localhost:8080'};
        return {enrolled:true};
      }
      if (action === 'local-runtime.credentials') return {email:'admin@localhost',password:'sample-password-only'};
      if (action === 'free.connect') { if (win.mock.freeError) throw new Error(win.mock.freeError); if (win.mock.afterEnroll) win.mock.status = win.mock.afterEnroll; return {enrolled:true,connection_mode:'free'}; }
      if (action === 'api-key.connect') { if (win.mock.apiKeyError) throw new Error(win.mock.apiKeyError); if (win.mock.afterEnroll) win.mock.status = win.mock.afterEnroll; return {enrolled:true,connection_mode:'api_key'}; }
      if (action === 'enrollment.connect') { if (win.mock.enrollError) throw new Error(win.mock.enrollError); if (win.mock.afterEnroll) win.mock.status = win.mock.afterEnroll; return win.mock.enrollResult || {}; }
      if (action === 'setup') {
        if (win.mock.setupError) throw new Error(win.mock.setupError);
        if (win.mock.afterSetup) win.mock.status = win.mock.afterSetup;
        return {steps:[], ...win.mock.status, ...(win.mock.setup || {})};
      }
      return {};
    }};
  }, mock);
  await page.goto('/');
  // Enrollment-form cases take the organization path; onboarding cases keep both choices.
  if (process.env.OPENAIDR_DESKTOP_EDITION !== 'enterprise' && mock.status.enrolled === false && !mock.setupChoices && !mock.statusError && mock.pendingAction !== 'status') {
    await page.getByRole('button', {name:'Connect organization',exact:true}).click();
  }
}
async function returnToWindow(page: Page) {
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy', 'false');
}

async function openSensorStatus(page: Page, diagnostics = true) {
  if (await page.locator('#health-card').evaluate(node => node.classList.contains('status-popover')) && !await page.locator('#health-card').isVisible()) {
    await page.locator('#sensor-status').click();
  }
  const details = page.locator('#sensor-details');
  if (diagnostics && await details.isVisible() && !await details.evaluate(node => (node as HTMLDetailsElement).open)) await details.locator('summary').click();
}

async function expectRoundStatusSpinner(page: Page) {
  const size = await page.locator('.status-icon').evaluate(node => {
    const style = getComputedStyle(node, '::after');
    const borderBox = style.boxSizing === 'border-box';
    return {
      width:parseFloat(style.width) + (borderBox ? 0 : parseFloat(style.borderLeftWidth) + parseFloat(style.borderRightWidth)),
      height:parseFloat(style.height) + (borderBox ? 0 : parseFloat(style.borderTopWidth) + parseFloat(style.borderBottomWidth)),
      slotWidth:node.getBoundingClientRect().width,
      slotHeight:node.getBoundingClientRect().height,
    };
  });
  expect(size.width).toBeGreaterThan(0);
  expect(size.width).toBe(size.height);
  expect(size.width).toBeLessThanOrEqual(size.slotWidth);
  expect(size.height).toBeLessThanOrEqual(size.slotHeight);
}

const requests = (page: Page) => page.evaluate(() => (window as unknown as {requests:Requests}).requests);

const usageTotals = (tokens:number) => ({summary:{tokens,calls:1,priced_calls:1,cost_usd:1},by_model:[],by_reasoning_effort:[],pending_exports:0});

function populatedUsage() {
  const counts = {tokens:1264500,calls:284,priced_calls:284,cost_usd:42.18};
  const series = Array.from({length:30}, (_, i) => ({date:new Date(Date.UTC(2026, 8, 8 + i)).toISOString().slice(0, 10),...(i === 29 ? counts : {tokens:0,calls:0,priced_calls:0,cost_usd:0})}));
  return {summary:counts,by_model:[{name:'gpt-6.1-sol',...counts}],by_reasoning_effort:[{name:'high',...counts}],series,pending_exports:0};
}

function guardrailStatus() {
  const common = {available:true,installed:true,current:true,trusted:true,config_exists:true,control_events:['UserPromptSubmit','PreToolUse','PostToolUse']};
  const profile = '/Users/example/Work profiles/Organization coding tools/';
  return {...converged,telemetry:{...converged.telemetry,codex_available:true,codex_installed:true,codex_current:true},hooks:{
    codex:{...common,config_path:profile + 'codex/hooks.json'},
    claude:{...common,config_path:profile + 'claude/settings.json'},
    hermes:{...common,current:false,approval_pending:true,control_events:['PreToolUse'],config_path:profile + 'hermes/config.yaml'},
    copilot:{...common,installed:false,current:false,opted_out:true,control_events:['PreToolUse'],config_path:profile + 'copilot/hooks/openaidr.json'},
    cursor:{...common,installed:false,current:false,disabled:true,control_events:['UserPromptSubmit','PreToolUse'],config_path:profile + 'cursor/hooks.json'},
    antigravity:{available:false,installed:false,config_exists:false,control_events:['PreToolUse'],config_path:profile + 'gemini/config/hooks.json'},
    opencode:{available:false,installed:false,config_exists:false,control_events:['PreToolUse'],config_path:profile + 'opencode/plugins/openaidr.js'},
    workbuddy:{...common,control_events:['PreToolUse'],config_path:profile + 'workbuddy-ai/settings.json'},
  }};
}

function guardrailActivity() {
  const counts = {completed:1240,allow:1230,warn:0,ask:3,deny:7,unavailable:3,pending:0};
  const empty = {completed:0,allow:0,warn:0,ask:0,deny:0,unavailable:0,pending:0};
  return {supported:true,days:1,since:'2026-10-27T07:00:00Z',until:'2026-10-28T07:00:00Z',mode:'shadow',summary:{...counts},
    by_mode:{shadow:{...counts},enforce:{...empty}},by_agent:[{product:'claude-code',last_check_at:'2026-10-28T06:58:00Z'}],
    recent:Array.from({length:20}, (_, i) => ({id:String(i),created_at:'2026-10-28T06:58:00Z',product:'claude-code',hook_event:'PreToolUse',mode:'shadow',status:'evaluated',evaluated_decision:i ? 'allow' : 'deny',returned_decision:'allow'}))};
}

async function expectTextContrast(locator:Locator) {
  await expect.poll(() => locator.evaluate(node => {
    const luminance = (color:string) => {
      const [r,g,b] = color.match(/[\d.]+/g)!.slice(0,3).map(value => {
        const channel = Number(value) / 255;
        return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const background = luminance(getComputedStyle(node).backgroundColor);
    return Math.min(...[node,...node.children].map(child => {
      const foreground = luminance(getComputedStyle(child).color);
      return (Math.max(foreground,background) + 0.05) / (Math.min(foreground,background) + 0.05);
    }));
  })).toBeGreaterThanOrEqual(4.5);
}

function denialFixtures(versioned = false) {
  const activity = guardrailActivity();
  activity.summary.deny = activity.by_mode.shadow.deny = 21;
  activity.summary.allow = activity.by_mode.shadow.allow = 1216;
  const checks = Array.from({length:21}, (_, i) => ({id:`00000000-0000-4000-8000-${String(i).padStart(12,'0')}`,
    created_at:'2026-10-28T06:58:00Z',product:'claude-code',hook_event:'PreToolUse',mode:'shadow',returned_decision:'allow',
    label:null,note:null,reviewed_at:null,reason:'Matched Guardrail risk threshold',
    actions:[{kind:'command',command:{text:'rm -rf /tmp/project-build-output; <script>alert(1)</script> ' + 'long/path/'.repeat(50)}}]}));
  if (versioned) for (const check of checks) Object.assign(check, {review_version:1,review_revision:0,evidence_sha256:'b'.repeat(64),evidence:{
    assessment_input:{state:{latest_prompt:{kind:'prompt',text:'Only inspect README <script>alert(2)</script>'},
      prior_events:Array.from({length:12}, (_, index) => ({kind:'command',command:{text:`git show ${index} -- ` + 'long/path/'.repeat(40)}}))}},
    decision_basis:{mode:'shadow',policy:{rules:[{name:'Protect production',action:'deny',reason:'Approval required'}]},
      company_policy:{prompt:'Ask before production changes.'},risk_settings:{enabled:true,ask_threshold:40,block_threshold:80}},
    decision:{evaluated_decision:'deny',returned_decision:'allow',reason:'Matched Guardrail risk threshold'},
    assessment:{status:'scored',score:92,category:'destructive_command',reason:'Removes project output.'},
    gaps:['bounded_context','content_redacted','service_request_mapping_unavailable'],
  }});
  return {guardrails:activity,denialPages:{'':{items:checks.slice(0,20),next_cursor:'older',...(versioned ? {review_version:1} : {})},older:{items:checks.slice(20),next_cursor:'',...(versioned ? {review_version:1} : {})}},
    denialDetails:Object.fromEntries(checks.map(check => [check.id,check]))};
}

for (const [connectionMode,mode,maxWindowHeight] of [
  ['free','shadow',720], ['api_key','shadow',320], ['organization','shadow',720], ['organization','enforce',320],
] as const) test(`Ask checks can be inspected on ${connectionMode} in ${mode} at ${maxWindowHeight}px`, async ({page}, testInfo) => {
  const fixture = denialFixtures(true);
  const command = 'Read deployed configuration <script>literal</script> ' + 'long/path/'.repeat(50);
  for (const detail of Object.values(fixture.denialDetails)) Object.assign(detail, {mode,returned_decision:mode === 'shadow' ? 'allow' : 'ask',
    reason:'Risk score reached the ask threshold.',actions:[{kind:'command',command:{text:command,cwd:'/project'}}],
    evidence:{assessment_input:null,decision_basis:{risk_settings:{enabled:true,ask_threshold:60,block_threshold:80}},
      assessment:{status:'scored',score:65,reason:'This action needs approval.'},
      decision:{evaluated_decision:'ask',returned_decision:mode === 'shadow' ? 'allow' : 'ask'},gaps:['bounded_context']}});
  fixture.guardrails.summary.ask = fixture.guardrails.by_mode.shadow.ask = 21;
  fixture.guardrails.summary.allow = fixture.guardrails.by_mode.shadow.allow = 1198;
  if (mode === 'enforce') {
    fixture.guardrails.mode = mode;
    [fixture.guardrails.by_mode.shadow,fixture.guardrails.by_mode.enforce] = [fixture.guardrails.by_mode.enforce,fixture.guardrails.by_mode.shadow];
  }
  await page.emulateMedia({colorScheme:maxWindowHeight === 720 ? 'light' : 'dark'});
  await boot(page, {status:{...guardrailStatus(),connection_mode:connectionMode},...fixture,askPages:fixture.denialPages,maxWindowHeight});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  const metric = page.getByRole('button', {name:mode === 'shadow' ? 'Would ask 21' : 'Ask 21',exact:true});
  await expect(metric).toBeEnabled();
  await page.screenshot({path:testInfo.outputPath('ask-check-summary.png'),animations:'disabled'});
  await metric.focus(); await page.keyboard.press('Enter');
  await expect(metric).toHaveAttribute('aria-expanded','true');
  await expect(page.getByRole('region', {name:'Ask checks',exact:true})).toBeVisible();
  await expect(page.locator('.guardrail-denial-row')).toHaveCount(20);
  expect((await requests(page)).filter(row => row.action === 'guardrails.denials').every(row => row.decision === 'ask' && row.until === fixture.guardrails.until)).toBe(true);
  await page.getByRole('button', {name:'Older checks',exact:true}).scrollIntoViewIfNeeded();
  expect(await page.locator('#app').evaluate(node => node.scrollTop)).toBeGreaterThan(0);
  await page.getByRole('button', {name:'Older checks',exact:true}).click();
  await expect(page.locator('.guardrail-denial-row')).toHaveCount(1);
  await page.locator('.guardrail-denial-row').click();
  await expect(page.locator('#denials-title')).toHaveText(`Claude Code · ${mode === 'shadow' ? 'Would ask' : 'Ask decision'}`);
  await expect(page.locator('#denials-title')).toBeFocused();
  await expect(page.locator('#denials-explanation-heading')).toHaveText('Why Guardrail recommends asking');
  await expect(page.locator('#denials-threshold-label')).toHaveText('Configured ask threshold');
  await expect(page.locator('#denials-threshold')).toHaveText('60');
  await expect(page.locator('#denials-score')).toHaveText('65 / 100');
  await expect(page.locator('#denials-assessment-reason')).toHaveText('This action needs approval.');
  await expect(page.locator('#denials-report')).toBeHidden();
  await expect(page.locator('#denials-sharing')).toBeHidden();
  await expect(page.locator('#denials-preview')).toHaveText(command);
  expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  expect(await page.locator('#denials-detail').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  if (maxWindowHeight === 720) await expect(page.locator('.denial-explanation')).toBeInViewport({ratio:1});
  await page.locator('#denials-technical > summary').scrollIntoViewIfNeeded();
  await expect(page.locator('#denials-technical > summary')).toBeInViewport({ratio:1});
  await page.screenshot({path:testInfo.outputPath('ask-check-detail.png'),animations:'disabled'});
  await page.locator('#denials-technical > summary').click();
  await expect(page.locator('#denials-meta')).toContainText(`Returned: ${mode === 'shadow' ? 'allow' : 'ask'} · Enforcement unconfirmed`);
  await page.locator('#denials-request > summary').click();
  await expect(page.locator('#denials-evidence')).toContainText(command);
  await expect(page.locator('#denials-evidence script')).toHaveCount(0);
  await page.getByRole('button', {name:'Close',exact:true}).click();
  await expect(metric).toBeFocused();
  await expect(metric).toHaveAttribute('aria-expanded','false');
  const id = Object.keys(fixture.denialDetails)[0];
  await page.evaluate(id => {
    const mock = (window as unknown as {mock:Mock}).mock;
    Object.assign(mock.denialDetails![id], {actions:[],evidence:{assessment_input:null,assessment:null,decision_basis:{},decision:{},gaps:['assessment_not_retained']}});
  }, id);
  await metric.click(); await page.locator('.guardrail-denial-row').first().click();
  await expect(page.locator('#denials-preview')).toHaveText('Request content was not retained.');
  await expect(page.locator('#denials-assessment-reason')).toHaveText('No scored assessment explanation was retained.');
  await expect(page.locator('#denials-score-row')).toBeHidden();
  expect((await requests(page)).filter(row => row.action === 'guardrails.review')).toHaveLength(0);
});

test('Ask inspection handles empty history and discards a closed pending read', async ({page}) => {
  await boot(page, {status:guardrailStatus(),guardrails:guardrailActivity()});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await page.locator('#guardrails-ask').click();
  await expect(page.locator('#denials-status')).toHaveText('No ask checks in this period.');
  await page.getByRole('button', {name:'Close',exact:true}).click();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'guardrails.denials'; });
  await page.locator('#guardrails-ask').click();
  await expect(page.locator('#denials-status')).toHaveText('Loading ask checks…');
  await page.getByRole('group', {name:'Guardrail period',exact:true}).getByRole('button',{name:'30 days'}).click();
  await page.evaluate(() => { const win = window as unknown as {mock:Mock;completeRequest:() => void}; win.mock.pendingAction = ''; win.completeRequest(); });
  await expect(page.locator('#guardrails-review')).toBeHidden();
  await expect(page.locator('.guardrail-denial-row')).toHaveCount(0);
});

for (const maxWindowHeight of [720,320]) {
  test(`Denied request formatting preserves evidence in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme:maxWindowHeight === 720 ? 'light' : 'dark'});
    const fixture = denialFixtures(true), id = Object.keys(fixture.denialDetails)[0];
    const command = 'curl -s https://example.invalid/topstories.json | python3 -c "import json, sys; print(json.load(sys.stdin)[:30])"\nfor id in $(cat ids.txt); do\n    curl -s https://example.invalid/items/$id.json -o items/$id.json\ndone';
    const directory = '/Users/example/Work projects/site';
    const action = {kind:'command',command:{text:command,cwd:directory},tool:{name:'Bash',input:{command,description:'Fetch current top 30 stories'}},extra:{captured:'Preserve this metadata'}};
    const reason = 'Download the script, review it, then run it.';
    const matchedRule = {name:'Block piping downloads into a shell',action:'deny',reason};
    const evidenceContext = (fixture.denialDetails[id] as unknown as {evidence:Record<string,unknown>}).evidence;
    Object.assign(fixture.denialDetails[id], {actions:[action],reason,evidence:{...evidenceContext,
      decision_basis:{...evidenceContext.decision_basis as object,matched_rule:matchedRule},
      decision:{...evidenceContext.decision as object,reason},assessment:{status:'scored',score:2.2,reason:'Parses public JSON data.'}}});
    await boot(page, {status:guardrailStatus(),...fixture,maxWindowHeight});
    await expect.poll(() => page.evaluate(() => [...document.images].every(image => image.complete && image.naturalWidth > 0))).toBe(true);
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    await page.locator('#guardrails-deny').click();
    await page.locator('.guardrail-denial-row').first().click();
    const evidence = page.locator('#denials-evidence'), cards = evidence.locator('.denial-request');
    const preview = page.locator('#denials-preview');
    expect(await preview.textContent()).toBe(command);
    expect((await preview.boundingBox())!.height).toBeLessThanOrEqual(34);
    await expect(evidence).toBeHidden();
    await expect(page.locator('#denials-context')).toBeHidden();
    await expect(page.getByLabel('Note (optional)', {exact:true})).toBeHidden();
    await expect(page.locator('#denials-meta')).toBeHidden();
    await expect(page.locator('#denials-sharing')).toBeHidden();
    await expect(page.locator('#guardrails-data')).toBeHidden();
    await expect(page.getByRole('region', {name:'Agent setup',exact:true})).toBeHidden();
    await expect(page.locator('#denials-title')).toHaveText('Claude Code · Would deny');
    await expect(page.getByRole('group', {name:'Decision reason',exact:true})).toBeVisible();
    await expect(page.locator('#denials-rule')).toHaveText(matchedRule.name);
    await expect(page.locator('#denials-rule')).toBeVisible();
    expect(await page.locator('#denials-reason').textContent()).toBe(reason);
    await expect(page.locator('#denials-meta')).toContainText('Returned: allow · Enforcement unconfirmed');
    if (maxWindowHeight === 720) {
      await page.locator('#app').evaluate(node => { node.scrollTop = 0; });
      await expect(page.locator('#denials-report')).toBeInViewport({ratio:1});
      await expect(page.locator('#denials-technical > summary')).toBeInViewport({ratio:1});
      expect(await page.locator('#app').evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
      await page.screenshot({path:testInfo.outputPath('compact-denial-review.png'),animations:'disabled'});
    } else {
      await page.locator('#denials-report').scrollIntoViewIfNeeded();
      await expect(page.locator('#denials-report')).toBeInViewport({ratio:1});
      await page.screenshot({path:testInfo.outputPath('compact-denial-review-small.png'),animations:'disabled'});
    }
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.getByText('Details', {exact:true}).click();
    await expect(page.locator('#denials-meta')).toBeVisible();
    await expect(page.locator('#denials-sharing')).toBeVisible();
    await page.locator('#denials-request > summary').click();
    await expect(page.locator('#denials-prompt-text')).toHaveText('Only inspect README <script>alert(2)</script>');
    await expect(page.locator('#denials-prompt script')).toHaveCount(0);
    await expect(cards).toHaveCount(1);
    await expect(cards.locator('dt')).toHaveText(['Command','Working directory','Tool','Input']);
    expect(await cards.locator('pre').first().textContent()).toBe(command);
    expect(await cards.locator('pre').nth(1).textContent()).toBe(directory);
    expect(await cards.locator('pre').last().textContent()).toBe(JSON.stringify(action.tool.input, null, 2));
    await expect(page.locator('#denials-raw')).toBeHidden();
    if (maxWindowHeight === 720) await page.locator('#denials-detail').screenshot({path:testInfo.outputPath('formatted-request.png'),animations:'disabled'});
    else await page.screenshot({path:testInfo.outputPath('formatted-request-small.png'),animations:'disabled'});

    const prompt = 'Inspect this exact text:\n<script>alert(1)</script>\n  Keep indentation.';
    const actions = [action,
      {kind:'prompt',text:prompt},
      {kind:'tool.call',tool:{name:'Read',input:{path:'/tmp/<img src=x onerror=alert(1)>.txt',offset:0}}},
      {kind:'tool.result',tool:{name:'Read',output:'First line\n  Second line',is_error:true}},
      {kind:'file.write',file:{path:'/tmp/report.txt',op:'write'}},
      {kind:'network',network:{url:'https://example.invalid/a?b=1&c=2',host:'example.invalid'}},
      {kind:'future.action',unknown:{content:'unchanged <script>alert(2)</script>'}},
      {kind:'command',command:['unexpected shape'],text:null},
      {kind:'prompt',text:'truncated text',truncated:true},
      null,
    ];
    await page.evaluate(({id,actions}) => { (window as unknown as {mock:Mock}).mock.denialDetails![id].actions = actions; }, {id,actions});
    await page.getByRole('button', {name:'Back to checks'}).click();
    await expect(page.locator('#guardrails-data')).toBeVisible();
    await expect(page.getByRole('region', {name:'Agent setup',exact:true})).toBeVisible();
    await page.locator('.guardrail-denial-row').first().click();
    await expect(evidence).toBeHidden();
    await page.getByText('Details', {exact:true}).click();
    await page.getByText(`Full request (${actions.length} actions)`, {exact:true}).click();
    await expect(cards).toHaveCount(actions.length);
    expect(await cards.nth(1).locator('pre').textContent()).toBe(prompt);
    expect(await cards.nth(2).locator('pre').last().textContent()).toBe(JSON.stringify(actions[2]!.tool!.input, null, 2));
    expect(await cards.nth(3).locator('pre').last().textContent()).toBe('First line\n  Second line');
    await expect(cards.nth(3)).toContainText('Error');
    await expect(cards.nth(4)).toContainText('/tmp/report.txt');
    await expect(cards.nth(5)).toContainText('https://example.invalid/a?b=1&c=2');
    expect(await cards.nth(6).locator('pre').textContent()).toBe(JSON.stringify(actions[6], null, 2));
    expect(await cards.nth(7).locator('pre').textContent()).toBe(JSON.stringify(actions[7], null, 2));
    await expect(cards.nth(8)).toContainText('The captured content was shortened.');
    await expect(evidence.locator('script,img,a')).toHaveCount(0);
    await cards.last().scrollIntoViewIfNeeded();
    await expect(cards.last()).toBeInViewport({ratio:1});
    expect(await page.locator('#app').evaluate(node => node.scrollTop > 0 && node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await evidence.locator('pre').evaluateAll(nodes => nodes.every(node => node.scrollWidth <= node.clientWidth))).toBe(true);
    await page.getByText('Raw request', {exact:true}).click();
    expect(JSON.parse((await page.locator('#denials-raw').textContent())!)).toEqual(actions);
    await expect(page.locator('#denials-raw script')).toHaveCount(0);

    await page.evaluate(id => { (window as unknown as {mock:Mock}).mock.denialDetails![id].actions = []; }, id);
    await page.getByRole('button', {name:'Back to checks'}).click();
    await page.locator('.guardrail-denial-row').first().click();
    await expect(preview).toHaveText('Request content was not captured.');
    await page.getByText('Details', {exact:true}).click();
    await page.locator('#denials-request > summary').click();
    await expect(evidence).toHaveText('Request content was not captured.');
    await expect(cards).toHaveCount(0);
    await expect(page.locator('#denials-raw')).toHaveText('[]');
    await page.getByRole('button', {name:'Close',exact:true}).click();
    await expect(page.locator('#guardrails-data')).toBeVisible();
    await expect(page.getByRole('region', {name:'Agent setup',exact:true})).toBeVisible();
    await expect(page.locator('#guardrails-deny')).toBeFocused();
  });
  for (const colorScheme of ['light','dark'] as const) test(`Denied check cards remain readable in ${colorScheme} at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme});
    await boot(page, {status:guardrailStatus(),...denialFixtures(),maxWindowHeight});
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    await page.locator('#guardrails-deny').click();
    const rows = page.locator('.guardrail-denial-row'), row = rows.first();
    await expect(rows).toHaveCount(20);
    await row.scrollIntoViewIfNeeded();
    const expectReadable = () => expectTextContrast(row);
    await page.mouse.move(0,0);
    await expectReadable();
    const idleBackground = await row.evaluate(node => getComputedStyle(node).backgroundColor);
    await page.screenshot({path:testInfo.outputPath('denied-checks.png'),animations:'disabled'});
    await row.hover();
    await expect.poll(() => row.evaluate(node => getComputedStyle(node).backgroundColor)).not.toBe(idleBackground);
    await page.screenshot({path:testInfo.outputPath('denied-checks-hover.png'),animations:'disabled'});
    await expectReadable();
    await page.mouse.down();
    await expectReadable();
    await page.mouse.move(0,0);
    await page.mouse.up();
    await page.keyboard.press('Tab');
    await row.focus();
    await expect(row).toBeFocused();
    expect(await row.evaluate(node => node.matches(':focus-visible'))).toBe(true);
    await expect(row).toHaveCSS('outline-style','solid');
    await expectReadable();
    await page.screenshot({path:testInfo.outputPath('denied-checks-focus.png'),animations:'disabled'});
    await expect(row).toBeInViewport({ratio:1});
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await rows.evaluateAll(nodes => nodes.every(node => node.scrollWidth <= node.clientWidth))).toBe(true);
    await page.keyboard.press('Enter');
    await expect(page.locator('#denials-title')).toBeFocused();
    await page.getByRole('button', {name:'Back to checks'}).click();
    await page.getByRole('button', {name:'Older checks',exact:true}).scrollIntoViewIfNeeded();
    expect(await page.locator('#app').evaluate(node => node.scrollTop)).toBeGreaterThan(0);
    await page.getByRole('button', {name:'Older checks',exact:true}).click();
    await expect(rows).toHaveCount(1);
    await row.scrollIntoViewIfNeeded();
    await expect(row).toBeInViewport({ratio:1});
  });
  for (const versioned of [false,true]) test(`Denied check reports and notes persist ${versioned ? 'with context' : 'on older servers'} in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme:maxWindowHeight === 720 ? 'light' : 'dark'});
    await boot(page, {status:guardrailStatus(),...denialFixtures(versioned),maxWindowHeight});
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    await page.getByRole('button', {name:'Would deny 21',exact:true}).click();
    await expect(page.locator('.guardrail-denial-row')).toHaveCount(20);
    const listCall = (await requests(page)).find(row => row.action === 'guardrails.denials');
    expect(listCall).toEqual({action:'guardrails.denials',days:1,until:guardrailActivity().until,cursor:''});
    await page.getByRole('button', {name:'Older checks',exact:true}).click();
    await expect(page.locator('.guardrail-denial-row')).toHaveCount(1);
    await page.locator('.guardrail-denial-row').click();
    await expect(page.locator('#denials-reason')).toHaveText('Matched Guardrail risk threshold');
    await expect(page.locator('#denials-assessment-reason')).toHaveText(versioned ? 'Removes project output.' : 'No scored assessment explanation was retained.');
    await expect(page.locator('#denials-rule')).toBeHidden();
    await expect(page.getByRole('group', {name:'Decision reason',exact:true})).toBeVisible();
    await expect(page.locator('#denials-evidence')).toBeHidden();
    await expect(page.locator('#denials-preview')).toBeVisible();
    await expect(page.locator('#denials-evidence')).toContainText('<script>alert(1)</script>');
    await expect(page.locator('#denials-evidence script')).toHaveCount(0);
    const report = page.getByRole('button', {name:'This is incorrect',exact:true});
    await expect(page.locator('#denials-detail').getByRole('button')).toHaveCount(1);
    await expect(page.locator('#denials-note-details')).toBeHidden();
    expect((await requests(page)).filter(row => row.action === 'guardrails.review')).toHaveLength(0);
    await report.scrollIntoViewIfNeeded();
    await expect(report).toBeInViewport({ratio:1});
    await expectTextContrast(report);
    await report.hover();
    await expectTextContrast(report);
    if (maxWindowHeight === 720) await expect(page.locator('#denials-preview')).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('denial-inline-review.png'),animations:'disabled'});
    await page.getByText('Details', {exact:true}).click();
    if (versioned) {
      await expect(page.locator('#denials-context')).toBeVisible();
      await page.getByText('Prior request context', {exact:true}).click();
      await expect(page.locator('#denials-prior')).toContainText('Only inspect README <script>');
      await expect(page.locator('#denials-prior script')).toHaveCount(0);
      await page.getByText('Policy and decision', {exact:true}).click();
      await expect(page.locator('#denials-policy')).toContainText('Protect production');
      await expect(page.locator('#denials-policy')).toContainText('Matched Guardrail risk threshold');
      await page.getByText('Evidence gaps', {exact:true}).click();
      await expect(page.locator('#denials-gaps')).toContainText('Some captured content was redacted.');
    } else {
      await expect(page.locator('#denials-legacy')).toBeVisible();
      expect((await requests(page)).filter(row => row.action.startsWith('guardrails.')).every(row => row.review_version === undefined)).toBe(true);
    }
    await page.getByText('Details', {exact:true}).click();
    await report.focus();
    await page.keyboard.press('Enter');
    const reported = page.getByRole('button', {name:'Reported',exact:true});
    await expect(reported).toBeDisabled();
    await expectTextContrast(reported);
    await expect(page.locator('#denials-feedback')).toHaveText('Report sent.');
    await expect(page.getByText('Add a note', {exact:true})).toBeFocused();
    let saves = (await requests(page)).filter(row => row.action === 'guardrails.review');
    expect(saves).toHaveLength(1);
    expect(saves[0]).toMatchObject({id:'00000000-0000-4000-8000-000000000020',scope:'a'.repeat(64),label:'false_positive',note:''});
    if (versioned) expect(saves[0]).toMatchObject({review_version:1,evidence_sha256:'b'.repeat(64),expected_revision:0,request_id:expect.any(String)});
    await page.screenshot({path:testInfo.outputPath('denial-reported.png'),animations:'disabled'});
    await page.getByText('Add a note', {exact:true}).click();
    await page.getByLabel('Note (optional)', {exact:true}).fill('Expected cleanup of generated output.');
    await page.getByRole('button', {name:'Save note',exact:true}).click();
    await expect(page.locator('#denials-feedback')).toHaveText('Note saved.');
    await expect(page.getByLabel('Note (optional)', {exact:true})).toBeHidden();
    saves = (await requests(page)).filter(row => row.action === 'guardrails.review');
    expect(saves).toHaveLength(2);
    expect(saves[1]).toMatchObject({label:'false_positive',note:'Expected cleanup of generated output.'});
    if (versioned) expect(saves[1]).toMatchObject({expected_revision:1,request_id:expect.any(String)});
    await page.getByRole('button', {name:'Back to checks'}).click();
    await expect(page.locator('.guardrail-denial-row')).toContainText('Reported');
    await page.locator('.guardrail-denial-row').click();
    await expect(reported).toBeDisabled();
    await expect(page.getByLabel('Note (optional)', {exact:true})).toBeHidden();
    await page.getByText('Edit note', {exact:true}).click();
    await expect(page.getByLabel('Note (optional)', {exact:true})).toHaveValue('Expected cleanup of generated output.');
    await page.getByLabel('Note (optional)', {exact:true}).fill('Discard this edit');
    await page.getByRole('button', {name:'Cancel',exact:true}).click();
    expect((await requests(page)).filter(row => row.action === 'guardrails.review')).toHaveLength(2);
    await page.getByText('Edit note', {exact:true}).click();
    await expect(page.getByLabel('Note (optional)', {exact:true})).toHaveValue('Expected cleanup of generated output.');
    await page.getByLabel('Note (optional)', {exact:true}).fill('');
    await page.getByRole('button', {name:'Save note',exact:true}).focus();
    await expect(page.getByRole('button', {name:'Save note',exact:true})).toBeInViewport({ratio:1});
    if (maxWindowHeight === 320) expect(await page.locator('#app').evaluate(node => node.scrollTop)).toBeGreaterThan(0);
    await page.keyboard.press('Enter');
    await expect(page.locator('#denials-feedback')).toHaveText('Note saved.');
    await expect(page.getByText('Add a note', {exact:true})).toBeFocused();
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.locator('#denials-detail').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await expect(page.getByText('Add a note', {exact:true})).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('denial-review.png'),animations:'disabled'});
    await page.getByRole('group', {name:'Guardrail period',exact:true}).getByRole('button',{name:'30 days'}).click();
    await expect(page.locator('#guardrails-review')).toBeHidden();
    await expect(page.locator('#guardrails-data')).toBeVisible();
    await expect(page.getByRole('region', {name:'Agent setup',exact:true})).toBeVisible();
    await page.locator('#guardrails-deny').click();
    await expect.poll(async () => (await requests(page)).filter(row => row.action === 'guardrails.denials').at(-1)?.days).toBe(30);
  });
}

for (const maxWindowHeight of [720,160]) for (const colorScheme of ['light','dark'] as const) {
  test(`Denial explanation shows recorded rationale and evidence in ${colorScheme} at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme});
    const fixture = denialFixtures(true), detail = Object.values(fixture.denialDetails)[0];
    const assessmentReason = 'This command recursively deletes project output. The user only asked to inspect the README, and the captured context contains no approval for deletion.';
    const mode = colorScheme === 'light' ? 'shadow' : 'enforce';
    Object.assign(detail, {mode,returned_decision:mode === 'shadow' ? 'allow' : 'deny',
      actions:[{kind:'command',command:{text:'rm -rf /tmp/project-build-output'}}],
      evidence:{...detail.evidence,assessment:{status:'scored',score:92,reason:assessmentReason},
        assessment_input:{state:{latest_prompt:{kind:'prompt',text:'Only inspect the README.'},prior_events:[]}}}});
    await boot(page, {status:guardrailStatus(),...fixture,maxWindowHeight});
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    await page.locator('#guardrails-deny').click();
    await page.locator('.guardrail-denial-row').first().click();
    await expect(page.locator('#denials-title')).toHaveText(`Claude Code · ${mode === 'shadow' ? 'Would deny' : 'Deny decision'}`);
    await expect.poll(() => page.locator('#denials-icon img').evaluate((image:HTMLImageElement) => image.complete && image.naturalWidth > 0)).toBe(true);
    await expect(page.locator('#denials-boundary')).toContainText(`Mode: ${mode === 'shadow' ? 'Monitoring (Shadow)' : 'Enforce'}`);
    await expect(page.locator('#denials-meta')).toContainText(`Returned: ${detail.returned_decision} · Enforcement unconfirmed`);
    await expect(page.locator('#denials-reason')).toHaveText('Matched Guardrail risk threshold');
    await expect(page.locator('#denials-assessment-reason')).toHaveText(assessmentReason);
    await expect(page.locator('#denials-score')).toHaveText('92 / 100');
    await expect(page.locator('#denials-threshold')).toHaveText('80');
    await expect(page.locator('#denials-prompt')).toBeHidden();
    await expect(page.locator('#denials-preview')).toBeVisible();
    await expect(page.locator('#denials-evidence')).toContainText('rm -rf /tmp/project-build-output');
    await expect(page.locator('#denials-assessment')).toBeHidden();
    await expect(page.locator('#guardrails-data')).toBeHidden();
    await expect(page.getByRole('region', {name:'Agent setup',exact:true})).toBeHidden();
    if (maxWindowHeight === 720) {
      await expectFitsWindow(page);
      await expect(page.locator('.denial-explanation')).toBeInViewport({ratio:1});
      await expect(page.locator('#denials-report')).toBeInViewport({ratio:1});
      await page.screenshot({path:testInfo.outputPath(`denial-explanation-${colorScheme}.png`)});
    }
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.getByText('Details', {exact:true}).click();
    await page.locator('#denials-request > summary').click();
    await expect(page.locator('#denials-prompt-text')).toBeVisible();
    await expect(page.locator('#denials-prompt-text')).toHaveText('Only inspect the README.');
    await page.getByText('Details', {exact:true}).click();
    await page.getByRole('button', {name:'This is incorrect',exact:true}).click();
    await expect(page.locator('#denials-feedback')).toHaveText('Report sent.');
    await page.getByText('Add a note', {exact:true}).click();
    for (const control of [page.locator('#denials-note'), page.locator('#denials-save-note'), page.locator('#denials-cancel-note')]) {
      await control.focus();
      await expect(control).toBeInViewport({ratio:1});
    }
    if (maxWindowHeight === 160) expect(await app.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
    await page.getByRole('button', {name:'Back to checks'}).click();
    await expect(page.locator('#guardrails-data')).toBeVisible();
    await page.getByRole('button', {name:'Close',exact:true}).click();
    await expect(page.locator('#guardrails-deny')).toBeFocused();
  });
}

test('Denial explanation preserves policy reasons and handles absent or malformed assessment fields', async ({page}) => {
  const fixture = denialFixtures(true), id = Object.keys(fixture.denialDetails)[0];
  fixture.denialDetails[id].product = 'unknown-agent';
  await boot(page, {status:guardrailStatus(),...fixture});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await page.locator('#guardrails-deny').click();
  const cases = [
    {assessment:{status:'scored',score:0,reason:'Low risk. <script>alert(1)</script>\nKeep this line.'},settings:{enabled:true,block_threshold:80},reason:'Policy requires approval: Jev file name',score:'0 / 100',threshold:'80'},
    {assessment:{status:'unavailable',score:92,reason:'timeout'},settings:{enabled:true,block_threshold:0},reason:'Approval required',score:null,threshold:'0'},
    {assessment:null,settings:null,reason:'',score:null,threshold:null},
    {assessment:{status:'scored',score:'92',reason:{text:'not a string'}},settings:{enabled:true,block_threshold:'80'},reason:'Policy denial',score:null,threshold:null},
    {assessment:{status:'scored',score:101,reason:'Out of range'},settings:{enabled:true,block_threshold:-1},reason:'Policy denial',score:null,threshold:null},
    {assessment:{status:'scored',score:92,reason:'Assessment retained but risk policy disabled'},settings:{enabled:false,block_threshold:80},reason:'Policy denial',score:'92 / 100',threshold:null},
  ];
  for (const entry of cases) {
    await page.evaluate(({id,entry}) => {
      const detail = (window as unknown as {mock:Mock}).mock.denialDetails![id];
      Object.assign(detail, {reason:entry.reason,evidence:{assessment:entry.assessment,assessment_input:null,
        decision_basis:{risk_settings:entry.settings},decision:{},gaps:[]}});
    }, {id,entry});
    await page.locator('.guardrail-denial-row').first().click();
    await expect(page.locator('#denials-icon')).toBeHidden();
    await expect(page.locator('#denials-icon img')).toHaveCount(0);
    await expect(page.locator('#denials-reason')).toHaveText(entry.reason || 'No decision reason was recorded.');
    const expected = entry.assessment?.status === 'scored' && typeof entry.assessment.reason === 'string'
      ? entry.assessment.reason : 'No scored assessment explanation was retained.';
    expect(await page.locator('#denials-assessment-reason').textContent()).toBe(expected);
    await expect(page.locator('.denial-explanation script')).toHaveCount(0);
    await expect(page.locator('#denials-prompt')).toBeHidden();
    for (const [field,value] of [['score',entry.score],['threshold',entry.threshold]]) {
      if (value === null) await expect(page.locator(`#denials-${field}-row`)).toBeHidden();
      else await expect(page.locator(`#denials-${field}`)).toHaveText(value);
    }
    await page.getByRole('button', {name:'Back to checks'}).click();
  }
});

test('Denied check reviews recover from read and save failures and discard stale responses', async ({page}) => {
  await boot(page, {status:guardrailStatus(),...denialFixtures(),denialError:'Could not connect.'});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await page.locator('#guardrails-deny').click();
  await expect(page.locator('#denials-status')).toHaveText('Could not connect.');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.denialError = ''; });
  await page.getByRole('button', {name:'Retry',exact:true}).click();
  await page.locator('.guardrail-denial-row').first().click();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.reviewError = 'Could not save the label.'; });
  await page.getByRole('button', {name:'This is incorrect',exact:true}).click();
  await expect(page.locator('#denials-feedback')).toHaveText('Could not save the label.');
  await expect(page.getByRole('button', {name:'This is incorrect',exact:true})).toBeEnabled();
  await expect(page.locator('#denials-note-details')).toBeHidden();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.reviewError = ''; });
  await page.getByRole('button', {name:'This is incorrect',exact:true}).click();
  await expect(page.getByRole('button', {name:'Reported',exact:true})).toBeDisabled();
  await page.getByText('Add a note', {exact:true}).click();
  await page.getByLabel('Note (optional)', {exact:true}).fill('Keep this unsaved note');
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.reviewError = 'Could not save the label.'; mock.pendingAction = 'guardrails.review';
  });
  await page.getByRole('button', {name:'Save note',exact:true}).click();
  await expect(page.locator('#denials-feedback')).toHaveText('Saving note…');
  await expect(page.getByRole('button', {name:'Save note',exact:true})).toBeDisabled();
  await expect(page.getByRole('button', {name:'Cancel',exact:true})).toBeDisabled();
  await expect(page.getByLabel('Note (optional)', {exact:true})).toBeDisabled();
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingAction = ''; win.completeRequest();
  });
  await expect(page.locator('#denials-feedback')).toHaveText('Could not save the label.');
  await expect(page.getByLabel('Note (optional)', {exact:true})).toHaveValue('Keep this unsaved note');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.reviewError = ''; });
  await page.getByRole('button', {name:'Save note',exact:true}).click();
  await expect(page.locator('#denials-feedback')).toHaveText('Note saved.');
  await page.getByRole('button', {name:'Close',exact:true}).click();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'guardrails.denials'; });
  await page.locator('#guardrails-deny').click();
  await expect(page.locator('#denials-status')).toHaveText('Loading denied checks…');
  await page.getByRole('group', {name:'Guardrail period',exact:true}).getByRole('button',{name:'30 days'}).click();
  await page.evaluate(() => { const win = window as unknown as {mock:Mock;completeRequest:() => void}; win.mock.pendingAction = ''; win.completeRequest(); });
  await expect(page.locator('#guardrails-review')).toBeHidden();
  await expect(page.locator('.guardrail-denial-row')).toHaveCount(0);
});

test('Denied review retries bind the displayed evidence and preserve the request identity', async ({page}) => {
  await boot(page, {status:guardrailStatus(),...denialFixtures(true),reviewLoseResponse:true});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await page.locator('#guardrails-deny').click();
  await page.locator('.guardrail-denial-row').first().click();
  await page.getByRole('button', {name:'This is incorrect',exact:true}).click();
  await expect(page.locator('#denials-feedback')).toHaveText('Could not confirm the saved label.');
  await page.getByRole('button', {name:'This is incorrect',exact:true}).click();
  await expect(page.locator('#denials-feedback')).toHaveText('Report sent.');
  let saves = (await requests(page)).filter(row => row.action === 'guardrails.review');
  expect(saves[1]).toEqual(saves[0]);
  expect(saves[0]).toMatchObject({evidence_sha256:'b'.repeat(64),expected_revision:0});
  await page.getByText('Add a note', {exact:true}).click();
  await page.getByLabel('Note (optional)', {exact:true}).fill('Confirmed after inspection');
  await page.getByRole('button', {name:'Save note',exact:true}).click();
  await expect(page.locator('#denials-feedback')).toHaveText('Note saved.');
  saves = (await requests(page)).filter(row => row.action === 'guardrails.review');
  expect(saves).toHaveLength(3);
  expect(saves[2].request_id).not.toBe(saves[0].request_id);
  expect(saves[2].expected_revision).toBe(1);
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    Object.values(mock.denialDetails!).forEach(detail => { detail.review_revision = 9; });
  });
  await page.getByText('Edit note', {exact:true}).click();
  await page.getByLabel('Note (optional)', {exact:true}).fill('A stale edit');
  await page.getByRole('button', {name:'Save note',exact:true}).click();
  await expect(page.locator('#denials-feedback')).toHaveText('Review changed. Reopen the check.');
  await expect(page.getByLabel('Note (optional)', {exact:true})).toHaveValue('A stale edit');
});

test('Denied checks preserve existing labels and notes until a user reports a mistake', async ({page}) => {
  const fixture = denialFixtures(true);
  const previousLabels = ['correct_denial','insufficient_context','false_positive'];
  const ids = Object.keys(fixture.denialDetails).slice(0,3);
  ids.forEach((id, index) => Object.assign(fixture.denialDetails[id], {label:previousLabels[index],note:'Existing note <script>kept exactly</script>',review_revision:1}));
  await boot(page, {status:guardrailStatus(),...fixture});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await page.locator('#guardrails-deny').click();
  for (const [index,label] of previousLabels.entries()) {
    await page.locator('.guardrail-denial-row').nth(index).click();
    expect((await requests(page)).filter(row => row.action === 'guardrails.review')).toHaveLength(index);
    if (label !== 'false_positive') {
      await page.getByText('Details', {exact:true}).click();
      await expect(page.locator('#denials-saved-review')).toHaveText(`Saved review: ${index === 0 ? 'Correct denial' : 'Insufficient context'}\nExisting note <script>kept exactly</script>`);
      await expect(page.locator('#denials-saved-review script')).toHaveCount(0);
      await page.getByRole('button', {name:'This is incorrect',exact:true}).click();
      await expect(page.locator('#denials-feedback')).toHaveText('Report sent.');
      const saved = (await requests(page)).filter(row => row.action === 'guardrails.review').at(-1);
      expect(saved).toMatchObject({id:ids[index],label:'false_positive',note:'Existing note <script>kept exactly</script>',expected_revision:1});
    }
    await expect(page.getByRole('button', {name:'Reported',exact:true})).toBeDisabled();
    await page.getByText('Edit note', {exact:true}).click();
    await expect(page.getByLabel('Note (optional)', {exact:true})).toHaveValue('Existing note <script>kept exactly</script>');
    await page.getByRole('button', {name:'Back to checks'}).click();
  }
});

for (const profiles of [false, true]) test(`native control flow selects Guardrails buttons separately from Usage icons ${profiles ? 'with Codex profiles' : 'with legacy status'}`, async ({page}) => {
  test.slow();
  const status = {...converged,control_ready:true,heartbeat:{last_success_at:new Date().toISOString()},
    telemetry:{...converged.telemetry,codex_available:true,codex_installed:true,codex_current:true,claude_available:false},
    hooks:{codex:guardrailStatus().hooks.codex}};
  if (profiles) Object.assign(status.hooks.codex, {profiles:[{...status.hooks.codex,name:'.codex'}]});
  const activity = guardrailActivity();
  activity.recent[0].product = 'codex-cli';
  await boot(page, {status,usage:populatedUsage(),guardrails:activity,maxWindowHeight:720,
    updateStatus:{state:'unavailable',latest:''},updateCheck:{state:'unavailable',latest:''}});
  const native = new NativeUI(text => text, {
    evaluate: (script, args) => page.evaluate(({script, args}) => new Function(script).apply(null, args), {script, args}),
    click: selector => page.locator(selector).click(),
    fill: (selector, value) => page.locator(selector).fill(value),
  });
  await native.connect();
  await exerciseAppControls({native,sensorId:status.sensor_id,publicCertificate:certificate,
    screenshot:async () => {},
    sensorStatus:() => page.evaluate(() => (window as unknown as {mock:Mock}).mock.status)});
  await native.healthy();
  expect((await requests(page)).filter(row => row.action === 'guardrails.configure').map(row => row.enabled)).toEqual([false,true,true]);
  expect((await requests(page)).filter(row => row.action === 'guardrails.configure').map(row => row.profile)).toEqual(
    Array(3).fill(profiles ? status.hooks.codex.config_path : undefined));
  await expect(page.locator('#usage-panel')).toBeVisible();
});

for (const maxWindowHeight of [720,320]) {
  test(`Guardrails navigation and compact setup fit a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme:maxWindowHeight === 720 ? 'light' : 'dark'});
    const status = guardrailStatus();
    status.hooks.opencode = {...status.hooks.opencode,available:true,installed:true};
    await boot(page, {status,usage:populatedUsage(),guardrails:guardrailActivity(),maxWindowHeight,alerts:[{...securityAlert,received_at:'2026-10-27T07:00:00Z',acknowledged_at:'2026-10-27T07:00:00Z'}]});
    await expect(page.locator('#usage-content')).toBeVisible();
    await page.getByRole('group', {name:'Usage period',exact:true}).getByRole('button',{name:'24 hours'}).click();
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    await expect(page.locator('#usage-panel')).toBeHidden();
    const heading = page.locator('#guardrails-page .usage-heading');
    await expect(heading.getByRole('heading', {name:'Guardrails',exact:true})).toBeInViewport({ratio:1});
    await expect(heading.getByText('This device', {exact:true})).toHaveCount(0);
    await expect(heading.getByRole('group', {name:'Guardrail period',exact:true})).toBeInViewport({ratio:1});
    await expect(page.locator('#guardrails-completed')).toHaveText('1,240');
    await expect(page.locator('#guardrails-deny-label')).toHaveText('Would deny');
    await expect(page.locator('#guardrails-exceptions')).toHaveText('3 checks unavailable');
    await expect(page.locator('.agent-row strong')).toHaveText(['Codex','Claude Code','Hermes Agent','GitHub Copilot','Cursor','OpenCode','WorkBuddy','Antigravity']);
    const lastAgent = page.locator('.agent-row').last();
    await lastAgent.scrollIntoViewIfNeeded();
    await expect(lastAgent).toBeInViewport({ratio:1});
    await lastAgent.click();
    await expect(page.locator('#agent-badge')).toHaveText('Agent not detected');
    await page.locator('.agent-row[data-agent="workbuddy"]').click();
    await expect(page.locator('#agent-path')).toHaveText(guardrailStatus().hooks.workbuddy.config_path);
    await expect(page.locator('#agent-checks')).toHaveText('Tool calls');
    await expect(page.locator('.agent-row[data-agent="workbuddy"] img')).toHaveAttribute('src','/agent-icons/workbuddy.svg');
    await expect(page.locator('.agent-section-heading')).toContainText('8 supported agents');
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) {
      expect(await app.evaluate(node => node.scrollHeight <= node.clientHeight + 1)).toBe(true);
      for (const id of ['page-navigation','agent-configuration','agent-reinstall','status-footer']) await expect(page.locator('#' + id)).toBeInViewport({ratio:1});
    } else {
      await page.locator('#agent-configuration').scrollIntoViewIfNeeded();
      await expect(page.locator('#agent-configuration')).toBeInViewport({ratio:1});
      expect(await app.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
      await page.locator('#show-about').scrollIntoViewIfNeeded();
      await expect(page.locator('#show-about')).toBeInViewport({ratio:1});
      await app.evaluate(node => { node.scrollTop = 0; });
    }
    await page.screenshot({path:testInfo.outputPath('guardrails-live.png'),animations:'disabled'});
    await page.getByRole('group', {name:'Guardrail period',exact:true}).getByRole('button',{name:'30 days'}).click();
    await expect(page.locator('#guardrails-completed')).toHaveText('1,240');
    await page.getByRole('tab', {name:'Guardrails',exact:true}).focus();
    await page.keyboard.press('ArrowLeft');
    await expect(page.getByRole('tab', {name:'Usage',exact:true})).toBeFocused();
    await expect(page.getByRole('group', {name:'Usage period',exact:true}).getByRole('button',{name:'24 hours'})).toHaveAttribute('aria-pressed','true');
    await expect(page.locator('#guardrails-page')).toBeHidden();
    await page.screenshot({path:testInfo.outputPath('usage-live.png'),animations:'disabled'});
    await page.keyboard.press('ArrowRight');
    await expect(page.getByRole('group', {name:'Guardrail period',exact:true}).getByRole('button',{name:'30 days'})).toHaveAttribute('aria-pressed','true');
    await page.locator('#guardrails-view').click();
    await expect(page.locator('.guardrail-activity-row')).toHaveCount(20);
    await page.locator('.guardrail-activity-row').last().scrollIntoViewIfNeeded();
    await expect(page.locator('.guardrail-activity-row').last()).toBeInViewport({ratio:1});
    expect(await app.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
    await page.locator('#agent-reinstall').scrollIntoViewIfNeeded();
    await expect(page.locator('#agent-reinstall')).toBeInViewport({ratio:1});
  });
}

test('Guardrails put undetected agents last and preserve selection and keyboard focus on refresh', async ({page}) => {
  const status = guardrailStatus();
  status.hooks.codex = {...status.hooks.codex,available:false,installed:false};
  status.hooks.opencode = {...status.hooks.opencode,available:true,installed:true};
  await boot(page, {status,guardrails:guardrailActivity()});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  const names = page.locator('.agent-row strong');
  await expect(names).toHaveText(['Claude Code','Hermes Agent','GitHub Copilot','Cursor','OpenCode','WorkBuddy','Codex','Antigravity']);
  const opencode = page.locator('.agent-row[data-agent="opencode"]');
  await opencode.click();
  await opencode.focus();
  await page.keyboard.press('Tab');
  await expect(page.locator('.agent-row[data-agent="workbuddy"]')).toBeFocused();
  await opencode.focus();
  await returnToWindow(page);
  await expect(opencode).toBeFocused();
  await page.evaluate(() => {
    const hooks = (window as unknown as {mock:Mock}).mock.status.hooks as Record<string, Record<string, unknown>>;
    hooks.codex = {...hooks.codex,available:true,installed:true};
    hooks.opencode = {...hooks.opencode,available:false,installed:false};
  });
  await returnToWindow(page);
  await expect(names).toHaveText(['Codex','Claude Code','Hermes Agent','GitHub Copilot','Cursor','WorkBuddy','Antigravity','OpenCode']);
  await expect(opencode).toHaveAttribute('aria-pressed','true');
  await expect(opencode).toBeFocused();
  await expect(page.locator('#agent-name')).toHaveText('OpenCode');
  await expect(page.locator('#agent-badge')).toHaveText('Agent not detected');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.status.hooks = {}; });
  await returnToWindow(page);
  await expect(names).toHaveText(['Codex','Claude Code','Hermes Agent','GitHub Copilot','Cursor','Antigravity','OpenCode','WorkBuddy']);
  await expect(page.locator('.agent-row small')).toHaveText(Array(8).fill('Status unavailable'));
});

for (const maxWindowHeight of [720,320]) {
  test(`Codex profiles have separate icons and controls at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    const status = guardrailStatus();
    const profiles = ['.codex','.codex-account2','.codex-account3'].map(name => ({...status.hooks.codex,name,config_path:`/Users/example/${name}/hooks.json`}));
    Object.assign(status.hooks.codex, {profiles});
    const activity = guardrailActivity();
    activity.by_agent.push({product:'codex-cli',last_check_at:activity.until});
    await boot(page, {status,usage:populatedUsage(),guardrails:activity,maxWindowHeight});
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    const codex = page.locator('.agent-row[data-agent="codex"]');
    await expect(codex).toHaveCount(3);
    await expect(page.locator('.agent-row')).toHaveCount(10);
    await expect(codex.locator('strong')).toHaveText(['Codex','Codex','Codex']);
    for (const image of await codex.locator('img').all()) await expect(image).toHaveAttribute('src', '/agent-icons/codex.png');
    await expect(codex.locator('small')).toHaveText(profiles.map(row => `${row.name} · Installed · On`));
    const list = page.getByRole('group', {name:'Coding agents',exact:true});
    expect(await list.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    expect(await list.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    const setupHeight = (await page.locator('.agent-setup').boundingBox())!.height;
    const lastAgent = list.locator('.agent-row').last();
    await lastAgent.focus();
    await expect(lastAgent).toBeInViewport({ratio:1});
    expect(await list.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
    await page.keyboard.press('Enter');
    await expect(page.locator('#agent-name')).toHaveText(await lastAgent.locator('strong').innerText());
    expect((await page.locator('.agent-setup').boundingBox())!.height).toBe(setupHeight);
    await codex.first().evaluate(node => node.scrollIntoView({block:'center'}));
    await codex.first().focus();
    await expect(codex.first()).toBeInViewport({ratio:1});
    expect(await list.evaluate(node => node.scrollTop)).toBe(0);
    await codex.nth(1).click();
    await expect(page.locator('#agent-name')).toHaveText('Codex · .codex-account2');
    await expect(page.locator('#agent-path')).toHaveText(profiles[1].config_path);
    await expect(page.locator('#agent-last-check')).toContainText('all profiles');
    await page.locator('#agent-configuration').click();
    expect((await requests(page)).filter(row => row.action === 'guardrails.configuration')).toEqual([
      {action:'guardrails.configuration',agent:'codex',profile:profiles[1].config_path},
    ]);
    await page.getByLabel('Enable guardrails', {exact:true}).uncheck();
    await expect(codex.nth(1)).toContainText('Guardrails off');
    await expect(codex.nth(0)).toContainText('Installed · On');
    await expect(codex.nth(2)).toContainText('Installed · On');
    await returnToWindow(page);
    await expect(codex.nth(1)).toHaveAttribute('aria-pressed', 'true');
    expect((await requests(page)).filter(row => row.action === 'setup')).toHaveLength(0);
    await page.locator('#agent-reinstall').click();
    await expect(codex.nth(1)).toContainText('Installed · On');
    expect((await requests(page)).filter(row => row.action === 'guardrails.configure')).toEqual([
      {action:'guardrails.configure',agent:'codex',profile:profiles[1].config_path,enabled:false},
      {action:'guardrails.configure',agent:'codex',profile:profiles[1].config_path,enabled:true},
    ]);
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) {
      expect(await app.evaluate(node => node.scrollHeight <= node.clientHeight + 1)).toBe(true);
      await expect(codex.nth(2)).toBeInViewport({ratio:1});
      await expect(page.locator('#agent-reinstall')).toBeInViewport({ratio:1});
    } else {
      for (const control of [codex.nth(2), page.locator('.agent-row').last(), page.locator('#agent-configuration'), page.locator('#show-about')]) {
        await control.scrollIntoViewIfNeeded();
        await expect(control).toBeInViewport({ratio:1});
      }
      expect(await app.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
      await app.evaluate(node => { node.scrollTop = 0; });
    }
    await page.screenshot({path:testInfo.outputPath('codex-profiles.png'),animations:'disabled'});
    await page.evaluate(() => {
      const hooks = (window as unknown as {mock:Mock}).mock.status.hooks as {codex:{profiles:unknown[]}};
      hooks.codex.profiles.splice(1, 1);
    });
    await returnToWindow(page);
    await expect(codex).toHaveCount(2);
    await expect(codex.first()).toHaveAttribute('aria-pressed', 'true');
  });
}

test('Codex profile discovery repairs extra profiles when the first profile is current', async ({page}) => {
  const status = guardrailStatus();
  const profiles = ['.codex','.codex-account2','.codex-account3'].map(name => ({...status.hooks.codex,name,config_path:`/Users/example/${name}/hooks.json`}));
  Object.assign(status.hooks.codex, {profiles});
  const afterSetup = structuredClone(status);
  Object.assign(profiles[1], {installed:false,current:false});
  await boot(page, {status,afterSetup,guardrails:guardrailActivity()});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await expect(page.locator('.agent-row[data-agent="codex"]')).toHaveCount(3);
  await expect(page.locator('.agent-row[data-agent="codex"] small')).toHaveText(profiles.map(row => `${row.name} · Installed · On`));
  expect((await requests(page)).filter(row => row.action === 'setup')).toHaveLength(1);
});

for (const agent of ['claude','workbuddy']) test(`Guardrails ${agent} setup persists opt-outs, exposes configuration, and recovers from failure`, async ({page}) => {
  await boot(page, {status:guardrailStatus(),guardrails:guardrailActivity()});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await page.locator(`.agent-row[data-agent="${agent}"]`).click();
  await page.locator('#agent-configuration').click();
  expect((await requests(page)).filter(r => r.action === 'guardrails.configuration')).toEqual([{action:'guardrails.configuration',agent}]);
  await page.getByLabel('Enable guardrails', {exact:true}).uncheck();
  await expect(page.locator('#agent-badge')).toHaveText('Guardrails off');
  await returnToWindow(page);
  await expect(page.getByLabel('Enable guardrails', {exact:true})).not.toBeChecked();
  expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(0);
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.guardrailSetupError = 'Could not write the agent configuration.'; });
  await page.getByLabel('Enable guardrails', {exact:true}).click();
  await expect(page.locator('#agent-feedback')).toHaveText('Could not write the agent configuration.');
  await expect(page.getByLabel('Enable guardrails', {exact:true})).not.toBeChecked();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.guardrailSetupError = ''; });
  await page.locator('#agent-reinstall').click();
  await expect(page.getByLabel('Enable guardrails', {exact:true})).toBeChecked();
  await page.locator('.agent-row[data-agent="hermes"]').click();
  await expect(page.locator('#agent-badge')).toHaveText('Approval needed');
  await expect(page.locator('#agent-guidance')).toContainText('Approval must be given in Hermes.');
  await page.locator('.agent-row[data-agent="opencode"]').click();
  await expect(page.locator('#agent-reinstall')).toBeDisabled();
  await expect(page.locator('#agent-configuration')).toBeDisabled();
});

test('Guardrails separate mixed modes, warnings, unavailable activity, and empty periods', async ({page}) => {
  const activity = guardrailActivity();
  activity.mode = 'enforce'; activity.summary.warn = 2; activity.summary.completed += 2;
  activity.by_mode.enforce.warn = 2; activity.by_mode.enforce.completed = 2;
  await boot(page, {status:guardrailStatus(),guardrails:activity});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await expect(page.locator('#guardrails-mode')).toHaveText('Enforce');
  await expect(page.locator('#guardrails-deny-label')).toHaveText('Deny');
  await expect(page.locator('#guardrails-exceptions')).toHaveText('2 warn decisions · 3 checks unavailable');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.guardrails = {supported:false}; });
  await returnToWindow(page);
  await expect(page.locator('#guardrails-data')).toBeHidden();
  await expect(page.locator('#guardrails-mode')).toHaveText('Policy unavailable');
  await expect(page.locator('#guardrails-message')).toContainText('updated organization server');
  await expect(page.locator('#guardrails-view')).toBeDisabled();
  await expect(page.locator('#guardrails-activity')).toBeHidden();
  await expect(page.locator('#agent-reinstall')).toBeEnabled();
  const empty = guardrailActivity();
  for (const counts of [empty.summary,empty.by_mode.shadow,empty.by_mode.enforce]) Object.keys(counts).forEach(key => { counts[key as keyof typeof counts] = 0; });
  empty.recent = []; empty.by_agent = [];
  await page.evaluate(data => { (window as unknown as {mock:Mock}).mock.guardrails = data; }, empty);
  await returnToWindow(page);
  await expect(page.locator('#guardrails-completed')).toHaveText('0');
  await expect(page.locator('#guardrails-exceptions')).toBeHidden();
  await expect(page.locator('#guardrails-view')).toBeEnabled();
  await expect(page.locator('#agent-last-check')).toHaveText('No checks in this period');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.guardrailsError = 'Could not connect to your organization.'; });
  await returnToWindow(page);
  await expect(page.locator('#guardrails-message')).toHaveText('Could not connect to your organization.');
  await expect(page.locator('#guardrails-data')).toBeHidden();
  await expect(page.locator('#guardrails-view')).toBeDisabled();
  await expect(page.locator('#guardrails-activity')).toBeHidden();
});

test('Guardrails ignore activity returned after the device connection changes', async ({page}) => {
  await boot(page, {status:guardrailStatus(),guardrails:guardrailActivity(),pendingAction:'guardrails.summary'});
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await expect.poll(async () => (await requests(page)).some(r => r.action === 'guardrails.summary')).toBe(true);
  await expect(page.locator('#guardrails-view')).toBeDisabled();
  await expect(page.locator('#guardrails-activity')).toBeHidden();
  await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.status = {...mock.status,sensor_id:'replacement'}; });
  await returnToWindow(page);
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingAction = ''; win.mock.guardrails = {supported:false}; win.completeRequest();
  });
  await expect(page.locator('#guardrails-message')).toContainText('updated organization server');
  await expect(page.locator('#guardrails-data')).toBeHidden();
});

for (const maxWindowHeight of [720, 160]) {
  test(`hook estimates stay separate and reachable at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    const estimates = {items:[
      {application:'github-copilot',model:'claude-sonnet-4-6',model_source:'configured',observations:1,priced_observations:1,estimated_input_tokens:100,estimated_output_tokens:0,estimated_cost_usd:'0.0003'},
      {application:'cursor',model:'auto',model_source:'hook',observations:1,priced_observations:0,estimated_input_tokens:200,estimated_output_tokens:100,estimated_cost_usd:null},
      {application:'cursor',model:'jev-long-model-name-that-must-wrap-without-clipping-in-the-native-window',model_source:'hook',observations:1,priced_observations:0,estimated_input_tokens:10000,estimated_output_tokens:20000,estimated_cost_usd:null},
    ]};
    const zero = {tokens:0,calls:0,priced_calls:0,cost_usd:null};
    await boot(page, {status:converged,maxWindowHeight,usageByDays:{
      30:{...populatedUsage(),hook_estimates:estimates},
      1:{summary:zero,by_model:[],by_reasoning_effort:[],pending_exports:0,source:'local',hook_estimates:{items:[estimates.items[1]]}},
    }});
    await expect(page.locator('#usage-cost')).toHaveText('$42.18');
    await expect(page.getByRole('button',{name:'Cost estimate information',exact:true})).toHaveAccessibleDescription('Historical cost may be incomplete.');
    const hooks = page.getByRole('region', {name:'Hook estimates',exact:true});
    await hooks.scrollIntoViewIfNeeded();
    await expect(hooks).toContainText('Assumed model: claude-sonnet-4-6');
    await expect(hooks).toContainText('~$0.0003');
    await expect(hooks.getByText('Cost unknown', {exact:true})).toHaveCount(2);
    await expect(hooks).toContainText('not billed spend');
    await expect(hooks).not.toContainText(/jev/i);
    await page.screenshot({path:testInfo.outputPath('hook-estimates.png')});
    const scroller = page.locator('#usage-hook-rows');
    await scroller.evaluate(node => { node.scrollTop = node.scrollHeight; });
    await expect(scroller.locator('.usage-hook-row').last()).toBeInViewport();
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await scroller.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) {
      expect(await page.locator('#app').evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
    } else {
      expect(await page.locator('#app').evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    }
    const period = page.getByRole('button', {name:'24 hours',exact:true});
    await period.focus();
    await expect(period).toBeInViewport({ratio:1});
    await period.click();
    await expect(page.locator('#usage-cost')).toHaveText('$0.00');
    await expect(page.locator('#usage-message')).toContainText('No reported usage');
    await expect(scroller.locator('.usage-hook-row')).toHaveCount(1);
    await hooks.scrollIntoViewIfNeeded();
    await expect(hooks).toContainText('Cost unknown');
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock};
      win.mock.usageByDays![1].hook_estimates = {items:[]};
    });
    await expect(hooks).toBeHidden();
  });
}

for (const label of ['Show in menu bar', 'Show in system tray']) for (const maxWindowHeight of [720, 240]) {
  test(`${label} in Settings saves and recovers from a write failure at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    const usage = populatedUsage();
    usage.by_model = ['gpt-6-astra','gpt-6.1-sol','claude-opus-5-5','claude-fable-5-1'].map((name,i) => ({...usage.summary,name,cost_usd:[30,8,3,1.18][i]}));
    usage.by_reasoning_effort = ['max','xhigh','low','medium'].map((name,i) => ({...usage.summary,name,cost_usd:[30,8,3,1.18][i]}));
    await boot(page, {status:converged,usage,menuBar:{supported:true,enabled:false,label},maxWindowHeight});
    const checkbox = page.getByRole('checkbox', {name:label});
    const settings = page.getByRole('button', {name:'Settings',exact:true});
    const dialog = page.getByRole('dialog', {name:'Settings'});
    await expect(checkbox).toBeHidden();
    await expect(settings).toBeVisible();
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) expect(await page.locator('#app').evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
    await settings.click();
    await expect(dialog).toBeVisible();
    await expect(checkbox).toBeFocused();
    await expect(checkbox).not.toBeChecked();
    await expect(page.locator('#usage-content')).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
    await checkbox.scrollIntoViewIfNeeded();
    await expect(checkbox).toBeInViewport({ratio:1});
    const alignment = await checkbox.evaluate(node => {
      const control = node.getBoundingClientRect(), range = document.createRange();
      range.selectNode(node.parentElement!.lastChild!);
      const text = range.getBoundingClientRect();
      return {gap:text.left - control.right,offset:Math.abs((text.top + text.bottom - control.top - control.bottom) / 2)};
    });
    expect(alignment.gap).toBeGreaterThanOrEqual(0);
    expect(alignment.offset).toBeLessThan(3);
    expect(await dialog.evaluate(node => {
      const link = node.querySelector('#enrollment-link')!.getBoundingClientRect();
      const connect = node.querySelector('#connect-link')!.getBoundingClientRect();
      const done = node.querySelector('#cancel-change')!.getBoundingClientRect();
      const connection = node.querySelector('#connect-card')!.getBoundingClientRect();
      return {
        connectBelowLink:connect.top >= link.bottom && Math.abs(connect.left - link.left) < 1 && Math.abs(connect.width - link.width) < 1,
        doneBelowConnection:done.top > connection.bottom,
      };
    })).toEqual({connectBelowLink:true,doneBelowConnection:true});
    await expect(dialog.locator('#settings-actions button')).toHaveText(['Done']);
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) expect(await dialog.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
    await dialog.getByRole('button', {name:'Done',exact:true}).focus();
    await expect(dialog.getByRole('button', {name:'Done',exact:true})).toBeInViewport({ratio:1});
    await dialog.getByRole('button', {name:'Connect',exact:true}).scrollIntoViewIfNeeded();
    await expect(dialog.getByRole('button', {name:'Connect',exact:true})).toBeInViewport({ratio:1});
    if (maxWindowHeight === 240) expect(await dialog.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
    await dialog.getByRole('button', {name:'Close Settings'}).focus();
    await expect(dialog.getByRole('button', {name:'Close Settings'})).toBeInViewport({ratio:1});
    await checkbox.check();
    await expect(checkbox).toBeEnabled();
    await expect(checkbox).toBeChecked();
    for (const colorScheme of ['light','dark'] as const) {
      await page.emulateMedia({colorScheme});
      await page.screenshot({path:testInfo.outputPath(`menu-bar-setting-${maxWindowHeight}-${colorScheme}.png`),animations:'disabled'});
      await page.keyboard.press('Escape');
      await expect(dialog).toBeHidden();
      await expect(settings).toBeFocused();
      await page.screenshot({path:testInfo.outputPath(`settings-main-${maxWindowHeight}-${colorScheme}.png`),animations:'disabled'});
      await settings.click();
      await expect(checkbox).toBeChecked();
    }
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.menuBarError = 'Could not save the menu bar setting. Try again.'; });
    await checkbox.click();
    await expect(page.locator('#menu-bar-error')).toContainText('Could not save');
    await expect(checkbox).toBeChecked();
    await checkbox.focus();
    await expect(checkbox).toBeInViewport({ratio:1});
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.menuBarError = ''; });
    await checkbox.uncheck();
    await expect(checkbox).toBeEnabled();
    await expect(checkbox).not.toBeChecked();
    await expect(page.locator('#menu-bar-error')).toBeHidden();
    await dialog.getByRole('button', {name:'Close Settings'}).click();
    await settings.click();
    await expect(checkbox).not.toBeChecked();
    expect((await requests(page)).filter(r => r.action === 'enrollment.connect')).toHaveLength(0);
  });
}

for (const statusError of ['', 'The sensor is unavailable.']) {
  test(`Settings offers the menu bar preference ${statusError ? 'without the sensor' : 'before enrollment'}`, async ({page}) => {
    await boot(page, {status:unenrolled,statusError,menuBar:{supported:true,enabled:false}});
    const checkbox = page.getByRole('checkbox', {name:'Show in menu bar'});
    await expect(checkbox).toBeHidden();
    if (!statusError) await expect(page.getByRole('heading', {name:'Connect your organization'})).toBeVisible();
    await page.getByRole('button', {name:'Settings',exact:true}).click();
    await expect(page.getByRole('dialog', {name:'Settings'})).toBeVisible();
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toHaveAttribute('aria-expanded','true');
    await expect(checkbox).toBeFocused();
    await expect(checkbox).not.toBeChecked();
    await checkbox.check();
    await expect(checkbox).toBeEnabled();
    await expect(checkbox).toBeChecked();
    if (statusError) await expect(page.getByLabel('Enrollment link', {exact:true})).toBeHidden();
    await page.getByRole('button', {name:'Done',exact:true}).click();
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeFocused();
    await expect(checkbox).toBeHidden();
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toHaveAttribute('aria-expanded','false');
    if (!statusError) await expect(page.getByRole('heading', {name:'Connect your organization'})).toBeVisible();
    await page.getByRole('button', {name:'Settings',exact:true}).click();
    await expect(checkbox).toBeChecked();
  });
}

test('system tray uses the same health and grace period while hidden without refreshing usage or setup', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-08T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-08T12:00:00Z'));
  await boot(page, {status:{...converged,heartbeat:{last_success_at:'2026-10-08T12:00:00Z',error:''}},usage:usageTotals(1000000),menuBar:{supported:true,enabled:true,label:'Show in system tray'}});
  const health = () => page.evaluate(() => (window as unknown as {menuHealth:{label:string;attention:boolean}}).menuHealth);
  await expect.poll(health).toEqual({label:'Connected',attention:false});
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').length).toBe(1);
  const before = await requests(page);
  await page.evaluate(() => {
    window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:false}));
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.status.heartbeat = {last_success_at:'2026-10-08T12:00:00Z',error:'[Errno 61] Connection refused'};
  });
  await page.clock.fastForward(60000);
  await page.evaluate(() => window.dispatchEvent(new Event('openaidr-background-status')));
  await expect.poll(health).toEqual({label:'Connected (1 min ago)',attention:false});
  await page.clock.fastForward(14 * 60000);
  await page.evaluate(() => window.dispatchEvent(new Event('openaidr-background-status')));
  await expect.poll(health).toEqual({label:'Connection lost',attention:true});
  for (const action of ['usage.summary','setup','desktop.update.status']) {
    expect((await requests(page)).filter(r => r.action === action)).toHaveLength(before.filter(r => r.action === action).length);
  }
  await page.evaluate(() => {
    (window as unknown as {mock:Mock}).mock.statusError = 'Local sensor unavailable';
    window.dispatchEvent(new Event('openaidr-background-status'));
  });
  await expect.poll(health).toEqual({label:'Status unavailable',attention:true});
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.statusError = '';
    mock.status.heartbeat = {last_success_at:new Date(Date.now()).toISOString(),error:''};
    window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:true}));
  });
  await expect.poll(health).toEqual({label:'Connected',attention:false});
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').length).toBe(2);
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await page.getByRole('checkbox', {name:'Show in system tray'}).uncheck();
  await expect(page.getByRole('checkbox', {name:'Show in system tray'})).toBeEnabled();
  const reads = (await requests(page)).filter(r => r.action === 'status').length;
  await page.evaluate(() => {
    window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:false}));
    window.dispatchEvent(new Event('openaidr-background-status'));
  });
  expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(reads);
});

for (const maxWindowHeight of [720, 240]) {
  test(`Linux tray fallback explains normal close and recovers when a host appears at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    await boot(page, {status:converged,usage:populatedUsage(),maxWindowHeight,
      menuBar:{supported:true,enabled:true,label:'Show in system tray',available:false}});
    await page.getByRole('button', {name:'Settings',exact:true}).click();
    const dialog = page.getByRole('dialog', {name:'Settings'});
    const checkbox = page.getByRole('checkbox', {name:'Show in system tray'});
    const description = page.locator('#menu-bar-description');
    await expect(checkbox).toBeChecked();
    await expect(description).toContainText('No system tray is available');
    await checkbox.scrollIntoViewIfNeeded();
    await expect(checkbox).toBeInViewport({ratio:1});
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) expect(await dialog.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
    await dialog.getByRole('button', {name:'Done',exact:true}).focus();
    await expect(dialog.getByRole('button', {name:'Done',exact:true})).toBeInViewport({ratio:1});
    if (maxWindowHeight === 240) expect(await dialog.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
    await checkbox.focus();
    await page.screenshot({path:testInfo.outputPath(`linux-tray-fallback-${maxWindowHeight}.png`),animations:'disabled'});
    await page.evaluate(() => window.dispatchEvent(new CustomEvent('openaidr-tray-availability', {detail:true})));
    await expect(description).toContainText('Keep status available');
    await page.evaluate(() => window.dispatchEvent(new CustomEvent('openaidr-tray-availability', {detail:false})));
    await expect(description).toContainText('Closing the window exits the app');
    await expect(checkbox).toBeChecked();
    await checkbox.uncheck();
    await expect(checkbox).toBeEnabled();
    await expect(checkbox).not.toBeChecked();
  });
}

test('About works without the sensor and keeps license and support actions local', async ({page}) => {
  await boot(page, {status:unenrolled,statusError:'The sensor is unavailable.'});
  await expect(page.getByRole('checkbox', {name:'Show in menu bar'})).toBeHidden();
  const button = page.getByRole('button', {name:'About',exact:true});
  await button.click();
  const dialog = page.getByRole('dialog', {name:'About OpenAIDR',exact:true});
  await expect(dialog).toBeVisible();
  await expect(page.locator('#about-title')).toBeFocused();
  await expect(dialog.locator('.about-content')).not.toContainText(/version|commit|copy details/i);
  await expect(dialog.getByRole('link', {name:'Contact support'})).toHaveAttribute('href','mailto:contact@opensecura.ai');
  await dialog.getByRole('link', {name:'Contact support'}).click();
  expect((await requests(page)).filter(r => r.action === 'desktop.support')).toEqual([{action:'desktop.support'}]);
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.supportError = 'No email app'; });
  await dialog.getByRole('link', {name:'Contact support'}).click();
  await expect(dialog.getByRole('alert')).toContainText('contact@opensecura.ai');
  // Notices must not depend on the company server or a public website.
  await page.context().setOffline(true);
  await dialog.getByRole('button', {name:'Licenses and acknowledgements'}).click();
  await expect(page.locator('#licenses-title')).toBeFocused();
  await dialog.locator('summary', {hasText:'Geist fonts'}).click();
  await expect(dialog.locator('pre').first()).toContainText('SIL OPEN FONT LICENSE');
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(button).toBeFocused();
  await expect(button).toHaveAttribute('aria-expanded','false');
  await button.click();
  await expect(page.locator('#about-licenses')).toBeHidden();
  await page.keyboard.press('Shift+Tab');
  await expect(dialog.getByRole('button', {name:'Close About OpenAIDR'})).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('#show-licenses')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(dialog.getByRole('link', {name:'Contact support'})).toBeFocused();
  await page.locator('#check-update').focus();
  await expect(page.locator('#check-update')).not.toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await page.keyboard.press('Shift+Tab');
  await expect(dialog.getByRole('button', {name:'Close About OpenAIDR'})).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await button.click();
  await page.mouse.click(3,3);
  await expect(dialog).toBeHidden();
});

for (const platform of ['macos','windows','linux'] as const) {
  test(`About renders with ${platform} capabilities in light and dark mode`, async ({page}, testInfo) => {
    const counts = {tokens:1264500,cached_input_tokens:800000,uncached_input_tokens:364500,output_tokens:100000,calls:284,priced_calls:284,cost_usd:42.18};
    const usage = {summary:counts,by_model:[{name:'gpt-6.1-sol',...counts}],by_reasoning_effort:[{name:'high',...counts}],pending_exports:0};
    await boot(page, {status:converged,usage,removalSupported:platform !== 'linux',nativeUninstaller:platform === 'windows'});
    for (const colorScheme of ['light','dark'] as const) {
      await page.emulateMedia({colorScheme});
      await page.getByRole('button', {name:'About',exact:true}).click();
      const dialog = page.locator('#about-dialog');
      await expect(dialog).toBeInViewport({ratio:1});
      await page.evaluate(() => document.fonts.ready);
      await expect.poll(() => dialog.evaluate(node => node.scrollHeight <= node.clientHeight && node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      for (const control of await dialog.locator('button, a').all()) await expect(control).toBeInViewport({ratio:1});
      await page.screenshot({path:testInfo.outputPath(`about-${platform}-${colorScheme}.png`),animations:'disabled'});
      await dialog.screenshot({path:testInfo.outputPath(`about-${platform}-${colorScheme}-dialog.png`),animations:'disabled'});
      await page.keyboard.press('Escape');
      await expect(page.locator('#show-about')).toBeFocused();
    }
  });
}

test('About controls and offline notices remain reachable in a small work area', async ({page}, testInfo) => {
  await boot(page, {status:converged,usage:usageTotals(1000000),maxWindowHeight:240});
  await page.getByRole('button', {name:'About',exact:true}).click();
  const dialog = page.locator('#about-dialog');
  await expect(dialog).toBeInViewport({ratio:1});
  expect(await dialog.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
  expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  await page.keyboard.press('Tab');
  await expect(page.locator('#show-licenses')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('#contact-support')).toBeFocused();
  await expect(page.locator('#contact-support')).toBeInViewport({ratio:1});
  await page.screenshot({path:testInfo.outputPath('about-small-work-area.png'),animations:'disabled'});
  await page.locator('#show-licenses').click();
  await dialog.locator('summary', {hasText:'Geist fonts'}).click();
  await dialog.locator('summary').last().focus();
  await expect(dialog.locator('summary').last()).toBeInViewport({ratio:1});
  expect(await dialog.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(page.locator('#show-about')).toBeFocused();
});

for (const maxWindowHeight of [720, 320]) {
  test(`AppImage first-launch setup can retry at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    const setup = {state:'installing',latest:'2026.10.21+1234567',setup:true};
    await boot(page, {status:converged,usage:usageTotals(1000000),updateStatus:setup,maxWindowHeight,removalSupported:false});
    await expect(page.locator('#update-notice')).toHaveText('Setting up automatic updates…');
    // A native status refresh can complete while the user holds the mouse down.
    await page.locator('#check-update span').hover();
    await page.mouse.down();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateStatus!.latest = '2026.10.21+7654321'; });
    await returnToWindow(page);
    await expect(page.locator('#update-version')).toHaveText('Version 2026.10.21+7654321');
    await page.mouse.up();
    const panel = page.locator('#update-panel');
    await expect(panel).toBeVisible();
    expect(await panel.evaluate(node => node.matches(':modal'))).toBe(true);
    await expect(page.locator('#update-title')).toHaveText('Setting up OpenAIDR...');
    await expect(page.locator('#update-message')).toContainText('Verifying and installing this app with automatic updates');
    await expect(page.locator('#close-update')).toBeHidden();
    expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) {
      await expect(panel).toBeInViewport({ratio:1});
      expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    }
    await page.screenshot({path:testInfo.outputPath(`appimage-setup-${maxWindowHeight}.png`),animations:'disabled'});
    await page.evaluate(() => {
      (window as unknown as {mock:Mock}).mock.updateStatus = {
        state:'error',latest:'2026.10.21+1234567',setup:true,
        error:'Cannot reach the release server. Check updates to try setup again.',
      };
    });
    await returnToWindow(page);
    await expect(page.locator('#update-title')).toHaveText('Could not finish app setup');
    await expect(page.locator('#update-message')).toContainText('Check updates to try setup again');
    await expect(panel).toBeVisible();
    const retry = panel.getByRole('button',{name:'Try again',exact:true});
    await retry.focus();
    await expect(retry).toBeInViewport({ratio:1});
    expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.evaluate(setup => { (window as unknown as {mock:Mock}).mock.updateCheck = setup; }, setup);
    await retry.click();
    await expect(page.locator('#update-title')).toHaveText('Setting up OpenAIDR...');
    expect((await requests(page)).filter(r => r.action === 'desktop.update.check')).toHaveLength(1);
    await page.evaluate(() => {
      (window as unknown as {mock:Mock}).mock.updateStatus = {
        state:'error',latest:'2026.10.21+1234567',setup:true,error:'The verification file is unavailable.',
      };
    });
    await returnToWindow(page);
    await expect(page.locator('#update-title')).toHaveText('Could not finish app setup');
    await expect(page.locator('#update-message')).toHaveText('The verification file is unavailable.');
  });
}

test('manual update checks stay in the app without enrollment or a working sensor', async ({page}) => {
  await boot(page, {status:unenrolled,updateStatus:null});
  const button = page.locator('#check-update');
  await button.click();
  await expect(page.locator('#update-title')).toHaveText("You're up to date");
  // The result is a modal dialog: centered, announced by its title, and dismissed from the backdrop.
  const panel = page.locator('#update-panel');
  expect(await panel.evaluate(node => node.matches(':modal'))).toBe(true);
  await expect(page.locator('#update-title')).toBeFocused();
  await expect(panel).toBeInViewport({ratio:1});
  const box = (await panel.boundingBox())!;
  expect(Math.abs(box.x + box.width / 2 - page.viewportSize()!.width / 2)).toBeLessThan(2);
  await page.mouse.click(4, 4);
  await expect(panel).toBeHidden();
  await expect(button).toBeFocused();
  await button.click();
  await page.getByRole('button',{name:'Done',exact:true}).click();
  await expect(button).toBeFocused();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'The sensor is unavailable.'; });
  await returnToWindow(page);
  await button.click();
  await expect(page.locator('#update-title')).toHaveText("You're up to date");
  expect((await requests(page)).filter(r => r.action === 'desktop.update.check')).toHaveLength(3);
  expect((await requests(page)).some(r => r.action === 'desktop.update.downloads' || r.action === 'desktop.update.install')).toBe(false);
  expect(page.context().pages()).toHaveLength(1);
  // A later automatic check must finish even after a manual result was shown.
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateStatus = {state:'checking',latest:''}; });
  await returnToWindow(page);
  await expect(button).toHaveText('Checking...');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateStatus = {state:'idle',latest:''}; });
  await returnToWindow(page);
  await expect(button).toHaveText('Check updates');
});

for (const maxWindowHeight of [720,160]) {
  test(`update status fits a compact window in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await boot(page, {status:converged,nativeUninstaller:true,maxWindowHeight,usage:usageTotals(30000)});
    await expect(page.locator('#usage-tokens')).toHaveText('30 k');
    await page.evaluate(message => { (window as unknown as {mock:Mock}).mock.statusError = message; }, operationBusy);
    await returnToWindow(page);
    await expect(page.locator('#sensor-status')).toHaveAccessibleName('Sensor status: Updating');
    await expect(page.locator('#usage-panel')).toBeHidden();
    await page.locator('#check-update').click();
    const panel = page.locator('#update-panel');
    const done = panel.getByRole('button', {name:'Done',exact:true});
    await expect(page.locator('#update-title')).toHaveText("You're up to date");
    for (const state of ['checking','available','downloading','installing','restarting','updated','error','unavailable','idle']) {
      await test.step(state, async () => {
        await page.evaluate(state => { (window as unknown as {mock:Mock}).mock.updateStatus = {
          state,latest:'2026.10.26+1234567',downloaded_bytes:10485760,total_bytes:20971520,
        }; }, state);
        await returnToWindow(page);
        await expect(panel).toHaveAttribute('data-state', state);
        await expect(panel).toBeInViewport({ratio:1});
        expect(page.viewportSize()!.width).toBe(config.app.windows[0].width);
        expect(await panel.evaluate(node => node.scrollWidth - node.clientWidth)).toBe(0);
        if (maxWindowHeight === 720) {
          await expectFitsWindow(page);
          for (const element of await panel.locator('h2, #update-version, #update-message:visible, #update-detail:visible, #update-progress:visible, button:visible').all()) {
            await expect(element).toBeInViewport({ratio:1});
          }
        } else {
          await expect.poll(() => page.viewportSize()!.height).toBe(160);
          for (const control of await panel.locator('button:visible').all()) {
            await control.scrollIntoViewIfNeeded();
            await expect(control).toBeInViewport({ratio:1});
          }
        }
      });
    }
    if (maxWindowHeight === 160) {
      expect(await panel.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await panel.evaluate(node => { node.scrollTop = 0; });
      await expect(page.locator('#close-update')).toBeInViewport({ratio:1});
      await panel.hover();
      await page.mouse.wheel(0, 400);
      await expect.poll(() => panel.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
      await expect(done).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath('compact-update-status.png')});
    if (maxWindowHeight === 720) {
      // A later CSS spacing change must not require a matching JavaScript constant.
      await panel.evaluate(node => { node.style.maxHeight = 'calc(100vh - 40px)'; node.style.borderWidth = '3px'; });
      await expectFitsWindow(page);
      await expect(done).toBeInViewport({ratio:1});
    }
    await done.click();
    await expect(panel).toBeHidden();
    await expect(page.locator('#check-update')).toBeFocused();
  });
}

test('manual update checking supports cancellation, retry, and duplicate prevention', async ({page}) => {
  await boot(page, {status:converged,pendingAction:'desktop.update.check'});
  const button = page.locator('#check-update');
  await button.click();
  await expect(button).toBeDisabled();
  await expect(page.locator('#update-title')).toHaveText('Checking for updates...');
  await returnToWindow(page);
  await expect(button).toBeDisabled();
  expect((await requests(page)).filter(r => r.action === 'desktop.update.check')).toHaveLength(1);
  // A native check can wait for the updater or sensor lock while status polls
  // still return the previous result. Complete that same request without retry.
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock; completeRequest:() => void};
    win.mock.updateCheck = {state:'available',latest:'2026.10.18+292409f'};
    win.completeRequest();
  });
  await expect(page.locator('#update-title')).toHaveText('Update available');
  expect((await requests(page)).filter(r => r.action === 'desktop.update.check')).toHaveLength(1);
  await page.getByRole('button',{name:'Later',exact:true}).click();
  await button.click();
  await expect(page.locator('#update-title')).toHaveText('Checking for updates...');
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await expect(page.locator('#update-panel')).toBeHidden();
  await expect(button).toBeEnabled();
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.pendingAction = undefined; mock.updateError = 'Cannot check the release server.';
  });
  await button.click();
  await expect(page.locator('#update-message')).toHaveText('Cannot check the release server.');
  await returnToWindow(page);
  await expect(page.locator('#update-message')).toHaveText('Cannot check the release server.');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateError = undefined; });
  await page.getByRole('button',{name:'Try again',exact:true}).click();
  await expect(page.locator('#update-title')).toHaveText("You're up to date");
  expect((await requests(page)).filter(r => r.action === 'desktop.update.cancel')).toHaveLength(1);
});

for (const maxWindowHeight of [720,320]) {
  test(`temporary update connection failures stay quiet in ${maxWindowHeight}px work areas`, async ({page}) => {
    const latest = '2026.10.17+c17a882';
    const deferred = {state:'error',latest,error:'Cannot check the release server. The current app was kept.',warning_deferred:true};
    const counts = {tokens:30000,calls:30,priced_calls:30,cost_usd:1};
    await boot(page, {status:converged,maxWindowHeight,updateStatus:deferred,updateCheck:deferred,
      usage:{summary:counts,pending_exports:0,by_model:[{name:'gpt-6-astra',...counts}],by_reasoning_effort:[{name:'xhigh',...counts}]}});
    await expect(page.locator('#usage-tokens')).toHaveText('30 k');
    await expect(page.locator('#update-notice')).toBeHidden();
    await expect(page.locator('#update-guidance')).toBeHidden();
    const button = page.locator('#check-update'), panel = page.locator('#update-panel');
    await button.click();
    await expect(page.locator('#update-title')).toHaveText('Check delayed');
    await expect(page.locator('#update-message')).toContainText('You can try again later.');
    await expect(panel.locator('.overlay-icon.warning, .overlay-icon.success')).toHaveCount(0);
    await expect(panel).not.toContainText("You're up to date");
    await expect(panel).not.toContainText('Contact your administrator');
    expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) expect(await page.locator('#app').evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
    else expect(await page.locator('#app').evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    const retry = page.getByRole('button',{name:'Try again',exact:true});
    await retry.scrollIntoViewIfNeeded();
    await expect(retry).toBeInViewport({ratio:1});
    await page.getByRole('button',{name:'Close',exact:true}).click();
    // Native status changes after the persisted outage exceeds 24 hours.
    await page.evaluate(() => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.updateStatus = {...mock.updateStatus,warning_deferred:false};
    });
    await returnToWindow(page);
    await expect(page.locator('#update-notice')).toHaveText('Update needs attention');
    await expect(page.locator('#update-guidance')).toContainText('Cannot check the release server.');
    // A successful explicit check clears both warning surfaces.
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateCheck = {state:'idle',latest:''}; });
    await button.click();
    await expect(page.locator('#update-title')).toHaveText("You're up to date");
    await expect(page.locator('#update-notice')).toBeHidden();
    await expect(page.locator('#update-guidance')).toBeHidden();
    await page.getByRole('button',{name:'Done',exact:true}).click();
    // Signature and installation failures still warn immediately.
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateStatus = {
      state:'error',latest:'',error:'The updated app failed macOS signature validation. The current app was kept.',
    }; });
    await returnToWindow(page);
    await expect(page.locator('#update-notice')).toHaveText('Update needs attention');
    await expect(page.locator('#update-guidance')).toContainText('signature validation');
  });

  test(`in-app update flow fits populated ${maxWindowHeight}px work areas`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme:maxWindowHeight === 320 ? 'dark' : 'light'});
    const latest = '2026.10.18+a7c91b2';
    const counts = {tokens:30000,calls:30,priced_calls:30,cost_usd:1};
    await boot(page, {status:converged,maxWindowHeight,updateCheck:{state:'available',latest},usage:{summary:counts,pending_exports:0,
      series:Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...counts})),
      by_model:[{name:'gpt-6-astra',...counts}],by_reasoning_effort:[{name:'xhigh',...counts}]}});
    await expect(page.locator('#usage-tokens')).toHaveText('30 k');
    const button = page.locator('#check-update'), panel = page.locator('#update-panel');
    await button.click();
    await expect(page.locator('#update-title')).toHaveText('Update available');
    await expect(page.locator('#update-version')).toHaveText(`Version ${latest}`);
    await expectControlHierarchy(page);
    const update = page.getByRole('button',{name:'Update now',exact:true});
    await expect(update).toBeInViewport({ratio:1});
    await expect.poll(() => panel.evaluate(node => node.scrollHeight - node.clientHeight)).toBe(0);
    expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) expect(await page.locator('#app').evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
    else expect(await page.locator('#app').evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await page.screenshot({path:testInfo.outputPath('update-available.png')});
    await page.getByRole('button',{name:'Later',exact:true}).click();
    expect((await requests(page)).some(r => r.action === 'desktop.update.install')).toBe(false);
    await button.click();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'desktop.update.install'; });
    await update.click();
    await page.evaluate(latest => { (window as unknown as {mock:Mock}).mock.updateStatus = {state:'downloading',latest,downloaded_bytes:10485760,total_bytes:20971520}; },latest);
    await returnToWindow(page);
    await expect(page.locator('#update-percent')).toHaveText('50%');
    await expect(page.locator('#update-bytes')).toHaveText('10.0 MiB of 20.0 MiB');
    await expect(page.getByRole('button',{name:'Cancel download',exact:true})).toBeInViewport({ratio:1});
    await expect.poll(() => panel.evaluate(node => node.scrollHeight - node.clientHeight)).toBe(0);
    await page.screenshot({path:testInfo.outputPath('update-downloading.png')});
    await page.getByRole('button',{name:'Cancel download',exact:true}).click();
    await expect(panel).toBeHidden();
    await expect(button).toBeEnabled();
    expect((await requests(page)).filter(r => r.action === 'desktop.update.install')).toEqual([{action:'desktop.update.install',version:latest}]);
    await page.evaluate(latest => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.pendingAction = undefined; mock.updateCheck = {state:'available',latest};
    }, latest);
    await button.click();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'desktop.update.install'; });
    await update.click();
    await page.evaluate(latest => { (window as unknown as {mock:Mock}).mock.updateStatus = {state:'installing',latest}; },latest);
    await returnToWindow(page);
    await expect(page.locator('#update-title')).toHaveText('Installing update...');
    await expect(page.locator('#close-update')).toBeHidden();
    await expect(page.locator('#update-secondary')).toBeHidden();
    await expect.poll(() => panel.evaluate(node => node.scrollHeight - node.clientHeight)).toBe(0);
    await page.keyboard.press('Escape');
    await expect(panel).toBeVisible();
    await page.screenshot({path:testInfo.outputPath('update-installing.png')});
    await page.evaluate(latest => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.updateInstall = {state:'restarting',latest}; win.completeRequest();
    },latest);
    await expect(page.locator('#update-title')).toHaveText('Restarting OpenAIDR...');
    await expect(page.locator('#update-message')).toHaveText('Finishing the app update.');
  });
}

for (const maxWindowHeight of [720,320]) {
for (const [platform, message] of [
  ['Windows', 'This build does not support in-app updates. Install an OpenAIDR release with update support.'],
  ['Linux', 'In-app updates require a signed, managed AppImage. Update DEB installations with your package manager.'],
]) {
test(`in-app updater explains ${platform} installation limits in ${maxWindowHeight}px work areas and confirms success only after restarting`, async ({page}, testInfo) => {
  const counts = {tokens:30000,calls:30,priced_calls:30,cost_usd:1};
  await boot(page, {status:converged,maxWindowHeight,removalSupported:false,updateCheck:{state:'unavailable',latest:'',error:message},usage:{summary:counts,pending_exports:0,
    series:Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...counts})),
    by_model:[{name:'gpt-6-astra',...counts}],by_reasoning_effort:[{name:'high',...counts}]}});
  await page.locator('#check-update').click();
  await expect(page.locator('#update-title')).toHaveText('In-app updates unavailable');
  await expect(page.locator('#update-notice')).toHaveText('In-app updates unavailable');
  await expect(page.locator('#update-message')).toHaveText(message);
  await expect(page.getByRole('button',{name:'Update now',exact:true})).toBeHidden();
  const panel = page.locator('#update-panel'), close = page.getByRole('button',{name:'Close',exact:true});
  await expect(close).toBeInViewport({ratio:1});
  await expect(page.locator('#update-message')).toBeInViewport({ratio:1});
  expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  if (maxWindowHeight === 720) expect(await page.locator('#app').evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
  else expect(await page.locator('#app').evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
  await page.screenshot({path:testInfo.outputPath('update-unavailable.png')});
  await close.click();
  const version = (await page.locator('#build-info').textContent())!.replace('Ver. ','');
  await page.evaluate(version => {
    localStorage.setItem('openaidr-pending-update',version);
    (window as unknown as {mock:Mock}).mock.updateStatus = {state:'updated',latest:version};
  },version);
  await returnToWindow(page);
  await expect(page.locator('#update-title')).toHaveText('OpenAIDR is up to date');
  await expect(page.locator('#update-version')).toHaveText(`Version ${version}`);
  await page.getByRole('button',{name:'Done',exact:true}).click();
  await returnToWindow(page);
  await expect(page.locator('#update-panel')).toBeHidden();
});
}
}


for (const maxWindowHeight of [720,320]) {
  test(`cached usage periods remain interactive during setup with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
    await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
    const counts = {tokens:30000,calls:30,priced_calls:30,cost_usd:1};
    const populatedUsage = {...usageTotals(30000),
      series:Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...counts,tokens:1000})),
      by_model:[{name:'gpt-6.1-sol',...counts}],by_reasoning_effort:[{name:'high',...counts}]};
    await boot(page, {status:converged,maxWindowHeight,usageByDays:{1:{...populatedUsage,summary:{...counts,tokens:14000}},30:populatedUsage},afterSetup:converged});
    await expect(page.locator('#usage-tokens')).toHaveText('30 k');
    await page.evaluate(() => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.status = {...mock.status,telemetry:{...mock.status.telemetry as object,claude_current:false}};
      mock.pendingAction = 'setup';
    });
    await returnToWindow(page);
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
    await expect(page.locator('#notice')).toHaveText('Setting up this device…');
    const shortPeriod = page.getByRole('button', {name:'24 hours',exact:true});
    const longPeriod = page.getByRole('button', {name:'30 days',exact:true});
    await expect(shortPeriod).toBeEnabled();
    await shortPeriod.click();
    await expect(page.locator('#usage-tokens')).toHaveText('14 k');
    await page.clock.setSystemTime(new Date('2026-10-07T12:02:00Z'));
    await longPeriod.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#usage-range')).toHaveText('Last 30 days');
    await expect(page.locator('#usage-tokens')).toHaveText('30 k');
    await shortPeriod.focus();
    await page.keyboard.press('Space');
    await expect(page.locator('#usage-range')).toHaveText('Last 24 hours');
    await expect(page.locator('#usage-tokens')).toHaveText('14 k');
    await expect(shortPeriod).toBeFocused();
    await expect(shortPeriod).toBeInViewport({ratio:1});
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else {
      const app = page.locator('#app');
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    }
    await page.screenshot({path:testInfo.outputPath('cached-usage-during-setup.png')});
    expect((await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30]);
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeDisabled();
    await expect(page.getByRole('button', {name:'Uninstall',exact:true})).toBeDisabled();
    await page.getByRole('button', {name:'Check updates',exact:true}).click();
    expect((await requests(page)).filter(r => r.action === 'desktop.update.check')).toEqual([{action:'desktop.update.check'}]);
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined;
      win.mock.usageByDays![1].summary = {tokens:28000,calls:30,priced_calls:30,cost_usd:1};
      win.completeRequest();
    });
    await expect(page.locator('#notice')).toBeHidden();
    await expect(page.locator('#usage-tokens')).toHaveText('28 k');
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeEnabled();
    await page.getByRole('button', {name:'Settings',exact:true}).focus();
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeInViewport({ratio:1});
    expect((await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30,1]);
  });
}

test('setup accepts pending usage without reading missing periods and restores reads after failure', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  await boot(page, {status:converged,legacyUsage:true,usageByDays:{1:usageTotals(70),30:usageTotals(300)},pendingUsageDays:30,
    setupError:'The sensor setup could not finish.'});
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30]);
  const shortPeriod = page.getByRole('button', {name:'24 hours',exact:true});
  const longPeriod = page.getByRole('button', {name:'30 days',exact:true});
  await shortPeriod.click();
  await longPeriod.click();
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void;completeUsage:() => void};
    win.completeUsage = win.completeRequest;
    win.mock.pendingUsageDays = undefined;
    win.mock.pendingAction = 'setup';
    win.mock.status = {...win.mock.status,telemetry:{...win.mock.status.telemetry as object,claude_current:false}};
  });
  await returnToWindow(page);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  await expect(shortPeriod).toBeDisabled();
  await expect(longPeriod).toBeDisabled();
  await page.evaluate(() => (window as unknown as {completeUsage:() => void}).completeUsage());
  await expect(longPeriod).toBeEnabled();
  await expect(shortPeriod).toBeDisabled();
  await longPeriod.click();
  await expect(page.locator('#usage-tokens')).toHaveText('300');
  await expect(page.locator('#notice')).toHaveText('Setting up this device…');
  expect((await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30]);
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingAction = undefined;
    win.completeRequest();
  });
  await expect(page.locator('#health-title')).toHaveText('Setup needs attention');
  await expect(shortPeriod).toBeEnabled();
  await shortPeriod.click();
  await expect(page.locator('#usage-tokens')).toHaveText('70');
  expect((await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30,1]);
});

test('usage refreshes each second while focused, slows on blur, and pauses in the tray', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  await boot(page, {status:converged,usageByDays:{1:usageTotals(70),30:usageTotals(300)}});
  await expect(page.locator('#usage-tokens')).toHaveText('300');
  await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.usageByDays![30] = usage; }, usageTotals(400));
  await page.clock.fastForward(999);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(1);
  await page.clock.fastForward(1);
  await expect(page.locator('#usage-tokens')).toHaveText('400');
  expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(1);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await page.evaluate(() => window.dispatchEvent(new Event('blur')));
  await page.clock.fastForward(9999);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await page.clock.fastForward(1);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(3);
  await page.clock.fastForward(1000);
  await returnToWindow(page);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(4);
  await page.clock.fastForward(1000);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(5);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:false})));
  await page.clock.fastForward(60000);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(5);
  await page.evaluate(usage => {
    (window as unknown as {mock:Mock}).mock.usageByDays![30] = usage;
    window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:true}));
  }, usageTotals(500));
  await expect(page.locator('#usage-tokens')).toHaveText('500');
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(6);
});

test('usage waits for slow reads and preserves an unchanged chart and tooltip', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  await boot(page, {status:converged,usage:populatedUsage()});
  const day = page.locator('#usage-chart .usage-day').last();
  await day.hover();
  await expect(page.locator('#usage-tooltip')).toBeVisible();
  const bar = await day.elementHandle();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingUsageDays = 30; });
  await page.clock.runFor(1000);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await returnToWindow(page);
  await page.clock.runFor(5000);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingUsageDays = undefined;
    win.mock.usageUntil = '2026-10-07T12:30:06Z';
    win.completeRequest();
  });
  await page.clock.runFor(999);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await page.clock.runFor(1);
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(3);
  expect(await bar!.evaluate(node => node.isConnected)).toBe(true);
  await expect(page.locator('#usage-tooltip')).toBeVisible();
  await expect(page.locator('#usage-tooltip')).toContainText('$42.18');
  await bar!.dispose();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.usageError = 'Read failed.'; });
  await page.clock.fastForward(1000);
  await expect(page.locator('#usage-message')).toContainText('Showing previously loaded usage.');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.usageError = undefined; });
  await page.clock.fastForward(1000);
  await expect(page.locator('#usage-message')).toBeHidden();
  await expect(page.locator('#usage-content')).toBeVisible();
});

function usageWithCurrentCost(cost_usd:number|null) {
  const usage = populatedUsage();
  const counts = {...usage.summary,cost_usd,priced_calls:cost_usd === null ? 0 : usage.summary.calls};
  return {...usage,summary:counts,series:usage.series.map((day,i) => i === 29 ? {...day,...counts} : day),
    by_model:[{name:'gpt-6.1-sol',...counts}],by_reasoning_effort:[{name:'high',...counts}]};
}

for (const days of [30,1] as const) {
  test(`current usage cost interpolates within 300ms in the ${days}-day view`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
    await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
    const maxWindowHeight = days === 30 ? 720 : 320;
    await boot(page, {status:converged,maxWindowHeight,usage:usageWithCurrentCost(1)});
    if (days === 1) await page.getByRole('button', {name:'24 hours',exact:true}).click();
    const current = page.locator('#usage-current');
    await expect(current).toHaveText('$1.00');
    await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.usage = usage; }, usageWithCurrentCost(2));
    await page.clock.fastForward(1000);
    await expect(page.locator('#usage-cost')).toHaveText('$2.00');
    await expect(current).toHaveText('$1.00');
    await page.clock.runFor(100);
    const amount = async () => Number((await current.textContent())!.slice(1));
    expect(await amount()).toBeGreaterThan(1);
    expect(await amount()).toBeLessThan(2);
    if (days === 30) await page.screenshot({path:testInfo.outputPath('usage-cost-transition.png')});
    await page.clock.runFor(200);
    await expect(current).toHaveText('$2.00');

    await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.usage = usage; }, usageWithCurrentCost(4));
    await page.clock.fastForward(700);
    await expect(page.locator('#usage-cost')).toHaveText('$4.00');
    await page.clock.runFor(100);
    const before = await amount();
    expect(before).toBeGreaterThan(2);
    expect(before).toBeLessThan(4);
    await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.usage = usage; }, usageWithCurrentCost(5));
    await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 10000));
    await returnToWindow(page);
    await expect(page.locator('#usage-cost')).toHaveText('$5.00');
    expect(await amount()).toBe(before);
    await page.clock.runFor(100);
    expect(await amount()).toBeGreaterThan(before);
    expect(await amount()).toBeLessThan(5);
    await page.clock.runFor(200);
    await expect(current).toHaveText('$5.00');
    await page.clock.runFor(1000);
    await expect(current).toHaveText('$5.00');

    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    await current.scrollIntoViewIfNeeded();
    await expect(current).toBeInViewport({ratio:1});
    if (maxWindowHeight === 320) expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeInViewport({ratio:1});
    await expect(page.getByRole('button', {name:'Check updates',exact:true})).toBeInViewport({ratio:1});
  });

  test(`current usage cost resets for period, bucket, device, and price changes in the ${days}-day view`, async ({page}) => {
    await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
    await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
    await boot(page, {status:converged,usageByDays:{
      30:usageWithCurrentCost(days === 30 ? 1 : 7),1:usageWithCurrentCost(days === 1 ? 1 : 7),
    }});
    const period = page.getByRole('button', {name:days === 1 ? '24 hours' : '30 days',exact:true});
    await period.click();
    const current = page.locator('#usage-current');
    await expect(current).toHaveText('$1.00');
    const progressing = async (from:number, to:number) => {
      await page.clock.runFor(100);
      const value = Number((await current.textContent())!.slice(1));
      expect(value).toBeGreaterThan(from); expect(value).toBeLessThan(to);
    };
    const refreshCost = async (cost:number|null, date?:string) => {
      const usage = usageWithCurrentCost(cost);
      if (date) usage.series.at(-1)!.date = date;
      await page.evaluate(({days,usage}) => { (window as unknown as {mock:Mock}).mock.usageByDays![days] = usage; }, {days,usage});
      await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 10000));
      await returnToWindow(page);
      await expect(page.locator('#usage-cost')).toHaveText(cost === null ? 'N/A' : `$${cost.toFixed(2)}`);
    };
    await refreshCost(2);
    await progressing(1, 2);
    await page.getByRole('button', {name:days === 30 ? '24 hours' : '30 days',exact:true}).click();
    await expect(current).toHaveText('$7.00');
    await page.clock.runFor(1000);
    await expect(current).toHaveText('$7.00');
    await period.click();
    await expect(current).toHaveText('$2.00');

    await refreshCost(4);
    await progressing(2, 4);
    await refreshCost(null);
    await expect(current).toHaveText('N/A');
    await page.clock.runFor(1000);
    await expect(current).toHaveText('N/A');
    await refreshCost(6);
    await expect(current).toHaveText('$6.00');
    await refreshCost(10);
    await progressing(6, 10);
    await refreshCost(7);
    await expect(current).toHaveText('$7.00');
    await page.clock.runFor(1000);
    await expect(current).toHaveText('$7.00');

    await refreshCost(9);
    await progressing(7, 9);
    const date = days === 1 ? '2026-10-07T13:00:00Z' : '2026-10-08';
    await refreshCost(20, date);
    await expect(current).toHaveText('$20.00');
    await refreshCost(30, date);
    await progressing(20, 30);
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.status.sensor_id = 'sensor-2'; });
    await refreshCost(40, date);
    await expect(current).toHaveText('$40.00');
    await page.clock.runFor(1000);
    await expect(current).toHaveText('$40.00');
  });
}

test('current usage cost settles on errors, tray hiding, and reduced motion', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  await page.emulateMedia({reducedMotion:'reduce'});
  await boot(page, {status:converged,usage:usageWithCurrentCost(1)});
  const current = page.locator('#usage-current');
  await expect(current).toHaveText('$1.00');
  await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.usage = usage; }, usageWithCurrentCost(2));
  await page.clock.fastForward(1000);
  await expect(current).toHaveText('$2.00');
  await page.evaluate(() => {
    (window as unknown as {motionPreferenceChanged:Promise<void>}).motionPreferenceChanged = new Promise(resolve => {
      matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', () => resolve(), {once:true});
    });
  });
  await page.emulateMedia({reducedMotion:'no-preference'});
  await page.evaluate(() => (window as unknown as {motionPreferenceChanged:Promise<void>}).motionPreferenceChanged);
  await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.usage = usage; }, usageWithCurrentCost(4));
  await page.clock.fastForward(1000);
  await expect(page.locator('#usage-cost')).toHaveText('$4.00');
  await page.clock.runFor(100);
  expect(Number((await current.textContent())!.slice(1))).toBeGreaterThan(2);
  expect(Number((await current.textContent())!.slice(1))).toBeLessThan(4);
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.usageError = 'The local usage read failed.'; });
  await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 10000));
  await returnToWindow(page);
  await expect(page.locator('#usage-message')).toContainText('Showing previously loaded usage.');
  await expect(current).toHaveText('$4.00');
  await page.evaluate(usage => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.usageError = undefined; mock.usage = usage;
  }, usageWithCurrentCost(6));
  await page.clock.fastForward(1000);
  await expect(page.locator('#usage-cost')).toHaveText('$6.00');
  await page.clock.runFor(100);
  expect(Number((await current.textContent())!.slice(1))).toBeGreaterThan(4);
  expect(Number((await current.textContent())!.slice(1))).toBeLessThan(6);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:false})));
  await expect(current).toHaveText('$6.00');
  const reads = (await requests(page)).filter(r => r.action === 'usage.summary').length;
  await page.clock.fastForward(60000);
  await expect(current).toHaveText('$6.00');
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(reads);
  await page.evaluate(usage => {
    (window as unknown as {mock:Mock}).mock.usage = usage;
    window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:true}));
  }, usageWithCurrentCost(7));
  await expect(page.locator('#usage-cost')).toHaveText('$7.00');
  await page.clock.runFor(100);
  expect(Number((await current.textContent())!.slice(1))).toBeGreaterThan(6);
  expect(Number((await current.textContent())!.slice(1))).toBeLessThan(7);
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.clock.runFor(1000);
  await expect(current).toHaveText('$7.00');
});

test('usage caches both periods and refreshes stale charts in the background', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  await boot(page, {status:converged,usageByDays:{1:usageTotals(70),30:usageTotals(300)}});
  await expect(page.locator('#usage-tokens')).toHaveText('300');
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30]);
  await page.getByRole('button', {name:'24 hours',exact:true}).click();
  await expect(page.locator('#usage-tokens')).toHaveText('70');
  await page.evaluate(usage => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.pendingUsageDays = 1;
    mock.usageByDays![1] = usage;
  }, usageTotals(140));
  for (const days of [30,1,1]) {
    await page.getByRole('button', {name:days === 1 ? '24 hours' : '30 days',exact:true}).click();
    await expect(page.locator('#usage-content')).toBeVisible();
    await expect(page.locator('#usage-range')).toHaveText(days === 1 ? 'Last 24 hours' : 'Last 30 days');
    await expect(page.locator('#usage-tokens')).toHaveText(days === 1 ? '70' : '300');
  }
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(1);
  const focusedDay = page.locator('#usage-chart').getByRole('img').last();
  await focusedDay.focus();
  await expect(page.getByRole('tooltip')).toBeVisible();
  await page.clock.fastForward(61000);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30,1]);
  await expect(page.locator('#usage-content')).toBeVisible();
  await expect(page.locator('#usage-tokens')).toHaveText('70');
  await expect(page.locator('#usage-message')).toBeHidden();
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingUsageDays = undefined;
    win.completeRequest();
  });
  await expect(page.locator('#usage-tokens')).toHaveText('140');
  await expect(focusedDay).toBeFocused();
  await expect(page.getByRole('tooltip')).toContainText('Oct 7');
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30,1]);
});

test('usage shares the initial request when periods change before loading finishes', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  await boot(page, {status:converged,usageByDays:{1:usageTotals(70),30:usageTotals(300)},pendingUsageDays:30});
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(1);
  for (const days of [1,30,1]) {
    await page.getByRole('button', {name:days === 1 ? '24 hours' : '30 days',exact:true}).click();
    await expect(page.locator('#usage-content')).toBeHidden();
    await expect(page.locator('#usage-message')).toHaveText('Loading usage…');
  }
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(1);
  await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
  await expect(page.locator('#usage-tokens')).toHaveText('70');
  await expect(page.locator('#usage-range')).toHaveText('Last 24 hours');
  await page.getByRole('button', {name:'30 days',exact:true}).click();
  await expect(page.locator('#usage-tokens')).toHaveText('300');
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(1);
});

for (const usagePeriods of [{}, {1:{days:1,summary:{tokens:999}}}]) {
  test(`usage falls back when the alternate period is ${Object.keys(usagePeriods).length ? 'invalid' : 'missing'}`, async ({page}) => {
    await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
    await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
    await boot(page, {status:converged,usageByDays:{1:usageTotals(70),30:usageTotals(300)},usagePeriods});
    await expect(page.locator('#usage-tokens')).toHaveText('300');
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30,1]);
    await page.getByRole('button', {name:'24 hours',exact:true}).click();
    await expect(page.locator('#usage-tokens')).toHaveText('70');
    await expect(page.locator('#usage-message')).toBeHidden();
  });
}

for (const maxWindowHeight of [720,320]) {
  test(`usage refresh preserves the focused date and tooltip with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
    await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
    const counts = (tokens:number) => ({tokens,output_tokens:tokens,calls:1,priced_calls:1,cost_usd:tokens / 100000});
    const series = Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...counts(1000)}));
    await boot(page, {status:converged,maxWindowHeight,usage:{summary:counts(30000),series,pending_exports:0,
      by_model:[{name:'gpt-6.1-sol',...counts(30000)}],by_reasoning_effort:[{name:'high',...counts(30000)}]}});
    await expect(page.locator('#usage-tokens')).toHaveText('30 k');
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(1);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    const app = page.locator('#app');
    const focusedDay = page.locator('#usage-chart').getByRole('img', {name:/^Oct 6:/});
    const tooltip = page.getByRole('tooltip');
    await focusedDay.focus();
    await expect(tooltip).toContainText('Estimated cost$0.01');
    if (maxWindowHeight === 320) await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
    const scrollTop = await app.evaluate(node => node.scrollTop);
    if (maxWindowHeight === 320) expect(scrollTop).toBeGreaterThan(0);
    await page.evaluate(series => {
      const usage = (window as unknown as {mock:Mock}).mock.usage!;
      usage.series = series;
      usage.summary = {...usage.summary as object,tokens:60000,cost_usd:0.6};
    }, [...series.slice(1).map(day => ({...day,...counts(2000)})),{date:'2026-10-08',...counts(2000)}]);
    await page.clock.fastForward(61000);
    await expect(page.locator('#usage-tokens')).toHaveText('60 k');
    await expect(focusedDay).toBeFocused();
    await expect(focusedDay).toHaveAccessibleName('Oct 6: $0.02 estimated cost.');
    await expect(tooltip).toContainText('Oct 6');
    await expect(tooltip).toContainText('Estimated cost$0.02');
    expect(await app.evaluate(node => node.scrollTop)).toBe(scrollTop);
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('usage-focus-after-refresh.png'),fullPage:true});

    await returnToWindow(page);
    await expect(focusedDay).toBeFocused();
    await expect(tooltip).toBeVisible();
    await page.keyboard.press('Escape');
    await returnToWindow(page);
    await expect(focusedDay).toBeFocused();
    await expect(tooltip).toBeHidden();

    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingUsageDays = 30; });
    const reads = (await requests(page)).filter(r => r.action === 'usage.summary' && r.days === 30).length;
    await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 61000));
    await returnToWindow(page);
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary' && r.days === 30).length).toBe(reads + 1);
    const period = page.getByRole('button', {name:'24 hours',exact:true});
    await period.focus();
    await expect(period).toBeInViewport({ratio:1});
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingUsageDays = undefined;
      win.completeRequest();
    });
    await expect(period).toBeFocused();
    await expect(tooltip).toBeHidden();

    await page.locator('#usage-chart').getByRole('img').first().focus();
    await page.evaluate(() => {
      const usage = (window as unknown as {mock:Mock}).mock.usage!;
      const series = usage.series as {date:string}[];
      usage.series = [...series.slice(1),{...series.at(-1),date:'2026-10-09'}];
    });
    await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 61000));
    await returnToWindow(page);
    await expect(page.locator('#usage-chart').getByRole('img').first()).toHaveAccessibleName(/^Sep 10:/);
    await expect(page.locator('body')).toBeFocused();
    await expect(tooltip).toBeHidden();

    await focusedDay.focus();
    await page.evaluate(() => {
      const usage = (window as unknown as {mock:Mock}).mock.usage!;
      const empty = {tokens:0,output_tokens:0,calls:0,priced_calls:0,cost_usd:0};
      usage.summary = empty;
      usage.series = (usage.series as Record<string,unknown>[]).map(day => ({...day,...empty}));
      usage.by_model = []; usage.by_reasoning_effort = [];
    });
    await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 61000));
    await returnToWindow(page);
    await expect(page.locator('#usage-tokens')).toHaveText('0');
    await expect(page.locator('#usage-content')).toBeVisible();
    await expect(focusedDay).toBeFocused();
    await expect(tooltip).toContainText('Estimated cost$0.00');
  });
}

test('legacy usage preserves cached charts and refresh errors across period reads', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  await boot(page, {status:converged,legacyUsage:true,usageByDays:{1:usageTotals(70),30:usageTotals(300)},pendingUsageDays:1});
  await expect(page.locator('#usage-tokens')).toHaveText('300');
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  for (let i = 0; i < 2; i++) {
    await page.getByRole('button', {name:'24 hours',exact:true}).click();
    await expect(page.locator('#usage-content')).toBeHidden();
    await expect(page.locator('#usage-message')).toHaveText('Loading usage…');
    await page.getByRole('button', {name:'30 days',exact:true}).click();
    await expect(page.locator('#usage-content')).toBeVisible();
    await expect(page.locator('#usage-tokens')).toHaveText('300');
  }
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
  await expect(page.locator('#usage-range')).toHaveText('Last 30 days');
  await page.getByRole('button', {name:'24 hours',exact:true}).click();
  await expect(page.locator('#usage-tokens')).toHaveText('70');
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);

  await page.getByRole('button', {name:'30 days',exact:true}).click();
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.pendingUsageDays = undefined;
    mock.usageErrorsByDays = {30:'The local usage read failed.'};
    mock.usageByDays![1].summary = {tokens:140,calls:1,priced_calls:1,cost_usd:1};
  });
  await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 61000));
  await returnToWindow(page);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').map(r => r.days)).toEqual([30,1,30,1]);
  await expect(page.locator('#usage-tokens')).toHaveText('300');
  await expect(page.locator('#usage-message')).toHaveText('Showing previously loaded usage. The local usage read failed.');
  await page.getByRole('button', {name:'24 hours',exact:true}).click();
  await expect(page.locator('#usage-tokens')).toHaveText('140');
  await expect(page.locator('#usage-message')).toBeHidden();
});

test('usage clears cached periods on device changes and ignores old responses', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  await boot(page, {status:converged,usageByDays:{1:usageTotals(70),30:usageTotals(300)},pendingUsageDays:30});
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(1);
  await page.evaluate(usageByDays => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void;oldRequest:() => void};
    win.oldRequest = win.completeRequest;
    const mock = win.mock;
    mock.status = {...mock.status,sensor_id:'sensor-2'};
    mock.usageByDays = usageByDays;
  }, {1:usageTotals(140),30:usageTotals(600)});
  await returnToWindow(page);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await page.evaluate(() => (window as unknown as {oldRequest:() => void}).oldRequest());
  await page.getByRole('button', {name:'24 hours',exact:true}).click();
  await expect(page.locator('#usage-content')).toBeHidden();
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingUsageDays = undefined;
    win.completeRequest();
  });
  await expect(page.locator('#usage-tokens')).toHaveText('140');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.status.disabled = true; });
  await returnToWindow(page);
  await expect(page.locator('#usage-panel')).toBeHidden();
  await expect(page.locator('#usage-content')).toBeHidden();
  expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(2);
  await page.evaluate(usage => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.status.disabled = false;
    mock.usageByDays![1] = usage;
  }, usageTotals(210));
  await returnToWindow(page);
  await expect(page.locator('#usage-tokens')).toHaveText('210');
  await expect(page.locator('#usage-content')).toBeVisible();
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(3);
});

async function expectControlHierarchy(page: Page) {
  await page.mouse.move(0, 0);
  await expect.poll(() => page.locator('button:visible, summary:visible').evaluateAll(elements => elements.flatMap(element => {
    const style = getComputedStyle(element);
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    // The status chip is a neutral surface (hover color while its popover is open); only its icon carries the exact brand status color.
    if (element.id === 'sensor-status') {
      const icon = getComputedStyle(element.querySelector('.status-icon')!).backgroundColor;
      const loading = element.classList.contains('loading');
      const surface = element.getAttribute('aria-expanded') === 'true' ? (dark ? 'rgb(26, 43, 77)' : 'rgb(233, 236, 241)') : (dark ? 'rgb(18, 33, 63)' : 'rgb(255, 255, 255)');
      return style.backgroundColor === surface && style.color === (dark ? 'rgb(230, 234, 241)' : 'rgb(28, 34, 48)')
        && (loading || ['rgb(60, 114, 61)', 'rgb(150, 77, 9)', 'rgb(135, 36, 32)'].includes(icon)) ? [] : [{control:element.id,background:style.backgroundColor,color:style.color,icon}];
    }
    // Period choices are a segmented control: a raised thumb marks the selection.
    if (element.matches('.usage-period button, .app-pages button')) {
      const navigation = element.matches('.app-pages button');
      const pressed = element.getAttribute(navigation ? 'aria-selected' : 'aria-pressed') === 'true';
      const expected = pressed ? {background:dark ? 'rgb(42, 63, 104)' : 'rgb(255, 255, 255)',color:dark ? 'rgb(230, 234, 241)' : 'rgb(28, 34, 48)'} : {background:'rgba(0, 0, 0, 0)',color:dark ? 'rgb(154, 166, 184)' : 'rgb(90, 99, 114)'};
      if (navigation && pressed) expected.color = dark ? 'rgb(111, 155, 230)' : 'rgb(23, 55, 111)';
      return style.backgroundColor === expected.background && style.color === expected.color && element.getBoundingClientRect().height >= 28 ? [] : [{control:element.textContent,background:style.backgroundColor,color:style.color}];
    }
    if (element.matches('.usage-cost-info')) {
      const {width,height} = element.getBoundingClientRect();
      return style.backgroundColor === 'rgba(0, 0, 0, 0)' && style.color === (dark ? 'rgb(154, 166, 184)' : 'rgb(90, 99, 114)')
        && width === 16 && height === 16 && style.boxShadow === 'none'
        ? [] : [{control:element.getAttribute('aria-label'),background:style.backgroundColor,color:style.color,width,height}];
    }
    const close = ['close-status','close-connection','close-update','close-about','simulation-dismiss'].includes(element.id);
    const creditDisclosure = element.matches('.credit-disclosure, #sensor-details > summary');
    const disclosure = creditDisclosure || element.matches('summary');
    const secondary = ['back-to-choices','choose-organization','choose-local-runtime','local-back','local-check','local-credentials','local-done','change-connection','remove-app','check-update','show-about','update-secondary','cancel-change','remove-certificate','cancel-remove','resume-app','show-simulation','simulation-close'].includes(element.id);
    const destructive = element.id === 'trash-app' || (element.id === 'confirm-remove' && /^(Uninstall|Delete)/.test(element.textContent || ''));
    const background = close || disclosure ? 'rgba(0, 0, 0, 0)' : secondary ? (dark ? 'rgb(15, 29, 56)' : 'rgb(247, 248, 250)') : destructive ? 'rgb(135, 36, 32)' : 'rgb(23, 55, 111)';
    const color = creditDisclosure ? (dark ? 'rgb(111, 155, 230)' : 'rgb(23, 55, 111)') : close || disclosure ? (dark ? 'rgb(154, 166, 184)' : 'rgb(90, 99, 114)') : secondary ? (dark ? 'rgb(230, 234, 241)' : 'rgb(28, 34, 48)') : 'rgb(255, 255, 255)';
    const {width,height} = element.getBoundingClientRect();
    const accessibleSize = element.matches('#retained-data-details summary') || height >= 32;
    const consistentClose = !close || (width === 32 && height === 32 && style.fontSize === '22px' && style.fontWeight === '400' && style.boxShadow === 'none');
    return style.backgroundColor === background && style.color === color && accessibleSize && consistentClose
      ? [] : [{control:element.id || element.textContent,background:style.backgroundColor,color:style.color,width,height}];
  }))).toEqual([]);
}

for (const colorScheme of ['light', 'dark'] as const) {
  test(`controls distinguish actions and use consistent close buttons in ${colorScheme} mode`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme});
    const counts = {tokens:312060,calls:9,priced_calls:9,cost_usd:.68};
    await boot(page, {status:converged,preview,usage:{summary:counts,pending_exports:0,
      series:Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...counts,tokens:i === 29 ? counts.tokens : 0})),
      by_model:[{name:'claude-opus-5-5',...counts}],by_reasoning_effort:[{name:'medium',...counts}],baseline:{status:'insufficient_data'}}});
    await expect(page.locator('#usage-tokens')).toHaveText('312 k');
    await expectControlHierarchy(page);
    await page.getByRole('button', {name:'24 hours',exact:true}).click();
    await expect(page.locator('#usage-range')).toHaveText('Last 24 hours');
    await expectControlHierarchy(page);
    await expect(page.getByRole('button', {name:'24 hours',exact:true})).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByRole('button', {name:'30 days',exact:true})).toHaveAttribute('aria-pressed', 'false');
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath(`buttons-status-${colorScheme}.png`)});
    await page.locator('#sensor-status').click();
    await expect(page.locator('#sensor-status')).toHaveAttribute('aria-expanded', 'true');
    // Wait for the open-state background so the hierarchy check reads the settled color, not a transition frame.
    await expect(page.locator('#sensor-status')).toHaveCSS('background-color', colorScheme === 'dark' ? 'rgb(26, 43, 77)' : 'rgb(233, 236, 241)');
    await expectControlHierarchy(page);
    await expect(page.getByRole('button', {name:'Close sensor status'})).toBeInViewport({ratio:1});
    for (const disclosure of [page.locator('#free-plan-toggle'),page.locator('#sensor-details > summary')]) {
      await disclosure.hover();
      await expect(disclosure).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
      await expect(disclosure).toHaveCSS('color', colorScheme === 'dark' ? 'rgb(111, 155, 230)' : 'rgb(23, 55, 111)');
    }
    await page.keyboard.press('Escape');

    const connection = page.getByRole('button', {name:'Settings',exact:true});
    await connection.hover();
    await expect(connection).toHaveCSS('background-color', colorScheme === 'dark' ? 'rgb(26, 43, 77)' : 'rgb(233, 236, 241)');
    const remove = page.getByRole('button', {name:'Uninstall',exact:true});
    await remove.focus();
    await page.keyboard.press('Shift+Tab');
    await expect(connection).toBeFocused();
    await expect(connection).toHaveCSS('outline-style', 'solid');
    await expect(connection).toHaveCSS('outline-width', '2px');

    await connection.click();
    const connect = page.getByRole('button', {name:'Connect',exact:true});
    await expect(connect).toBeDisabled();
    await expect(connect).toHaveCSS('opacity', '0.45');
    await expectControlHierarchy(page);
    await page.getByRole('button', {name:'Close Settings'}).focus();
    await page.keyboard.press('Tab');
    await page.keyboard.press('Shift+Tab');
    await expect(page.getByRole('button', {name:'Close Settings'})).toBeFocused();
    await expect(page.getByRole('button', {name:'Close Settings'})).toHaveCSS('outline-style', 'solid');
    const certificateOptions = page.locator('#certificate-options summary');
    await certificateOptions.focus();
    await page.keyboard.press('Enter');
    const file = page.getByLabel('Organization CA certificate', {exact:true});
    await expect(file).toBeVisible();
    expect(await file.evaluate(element => {
      const style = getComputedStyle(element, '::file-selector-button');
      return {background:style.backgroundColor,color:style.color};
    })).toEqual(colorScheme === 'dark' ? {background:'rgb(15, 29, 56)',color:'rgb(230, 234, 241)'} : {background:'rgb(247, 248, 250)',color:'rgb(28, 34, 48)'});
    await page.getByLabel('Enrollment link', {exact:true}).fill(link);
    await file.setInputFiles({name:'organization.pem',mimeType:'application/x-pem-file',buffer:Buffer.from(certificate)});
    await expect(connect).toBeEnabled();
    await expectControlHierarchy(page);
    const dialog = page.getByRole('dialog', {name:'Settings'});
    await expect(dialog).toBeInViewport({ratio:1});
    expect(await dialog.evaluate(node => node.scrollHeight <= node.clientHeight && node.scrollWidth <= node.clientWidth)).toBe(true);
    await connect.focus();
    await expect(connect).toBeInViewport({ratio:1});
    await page.getByRole('button', {name:'Done',exact:true}).focus();
    await expect(page.getByRole('button', {name:'Done',exact:true})).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath(`buttons-connection-${colorScheme}.png`)});
    await page.getByRole('button', {name:'Done',exact:true}).click();
    await expect(connection).toBeFocused();
    await expectFitsWindow(page);
    await remove.click();
    await expect(page.getByRole('dialog', {name:'Uninstall OpenAIDR?'})).toBeVisible();
    await expectControlHierarchy(page);
    await page.screenshot({path:testInfo.outputPath(`buttons-removal-${colorScheme}.png`)});
    await page.getByRole('button', {name:'Cancel',exact:true}).click();
    await expect(page.getByRole('dialog')).toBeHidden();
  });
}

for (const colorScheme of ['light', 'dark'] as const) {
  test(`status popover shows all details and recovers through three colors in ${colorScheme} mode`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme});
    await page.clock.install({time:new Date('2026-10-08T02:50:00Z')});
    const healthy = {...converged,tenant_name:'Example organization',heartbeat:{last_success_at:'2026-10-08T02:50:00Z',error:''},activity:{queue_depth:0},telemetry:{...converged.telemetry,codex_available:true,codex_current:true,received:1247341,forwarded:1248023,queue_depth:1}};
    const counts = {tokens:279440000,calls:100,priced_calls:99,cost_usd:169.13};
    await boot(page, {status:healthy,maxWindowHeight:720,usage:{summary:counts,pending_exports:0,source:'local',history_incomplete:true,
      by_model:[{name:'gpt-6-astra',...counts}],by_reasoning_effort:[{name:'unknown',...counts}],
      series:Array.from({length:30},(_,i) => ({...counts,tokens:i === 29 ? counts.tokens : 0,date:new Date(Date.UTC(2026,8,9+i)).toISOString().slice(0,10)}))}});
    const trigger = page.locator('#sensor-status');
    const panel = page.locator('#health-card');
    await expect(page.locator('#usage-tokens')).toHaveText('279 M');
    await expect(trigger).toHaveAccessibleName('Sensor status: Connected');
    await expect(trigger.locator('.status-icon')).toHaveCSS('background-color','rgb(60, 114, 61)');
    await expect(panel).toBeHidden();
    await expectFitsWindow(page);
    const chart = await page.locator('#usage-chart').boundingBox();
    const right = await trigger.evaluate(node => node.getBoundingClientRect().right);
    expect(right).toBeCloseTo(page.viewportSize()!.width - 12, 1);
    await page.screenshot({path:testInfo.outputPath(`status-green-closed-${colorScheme}.png`)});
    await trigger.focus();
    await page.keyboard.press('Enter');
    await expect(panel).toBeVisible();
    await expect(trigger).toHaveAttribute('aria-expanded','true');
    await expect(page.locator('#close-status')).toBeFocused();
    await expect(page.locator('#sensor-details')).not.toHaveAttribute('open', '');
    await page.locator('#sensor-details summary').click();
    await expect(page.locator('#sensor-state')).toHaveText('Running');
    await expect(page.locator('#server-state')).toHaveText('Connected');
    await expect(page.locator('#health-description')).toHaveText('The sensor is running and connected to Example organization.');
    await expect(page.locator('#connected-agents')).toHaveText('Codex, Claude Code');
    await expect(page.getByText('Last successful contact', {exact:true})).toHaveCount(0);
    await expect(page.locator('#collection-guidance')).toBeHidden();
    for (const id of ['delivery','sent','queued','activity-queued']) await expect(page.locator(`#${id}`)).toBeVisible();
    await expect(page.locator('#delivery')).toHaveText('1,247,341');
    await expect(page.locator('#sent')).toHaveText('1,248,023');
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,live:{queue_depth:12},telemetry:{...healthy.telemetry,queue_depth:null,last_error:null}});
    await returnToWindow(page);
    await expect(trigger).toHaveAccessibleName('Sensor status: Connected');
    await expect(page.locator('#queued')).toHaveText('N/A');
    await expect(page.locator('#delivery')).toHaveText('1,247,341');
    await expect(page.locator('#retry-row')).toBeHidden();
    expect((await requests(page)).filter(request => request.action === 'setup')).toHaveLength(0);
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,live:{queue_depth:12},telemetry:{...healthy.telemetry,queue_depth:undefined}});
    await returnToWindow(page);
    await expect(page.locator('#queued')).toHaveText('12');
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, healthy);
    await returnToWindow(page);
    await expect(page.locator('#queued')).toHaveText('1');
    await expectFitsWindow(page);
    expect(await page.locator('#usage-chart').boundingBox()).toEqual(chart);
    expect(await panel.evaluate(node => node.getBoundingClientRect().right)).toBeCloseTo(right, 1);
    expect(await page.locator('main button:visible:not(.usage-period button, .app-pages button, .usage-cost-info), .usage-period:visible, .app-pages:visible').evaluateAll(nodes => [...new Set(nodes.map(node => node.getBoundingClientRect().height))])).toEqual([32]);
    await page.screenshot({path:testInfo.outputPath(`status-green-open-${colorScheme}.png`)});
    await page.keyboard.press('Escape');
    await expect(panel).toBeHidden();
    await expect(trigger).toBeFocused();
    await trigger.click();
    await trigger.click();
    await expect(panel).toBeHidden();
    await trigger.click();
    await page.locator('.brand').click();
    await expect(panel).toBeHidden();
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,heartbeat:{...healthy.heartbeat,error:'[Errno 61] Connection refused'},activity:{queue_depth:232,last_error:'Upload rejected'},telemetry:{...healthy.telemetry,queue_depth:12}});
    await returnToWindow(page);
    await expect(trigger).toHaveAccessibleName('Sensor status: Connection lost');
    await expect(trigger.locator('.status-icon')).toHaveCSS('background-color','rgb(150, 77, 9)');
    await expect(panel).toBeHidden();
    expect(await page.locator('#usage-chart').boundingBox()).toEqual(chart);
    await page.screenshot({path:testInfo.outputPath(`status-orange-closed-${colorScheme}.png`)});
    await openSensorStatus(page);
    await expect(page.locator('#health-error')).toBeVisible();
    await expect(page.locator('#health-error')).toContainText('[Errno 61] Connection refused');
    await expect.poll(() => page.locator('#health-error').evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
    await expect(page.locator('#activity-queued')).toHaveText('232');
    await expect(page.getByRole('button',{name:'Check again',exact:true})).toBeVisible();
    await page.locator('#counter-note').scrollIntoViewIfNeeded();
    await expect(page.locator('#counter-note')).toBeInViewport({ratio:1});
    await page.locator('#sensor-details summary').click();
    await panel.evaluate(node => { node.scrollTop = 0; });
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath(`status-orange-open-${colorScheme}.png`)});
    await page.locator('#close-status').click();
    await expect(trigger).toBeFocused();
    await page.evaluate(status => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.status = status;
      mock.setup = {steps:[{step:'service.start',ok:false,error:'The local receiver did not respond'}]};
    }, {...healthy,running:false,service:'stopped'});
    await returnToWindow(page);
    await expect(trigger).toHaveAccessibleName('Sensor status: Offline');
    await expect(trigger.locator('.status-icon')).toHaveCSS('background-color','rgb(135, 36, 32)');
    await expect(panel).toBeHidden();
    await page.screenshot({path:testInfo.outputPath(`status-red-closed-${colorScheme}.png`)});
    await openSensorStatus(page);
    await expect(page.locator('#sensor-state')).toHaveText('Stopped');
    await expect(page.locator('#server-state')).toHaveText('Not checked');
    await expect(page.locator('#connected-agents')).toHaveText('Not checked');
    await expect(page.locator('#collection-guidance')).toContainText('Activity collection is stopped.');
    await expect(page.getByRole('button',{name:'Retry setup',exact:true})).toBeVisible();
    await page.locator('#sensor-details summary').click();
    await panel.evaluate(node => { node.scrollTop = 0; });
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath(`status-red-open-${colorScheme}.png`)});
    await page.evaluate(status => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.afterSetup = status; mock.setup = {steps:[]};
    }, healthy);
    await page.getByRole('button',{name:'Retry setup',exact:true}).click();
    await expect(trigger).toHaveAccessibleName('Sensor status: Connected');
    await expect(panel).toBeVisible();
    await expect(page.locator('#health-error')).toBeHidden();
    await expect(page.locator('#collection-guidance')).toContainText('Collecting activity in the background.');
    await page.locator('#close-status').click();
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,heartbeat:{last_success_at:null,error:''}});
    await returnToWindow(page);
    await expect(trigger).toHaveAccessibleName('Sensor status: Connecting');
    expect(await trigger.locator('.status-icon').evaluate(node => getComputedStyle(node, '::after').borderTopColor)).toBe('rgb(150, 77, 9)');
    await expectRoundStatusSpinner(page);
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath(`status-connecting-${colorScheme}.png`)});
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,running:false,heartbeat:{...healthy.heartbeat,error:'Previous connection failed'}});
    await returnToWindow(page);
    await expect(page.locator('#sensor-state')).toHaveText('Not responding');
    await expect(page.locator('#health-description')).not.toContainText('The sensor is running');
  });
}

test('connected agents follow current telemetry and guardrail settings on refresh', async ({page}) => {
  const telemetry = {...converged.telemetry,codex_available:true,codex_installed:true,codex_current:true};
  const hooks = {codex:{installed:true,trusted:true,current:true},claude:{installed:true,current:true}};
  await boot(page, {status:converged});
  await openSensorStatus(page);
  await expect(page.locator('#connected-agents')).toHaveText('Claude Code');
  for (const example of [
    {name:'stale telemetry',status:{telemetry:{...telemetry,codex_current:false}},agents:'Claude Code'},
    {name:'telemetry opt-out',status:{telemetry:{...telemetry,codex_opted_out:true}},agents:'Claude Code'},
    {name:'unavailable agent',status:{telemetry:{...telemetry,codex_available:false}},agents:'Claude Code'},
    {name:'legacy telemetry status',status:{telemetry:{...telemetry,codex_current:undefined,claude_current:undefined}},agents:'Codex, Claude Code'},
    {name:'no current connections',status:{telemetry:{...telemetry,codex_current:false,claude_current:false}},agents:'None'},
    {name:'guardrails without telemetry',status:{telemetry:{...telemetry,enabled:false},hooks},agents:'Codex, Claude Code'},
    {name:'hook opt-out',status:{telemetry:{...telemetry,enabled:false},hooks:{...hooks,codex:{...hooks.codex,opted_out:true}}},agents:'Claude Code'},
    {name:'disabled hooks',status:{telemetry:{...telemetry,enabled:false},hooks:{...hooks,claude:{...hooks.claude,disabled:true}}},agents:'Codex'},
    {name:'stale hooks',status:{telemetry:{...telemetry,enabled:false},hooks:{codex:{...hooks.codex,current:false}}},agents:'None'},
    {name:'legacy trusted hooks',status:{telemetry:{...telemetry,enabled:false},hooks:{codex:{installed:true,trusted:true}}},agents:'Codex'},
    {name:'legacy untrusted hooks',status:{telemetry:{...telemetry,enabled:false},hooks:{codex:{installed:true,trusted:false}}},agents:'None'},
    {name:'disabled sensor',status:{telemetry,hooks,disabled:true},agents:'None'},
  ]) {
    await test.step(example.name, async () => {
      await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...converged,...example.status});
      await returnToWindow(page);
      await expect(page.locator('#connected-agents')).toHaveText(example.agents);
      if (example.name === 'guardrails without telemetry') {
        await expect(page.locator('#collection-guidance')).toBeVisible();
        await expect(page.locator('#collection-guidance')).toContainText('Restart coding-agent sessions');
      }
    });
  }
});

test('status details and recovery stay reachable in a short window', async ({page}) => {
  const status = {...converged,heartbeat:{last_success_at:null,error:''},telemetry:{...converged.telemetry,queue_depth:1,forwarded:1248023,received:1247341}};
  await boot(page, {status,maxWindowHeight:320,usage:usageTotals(279440000)});
  await expect(page.locator('#status-label')).toHaveText('Connecting');
  await expect(page.locator('#usage-tokens')).toHaveText('279 M');
  await expectRoundStatusSpinner(page);
  await expect.poll(() => page.viewportSize()!.height).toBe(320);
  const app = page.locator('#app');
  expect(await app.evaluate(node => node.scrollHeight > node.clientHeight && node.scrollWidth === node.clientWidth)).toBe(true);
  await expect(page.locator('#sensor-status')).toBeInViewport({ratio:1});
  await page.getByRole('button', {name:'Uninstall',exact:true}).focus();
  await expect(page.getByRole('button', {name:'Uninstall',exact:true})).toBeInViewport({ratio:1});
  await page.locator('#sensor-status').focus();
  await expect(page.locator('#sensor-status')).toBeInViewport({ratio:1});
  await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...status,heartbeat:{last_success_at:null,error:'Connection refused. '.repeat(200)}});
  await returnToWindow(page);
  await expect(page.locator('#status-label')).toHaveText('Connection lost');
  await openSensorStatus(page);
  const panel = page.locator('#health-card');
  await expect(panel).toBeInViewport({ratio:1});
  await expect.poll(() => page.viewportSize()!.height).toBe(320);
  expect(await panel.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
  await page.locator('#retry').focus();
  await expect(page.locator('#retry')).toBeInViewport({ratio:1});
  await expect(panel).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(panel).toBeHidden();
  await expect(page.locator('#sensor-status')).toBeFocused();
});

for (const maxWindowHeight of [720, 320]) {
  test(`seven coding agents remain readable with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const hooks = Object.fromEntries(['codex','claude','copilot','cursor','antigravity','opencode','hermes'].map(agent => [agent,{available:true,installed:true,current:true,trusted:true}]));
    const status = {...converged,hooks,telemetry:{...converged.telemetry,enabled:false}};
    await boot(page,{status,maxWindowHeight,usage:usageTotals(279440000)});
    await openSensorStatus(page, false);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    await page.locator('#sensor-details summary').focus();
    await page.keyboard.press('Enter');
    const agents = page.locator('#connected-agents');
    await expect(agents).toHaveText('Codex, Claude Code, GitHub Copilot, Cursor, Antigravity, OpenCode, Hermes Agent');
    await agents.scrollIntoViewIfNeeded();
    await expect(agents).toBeInViewport({ratio:1});
    expect(await agents.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.locator('#retry').focus();
    await expect(page.locator('#retry')).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('connected-agents.png')});
    await page.keyboard.press('Escape');
    const uninstall = page.getByRole('button',{name:'Uninstall',exact:true});
    await uninstall.focus();
    await expect(uninstall).toBeInViewport({ratio:1});
  });
}

test('new coding agents repair hooks without native telemetry setup', async ({page}) => {
  const agents = ['copilot','cursor','antigravity','opencode'];
  const hooks = Object.fromEntries(agents.map(agent => [agent,{available:true,installed:false,current:false}]));
  const repaired = Object.fromEntries(agents.map(agent => [agent,{available:true,installed:true,current:true}]));
  await boot(page,{status:{...converged,hooks},afterSetup:{...converged,hooks:repaired},
    setup:{steps:agents.map(agent => ({step:'hooks.install',ok:true,agents:[agent]})),restart_required:true}});
  await openSensorStatus(page);
  await expect(page.locator('#connected-agents')).toHaveText('Claude Code, GitHub Copilot, Cursor, Antigravity, OpenCode');
  expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  await page.evaluate(() => {
    const status = (window as unknown as {mock:Mock}).mock.status;
    const hooks = status.hooks as Record<string,Record<string,boolean>>;
    hooks.copilot.opted_out = true;
    hooks.cursor.disabled = true;
  });
  await returnToWindow(page);
  await expect(page.locator('#connected-agents')).toHaveText('Claude Code, Antigravity, OpenCode');
  expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
});

for (const maxWindowHeight of [720,320]) {
  test(`connection grace expires and recovers with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-08T12:03:00Z')});
    const error = 'The read operation timed out';
    const status = {...converged,heartbeat:{last_success_at:'2026-10-08T12:00:00Z',error},activity:{queue_depth:113,last_error:error},telemetry:{...converged.telemetry,received:309123,forwarded:309118,queue_depth:1,last_error:error}};
    const counts = {tokens:33670000,calls:100,priced_calls:100,cost_usd:51.50};
    await boot(page, {status,maxWindowHeight,usage:{summary:counts,pending_exports:0,source:'local',history_incomplete:true,by_model:[{name:'gpt-6-astra',...counts}],by_reasoning_effort:[{name:'high',...counts}],
      series:Array.from({length:30},(_,i) => ({...counts,tokens:i === 29 ? counts.tokens : 0,date:new Date(Date.UTC(2026,8,9+i)).toISOString().slice(0,10)}))}});
    const trigger = page.locator('#sensor-status');
    const panel = page.locator('#health-card');
    await expect(trigger).toHaveAccessibleName('Sensor status: Connected (3 mins ago)');
    await expect(trigger.locator('.status-icon')).toHaveCSS('background-color','rgb(60, 114, 61)');
    await expect(trigger).toBeInViewport({ratio:1});
    await openSensorStatus(page, false);
    await expect(page.locator('#server-state')).toHaveText('Connected (3 mins ago)');
    await expect(page.locator('#health-description')).toHaveText('Last connected 3 mins ago. Retrying automatically.');
    await expect(page.locator('#health-description')).not.toHaveAttribute('title');
    await expect(page.locator('#health-error')).toHaveText(`Organization connection, Activity upload, Telemetry upload: ${error}`);
    await expect(page.locator('#activity-queued')).toHaveText('113');
    expect(await page.locator('#app').evaluate(node => node.scrollWidth === node.clientWidth)).toBe(true);
    expect(await panel.evaluate(node => node.scrollWidth === node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    await page.locator('#sensor-details summary').focus();
    await page.keyboard.press('Enter');
    if (maxWindowHeight === 320) {
      expect(await page.locator('#app').evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      expect(await panel.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await page.locator('#health-error').focus();
      await expect(page.locator('#health-error')).toBeInViewport({ratio:1});
      await page.locator('#close-status').focus();
      await expect(page.locator('#close-status')).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath('connection-grace.png')});
    await page.clock.fastForward(60000);
    await expect(page.locator('#status-label')).toHaveText('Connected (4 mins ago)');
    await page.clock.fastForward(10 * 60000 + 45000);
    await expect(page.locator('#status-label')).toHaveText('Connected (14 mins ago)');
    await page.clock.fastForward(15000);
    await expect(page.locator('#status-label')).toHaveText('Connection lost');
    await expect(trigger.locator('.status-icon')).toHaveCSS('background-color','rgb(150, 77, 9)');
    await expect(page.locator('#server-state')).toHaveText('Unreachable');
    await page.locator('#retry').focus();
    await expect(page.locator('#retry')).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('connection-grace-expired.png')});
    await page.evaluate(() => {
      const status = (window as unknown as {mock:Mock}).mock.status;
      status.heartbeat = {last_success_at:new Date().toISOString(),error:''};
      status.activity = {queue_depth:0,last_error:''};
      status.telemetry = {...status.telemetry as object,forwarded:309123,queue_depth:0,last_error:''};
    });
    await page.clock.fastForward(15000);
    await expect(page.locator('#status-label')).toHaveText('Connected');
    await expect(page.locator('#server-state')).toHaveText('Connected');
    await expect(page.locator('#health-error')).toBeHidden();
    await expect(page.locator('#activity-queued')).toHaveText('0');
    await expect(page.locator('#sent')).toHaveText('309,123');
    expect((await requests(page)).filter(request => request.action === 'setup')).toHaveLength(0);
    await page.keyboard.press('Escape');
    await page.getByRole('button', {name:'Settings',exact:true}).focus();
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeInViewport({ratio:1});
  });
}

for (const channel of ['activity','telemetry']) {
  test(`connection grace bounds continuing ${channel} failures despite successful heartbeats`, async ({page}) => {
    await page.clock.install({time:new Date('2026-10-08T12:00:00Z')});
    const error = '[Errno 61] Connection refused';
    const status = {...converged,heartbeat:{last_success_at:'2026-10-08T12:00:00Z',error:''},[channel]:{...(channel === 'telemetry' ? converged.telemetry : {}),queue_depth:1,last_error:error}};
    await boot(page,{status});
    await expect(page.locator('#status-label')).toHaveText('Connected (just now)');
    for (let minute = 1; minute <= 15; minute++) {
      await page.evaluate(() => {
        (window as unknown as {mock:Mock}).mock.status.heartbeat = {last_success_at:new Date(Date.now() + 60000).toISOString(),error:''};
      });
      await page.clock.fastForward(60000);
      await expect(page.locator('#status-label')).toHaveText(minute < 15 ? 'Connected (just now)' : 'Connection lost');
    }
    await expect(page.locator('#sensor-status')).toHaveClass(/warning/);
    await openSensorStatus(page);
    await expect(page.locator('#health-error')).toContainText(error);
    await expect(page.locator(channel === 'activity' ? '#activity-queued' : '#queued')).toHaveText('1');
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'Local sensor unavailable'; });
    await returnToWindow(page);
    await expect(page.locator('#status-label')).toHaveText('Offline');
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = ''; });
    await returnToWindow(page);
    await expect(page.locator('#status-label')).toHaveText('Connection lost');
    // A different enrollment gets its own grace period.
    await page.evaluate(() => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.status = {...mock.status,sensor_id:'sensor-2'};
    });
    await returnToWindow(page);
    await expect(page.locator('#status-label')).toHaveText('Connected (just now)');
    await page.evaluate(channel => {
      const status = (window as unknown as {mock:Mock}).mock.status;
      status[channel] = {...status[channel] as object,last_error:'',queue_depth:0};
    },channel);
    await returnToWindow(page);
    await expect(page.locator('#status-label')).toHaveText('Connected');
    await page.clock.fastForward(15 * 60000);
    await page.evaluate(({channel,error}) => {
      const status = (window as unknown as {mock:Mock}).mock.status;
      status.heartbeat = {last_success_at:new Date().toISOString(),error:''};
      status[channel] = {...status[channel] as object,last_error:error,queue_depth:1};
    },{channel,error});
    await returnToWindow(page);
    await expect(page.locator('#status-label')).toHaveText('Connected (just now)');
  });
}

test('connection grace requires recent contact and preserves other failures', async ({page}) => {
  await page.clock.setFixedTime(new Date('2026-10-08T12:15:00Z'));
  const error = '[Errno 61] Connection refused';
  const status = {...converged,heartbeat:{last_success_at:'2026-10-08T12:14:00Z',error}};
  await boot(page,{status});
  for (const example of [
    {name:'one minute',fields:{},label:'Connected (1 min ago)'},
    {name:'less than one minute',fields:{heartbeat:{last_success_at:'2026-10-08T12:14:59Z',error}},label:'Connected (just now)'},
    {name:'just before expiry',fields:{heartbeat:{last_success_at:'2026-10-08T12:00:00.001Z',error}},label:'Connected (14 mins ago)'},
    {name:'exact expiry',fields:{heartbeat:{last_success_at:'2026-10-08T12:00:00Z',error}},label:'Connection lost'},
    {name:'no previous contact',fields:{heartbeat:{last_success_at:null,error}},label:'Connection lost'},
    {name:'invalid timestamp',fields:{heartbeat:{last_success_at:'invalid',error}},label:'Connection lost'},
    {name:'future timestamp',fields:{heartbeat:{last_success_at:'2026-10-08T12:16:00Z',error}},label:'Connection lost'},
    {name:'upload retry after heartbeat recovery',fields:{heartbeat:{...status.heartbeat,error:''},activity:{queue_depth:113,last_error:error}},label:'Connected (1 min ago)'},
    {name:'DNS failure',fields:{heartbeat:{...status.heartbeat,error:'[Errno 8] nodename nor servname provided, or not known'}},label:'Connected (1 min ago)'},
    {name:'gateway unavailable',fields:{heartbeat:{...status.heartbeat,error:"Server error '502 Bad Gateway' for url 'https://tenant.example/ingest/v1/heartbeat'"}},label:'Connected (1 min ago)'},
    {name:'authorization rejection',fields:{heartbeat:{...status.heartbeat,error:'403 Forbidden'}},label:'Connection lost'},
    {name:'certificate failure',fields:{heartbeat:{...status.heartbeat,error:'[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed'}},label:'Connection lost'},
    {name:'upload rejection',fields:{activity:{queue_depth:1,last_error:'403 Forbidden'}},label:'Connection lost'},
    {name:'disabled hooks',fields:{hooks:{claude:{installed:true,current:true,disabled:true}}},label:'Attention'},
    {name:'organization disabled sensor',fields:{disabled:true},label:'Disabled'},
  ]) {
    await test.step(example.name,async () => {
      await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },{...status,...example.fields});
      await returnToWindow(page);
      await expect(page.locator('#status-label')).toHaveText(example.label);
      if (!example.label.startsWith('Connected')) await expect(page.locator('#sensor-status')).not.toHaveClass(/online/);
    });
  }
});

for (const maxWindowHeight of [720,320]) {
  test(`usage breakdowns sort by descending cost with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const counts = {tokens:1000000,calls:10,priced_calls:10,cost_usd:10};
    const summary = {tokens:5000000,calls:50,priced_calls:40,cost_usd:60};
    const usage = {summary,pending_exports:0,
      series:Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
        ...(i === 29 ? summary : {tokens:0,calls:0,priced_calls:0,cost_usd:null})})),
      by_model:[{name:'unpriced-model',...counts,cost_usd:null,priced_calls:0},
        {name:'gpt-6.1-sol',...counts},{name:'free-model',...counts,cost_usd:0},
        {name:'gpt-6-astra',...counts,cost_usd:40},{name:'claude-opus-5-5',...counts}],
      by_reasoning_effort:[{name:'unknown',...counts,cost_usd:null,priced_calls:0},
        {name:'medium',...counts},{name:'none',...counts,cost_usd:0},
        {name:'xhigh',...counts,cost_usd:40},{name:'low',...counts}]};
    await boot(page, {status:converged,maxWindowHeight,usage});
    for (const days of [30,1,30]) {
      await page.getByRole('button', {name:days === 1 ? '24 hours' : '30 days',exact:true}).click();
      await expect(page.locator('#usage-range')).toHaveText(days === 1 ? 'Last 24 hours' : 'Last 30 days');
      await expect(page.locator('#usage-models .usage-row > div:first-child')).toHaveText([
        'gpt-6-astra$40.00','claude-opus-5-5$10.00','gpt-6.1-sol$10.00','free-model$0.00','unpriced-modelN/A',
      ]);
      await expect(page.locator('#usage-efforts .usage-row > div:first-child')).toHaveText([
        'Extra high$40.00','Low$10.00','Medium$10.00','None$0.00','UnknownN/A',
      ]);
    }
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else {
      const app = page.locator('#app');
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await app.hover();
      await page.mouse.wheel(0, 1000);
      await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeInViewport({ratio:1});
      await expect(page.getByRole('button', {name:'Uninstall',exact:true})).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath('usage-cost-order.png')});
    for (const id of ['models','efforts']) {
      const rows = page.locator(`#usage-${id}`);
      expect(await rows.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await rows.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await rows.hover();
      await page.mouse.wheel(0, 1000);
      await expect(rows.locator('.usage-row').last()).toBeInViewport({ratio:1});
    }
  });
}

test('usage tool icons follow current detection rather than connection settings or usage history', async ({page}) => {
  const telemetry = {...converged.telemetry,codex_available:true,codex_installed:true,codex_current:true};
  const status = {...converged,telemetry};
  await boot(page, {status,usage:usageTotals(1000)});
  const tools = page.getByRole('group',{name:'Coding tools detected on this device'});
  const icons = page.locator('.detected-tool:visible');
  await expect(icons).toHaveCount(2);
  for (const example of [
    {name:'telemetry disconnected',fields:{telemetry:{...telemetry,enabled:false,codex_opted_out:true,claude_opted_out:true}},names:['Codex','Claude Code']},
    {name:'WorkBuddy only',fields:{telemetry:{codex_available:false,claude_available:false,workbuddy_available:true,workbuddy_opted_out:true}},names:['WorkBuddy']},
    {name:'WorkBuddy configured without detection',fields:{telemetry:{workbuddy_current:true}},names:[]},
    {name:'Codex only',fields:{telemetry:{...telemetry,claude_available:false}},names:['Codex']},
    {name:'Claude Code only',fields:{telemetry:{...telemetry,codex_available:false}},names:['Claude Code']},
    {name:'Hermes only',fields:{telemetry:{...telemetry,codex_available:false,claude_available:false},hooks:{hermes:{available:true,installed:true,current:true}}},names:['Hermes Agent']},
    {name:'Hermes without telemetry status',fields:{telemetry:undefined,hooks:{hermes:{available:true,installed:true,current:true}}},names:['Hermes Agent']},
    {name:'Hermes awaiting native approval',fields:{hooks:{hermes:{available:true,installed:true,current:false,approval_pending:true}}},names:['Codex','Claude Code','Hermes Agent']},
    {name:'Hermes connection flags without detection',fields:{hooks:{hermes:{installed:true,current:true}}},names:['Codex','Claude Code']},
    {name:'neither detected',fields:{telemetry:{...telemetry,codex_available:false,claude_available:false}},names:[]},
    {name:'legacy connection flags without detection',fields:{telemetry:{codex_installed:true,claude_installed:true}},names:[]},
    {name:'missing telemetry',fields:{telemetry:undefined},names:[]},
    {name:'cached detection during update',fields:{hooks:{hermes:{available:true}},desktop_update:{state:'installing',status_cached:true}},names:[]},
    {name:'fresh detection after update',fields:{},names:['Codex','Claude Code']},
  ]) {
    await test.step(example.name, async () => {
      await page.evaluate(status => {(window as unknown as {mock:Mock}).mock.status=status;}, {...status,...example.fields});
      await returnToWindow(page);
      await expect(icons).toHaveCount(example.names.length);
      expect(await icons.evaluateAll(nodes=>nodes.map(node=>node.getAttribute('aria-label')))).toEqual(example.names);
      if (example.names.length) await expect(tools).toBeVisible();
      else await expect(tools).toBeHidden();
      await expect(page.locator('#usage-cost')).toHaveText('$1.00');
    });
  }
  await page.evaluate(()=>{(window as unknown as {mock:Mock}).mock.statusError='Sensor unavailable';});
  await returnToWindow(page);
  await expect(tools).toBeHidden();
  await page.evaluate(()=>{delete (window as unknown as {mock:Mock}).mock.statusError;});
  await returnToWindow(page);
  await expect(icons).toHaveCount(2);
});

test.describe('dashboard typography', () => {
  test.use({deviceScaleFactor:2});
  for (const maxWindowHeight of [720,320]) {
    test(`bundled fonts fit populated ${maxWindowHeight}px work areas`, async ({page}, testInfo) => {
      await page.clock.install({time:new Date('2026-10-17T12:00:00Z')});
      const count = (cost_usd:number) => ({tokens:1000000,calls:100,priced_calls:100,cost_usd});
      const costs = [906.25,1031.03,475.25,324.61,369.29,852.80];
      const series = Array.from({length:30},(_,i) => {
        const cost = costs[i - 24] ?? 0;
        const claudeCost = [0,5,130,45,48,16.4][i - 24] ?? 0;
        return {date:new Date(Date.UTC(2026,8,18+i)).toISOString().slice(0,10),...count(cost),
          breakdown:cost ? [{...count(cost - claudeCost),application:'codex',model:'gpt-6-astra',reasoning_effort:'xhigh'},
            {...count(claudeCost),application:'claude_code',model:'claude-opus-5-5',reasoning_effort:'medium'},
            {...count(0),cost_usd:null,priced_calls:0,application:'workbuddy',model:'claude-opus-5-5',reasoning_effort:'unknown'}] : []};
      });
      await boot(page, {status:{...converged,hooks:{hermes:{available:true,installed:true,current:true}},telemetry:{...converged.telemetry,codex_available:true,codex_installed:true,codex_current:true,workbuddy_available:true},heartbeat:{last_success_at:'2026-10-17T11:59:00Z',error:''}},preview,maxWindowHeight,
        usage:{summary:{...count(3959.23),tokens:8177300000,cached_input_tokens:8029440000,uncached_input_tokens:130560000,
          output_tokens:17300000,calls:40000,priced_calls:2040},series,breakdown:series.flatMap(day => day.breakdown),pending_exports:0,
          by_model:[{name:'gpt-6-astra',...count(3650.35)},{name:'claude-fable-5-1',...count(110.91)},
            {name:'claude-opus-5-5',...count(83.10)},{name:'claude-sonnet-5-5',...count(58.41)}],
          by_reasoning_effort:[{name:'xhigh',...count(3667.91)},{name:'medium',...count(141.51)},
            {name:'high',...count(113.58)},{name:'unknown',...count(36.23)}]}});
      await expect(page.locator('#usage-tokens')).toHaveText('8.16 B in (98.4% cached) / 17.3 M out');
      await expect(page.locator('#usage-cost')).toHaveText('$3,959.23');
      await expect(page.locator('#usage-legend')).toHaveText('CodexClaude CodeWorkBuddy');
      await expect(page.locator('.usage-stack [data-application=codex]')).toHaveCount(6);
      await expect(page.locator('#status-label')).toHaveText('Connected');
      await page.evaluate(() => document.fonts.ready);
      const tools = page.getByRole('group',{name:'Coding tools detected on this device'});
      await expect(tools.getByRole('img')).toHaveCount(4);
      await expect(tools.getByRole('img',{name:'Codex',exact:true}).locator('img')).toHaveAttribute('src','/agent-icons/codex.png');
      await expect(tools.getByRole('img',{name:'Claude Code',exact:true}).locator('img')).toHaveAttribute('src','/agent-icons/claude-code.png');
      await expect(tools.getByRole('img',{name:'Hermes Agent',exact:true}).locator('img')).toHaveAttribute('src','/agent-icons/hermes.png');
      await expect(tools.getByRole('img',{name:'WorkBuddy',exact:true}).locator('img')).toHaveAttribute('src','/agent-icons/workbuddy.svg');
      await expect.poll(()=>tools.locator('img').evaluateAll(images=>images.every(image=>image.complete && image.naturalWidth>0))).toBe(true);
      const title = (await page.locator('#usage-panel .usage-heading h1').boundingBox())!;
      const toolBounds = (await tools.boundingBox())!;
      const period = (await page.getByRole('group',{name:'Usage period'}).boundingBox())!;
      expect(toolBounds.x).toBeGreaterThan(title.x+title.width);
      expect(toolBounds.x+toolBounds.width).toBeLessThan(period.x);
      await tools.getByRole('img',{name:'Codex',exact:true}).hover();
      await expect(page.locator('#codex-detected')).toHaveText('CodexDetected on this device');
      await expect(page.locator('#codex-detected')).toBeInViewport({ratio:1});
      await page.locator('#codex-detected').hover();
      await expect(page.locator('#codex-detected')).toBeVisible();
      await tools.getByRole('img',{name:'Codex',exact:true}).focus();
      await page.keyboard.press('Escape');
      await expect(page.locator('#codex-detected')).toBeHidden();
      await expect(tools.getByRole('img',{name:'Codex',exact:true})).toBeFocused();
      await page.mouse.move(0,0);
      await page.keyboard.press('Tab');
      await expect(tools.getByRole('img',{name:'Claude Code',exact:true})).toBeFocused();
      await expect(page.locator('#claude-detected')).toBeInViewport({ratio:1});
      await page.keyboard.press('Tab');
      await expect(tools.getByRole('img',{name:'Hermes Agent',exact:true})).toBeFocused();
      await expect(page.locator('#hermes-detected')).toHaveText('Hermes AgentDetected on this device');
      await expect(page.locator('#hermes-detected')).toBeInViewport({ratio:1});
      await page.keyboard.press('Tab');
      await expect(tools.getByRole('img',{name:'WorkBuddy',exact:true})).toBeFocused();
      await expect(page.locator('#workbuddy-detected')).toHaveText('WorkBuddyDetected on this device');
      await expect(page.locator('#workbuddy-detected')).toBeInViewport({ratio:1});
      await page.keyboard.press('Tab');
      await expect(page.getByRole('button',{name:'24 hours',exact:true})).toBeFocused();
      await expect(page.locator('#claude-detected')).toBeHidden();
      await expect(page.locator('#hermes-detected')).toBeHidden();
      await page.locator('#usage-panel .usage-heading h1').click();
      await expect(page.locator('body')).toHaveCSS('font-family', /^Geist,/);
      await expect(page.locator('#change-connection')).toHaveCSS('font-family', /^Geist,/);
      const app = page.locator('#app');
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      if (maxWindowHeight === 720) {
        await expectFitsWindow(page);
        expect(await page.locator('#status-footer > :visible').evaluateAll(nodes => nodes.every(node => node.scrollWidth <= node.clientWidth))).toBe(true);
        await page.screenshot({path:testInfo.outputPath('geist-usage.png'),animations:'disabled'});
        await page.emulateMedia({colorScheme:'dark'});
        await expect(tools).toBeInViewport({ratio:1});
        await page.screenshot({path:testInfo.outputPath('detected-tools-dark.png'),animations:'disabled'});
        await page.emulateMedia({colorScheme:'light'});
      } else {
        await expect.poll(() => page.viewportSize()!.height).toBe(320);
        expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
        await app.hover();
        await page.mouse.wheel(0,1000);
        await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
      }
      await page.getByRole('button',{name:'Settings',exact:true}).click();
      await page.locator('#enrollment-link').fill(link);
      await expect(page.locator('#link-server')).toHaveText(preview.server_url);
      await page.evaluate(() => document.fonts.ready);
      expect(await page.evaluate(() => ['Geist','Geist Mono'].every(family => [...document.fonts].some(font => font.family.replace(/"/g,'') === family && font.status === 'loaded')))).toBe(true);
      for (const id of ['enrollment-link','link-server']) {
        await expect(page.locator(`#${id}`)).toHaveCSS('font-family', /"?Geist Mono"?/);
        await expect(page.locator(`#${id}`)).toHaveCSS('font-weight','400');
      }
      await expect(page.locator('#link-organization')).toHaveCSS('font-family', /^Geist,/);
      const dialog = page.locator('#connection-dialog');
      expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      await page.locator('#connect-link').focus();
      await expect(page.locator('#connect-link')).toBeInViewport({ratio:1});
      if (maxWindowHeight === 720) {
        await expectFitsWindow(page);
        await page.screenshot({path:testInfo.outputPath('geist-connection.png'),animations:'disabled'});
      }
    });
  }
});

test('populated usage fits the window after setup and when changing periods', async ({page}, testInfo) => {
  await page.clock.install();
  const count = (tokens:number,cost:number,calls:number) => ({tokens,cost_usd:cost,calls,priced_calls:calls});
  const series = Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...count(i === 27 ? 25000000 : i === 28 ? 12200000 : i === 29 ? 639305 : 639285, i === 27 ? 850 : i === 29 ? 36.96 : 36.76, i === 27 ? 800 : 70)}));
  const usage = {summary:{...count(55100000,1916.24,2830),cached_input_tokens:19230000,uncached_input_tokens:490370,output_tokens:50460},series,pending_exports:0,
    by_model:[{name:'gpt-6-astra',...count(38000000,1438.67,1600)},{name:'gpt-6.1-sol',...count(12000000,327.10,800)},{name:'Opus 5.5',...count(4000000,118.36,380)},{name:'Other',...count(1100000,32.11,50)}],
    by_reasoning_effort:[{name:'medium',...count(15000000,441.24,750)},{name:'high',...count(26000000,980,1350)},{name:'xhigh',...count(12000000,420,600)},{name:'unknown',...count(2100000,75,130)}],
    baseline:{status:'available',model:'gpt-6-astra',own_high_share:.78,company_high_share:.42,peer_calls:4210,peer_devices:18,own_coverage:.95,company_coverage:.91}};
  await boot(page, {status:{...converged,telemetry:{...converged.telemetry,claude_current:false}},afterSetup:converged,
    setup:{steps:[{step:'telemetry.install',ok:true,agents:['codex','claude']},{step:'hooks.install',ok:true,agents:['codex','claude']}],restart_required:true},usage});
  await expect(page.locator('#usage-tokens')).toHaveText('55.1 M');
  expect((await requests(page)).filter(request => request.action === 'setup')).toHaveLength(1);
  await expect(page.locator('#usage-cost')).toHaveText('$1,916.24');
  await expect(page.locator('#usage-average')).toHaveText('$63.87');
  // Wait for the bundled interface font before measuring the populated layout.
  expect(await page.evaluate(async () => { await document.fonts.ready; return [...document.fonts].some(font => font.family.replace(/"/g, '') === 'Geist' && font.status === 'loaded'); })).toBe(true);
  await expect(page.locator('#usage-efforts')).toContainText('Extra high');
  await expect(page.locator('#usage-efforts')).toContainText('Unknown');
  await expect(page.getByRole('region', {name:'Company comparison'})).toHaveCount(0);
  await expect(page.getByText('Effort reported for', {exact:false})).toHaveCount(0);
  await expect(page.locator('#status-label')).toHaveText('Running');
  await expect(page.locator('#health-card')).toBeHidden();
  await expect(page.locator('#stats')).toBeHidden();
  await expect(page.locator('#usage-chart').getByRole('img')).toHaveCount(30);
  await expect(page.locator('#usage-chart').getByRole('button')).toHaveCount(0);
  await expect(page.locator('.usage-totals>div>span,.usage-totals>div>strong')).toHaveText(['Total tokens','55.1 M','Estimated cost (API equivalent)','$1,916.24']);
  await expect(page.locator('#usage-models .usage-row')).toHaveCount(4);
  await expect(page.locator('#usage-efforts .usage-row')).toHaveCount(4);
  await expectFitsWindow(page);
  const peak = page.locator('#usage-chart').getByRole('img', {name:/^Oct 5: \$850.00 estimated cost/});
  await peak.focus();
  await expect(peak).toBeFocused();
  await expect(page.getByRole('tooltip')).toContainText('Estimated cost$850.00');
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(config.app.windows[0].width);
  await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
  await page.screenshot({path:testInfo.outputPath('reasoning-effort.png'),fullPage:true});
  await openSensorStatus(page);
  await expect(page.locator('#stats')).toBeVisible();
  await expect(page.locator('#health-description')).toBeVisible();
  await expect(page.locator('#status-label')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', {name:'24 hours',exact:true}).click();
  await expect(page.locator('#usage-chart').getByRole('img')).toHaveCount(25);
  await expect(page.locator('#usage-range')).toHaveText('Last 24 hours');
  await expect(page.locator('#usage-axis span')).toHaveCount(5);
  await expect(page.locator('#usage-average')).toHaveText('$79.84');
  await expect(page.getByRole('button', {name:'24 hours',exact:true})).toHaveAttribute('aria-pressed','true');
  await expectFitsWindow(page);
  await page.screenshot({path:testInfo.outputPath('usage-24-hours.png'),fullPage:true});
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.usageError = 'Could not reach your organization for usage.'; });
  await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 61000));
  await returnToWindow(page);
  await expect(page.locator('#usage-content')).toBeVisible();
  await expect(page.locator('#usage-tokens')).toHaveText('55.1 M');
  await expect(page.locator('#usage-message')).toContainText('Showing previously loaded usage.');
  await expect(page.locator('#usage-message')).toContainText('Could not reach');
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.usageError = '';
    mock.usage = {summary:{tokens:0,calls:0,priced_calls:0,cost_usd:null},by_model:[],by_reasoning_effort:[],baseline:{status:'insufficient_data'},pending_exports:0,history_incomplete:true};
  });
  await page.clock.setSystemTime(new Date(await page.evaluate(() => Date.now()) + 61000));
  await returnToWindow(page);
  await expect(page.locator('#usage-content')).toBeVisible();
  await expect(page.locator('#usage-cost')).toHaveText('$0.00');
  await expect(page.locator('#usage-average')).toHaveText('$0.00');
  await expect(page.locator('#usage-peak')).toHaveText('$0.00');
  await expect(page.locator('#usage-models .usage-row')).toHaveCount(0);
  await expect(page.locator('#usage-efforts .usage-row')).toHaveCount(0);
  expect(await page.locator('.usage-bar').evaluateAll(bars => bars.every(bar => bar.getBoundingClientRect().height === 0))).toBe(true);
  await expect(page.locator('#usage-message')).toContainText('Older activity may be missing for this device');
});

for (const maxWindowHeight of [720,320]) {
  test(`empty usage keeps a blank chart and reachable controls at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
    await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
    const counts = {tokens:0,calls:0,priced_calls:0,cost_usd:null,
      cached_input_tokens:0,uncached_input_tokens:0,output_tokens:0};
    await boot(page, {status:converged,maxWindowHeight,usage:{source:'local',summary:counts,
      by_model:[],by_reasoning_effort:[],breakdown:[],pending_exports:0}});
    const app = page.locator('#app');
    for (const days of [30,1,30]) {
      await page.getByRole('button', {name:days === 1 ? '24 hours' : '30 days',exact:true}).click();
      await expect(page.locator('#usage-content')).toBeVisible();
      await expect(page.locator('#usage-chart')).toBeVisible();
      await expect(page.locator('#usage-chart-title')).toHaveText(days === 1 ? 'Hourly estimated cost' : 'Daily estimated cost');
      await expect(page.locator('#usage-range')).toHaveText(days === 1 ? 'Last 24 hours' : 'Last 30 days');
      await expect(page.locator('#usage-axis span')).toHaveCount(days === 1 ? 5 : 2);
      await expect(page.locator('#usage-tokens')).toHaveText('0 in (N/A cached) / 0 out');
      for (const metric of ['cost','average','peak','current']) await expect(page.locator(`#usage-${metric}`)).toHaveText('$0.00');
      await expect(page.locator('#usage-peak-label')).toHaveText(days === 1 ? 'Peak hour' : 'Peak day');
      await expect(page.locator('#usage-average-line')).toBeHidden();
      await expect(page.locator('#usage-legend')).toBeHidden();
      await expect(page.locator('.usage-row')).toHaveCount(0);
      await expect(page.locator('#usage-message')).toContainText('No usage stored for this period.');
      const bars = page.locator('#usage-chart').getByRole('img');
      await expect(bars).toHaveCount(days === 1 ? 25 : 30);
      expect(await page.locator('.usage-bar').evaluateAll(bars => bars.every(bar => bar.getBoundingClientRect().height === 0))).toBe(true);
      expect((await page.locator('#usage-chart').boundingBox())!.height).toBeGreaterThan(0);
      await bars.last().focus();
      await expect(page.locator('#usage-tooltip')).toContainText('Estimated cost$0.00');
      await page.keyboard.press('Escape');
      await page.getByRole('heading', {name:'Your usage',exact:true}).click();
      await page.evaluate(() => document.fonts.ready);
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      if (maxWindowHeight === 720) await expectFitsWindow(page);
      else {
        expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
        await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
      }
      await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
      for (const name of ['Settings','Uninstall','Check updates','About']) {
        await expect(page.getByRole('button', {name,exact:true})).toBeInViewport({ratio:1});
      }
      await page.screenshot({path:testInfo.outputPath(`empty-usage-${days}-days.png`),animations:'disabled'});
    }
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.usageError = 'Read failed.'; });
    await page.clock.fastForward(1000);
    await expect(page.locator('#usage-message')).toHaveText('Showing previously loaded usage. Read failed.');
    await expect(page.locator('#usage-content')).toBeVisible();
    await expect(page.locator('#usage-cost')).toHaveText('$0.00');
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.usageError = ''; });
    await page.clock.fastForward(1000);
    await expect(page.locator('#usage-message')).toContainText('No usage stored for this period.');
    await expect(page.locator('#usage-content')).toBeVisible();
  });
}

test('local usage remains visible offline without a company request', async ({page}, testInfo) => {
  const counts = {tokens:120000,cost_usd:.4,calls:100,priced_calls:100,
    cached_input_tokens:70000,uncached_input_tokens:10000,output_tokens:20000};
  const usage = {source:'local',summary:counts,pending_exports:0,history_incomplete:true,
    series:Array.from({length:30}, (_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
      tokens:i >= 28 ? 60000 : 0,cost_usd:i >= 28 ? .2 : null,calls:i >= 28 ? 50 : 0,priced_calls:i >= 28 ? 50 : 0,
      cached_input_tokens:i >= 28 ? 35000 : 0,uncached_input_tokens:i >= 28 ? 5000 : 0,output_tokens:i >= 28 ? 10000 : 0})),
    by_model:[{name:'gpt-6.1-sol',...counts}],by_reasoning_effort:[{name:'high',...counts}],
    baseline:{status:'unavailable'}};
  await boot(page, {status:converged,usage,maxWindowHeight:720});
  await expect(page.locator('#usage-tokens')).toHaveText('120 k');
  await expect(page.locator('#usage-chart').getByRole('img')).toHaveCount(30);
  await expect(page.locator('#usage-models')).toContainText('gpt-6.1-sol');
  await expect(page.locator('#usage-efforts')).toContainText('High');
  await expect(page.locator('#usage-message')).toBeHidden();
  await page.locator('#usage-chart').getByRole('img').last().hover();
  await expect(page.getByRole('tooltip')).toContainText('Estimated cost$0.20');
  expect((await requests(page)).some(item => item.action === 'usage.comparison')).toBe(false);
  await page.getByRole('button', {name:'24 hours',exact:true}).click();
  await expect(page.locator('#usage-chart').getByRole('img')).toHaveCount(25);
  await expect(page.locator('#usage-tokens')).toHaveText('120 k');
  await expect(page.locator('#usage-message')).toBeHidden();
  await returnToWindow(page);
  await expect(page.locator('#usage-content')).toBeVisible();
  await expect(page.locator('#usage-cost')).toHaveText('$0.40');
  await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
  await page.screenshot({path:testInfo.outputPath('offline-usage.png'),fullPage:true});
  await page.evaluate(() => {
    (window as unknown as {mock:Mock}).mock.usage!.history_incomplete = false;
  });
  await returnToWindow(page);
  await expect(page.locator('#usage-message')).toBeHidden();
  await expect(page.locator('#usage-tokens')).toHaveText('120 k');
});

for (const maxWindowHeight of [720,320]) {
  for (const colorScheme of ['light','dark'] as const) {
    test(`app and model breakdowns reconcile at ${maxWindowHeight}px in ${colorScheme}`, async ({page}, testInfo) => {
      await page.emulateMedia({colorScheme});
      await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
      await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
      const counts = (cost_usd:number|null,calls = 1,priced_calls = cost_usd === null ? 0 : calls) => ({
        cost_usd,calls,priced_calls,tokens:calls*1000,cached_input_tokens:calls*800,uncached_input_tokens:calls*100,output_tokens:calls*100,
      });
      const today = [
        {application:'codex',model:'gpt-6-astra',reasoning_effort:'xhigh',...counts(40,7)},
        {application:'codex',model:'gpt-6-astra',reasoning_effort:'low',...counts(10)},
        {application:'codex',model:'gpt-6-astra',reasoning_effort:'unknown',...counts(null)},
        {application:'codex',model:'gpt-6.1-sol',reasoning_effort:'low',...counts(25,5)},
        {application:'claude_code',model:'gpt-6-astra',reasoning_effort:'high',...counts(10,3)},
        {application:'cowork',model:'claude-opus-5-5',reasoning_effort:'medium',...counts(5)},
        {application:'unknown',model:'legacy-model-with-a-long-name-that-must-stay-readable',reasoning_effort:'unknown',...counts(null)},
      ];
      const yesterday = [{application:'unknown',model:'legacy-model',reasoning_effort:'high',...counts(30)}];
      const older = [{application:'codex',model:'gpt-6-luna',reasoning_effort:'low',...counts(100,2)}];
      const sum = (rows:ReturnType<typeof counts>[]) => rows.reduce((total,row) => ({
        cost_usd:row.cost_usd === null ? total.cost_usd : (total.cost_usd ?? 0)+row.cost_usd,
        calls:total.calls+row.calls,priced_calls:total.priced_calls+row.priced_calls,tokens:total.tokens+row.tokens,
        cached_input_tokens:total.cached_input_tokens+row.cached_input_tokens,
        uncached_input_tokens:total.uncached_input_tokens+row.uncached_input_tokens,output_tokens:total.output_tokens+row.output_tokens,
      }),counts(null,0));
      const series = Array.from({length:30},(_,i) => {
        const breakdown = i === 2 ? older : i === 28 ? yesterday : i === 29 ? today : [];
        return {date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...sum(breakdown),breakdown};
      });
      const usage = (days:1|30) => {
        const breakdown = [...today,...yesterday,...(days === 30 ? older : [])];
        return {source:'local',summary:sum(breakdown),series:days === 1 ? series.slice(-25) : series,breakdown,pending_exports:0,
          by_model:[...new Set(breakdown.map(row => row.model))].map(name => ({name,...sum(breakdown.filter(row => row.model === name))})),
          by_reasoning_effort:['xhigh','low','high','medium','unknown'].map(name => ({name,...sum(breakdown.filter(row => row.reasoning_effort === name))}))};
      };
      await boot(page, {status:converged,maxWindowHeight,usageByDays:{1:usage(1),30:usage(30)}});
      await expect(page.locator('#usage-cost')).toHaveText('$220.00');
      await expect(page.getByRole('heading',{name:'Models',exact:true})).toBeVisible();
      await expect(page.locator('#usage-legend')).toHaveText('CodexUnattributedClaude CodeClaude Cowork');
      await expect(page.locator('#usage-coverage')).toHaveText('2 unpriced calls excluded. Unattributed usage has no recorded app identity. Older sensor versions did not retain it.');
      await expect(page.locator('#usage-models .usage-row>div:first-child')).toHaveText([
        'gpt-6-luna$100.00','gpt-6-astra$60.00','legacy-model$30.00','gpt-6.1-sol$25.00','claude-opus-5-5$5.00','legacy-model-with-a-long-name-that-must-stay-readableN/A',
      ]);
      await expect(page.locator('#usage-efforts .usage-row>div:first-child')).toHaveText(['Low$135.00','High$40.00','Extra high$40.00','Medium$5.00','UnknownN/A']);
      const app = page.locator('#app');
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      if (maxWindowHeight === 720) {
        // The native IPC fixture resizes the viewport asynchronously after usage renders.
        await expect.poll(() => app.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
        await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
        await page.screenshot({path:testInfo.outputPath('app-model-usage.png')});
      }
      const day = page.locator('.usage-day').last();
      await day.focus();
      const tooltip = page.getByRole('tooltip');
      await expect(day).toHaveAttribute('aria-describedby','usage-tooltip');
      await expect(tooltip).toBeInViewport({ratio:1});
      await expect(tooltip.locator('.usage-app-heading')).toHaveText(['Codex$75.00','Claude Code$10.00','Claude Cowork$5.00','UnattributedN/A']);
      await expect(tooltip.locator('.usage-app-detail')).toHaveText([
        'gpt-6-astra$50.00','gpt-6.1-sol$25.00',
        'gpt-6-astra$10.00','claude-opus-5-5$5.00','legacy-model-with-a-long-name-that-must-stay-readableN/A',
      ]);
      await expect(tooltip).not.toContainText('Extra high');
      await expect(tooltip.getByText('2 unpriced calls excluded.',{exact:true})).toHaveCount(1);
      await expect(tooltip).toContainText('Estimated cost$90.00');
      const appFontSize = await tooltip.locator('.usage-app-heading').first().evaluate(node => getComputedStyle(node).fontSize);
      await expect(tooltip.getByText('Estimated cost',{exact:true})).toHaveCSS('font-size',appFontSize);
      await expect(tooltip.getByText('$90.00',{exact:true})).toHaveCSS('font-size',appFontSize);
      await expect(tooltip.getByText('Estimated cost',{exact:true})).toHaveCSS('font-weight','650');
      await expect(tooltip.getByText('$90.00',{exact:true})).toHaveCSS('font-weight','650');
      await expect(tooltip.getByText('$75.00',{exact:true})).toHaveCSS('font-weight','650');
      await expect(tooltip.getByText('$50.00',{exact:true})).toHaveCSS('font-weight','500');
      const codexBar = day.locator('[data-application="codex"]');
      await expect(codexBar).toHaveCSS('background-color','rgb(16, 163, 127)');
      await expect(codexBar).toHaveCSS('background-color',await page.locator('#usage-legend [data-application="codex"] .usage-swatch').evaluate(node => getComputedStyle(node).backgroundColor));
      await expect(day.locator('[data-application="cowork"]')).toHaveCSS('background-color',await page.locator('#usage-legend [data-application="cowork"] .usage-swatch').evaluate(node => getComputedStyle(node).backgroundColor));
      const heights = await day.locator('.usage-stack>span').evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().height));
      expect(heights[0]/heights.reduce((a,b) => a+b,0)).toBeCloseTo(75/90,2);
      expect(await tooltip.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      await tooltip.focus();
      await tooltip.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(tooltip.locator('p').last()).toBeInViewport({ratio:1});
      const tooltipScroll = await tooltip.evaluate(node => node.scrollTop);
      await page.clock.fastForward(61000);
      await expect(tooltip).toBeFocused();
      expect(await tooltip.evaluate(node => node.scrollTop)).toBe(tooltipScroll);
      await expect(tooltip.locator('.usage-app-heading')).toHaveText(['Codex$75.00','Claude Code$10.00','Claude Cowork$5.00','UnattributedN/A']);
      await page.screenshot({path:testInfo.outputPath('app-model-tooltip.png')});
      await page.keyboard.press('Escape');
      await expect(tooltip).toBeHidden();
      await page.getByRole('button',{name:'24 hours',exact:true}).click();
      await expect(page.locator('#usage-cost')).toHaveText('$120.00');
      await expect(page.locator('.usage-day')).toHaveCount(25);
      await expect(page.locator('#usage-models .usage-row>div:first-child')).toHaveText([
        'gpt-6-astra$60.00','legacy-model$30.00','gpt-6.1-sol$25.00','claude-opus-5-5$5.00','legacy-model-with-a-long-name-that-must-stay-readableN/A',
      ]);
      await day.hover();
      const dayBox = (await day.boundingBox())!;
      const tooltipBox = (await tooltip.boundingBox())!;
      await page.mouse.move(tooltipBox.x + tooltipBox.width - 2, dayBox.y + dayBox.height / 2, {steps:20});
      await expect(tooltip.locator(':scope > strong')).toContainText('Oct 7');
      await tooltip.hover();
      await expect(tooltip).toBeVisible();
      await page.getByRole('heading',{name:'Your usage',exact:true}).hover();
      await expect(tooltip).toBeHidden();
      await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await page.clock.fastForward(61000);
      await expect(page.getByRole('heading',{name:'Models',exact:true})).toBeVisible();
      await page.locator('#usage-models').evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(page.locator('#usage-models .usage-row').last()).toBeInViewport({ratio:1});
      expect(await page.locator('#usage-models').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeInViewport({ratio:1});
      await expect(page.getByRole('button',{name:'Uninstall',exact:true})).toBeInViewport({ratio:1});
      expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(maxWindowHeight === 320);
      expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(3);
    });
  }
}

async function expectUsageAverageLine(page:Page, ratio:number) {
  const line = page.locator('#usage-average-line');
  await expect(line).toBeVisible();
  await expect(line).toHaveText('Average');
  await expect(line.locator('span')).toHaveCSS('background-color','rgba(0, 0, 0, 0)');
  await expect(line.locator('span')).toHaveCSS('text-shadow',/rgb\(255, 255, 255\).*1px/);
  const geometry = await line.evaluate(node => {
    const chart = document.querySelector<HTMLElement>('#usage-chart')!;
    const chartBox = chart.getBoundingClientRect();
    const lineBox = node.getBoundingClientRect();
    const label = node.firstElementChild!.getBoundingClientRect();
    const legend = document.querySelector<HTMLElement>('#usage-legend')!;
    const heading = (legend.hidden ? document.querySelector('#usage-chart-title')! : legend).getBoundingClientRect();
    return {baseline:chartBox.bottom - parseFloat(getComputedStyle(chart).borderBottomWidth),
      peakHeight:Math.max(...Array.from(chart.querySelectorAll('.usage-bar'), bar => bar.getBoundingClientRect().height)),
      lineY:lineBox.y,lineLeft:lineBox.left,lineRight:lineBox.right,chartLeft:chartBox.left,chartRight:chartBox.right,
      labelTop:label.top,labelBottom:label.bottom,labelLeft:label.left,labelRight:label.right,headingBottom:heading.bottom};
  });
  expect(geometry.peakHeight).toBeGreaterThan(0);
  expect(Math.abs(geometry.lineY - (geometry.baseline - geometry.peakHeight * ratio))).toBeLessThan(1);
  expect(geometry.lineLeft).toBe(geometry.chartLeft);
  expect(geometry.lineRight).toBe(geometry.chartRight);
  expect(geometry.labelTop).toBeGreaterThanOrEqual(geometry.headingBottom);
  expect(geometry.labelBottom).toBeLessThan(geometry.lineY);
  expect(geometry.labelLeft).toBeGreaterThanOrEqual(geometry.chartLeft);
  expect(geometry.labelRight).toBeLessThanOrEqual(geometry.chartRight);
}

test.describe('usage history', () => {
  test.use({timezoneId:'America/Los_Angeles',deviceScaleFactor:2});
  for (const maxWindowHeight of [720,320]) {
    test(`keeps the cost note without a tracking marker in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
      await page.clock.install({time:new Date('2026-10-07T12:30:00Z')});
      const counts = (cost:number) => ({tokens:Math.round(cost * 102000),cached_input_tokens:Math.round(cost * 98000),
        uncached_input_tokens:Math.round(cost * 2000),output_tokens:Math.round(cost * 2000),
        calls:Math.round(cost * 100),priced_calls:Math.round(cost * 100),cost_usd:cost});
      const breakdown = (cost:number) => [
        {application:'codex',model:'gpt-6.1-sol',reasoning_effort:'high',share:.6},
        {application:'claude_code',model:'claude-sonnet-5-5',reasoning_effort:'medium',share:.25},
        {application:'gemini',model:'gemini-2.5-flash',reasoning_effort:'unknown',share:.15},
      ].map(({share,...row}) => ({...row,...counts(cost * share)}));
      const costs = [...Array<number>(16).fill(0),5,8,4,11,7,10,12,9,6,14,8,18,16,11];
      const total = costs.reduce((sum, cost) => sum + cost, 0);
      const series = costs.map((cost,i) => ({...counts(cost),date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),breakdown:breakdown(cost)}));
      await boot(page, {status:{...converged,heartbeat:{last_success_at:'2026-10-07T12:30:00Z',error:''},telemetry:{...converged.telemetry,codex_available:true}},maxWindowHeight,
        usage:{source:'local',tracking_started_at:'2026-09-30T19:00:00Z',summary:counts(total),series,breakdown:breakdown(total),pending_exports:0,
          by_model:breakdown(total).map(row => ({...row,name:row.model})),
          by_reasoning_effort:breakdown(total).map(row => ({...row,name:row.reasoning_effort}))}});
      const marker = page.locator('#usage-tracking-line');
      const app = page.locator('#app');
      await expect(page.locator('#usage-cost')).toHaveText('$139.00');
      await expect(marker).toHaveCount(0);
      await expect(page.getByText(/Tracking started/)).toHaveCount(0);
      await expect(page.locator('#usage-history-note')).toHaveText('Historical cost may be incomplete.');
      const info = page.getByRole('button',{name:'Cost estimate information',exact:true});
      const note = page.locator('#usage-history-note');
      await expect(info).toHaveAccessibleDescription('Historical cost may be incomplete.');
      await expect(note).toBeHidden();
      const card = page.getByRole('region',{name:'Usage trend',exact:true});
      expect(await card.evaluate(node => node.getBoundingClientRect().bottom
        - node.querySelector('.usage-metrics')!.getBoundingClientRect().bottom)).toBeLessThanOrEqual(11);
      await expect(page.locator('#usage-legend')).toContainText('Gemini CLI');
      for (const colorScheme of ['light','dark'] as const) {
        await page.emulateMedia({colorScheme});
        await info.hover();
        await expect(note).toBeVisible();
        await expect(note).toBeInViewport({ratio:1});
        await note.hover();
        await expect(note).toBeVisible();
        await page.getByRole('heading',{name:'Your usage',exact:true}).hover();
        await expect(note).toBeHidden();
        await page.getByRole('button',{name:'30 days',exact:true}).focus();
        await page.keyboard.press('Tab');
        await expect(info).toBeFocused();
        await expect(note).toBeInViewport({ratio:1});
        const labelBox = (await page.locator('#usage-cost-label').boundingBox())!;
        const infoBox = (await info.boundingBox())!;
        expect(infoBox.y).toBe(labelBox.y);
        expect(infoBox.x).toBeGreaterThanOrEqual(labelBox.x + labelBox.width - 20);
        await page.screenshot({path:testInfo.outputPath(`usage-cost-info-${maxWindowHeight}-${colorScheme}.png`),animations:'disabled'});
        await page.keyboard.press('Escape');
        await expect(note).toBeHidden();
        await expect(info).toBeFocused();
        await page.keyboard.press('Shift+Tab');
        expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        if (maxWindowHeight === 720) {
          await expectFitsWindow(page);
          await page.locator('#usage-panel').screenshot({path:testInfo.outputPath(`usage-history-${colorScheme}.png`),animations:'disabled'});
        } else {
          expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
          await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
          for (const name of ['Settings','Uninstall','Check updates','About'])
            await expect(page.getByRole('button',{name,exact:true})).toBeInViewport({ratio:1});
        }
      }
      await page.getByRole('button',{name:'24 hours',exact:true}).click();
      await expect(page.locator('#usage-chart-title')).toHaveText('Hourly estimated cost');
      await expect(page.locator('.usage-day')).toHaveCount(25);
      await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.usage!.tracking_started_at = '2026-10-06T12:45:00Z'; });
      await page.clock.fastForward(1000);
      await expect(marker).toHaveCount(0);
      await expect(page.getByText(/Tracking started/)).toHaveCount(0);
      await info.focus();
      await expect(note).toBeInViewport({ratio:1});
      await page.getByRole('button',{name:'30 days',exact:true}).click();
      await expect(page.locator('#usage-cost')).toHaveText('$139.00');
      await expect(page.locator('.usage-day')).toHaveCount(30);
      await expect(marker).toHaveCount(0);
    });
  }
});

for (const maxWindowHeight of [720,320]) {
  test(`shows history recovery results and incomplete sources in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-07T12:30:00Z')});
    const counts = {tokens:9000000,cached_input_tokens:8000000,uncached_input_tokens:800000,output_tokens:200000,
      calls:1240,priced_calls:1240,cost_usd:48.62};
    const history_recovery = {recovered_calls:124,last_scan_at:'2026-10-07T12:25:00Z',blocked_files:1,
      inaccessible_sources:1,inaccessible_files:1,invalid_records:2,unsupported_records:1,pending_files:1,unreconciled_records:1};
    const share = (parts:number, cost:number) => ({...Object.fromEntries(Object.entries(counts).map(([key,value]) => [key,value / parts])),cost_usd:cost});
    const series = Array.from({length:30}, (_,index) => ({...share(index < 28 ? Infinity : 2,index < 28 ? 0 : 24.31),
      date:new Date(Date.UTC(2026,8,8 + index)).toISOString().slice(0,10)}));
    const costs = [24,12,8,4.62];
    await boot(page, {status:converged,maxWindowHeight,usage:{source:'local',summary:counts,series,pending_exports:0,history_recovery,
      by_model:['gpt-6-astra','gpt-6.1-sol','claude-fable-5-1','claude-opus-5-5'].map((name,index) => ({name,...share(4,costs[index]!)})),
      by_reasoning_effort:['high','low','medium','xhigh'].map((name,index) => ({name,...share(4,costs[index]!)}))}});
    const app = page.locator('#app');
    const coverage = page.locator('#usage-coverage');
    await expect(coverage).toContainText('History recovery: 124 additional calls in the last 30 days.');
    await expect(coverage).toContainText('Last checked');
    await expect(coverage).toContainText('Some history sources could not be read.');
    await expect(coverage).toContainText('Some history could not be matched safely to existing usage.');
    await expect(coverage).toContainText('Some history records could not be recovered.');
    await expect(coverage).toContainText('Some older history could not be updated.');
    await expect(coverage).toContainText('Waiting for history files to finish writing.');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else {
      await coverage.scrollIntoViewIfNeeded();
      await expect(coverage).toBeInViewport({ratio:1});
      await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
      for (const name of ['Settings','Uninstall','Check updates','About'])
        await expect(page.getByRole('button',{name,exact:true})).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath(`history-recovery-${maxWindowHeight}.png`),animations:'disabled'});
    await page.evaluate(() => {
      const data = (window as unknown as {mock:Mock}).mock.usage!;
      data.history_recovery = {...data.history_recovery as Record<string,unknown>,recovered_calls:125,
        blocked_files:0,inaccessible_sources:0,inaccessible_files:0,invalid_records:0,unsupported_records:0,pending_files:0,unreconciled_records:0};
    });
    await page.clock.fastForward(1000);
    await expect(coverage).toContainText('History recovery: 125 additional calls');
    await expect(coverage).not.toContainText('could not');
    await expect(coverage).not.toContainText('Waiting');
  });
}

for (const timezoneId of ['America/Los_Angeles', 'Asia/Kathmandu']) {
  test.describe(`hourly costs in ${timezoneId}`, () => {
    test.use({timezoneId,deviceScaleFactor:2});
    for (const maxWindowHeight of [720,320]) {
      test(`24-hour usage shows hourly costs and reachable controls at ${maxWindowHeight}px`, async ({page}, testInfo) => {
        await page.clock.install({time:new Date('2026-10-07T12:30:00Z')});
        const counts = (cost_usd:number) => ({cost_usd,tokens:cost_usd*5000,calls:cost_usd,priced_calls:cost_usd,
          cached_input_tokens:cost_usd*3000,uncached_input_tokens:cost_usd*1000,output_tokens:cost_usd*1000});
        const breakdown = (cost:number) => [
          {application:'codex',model:'gpt-6-astra',reasoning_effort:'max',...counts(cost*.75)},
          {application:'claude_code',model:'claude-opus-5-5',reasoning_effort:'high',...counts(cost*.25)},
        ];
        const first = new Date(timezoneId === 'Asia/Kathmandu' ? '2026-10-06T12:15:00Z' : '2026-10-06T12:00:00Z').valueOf();
        const series = Array.from({length:25}, (_,i) => {
          const cost = i === 0 ? 4 : i === 10 ? 60 : i === 24 ? 8 : 0;
          return {...counts(cost),date:new Date(first+i*3600000).toISOString(),breakdown:breakdown(cost)};
        });
        const data = (cost:number) => ({summary:counts(cost),pending_exports:0,breakdown:breakdown(cost),
          by_model:breakdown(cost).map(row => ({...row,name:row.model})),
          by_reasoning_effort:breakdown(cost).map(row => ({...row,name:row.reasoning_effort}))});
        await boot(page, {status:{...converged,telemetry:{...converged.telemetry,codex_available:true},hooks:{hermes:{available:true}}},
          maxWindowHeight,usageByDays:{1:{...data(72),series},30:{...data(240),
            series:Array.from({length:30},(_,i) => ({...counts(i === 28 ? 210 : i === 29 ? 30 : 0),
              date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10)}))}}});
        await expect(page.locator('#usage-cost')).toHaveText('$240.00');
        await expect(page.locator('#usage-current-label')).toHaveText('Today');
        await expect(page.locator('#usage-current')).toHaveText('$30.00');
        await page.getByRole('button',{name:'24 hours',exact:true}).click();
        await expect(page.getByRole('button',{name:'14 days',exact:true})).toHaveCount(0);
        await expect(page.getByRole('heading',{name:'Hourly estimated cost',exact:true})).toBeVisible();
        await expect(page.getByRole('group',{name:'Hourly estimated cost in USD',exact:true})).toBeVisible();
        await expect(page.locator('#usage-range')).toHaveText('Last 24 hours');
        await expect(page.locator('#usage-tokens')).toHaveText('288 k in (75% cached) / 72 k out');
        await expect(page.locator('#usage-cost')).toHaveText('$72.00');
        await expect(page.locator('#usage-average-label')).toHaveText('Hourly average');
        await expect(page.locator('#usage-average')).toHaveText('$3.00');
        await expectUsageAverageLine(page, 3 / 60);
        await expect(page.locator('#usage-peak')).toHaveText('$60.00');
        await expect(page.locator('#usage-peak-label')).toHaveText(timezoneId === 'Asia/Kathmandu' ? 'Peak · 4 AM' : 'Peak · 3 PM');
        await expect(page.locator('#usage-current-label')).toHaveText('This hour');
        await expect(page.locator('#usage-current')).toHaveText('$8.00');
        await expect(page.locator('#usage-axis span')).toHaveText(timezoneId === 'Asia/Kathmandu'
          ? ['6 PM','12 AM','6 AM','12 PM','6 PM'] : ['5 AM','11 AM','5 PM','11 PM','5 AM']);
        await expect(page.locator('#usage-models .usage-row>div:first-child')).toHaveText(['gpt-6-astra$54.00','claude-opus-5-5$18.00']);
        const bars = page.locator('#usage-chart').getByRole('img');
        await expect(bars).toHaveCount(25);
        const peak = bars.nth(10);
        const peakBox = (await peak.boundingBox())!;
        const lineBox = (await page.locator('#usage-average-line').boundingBox())!;
        await peak.hover({position:{x:peakBox.width / 2,y:lineBox.y - peakBox.y}});
        await expect(page.getByRole('tooltip')).toContainText('Estimated cost$60.00');
        await peak.focus();
        const tooltip = page.getByRole('tooltip');
        await expect(tooltip).toContainText('Estimated cost$60.00');
        await expect(tooltip.locator('strong')).toContainText(timezoneId === 'Asia/Kathmandu' ? /Oct 7.*4:00 AM/ : /Oct 6.*3:00 PM/);
        await expect(tooltip.locator('.usage-app-heading')).toHaveText(['Codex$45.00','Claude Code$15.00']);
        await expect(tooltip).toBeInViewport({ratio:1});
        await page.clock.fastForward(61000);
        await expect(peak).toBeFocused();
        await expect(tooltip).toBeVisible();
        await page.keyboard.press('Escape');
        await page.getByRole('heading',{name:'Your usage',exact:true}).click();
        await expect(tooltip).toBeHidden();
        const app = page.locator('#app');
        expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        if (maxWindowHeight === 720) await expectFitsWindow(page);
        else expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
        await page.screenshot({path:testInfo.outputPath('usage-24-hours.png'),animations:'disabled'});
        await bars.nth(1).focus();
        await expect(tooltip).toContainText('Estimated cost$0.00');
        await page.keyboard.press('Escape');
        await page.getByRole('button',{name:'30 days',exact:true}).click();
        await expect(page.getByRole('heading',{name:'Daily estimated cost',exact:true})).toBeVisible();
        await expect(bars).toHaveCount(30);
        await expect(page.locator('#usage-cost')).toHaveText('$240.00');
        await expect(page.locator('#usage-average-label')).toHaveText('Daily average');
        await expect(page.locator('#usage-current-label')).toHaveText('Today');
        await expect(page.locator('#usage-current')).toHaveText('$30.00');
        await page.locator('#usage-current').scrollIntoViewIfNeeded();
        await expect(page.locator('#usage-current')).toBeInViewport({ratio:1});
        expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        if (maxWindowHeight === 720) await expectFitsWindow(page);
        if (maxWindowHeight === 320) await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
        await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeInViewport({ratio:1});
        await expect(page.getByRole('button',{name:'Check updates',exact:true})).toBeInViewport({ratio:1});
        await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.usageByDays![1] = usage; },
          {...data(25),series:series.map(day => ({...counts(1),date:day.date,breakdown:breakdown(1)}))});
        await page.clock.fastForward(61000);
        await page.getByRole('button',{name:'24 hours',exact:true}).click();
        await expect(page.locator('#usage-average')).toHaveText('$1.04');
        await expect(page.locator('#usage-peak')).toHaveText('$1.00');
        await expectUsageAverageLine(page, 25 / 24);
      });
    }
  });
}

for (const timezoneId of ['America/Los_Angeles', 'Asia/Kathmandu']) {
  test.describe(`daily costs in ${timezoneId}`, () => {
    test.use({timezoneId,deviceScaleFactor:2});
    for (const colorScheme of ['light', 'dark'] as const) {
      test(`daily usage bars and metrics show estimated cost on hover and focus in ${colorScheme}`, async ({page}, testInfo) => {
        await page.emulateMedia({colorScheme});
        const counts = (cached:number,uncached:number,output:number,cost:number) => ({
          tokens:cached+uncached+output,cached_input_tokens:cached,uncached_input_tokens:uncached,
          output_tokens:output,cost_usd:cost,calls:cached ? 10 : 0,priced_calls:cached ? 9 : 0,
        });
        const total = {...counts(200000000,20000000,56110000,167.06),calls:20,priced_calls:18};
        const series = Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
          ...(i === 28 ? counts(40000000,4000000,9300000,134.92) : i === 29 ? counts(160000000,16000000,46810000,32.14) : counts(0,0,0,0))}));
        await boot(page, {status:converged,usage:{source:'local',summary:total,series,pending_exports:0,history_incomplete:true,
          by_model:[{name:'gpt-6-astra',...total,cost_usd:146.96},{name:'gpt-6.1-sol',...total,cost_usd:20.10}],
          by_reasoning_effort:[{name:'unknown',...total}]}});
        await expect(page.locator('#usage-tokens')).toHaveText('220 M in (90.9% cached) / 56.1 M out');
        await expect(page.locator('#usage-cost')).toHaveText('$167.06');
        await expect(page.locator('.usage-totals>div>span')).toHaveText(['Total tokens','Estimated cost (API equivalent)']);
        for (const label of await page.locator('.usage-totals>div>span').all()) await expect(label).toHaveCSS('text-transform','none');
        const headingSize = await page.getByRole('heading', {name:'Your usage'}).evaluate(node => getComputedStyle(node).fontSize);
        await expect(page.locator('#usage-tokens')).toHaveCSS('font-size',headingSize);
        await expect(page.locator('#usage-cost')).toHaveCSS('font-size',headingSize);
        await expect(page.getByText('Stored on this device · UTC',{exact:true})).toHaveCount(0);
        await expect(page.locator('#usage-message')).toBeHidden();
        await expect(page.locator('.usage-totals>div>span,.usage-totals>div>strong')).toHaveText(['Total tokens','220 M in (90.9% cached) / 56.1 M out','Estimated cost (API equivalent)','$167.06']);
        await expect(page.getByRole('heading', {name:'Daily estimated cost'})).toBeVisible();
        await expect(page.locator('#usage-average')).toHaveText('$83.53');
        await expectUsageAverageLine(page, (167.06 / 2) / 134.92);
        await expect(page.locator('#usage-coverage')).toHaveText('2 unpriced calls excluded.');
        await expect(page.getByRole('tooltip')).toBeHidden();
        await expect(page.locator('#usage-chart').getByRole('img')).toHaveCount(30);
        await expect(page.locator('#usage-axis span')).toHaveText(['Sep 8','Oct 7']);
        await expect(page.locator('#usage-peak-label')).toHaveText('Peak · Oct 6');
        await expect(page.locator('#usage-peak')).toHaveText('$134.92');
        await expect(page.locator('#usage-current')).toHaveText('$32.14');
        await expect(page.locator('#usage-current-label')).toHaveText('Today');
        const peak = page.locator('#usage-chart').getByRole('img', {name:/^Oct 6:/});
        const today = page.locator('#usage-chart').getByRole('img').last();
        await expect(peak).toHaveAccessibleName('Oct 6: $134.92 estimated cost. 1 unpriced call excluded.');
        const peakHeight = await peak.locator('.usage-bar').evaluate(bar => bar.getBoundingClientRect().height);
        const todayHeight = await today.locator('.usage-bar').evaluate(bar => bar.getBoundingClientRect().height);
        expect(peakHeight).toBeGreaterThan(0);
        expect(todayHeight / peakHeight).toBeCloseTo(32.14 / 134.92, 2);
        await peak.focus();
        const tooltip = page.getByRole('tooltip');
        await expect(tooltip).toBeVisible();
        await expect(tooltip).toContainText('Oct 6');
        await expect(tooltip).toContainText('Estimated cost$134.92');
        await expect(tooltip).toContainText('1 unpriced call excluded.');
        await page.keyboard.press('Escape');
        await expect(tooltip).toBeHidden();
        await page.getByRole('button',{name:'24 hours',exact:true}).focus();
        await peak.hover();
        await expect(tooltip).toBeVisible();
        await tooltip.hover();
        await expect(tooltip).toBeVisible();
        await expectFitsWindow(page);
        await expect(tooltip).toBeInViewport({ratio:1});
        await page.screenshot({path:testInfo.outputPath(`daily-token-cost-${colorScheme}.png`),fullPage:true});
        await page.getByRole('heading',{name:'Your usage'}).hover();
        await expect(tooltip).toBeHidden();
        await page.getByRole('heading',{name:'Your usage',exact:true}).click();
        await page.screenshot({path:testInfo.outputPath(`usage-30-days-${colorScheme}.png`),animations:'disabled'});
        await page.getByRole('button',{name:'30 days',exact:true}).click();
        await expect(page.locator('#usage-chart').getByRole('img')).toHaveCount(30);
        await expect(page.locator('#usage-axis span')).toHaveText(['Sep 8','Oct 7']);
        await page.locator('#usage-chart').getByRole('img').first().focus();
        await expect(tooltip).toContainText('Estimated cost$0.00');
        await expect(tooltip).not.toContainText('unpriced');
        await expect(page.locator('#usage-average')).toHaveText('$83.53');
      });
    }
  });
}

for (const maxWindowHeight of [720,320]) {
  test(`token summary shows input, cached share, and output with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-07T12:00:00Z')});
    const counts = {tokens:1000899900000,cached_input_tokens:983901600000,uncached_input_tokens:15998400000,
      output_tokens:999900000,calls:100,priced_calls:100,cost_usd:99971.97};
    const breakdown = [
      {application:'codex',model:'gpt-6-astra',reasoning_effort:'xhigh',share:.8,cost_usd:79977.58},
      {application:'codex',model:'gpt-6.1-sol',reasoning_effort:'low',share:.12,cost_usd:11996.63},
      {application:'claude_code',model:'claude-opus-5-5',reasoning_effort:'medium',share:.06,cost_usd:5998.32},
      {application:'unknown',model:'claude-fable-5-1',reasoning_effort:'unknown',share:.02,cost_usd:1999.44},
    ].map(({share,...row}) => ({...row,tokens:Math.round(counts.tokens * share),calls:100 * share,priced_calls:100 * share}));
    const series = Array.from({length:30}, (_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
      ...(i === 29 ? {...counts,breakdown} : {tokens:0,calls:0,priced_calls:0,cost_usd:null})}));
    await boot(page, {status:converged,maxWindowHeight,usage:{summary:counts,series,breakdown,pending_exports:0,
      by_model:breakdown.map(row => ({...row,name:row.model})),by_reasoning_effort:breakdown.map(row => ({...row,name:row.reasoning_effort}))}});
    const tokens = page.locator('#usage-tokens');
    await expect(tokens).toHaveText('1 T in (98.4% cached) / 1 B out');
    await expect(tokens).toHaveAttribute('title', /999,900,000,000 input tokens \(983,901,600,000 cached\), 999,900,000 output tokens/);
    await expect(page.locator('#usage-cost')).toHaveText('$99,971.97');
    const totals = await page.locator('.usage-totals>div').evaluateAll(nodes => nodes.map(node => {
      const {left,top,right} = node.getBoundingClientRect(); return {left,top,right};
    }));
    expect(totals[1].top).toBe(totals[0].top);
    expect(totals[1].left).toBeGreaterThan(totals[0].right);
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    for (const total of await page.locator('.usage-totals>div').all()) {
      expect(await total.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    }
    expect(await tokens.locator('span').evaluateAll(nodes => nodes[0].getBoundingClientRect().top === nodes[1].getBoundingClientRect().top)).toBe(true);
    const footerItems = page.locator('#status-footer > :visible');
    const centers = await footerItems.evaluateAll(nodes => nodes.map(node => {
      const {top,height} = node.getBoundingClientRect(); return top + height / 2;
    }));
    expect(Math.max(...centers) - Math.min(...centers)).toBeLessThanOrEqual(1);
    expect(await footerItems.evaluateAll(nodes => nodes.every(node => node.scrollWidth <= node.clientWidth))).toBe(true);
    await expect(page.locator('#status-footer button')).toHaveText(['Settings','Uninstall','Check updates','About']);
    await expect(page.locator('header').getByRole('button',{name:'About',exact:true})).toHaveCount(0);
    expect(await page.locator('#status-footer button').evaluateAll(buttons => buttons.every(button => {
      const icon = button.querySelector('svg')!.getBoundingClientRect();
      const label = button.querySelector('span')?.firstChild ?? Array.from(button.childNodes).find(node => node.nodeType === Node.TEXT_NODE && node.textContent?.trim())!;
      const range = document.createRange(); range.selectNodeContents(label);
      return icon.right < range.getBoundingClientRect().left;
    }))).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('inline-desktop-summary.png'),animations:'disabled'});
    await page.getByRole('button',{name:'24 hours',exact:true}).click();
    await expect(page.locator('#usage-chart').getByRole('img')).toHaveCount(25);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('inline-desktop-summary-24-hours.png'),animations:'disabled'});
    await page.getByRole('button',{name:'30 days',exact:true}).click();
    if (maxWindowHeight === 320) {
      await app.hover();
      await page.mouse.wheel(0,1000);
      await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeInViewport({ratio:1});
      await expect(page.getByRole('button',{name:'Uninstall',exact:true})).toBeInViewport({ratio:1});
    }
    await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
    const updateButton = page.getByRole('button',{name:'Check updates',exact:true});
    await updateButton.focus();
    await expect(updateButton).toBeInViewport({ratio:1});
    await expect(updateButton.locator('svg')).toBeInViewport({ratio:1});
    await expect(updateButton.locator('svg')).toHaveAttribute('aria-hidden','true');
    await updateButton.screenshot({path:testInfo.outputPath('update-button.png')});
    await page.keyboard.press('Tab');
    const aboutButton = page.getByRole('button',{name:'About',exact:true});
    await expect(aboutButton).toBeFocused();
    await expect(aboutButton).toBeInViewport({ratio:1});
    await expect(aboutButton.locator('svg')).toHaveAttribute('aria-hidden','true');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog',{name:'About OpenAIDR',exact:true})).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(aboutButton).toBeFocused();
    expect(await page.locator('#build-info').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    for (const example of [
      {summary:{tokens:1000899900000,cached_input_tokens:979902000000,uncached_input_tokens:19998000000,output_tokens:999900000},text:'1 T in (98% cached) / 1 B out',incomplete:false},
      {summary:{tokens:1000899900000,cached_input_tokens:998900100000,uncached_input_tokens:999900000,output_tokens:999900000},text:'1 T in (99.9% cached) / 1 B out',incomplete:false},
      {summary:{tokens:1999800000,cached_input_tokens:998900100,uncached_input_tokens:999900,output_tokens:999900000},text:'1 B in (99.9% cached) / 1 B out',incomplete:false},
      {summary:{tokens:1998000000,cached_input_tokens:998001000,uncached_input_tokens:999000,output_tokens:999000000},text:'999 M in (99.9% cached) / 999 M out',incomplete:false},
      {summary:{tokens:199800000,cached_input_tokens:99800100,uncached_input_tokens:99900,output_tokens:99900000},text:'99.9 M in (99.9% cached) / 99.9 M out',incomplete:false},
      {summary:{tokens:19980000,cached_input_tokens:9980010,uncached_input_tokens:9990,output_tokens:9990000},text:'9.99 M in (99.9% cached) / 9.99 M out',incomplete:false},
      {summary:{tokens:1998000,cached_input_tokens:998001,uncached_input_tokens:999,output_tokens:999000},text:'999 k in (99.9% cached) / 999 k out',incomplete:false},
      {summary:{tokens:1998998,cached_input_tokens:0,uncached_input_tokens:999499,output_tokens:999499},text:'999 k in (0% cached) / 999 k out',incomplete:false},
      {summary:{tokens:1999000,cached_input_tokens:0,uncached_input_tokens:999500,output_tokens:999500},text:'1 M in (0% cached) / 1 M out',incomplete:false},
      {summary:{tokens:1000000,cached_input_tokens:0,uncached_input_tokens:800000,output_tokens:200000},text:'800 k in (0% cached) / 200 k out',incomplete:false},
      {summary:{tokens:1000000,cached_input_tokens:1000000,uncached_input_tokens:0,output_tokens:0},text:'1 M in (100% cached) / 0 out',incomplete:false},
      {summary:{tokens:800,cached_input_tokens:0,uncached_input_tokens:0,output_tokens:800},text:'0 in (N/A cached) / 800 out',incomplete:false},
      {summary:{tokens:3000000,cached_input_tokens:1000000,uncached_input_tokens:500000,output_tokens:500000},text:'3 M',incomplete:true},
      {summary:{tokens:1000000},text:'1 M',incomplete:true},
      {summary:{tokens:1234567},text:'1.23 M',incomplete:true},
    ]) {
      await page.evaluate(summary => {
        (window as unknown as {mock:Mock}).mock.usage!.summary = {...summary,calls:1,priced_calls:1,cost_usd:999999.99};
      }, example.summary);
      await page.clock.fastForward(61000);
      await expect(tokens).toHaveText(example.text);
      if (!example.incomplete) {
        const width = await tokens.evaluate(node => {
          const spans = node.querySelectorAll('span');
          const firstTop = spans[0].getBoundingClientRect().top, lastTop = spans[1].getBoundingClientRect().top;
          const range = document.createRange(); range.selectNodeContents(node);
          const required = range.getBoundingClientRect().width;
          return {required,available:node.getBoundingClientRect().width,firstTop,lastTop};
        });
        await testInfo.attach('token-summary-width', {body:JSON.stringify(width),contentType:'application/json'});
        expect(width.lastTop).toBe(width.firstTop);
        expect(width.required).toBeLessThanOrEqual(width.available);
        await expect(page.locator('#usage-cost')).toHaveText('$999,999.99');
        expect(await page.locator('#usage-cost-label').evaluate(node => {
          const range = document.createRange(); range.selectNodeContents(node);
          return range.getClientRects().length;
        })).toBe(1);
        for (const total of await page.locator('.usage-totals>div').all()) {
          expect(await total.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        }
        expect(await page.locator('.usage-totals').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        if (maxWindowHeight === 720) await expectFitsWindow(page);
        else {
          await app.hover();
          await page.mouse.wheel(0,1000);
          await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeInViewport({ratio:1});
          await expect(page.getByRole('button',{name:'Uninstall',exact:true})).toBeInViewport({ratio:1});
        }
        await tokens.scrollIntoViewIfNeeded();
        if (example.text.startsWith('99.9 M')) await page.screenshot({path:testInfo.outputPath('input-output-tokens-wide.png')});
      }
      if (example.incomplete) await expect(tokens).toHaveAttribute('title',`${example.summary.tokens.toLocaleString('en-US')} total tokens. Input/output breakdown is incomplete for this period.`);
      else {
        const {cached_input_tokens:cached,uncached_input_tokens:uncached,output_tokens:output} = example.summary;
        await expect(tokens).toHaveAttribute('title',`${(cached! + uncached!).toLocaleString('en-US')} input tokens (${cached!.toLocaleString('en-US')} cached), ${output!.toLocaleString('en-US')} output tokens. Cache rate is cached input divided by total input.`);
      }
    }
  });
}

for (const maxWindowHeight of [720,320]) {
  test(`daily average starts at the first recorded day and includes idle days at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-07T12:00:00Z')});
    const empty = {tokens:0,calls:0,priced_calls:0,cost_usd:null};
    const free = {tokens:1000,calls:1,priced_calls:1,cost_usd:0};
    const paid = {...free,cost_usd:12};
    const series = Array.from({length:30}, (_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
      ...(i === 26 ? free : i === 28 ? paid : empty)}));
    await boot(page, {status:converged,maxWindowHeight,usage:{summary:{...paid,tokens:2000,calls:2,priced_calls:2},
      series,pending_exports:0,by_model:[{name:'gpt-6-astra',...paid}],by_reasoning_effort:[{name:'high',...paid}]}});
    await expect(page.locator('#usage-cost')).toHaveText('$12.00');
    await expect(page.locator('#usage-average')).toHaveText('$3.00');
    await expectUsageAverageLine(page, 1 / 4);
    await expect(page.locator('#usage-current')).toHaveText('$0.00');
    await expect(page.locator('#usage-chart').getByRole('img')).toHaveCount(30);
    await page.evaluate(() => document.fonts.ready);
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) {
      await expectFitsWindow(page);
      await page.screenshot({path:testInfo.outputPath('daily-average.png'),animations:'disabled'});
    } else {
      expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await page.locator('#usage-average').scrollIntoViewIfNeeded();
      await expect(page.locator('#usage-average')).toBeInViewport({ratio:1});
      await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeInViewport({ratio:1});
      await expect(page.getByRole('button',{name:'Check updates',exact:true})).toBeInViewport({ratio:1});
    }
  });
}

for (const cost of [null, 0, 12]) {
  test(`daily costs distinguish unpriced calls, free calls, and empty days with cost ${cost}`, async ({page}) => {
    const empty = {tokens:0,calls:0,priced_calls:0,cost_usd:null};
    const unpriced = {tokens:1000000,calls:1,priced_calls:0,cost_usd:null};
    const today = {...unpriced,cost_usd:cost,priced_calls:cost === null ? 0 : 1};
    const series = Array.from({length:30}, (_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
      ...(i === 28 ? unpriced : i === 29 ? today : empty)}));
    await page.clock.install({time:new Date('2026-10-07T12:00:00Z')});
    await boot(page, {status:converged,usage:{summary:{...today,tokens:2000000,calls:2},series,pending_exports:0,
      by_model:[],by_reasoning_effort:[]}});
    const amount = cost === null ? 'N/A' : `$${cost.toFixed(2)}`;
    await expect(page.locator('#usage-cost')).toHaveText(amount);
    await expect(page.locator('#usage-peak')).toHaveText(amount);
    await expect(page.locator('#usage-average')).toHaveText(cost === null ? 'N/A' : `$${(cost / 2).toFixed(2)}`);
    if (cost === null || cost === 0) await expect(page.locator('#usage-average-line')).toBeHidden();
    else await expectUsageAverageLine(page, 1 / 2);
    await expect(page.locator('#usage-current-label')).toHaveText('Today');
    await expect(page.locator('#usage-current')).toHaveText(amount);
    const bars = page.locator('#usage-chart').getByRole('img');
    await bars.last().focus();
    await expect(page.getByRole('tooltip')).toContainText(`Estimated cost${amount}`);
    await expect(page.getByRole('tooltip')).toContainText(cost === null ? '1 unpriced call excluded.' : 'Oct 7');
    if (cost !== null) await expect(page.getByRole('tooltip')).not.toContainText('unpriced');
    await bars.nth(28).focus();
    await expect(page.getByRole('tooltip')).toContainText('Estimated costN/A');
    await expect(page.getByRole('tooltip')).toContainText('1 unpriced call excluded.');
    await bars.first().focus();
    await expect(page.getByRole('tooltip')).toContainText('Estimated cost$0.00');
    await expect(page.getByRole('tooltip')).not.toContainText('unpriced');
    await page.evaluate(empty => {
      const usage = (window as unknown as {mock:Mock}).mock.usage!;
      const series = usage.series as {date:string}[];
      series[29] = {...series[29],...empty};
      usage.summary = {...usage.summary as object,tokens:1000000,calls:1,priced_calls:0,cost_usd:null};
    }, empty);
    await page.clock.fastForward(61000);
    await expect(page.locator('#usage-current')).toHaveText('$0.00');
    await page.evaluate(({empty,today}) => {
      const usage = (window as unknown as {mock:Mock}).mock.usage!;
      const series = usage.series as {date:string}[];
      series[28] = {...series[28],...empty};
      series[29] = {...series[29],...today};
      usage.summary = today;
    }, {empty,today});
    await page.clock.fastForward(61000);
    await expect(page.locator('#usage-average')).toHaveText(amount);
    if (cost === null || cost === 0) await expect(page.locator('#usage-average-line')).toBeHidden();
    else await expectUsageAverageLine(page, 1);
  });
}

for (const [application, label] of [['copilot', 'GitHub Copilot'], ['cursor', 'Cursor'], ['hermes', 'Hermes Agent'], ['opencode', 'OpenCode']]) {
  for (const maxWindowHeight of [720, 320]) {
    test(`native ${application} usage keeps unknown costs at ${maxWindowHeight}px`, async ({page}) => {
      await page.clock.install({time:new Date('2026-10-07T12:00:00Z')});
      const counts = {tokens:120,calls:1,priced_calls:0,cost_usd:null,
        cached_input_tokens:60,uncached_input_tokens:40,output_tokens:20};
      const breakdown = [{application,model:'reported-model',reasoning_effort:'unknown',...counts}];
      const empty = {tokens:0,calls:0,priced_calls:0,cost_usd:null};
      const series = Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
        ...(i === 29 ? counts : empty),breakdown:i === 29 ? breakdown : []}));
      const status = {...converged,telemetry:{...converged.telemetry,claude_available:false},
        hooks:{[application]:{available:true,installed:true,current:true}}};
      await boot(page,{status,maxWindowHeight,usage:{summary:counts,series,breakdown,pending_exports:0,
        by_model:[{name:'reported-model',...counts}],by_reasoning_effort:[{name:'unknown',...counts}]}});
      if (application === 'hermes') {
        const tools = page.getByRole('group',{name:'Coding tools detected on this device'});
        await expect(tools.getByRole('img')).toHaveCount(1);
        const logo = tools.getByRole('img',{name:'Hermes Agent',exact:true}).locator('img');
        await expect(logo).toHaveAttribute('src','/agent-icons/hermes.png');
        await expect.poll(()=>logo.evaluate((image:HTMLImageElement)=>image.complete && image.naturalWidth>0)).toBe(true);
      }
      await expect(page.locator('#usage-cost')).toHaveText('N/A');
      await expect(page.locator('#usage-legend')).toHaveText(label);
      await expect(page.locator('#usage-tokens')).toHaveAttribute('title',
        '100 input tokens (60 cached), 20 output tokens. Cache rate is cached input divided by total input.');
      await page.locator('.usage-day').last().focus();
      await expect(page.getByRole('tooltip').locator('.usage-app-heading')).toHaveText(`${label}N/A`);
      await expect(page.getByRole('tooltip')).toContainText('1 unpriced call excluded.');
      await expect(page.getByRole('tooltip')).toBeInViewport({ratio:1});
      await page.keyboard.press('Escape');
      const app = page.locator('#app');
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      if (maxWindowHeight === 720) expect(await app.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
      await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeInViewport({ratio:1});
    });
  }
}

for (const removalSupported of [false, null]) {
  test(`removal stays hidden without native support (${removalSupported})`, async ({page}) => {
    await boot(page, {status:converged,removalSupported});
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#remove-app')).toBeHidden();
    await expect(page.locator('#resume-app')).toBeHidden();
    await expect(page.locator('#trash-app')).toBeHidden();
    await returnToWindow(page);
    await expect(page.locator('#remove-app')).toBeHidden();
    expect((await requests(page)).some(request => ['desktop.remove', 'desktop.resume'].includes(request.action))).toBe(false);
  });
}

test('supported removal remains available when the initial sensor status fails', async ({page}) => {
  await boot(page, {status:converged,statusError:'The retained sensor could not start.'});
  await page.getByRole('button', {name:'Uninstall',exact:true}).click();
  await page.getByRole('button', {name:'Uninstall OpenAIDR',exact:true}).click();
  expect((await requests(page)).some(request => request.action === 'desktop.remove')).toBe(true);
});

for (const nativeUninstaller of [false, true]) for (const maxWindowHeight of [720, 160]) {
  test(`${nativeUninstaller ? 'Windows' : 'macOS'} uninstall confirmation stays reachable at ${maxWindowHeight}px and hands off removal`, async ({page}, testInfo) => {
    const retained_data = '/Volumes/Work Records/OpenAIDR data';
    const counts = {tokens:312060,calls:9,priced_calls:9,cost_usd:.68};
    await boot(page, {status:converged,maxWindowHeight,nativeUninstaller,afterRemove:{desktop_removal:{state:'complete',retained_data}},
      usage:{summary:counts,pending_exports:0,by_model:[{name:'claude-opus-5-5',...counts}],by_reasoning_effort:[{name:'medium',...counts}],
        series:Array.from({length:30},(_,i) => ({...counts,date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),tokens:i === 29 ? counts.tokens : 0}))}});
    await expect(page.locator('#usage-tokens')).toHaveText('312 k');
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    if (nativeUninstaller && maxWindowHeight === 720) await page.screenshot({path:testInfo.outputPath('windows-uninstall-button.png')});
    await page.getByRole('button', {name:'Uninstall',exact:true}).click();
    const dialog = page.getByRole('dialog', {name:'Uninstall OpenAIDR?'});
    await expect(dialog.locator('#remove-description')).toHaveText(nativeUninstaller
      ? 'OpenAIDR will close and open the Windows uninstaller. Follow its steps to remove the app and stop background services.'
      : 'Uninstalling stops the background sensor and any local runtime created by this app, and removes OpenAIDR’s hooks.');
    await expect(dialog.locator('#removal-retention')).toHaveText('Local and uploaded data are kept. Restart Codex and Claude Code after uninstalling.');
    await expect(dialog).toBeInViewport({ratio:1});
    const cancel = dialog.getByRole('button', {name:'Cancel',exact:true});
    const confirm = dialog.locator('#confirm-remove');
    await expect(confirm).toHaveText(nativeUninstaller ? 'Open uninstaller' : 'Uninstall OpenAIDR');
    await expect(cancel).toBeFocused();
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await dialog.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(maxWindowHeight === 160);
    if (maxWindowHeight === 160) {
      await dialog.evaluate(node => { node.scrollTop = 0; });
      await expect(dialog.getByRole('heading', {name:'Uninstall OpenAIDR?'})).toBeInViewport({ratio:1});
    }
    await confirm.focus();
    await expect(confirm).toBeFocused();
    await expect(confirm).toBeInViewport({ratio:1});
    await cancel.focus();
    await expect(cancel).toBeFocused();
    await expect(cancel).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('uninstall-confirmation.png')});
    expect((await requests(page)).some(request => request.action === 'desktop.remove')).toBe(false);
    await cancel.click();
    expect((await requests(page)).some(request => request.action === 'desktop.remove')).toBe(false);
    await page.getByRole('button', {name:'Uninstall',exact:true}).click();
    await confirm.click();
    if (nativeUninstaller) {
      // The app exits after opening the wizard. Launching it is not evidence
      // of completed removal, and no refresh/setup may run during that exit.
      await expect(confirm).toHaveText('Opening uninstaller…');
      await expect(confirm).toBeDisabled();
      await expect(cancel).toBeDisabled();
      await expect(page.locator('#resume-app')).toBeHidden();
      await expect(page.locator('#trash-app')).toBeHidden();
      const before = await requests(page);
      expect(before.filter(request => request.action === 'desktop.remove')).toHaveLength(1);
      await page.evaluate(() => window.dispatchEvent(new Event('focus')));
      expect((await requests(page)).filter(request => ['status', 'setup'].includes(request.action)))
        .toEqual(before.filter(request => ['status', 'setup'].includes(request.action)));
      return;
    }
    await expect(page.locator('#health-title')).toHaveText('Background services stopped.');
    await expect(page.locator('#health-description')).toHaveText('Restart Codex and Claude Code to finish removal.');
    await expect(page.locator('#retained-data')).toBeHidden();
    await page.locator('#retained-data-details summary').click();
    await expect(page.getByRole('region', {name:'Retained data',exact:true})).toContainText(retained_data);
    await page.locator('#retained-data-details summary').click();
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Background services stopped.');
    await expect(page.locator('#connect-card')).toBeHidden();
    expect((await requests(page)).filter(request => request.action === 'setup')).toHaveLength(0);
    await page.screenshot({path:testInfo.outputPath('remove-complete.png')});
  });
}

test('Windows uninstall launch errors remain retryable even when the sensor cannot start', async ({page}) => {
  await boot(page, {status:converged,nativeUninstaller:true,statusError:'The sensor could not start.',
    removeError:'The Windows uninstaller is missing. Reinstall OpenAIDR, then try again.'});
  await page.getByRole('button', {name:'Uninstall',exact:true}).click();
  const dialog = page.getByRole('dialog', {name:'Uninstall OpenAIDR?'});
  const confirm = dialog.locator('#confirm-remove');
  await confirm.click();
  await expect(dialog.locator('#remove-error')).toContainText('The Windows uninstaller is missing.');
  await expect(confirm).toBeEnabled();
  await expect(dialog.getByRole('button', {name:'Cancel',exact:true})).toBeEnabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    delete mock.removeError;
    mock.pendingAction = 'desktop.remove';
  });
  await page.getByRole('button', {name:'Uninstall',exact:true}).click();
  await confirm.click();
  await expect(confirm).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeVisible();
  expect((await requests(page)).filter(request => request.action === 'desktop.remove')).toHaveLength(2);
  await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
  await expect(confirm).toHaveText('Opening uninstaller…');
  await expect(dialog.locator('#remove-error')).toBeHidden();
  expect((await requests(page)).some(request => ['setup', 'desktop.resume', 'desktop.trash'].includes(request.action))).toBe(false);
});

for (const state of ['pending', 'complete']) {
  test(`long retained data paths remain readable after ${state} removal`, async ({page}) => {
    const retained_data = '/Volumes/' + 'long-custom-directory/'.repeat(80) + 'sensitive-queue';
    await boot(page, {status:{desktop_removal:{state,retained_data}}});
    await page.locator('#retained-data-details summary').click();
    const retained = page.getByRole('region', {name:'Retained data',exact:true});
    await expect(retained).toContainText(retained_data);
    await expect(retained).toContainText('~/Library/Application Support/OpenAIDR');
    await expect(retained).toContainText('after removal completes');
    await expect(retained.locator('code')).toHaveText([retained_data,'~/Library/Application Support/OpenAIDR']);
    await expect(retained.locator('code').first()).toHaveCSS('font-family', /"?Geist Mono"?/);
    await expect(retained).toHaveCSS('font-family', /^Geist,/);
    expect(await retained.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await retained.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await retained.focus();
    await page.keyboard.press('PageDown');
    await expect.poll(() => retained.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
    await expect(page.locator('#resume-app')).toBeInViewport({ratio:1});
  });
}

test('partial removal supports retry and one-click reinstall restores collection', async ({page}) => {
  const pending = {desktop_removal:{state:'pending',errors:['The sensor is still stopping. Retry removal shortly.']}};
  await boot(page, {status:pending,afterResume:converged});
  await expect(page.locator('#health-title')).toHaveText('Removal needs attention');
  await expect(page.locator('#trash-app')).toBeHidden();
  await page.getByRole('button', {name:'Retry uninstall',exact:true}).click();
  await page.getByRole('button', {name:'Uninstall OpenAIDR',exact:true}).click();
  await expect(page.locator('#health-title')).toHaveText('Background services stopped.');
  await page.getByRole('button', {name:'Reinstall',exact:true}).click();
  await expect(page.locator('#remove-dialog')).toBeHidden();
  expect((await requests(page)).filter(request => request.action === 'desktop.resume')).toHaveLength(1);
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expect(page.locator('#trash-app')).toBeHidden();
  await expect(page.locator('.brand')).toBeVisible();
  await expect(page.getByRole('button', {name:'Check updates',exact:true})).toBeVisible();
  await expectFitsWindow(page);
});

for (const maxWindowHeight of [720, 320]) {
  test(`install keeps progress visible until the main view is available at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    const counts = {tokens:431440000,cost_usd:364.71,calls:1800,priced_calls:1800};
    await boot(page, {status:{desktop_removal:{state:'complete'}}, pendingAction:'desktop.resume',
      afterResume:{...enrolled,service:'stopped',running:false}, afterSetup:converged,
      maxWindowHeight, usage:{summary:counts,pending_exports:0,
        by_model:[{name:'gpt-6-astra',...counts}],by_reasoning_effort:[{name:'high',...counts}],
        series:Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
          ...(i === 29 ? counts : {tokens:0,cost_usd:null,calls:0,priced_calls:0})}))}});
    await page.getByRole('button', {name:'Reinstall',exact:true}).click();
    const resume = page.locator('#resume-app');
    await expect(page.locator('#remove-dialog')).toBeHidden();
    await expect(resume).toHaveText('Installing…');
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = 'status';
      win.completeRequest();
    });
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'status')).toHaveLength(2);
    await expect(resume).toHaveText('Installing…');
    await expect(resume).toBeDisabled();
    await expect(page.locator('#trash-app')).toBeDisabled();
    await page.keyboard.press('Escape');
    await expect(page.locator('#remove-dialog')).toBeHidden();
    await expect(resume).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('install-waiting-for-status.png')});
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = 'setup';
      win.completeRequest();
    });
    await expect(page.locator('#remove-dialog')).toBeHidden();
    await expect(page.locator('#usage-panel')).toBeVisible();
    await expect(page.locator('#removal-actions')).toBeHidden();
    await expect(page.locator('#health-title')).not.toHaveText('Background services stopped.');
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined;
      win.completeRequest();
    });
    await expect(page.locator('#usage-tokens')).toHaveText('431 M');
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else {
      const app = page.locator('#app');
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await app.hover();
      await page.mouse.wheel(0, 1000);
      await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeInViewport({ratio:1});
      await expect(page.getByRole('button', {name:'Uninstall',exact:true})).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath('install-main-view.png')});
  });
}

for (const staleRemoval of [false, true]) {
  test(`install retries ${staleRemoval ? 'a stale removal status' : 'a failed status read'} without repeating the completed install`, async ({page}) => {
    const removed = {desktop_removal:{state:'complete'}};
    await boot(page, {status:removed, afterResume:staleRemoval ? removed : converged});
    if (!staleRemoval) await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'Could not read sensor status.'; });
    const resume = page.locator('#resume-app');
    await resume.click();
    await expect(page.locator('#remove-dialog')).toBeHidden();
    await expect(page.locator('#notice')).toHaveText(staleRemoval ? 'Installation is still finishing. Try again shortly.' : 'Could not read sensor status.');
    await expect(resume).toBeEnabled();
    await page.evaluate(status => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.status = status;
      mock.statusError = undefined;
      mock.resumeError = 'The saved removal preferences are invalid.';
    }, converged);
    await resume.click();
    await expect(page.locator('#remove-dialog')).toBeHidden();
    await expect(page.locator('#usage-panel')).toBeVisible();
    await expect(page.locator('#removal-actions')).toBeHidden();
    expect((await requests(page)).filter(r => r.action === 'desktop.resume')).toHaveLength(1);
  });
}

for (const colorScheme of ['light', 'dark'] as const) {
  test(`completed removal distinguishes Install and destructive Trash actions in ${colorScheme} mode`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme});
    await boot(page, {status:{desktop_removal:{state:'complete',retained_data:'/Users/example/Library/Application Support/OpenAIDR/data'}},pendingAction:'desktop.trash'});
    const resume = page.getByRole('button', {name:'Reinstall',exact:true});
    const trash = page.getByRole('button', {name:'Move app to Trash',exact:true});
    await expect(resume).toHaveClass(/button-secondary/);
    await expect(trash).toHaveCSS('background-color', 'rgb(135, 36, 32)');
    await expect(trash).toHaveCSS('color', 'rgb(255, 255, 255)');
    await expect(page.locator('#health-title')).toHaveText('Background services stopped.');
    await expect(page.locator('#health-description')).toHaveText('Restart Codex and Claude Code to finish removal.');
    await expect(page.locator('.brand')).toBeHidden();
    await expect(page.getByRole('button', {name:'Check updates',exact:true})).toBeHidden();
    await expect(page.locator('#health-dot .status-check')).toBeVisible();
    const disclosure = page.locator('#retained-data-details summary');
    await expect(disclosure).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
    await expect(disclosure).toHaveCSS('box-shadow', 'none');
    await expectFitsWindow(page);
    const summaryBounds = await disclosure.boundingBox();
    const installBounds = await resume.boundingBox();
    expect(summaryBounds!.y + summaryBounds!.height).toBeLessThan(installBounds!.y);
    await expect(resume).toBeInViewport({ratio:1});
    await expect(trash).toBeInViewport({ratio:1});
    await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
    expect((await requests(page)).some(request => request.action === 'desktop.trash')).toBe(false);
    await expectControlHierarchy(page);
    await page.locator('#retained-data-details summary').click();
    await expect(page.getByRole('region', {name:'Retained data',exact:true})).toBeVisible();
    await expectControlHierarchy(page);
    await expectFitsWindow(page);
    await page.locator('#retained-data-details summary').click();
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath(`removal-${colorScheme}.png`)});
    await trash.click();
    await expect(page.getByRole('button', {name:'Moving to Trash…',exact:true})).toBeDisabled();
    await expect(resume).toBeDisabled();
    await expect.poll(() => requests(page).then(items => items.filter(request => request.action === 'desktop.trash'))).toEqual([{action:'desktop.trash'}]);
    await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
    await expect(resume).toBeDisabled();
  });
}

test('completed removal keeps guidance, retained paths and actions reachable in a small work area', async ({page}) => {
  const retained_data = '/Volumes/Work Records/' + 'organization-archive/'.repeat(40) + 'OpenAIDR data';
  await boot(page, {status:{desktop_removal:{state:'complete',retained_data}},maxWindowHeight:160});
  const app = page.locator('#app');
  await expect.poll(() => app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
  await expect(page.locator('#health-title')).toBeInViewport({ratio:1});
  await expect(page.locator('#health-description')).toBeInViewport({ratio:1});
  const disclosure = page.locator('#retained-data-details summary');
  await disclosure.focus();
  await page.keyboard.press('Enter');
  const retained = page.getByRole('region', {name:'Retained data',exact:true});
  await expect(retained).toContainText(retained_data);
  await retained.focus();
  await page.keyboard.press('PageDown');
  await expect.poll(() => retained.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
  for (const name of ['Reinstall', 'Move app to Trash']) {
    const button = page.getByRole('button', {name,exact:true});
    await button.focus();
    await expect(button).toBeFocused();
    await expect(button).toBeInViewport({ratio:1});
  }
  await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
  expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth && node.scrollTop > 0)).toBe(true);
  expect((await requests(page)).some(request => ['desktop.resume','desktop.trash'].includes(request.action))).toBe(false);
});

for (const colorScheme of ['light','dark'] as const) for (const maxWindowHeight of [720,160]) {
  test(`local data deletion requires confirmation in ${colorScheme} at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    await page.clock.install();
    await page.emulateMedia({colorScheme});
    const retained_data = '/Users/example/Library/Application Support/OpenAIDR/data';
    await boot(page, {status:{desktop_removal:{state:'complete',retained_data}},maxWindowHeight,pendingAction:'desktop.trash'});
    const checkbox = page.getByRole('checkbox',{name:'Delete local data',exact:true});
    await expect(checkbox).not.toBeChecked();
    await expect(page.locator('#trash-app')).toHaveText('Move app to Trash');
    if (maxWindowHeight === 720) await page.screenshot({path:testInfo.outputPath(`delete-data-default-${colorScheme}.png`)});
    await checkbox.check();
    await returnToWindow(page);
    await expect(checkbox).toBeChecked();
    const trash = page.getByRole('button',{name:'Delete data and move to Trash',exact:true});
    await expect(trash).toBeVisible();
    await checkbox.uncheck();
    await expect(page.locator('#trash-app')).toHaveText('Move app to Trash');
    await checkbox.check();
    await trash.focus();
    await expect(trash).toBeInViewport({ratio:1});
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect((await requests(page)).filter(r => r.action === 'desktop.trash')).toEqual([]);
    if (maxWindowHeight === 720) {
      await expectFitsWindow(page);
      await page.screenshot({path:testInfo.outputPath(`delete-data-${colorScheme}.png`)});
    }
    await trash.click();
    const dialog = page.getByRole('dialog',{name:'Delete local data?',exact:true});
    await expect(dialog).toContainText('This cannot be undone. Uploaded data is kept.');
    await expect(dialog).toContainText('the dashboard runtime and database created by this app');
    await expect(dialog).toContainText('Separately installed runtimes are kept.');
    await expect(dialog.getByRole('button',{name:'Cancel',exact:true})).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    expect((await requests(page)).filter(r => r.action === 'desktop.trash')).toEqual([]);
    await trash.click();
    const confirm = dialog.locator('#confirm-remove');
    await expect(confirm).toHaveText('Delete data and move to Trash');
    await confirm.focus();
    await expect(confirm).toBeInViewport({ratio:1});
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.screenshot({path:testInfo.outputPath(`delete-data-confirm-${colorScheme}.png`)});
    await confirm.click();
    await expect(checkbox).toBeDisabled();
    await expect(confirm).toHaveText('Deleting local data…');
    await expect(dialog).toContainText('Desktop diagnostic logs outside this folder are kept.');
    await expect(dialog.locator('#removal-stage')).toHaveText('Waiting for other operations…');
    await page.evaluate(() => (window as unknown as {removalProgress:(stage:string) => void}).removalProgress('scan'));
    await expect(dialog.locator('#removal-stage')).toHaveText('Checking local files…');
    await page.clock.runFor(1100);
    await expect(dialog.locator('#removal-elapsed')).toContainText(/Elapsed [1-9][0-9]*s/);
    const firstElapsed = await dialog.locator('#removal-elapsed').textContent();
    await page.clock.runFor(1100);
    await expect(dialog.locator('#removal-elapsed')).not.toHaveText(firstElapsed!);
    await page.evaluate(() => (window as unknown as {removalProgress:(stage:string) => void}).removalProgress('deletion'));
    await expect(dialog.locator('#removal-stage')).toHaveText('Deleting local data and the app-created runtime…');
    await dialog.locator('#removal-stage').scrollIntoViewIfNeeded();
    await expect(dialog.locator('#removal-stage')).toBeInViewport({ratio:1});
    await expect(dialog.getByRole('button',{name:'Cancel',exact:true})).toBeDisabled();
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) {
      await expect(confirm).toBeInViewport({ratio:1});
      await page.screenshot({path:testInfo.outputPath(`deletion-progress-${colorScheme}.png`)});
    } else {
      await confirm.scrollIntoViewIfNeeded();
      await expect(confirm).toBeInViewport({ratio:1});
    }
    await page.keyboard.press('Escape');
    await expect(dialog).toBeVisible();
    await expect.poll(() => requests(page).then(items => items.filter(r => r.action === 'desktop.trash'))).toEqual([{action:'desktop.trash',delete_data:true}]);
    await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
    await expect(confirm).toBeDisabled();
  });
}

test('data deletion errors retain the stopped state and successful cleanup survives a Trash failure', async ({page}) => {
  const retained_data = '/Users/example/Library/Application Support/OpenAIDR/data';
  await boot(page, {status:{desktop_removal:{state:'complete',retained_data}},trashError:'Local data deletion is incomplete. Retry deletion.'});
  const checkbox = page.getByRole('checkbox',{name:'Delete local data',exact:true});
  await checkbox.check();
  await page.locator('#trash-app').click();
  const dialog = page.locator('#remove-dialog');
  await dialog.locator('#confirm-remove').click();
  await expect(dialog.getByRole('alert')).toContainText('incomplete');
  await expect(dialog.locator('#removal-progress')).toBeHidden();
  await page.evaluate(() => (window as unknown as {removalProgress:(stage:string) => void}).removalProgress('trash'));
  await expect(dialog.locator('#removal-progress')).toBeHidden();
  await expect(dialog.locator('#confirm-remove')).toBeEnabled();
  await expect(checkbox).toBeChecked();
  expect((await requests(page)).some(r => r.action === 'setup')).toBe(false);
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.status = {desktop_removal:{state:'complete',data_deletion_started:true,data_deleted:true}};
    mock.trashError = 'Could not move OpenAIDR to Trash.';
  });
  await dialog.locator('#confirm-remove').click();
  await expect(dialog.getByRole('alert')).toContainText('Could not move');
  await expect(dialog.locator('#remove-title')).toHaveText('Local data deleted');
  await expect(dialog.locator('#confirm-remove')).toHaveText('Move app to Trash');
  await expect(dialog.locator('#removal-progress')).toBeHidden();
  await dialog.locator('#confirm-remove').click();
  await expect.poll(() => requests(page).then(items => items.filter(r => r.action === 'desktop.trash').at(-1))).toEqual({action:'desktop.trash'});
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
  await expect(page.locator('#removal-data')).toBeHidden();
  await expect(page.locator('#removal-data-note')).toHaveText('Local data deleted. Uploaded data is kept.');
  await expect(page.locator('#trash-app')).toHaveText('Move app to Trash');
  await page.getByRole('button',{name:'Reinstall',exact:true}).click();
  await expect(page.locator('#remove-dialog')).toBeHidden();
  await expect(page.locator('#health-title')).toHaveText('Welcome to OpenAIDR');
  await expect(page.locator('#setup-choices')).toBeVisible();
  expect((await requests(page)).filter(request => request.action === 'desktop.resume')).toHaveLength(1);
});

test('failed Trash action keeps the app open and can be retried', async ({page}) => {
  await boot(page, {status:{desktop_removal:{state:'complete'}},trashError:'Could not move OpenAIDR to Trash. Quit and move it to Trash in Finder.'});
  await page.getByRole('button', {name:'Move app to Trash',exact:true}).click();
  await expect(page.locator('#notice')).toContainText('Quit and move it to Trash in Finder.');
  await expect(page.locator('#health-title')).toHaveText('Background services stopped.');
  await expect(page.getByRole('button', {name:'Move app to Trash',exact:true})).toBeEnabled();
  await expect(page.getByRole('button', {name:'Reinstall',exact:true})).toBeEnabled();
  expect((await requests(page)).some(request => request.action === 'setup')).toBe(false);
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'The local service request failed.'; });
  await returnToWindow(page);
  await expect(page.locator('#health-title')).toHaveText('Status unavailable');
  await expect(page.locator('.brand')).toBeVisible();
  await expect(page.getByRole('button', {name:'Retry status',exact:true})).toBeVisible();
  await expect(page.locator('#health-dot')).toHaveCSS('background-color', 'rgb(135, 36, 32)');
  await expectFitsWindow(page);
});

for (const action of ['desktop.resume', 'desktop.remove']) {
  test(`${action} shows progress and supports retry after failure`, async ({page}, testInfo) => {
    const resume = action === 'desktop.resume';
    const label = resume ? 'Reinstall' : 'Uninstall OpenAIDR';
    const working = resume ? 'Installing…' : 'Uninstalling…';
    const error = 'An update is in progress. Try again shortly.';
    await boot(page, {status:resume ? {desktop_removal:{state:'complete'}} : converged,usage:usageTotals(300),
      pendingAction:action,afterResume:converged,...(resume ? {resumeError:error} : {removeError:error})});
    if (!resume) await expect(page.locator('#usage-tokens')).toHaveText('300');
    await page.getByRole('button', {name:resume ? 'Reinstall' : 'Uninstall',exact:true}).click();
    const dialog = page.locator('#remove-dialog');
    const confirm = page.locator(resume ? '#resume-app' : '#confirm-remove');
    const errorNotice = page.locator(resume ? '#notice' : '#remove-error');
    const cancel = dialog.getByRole('button', {name:'Cancel',exact:true});
    if (!resume) await confirm.click();
    await expect(confirm).toHaveText(working);
    await expect(confirm).toHaveAttribute('aria-busy', 'true');
    await expect(confirm).toBeDisabled();
    if (resume) await expect(page.locator('#trash-app')).toBeDisabled();
    else await expect(cancel).toBeDisabled();
    await expect(page.locator('#usage-panel [data-days="1"]')).toBeDisabled();
    await expect(page.locator('#usage-panel [data-days="30"]')).toBeDisabled();
    await page.keyboard.press('Escape');
    await expect(dialog).toBeVisible({visible:!resume});
    await expect(confirm).toBeInViewport({ratio:1});
    if (resume) {
      await confirm.evaluate((button:HTMLButtonElement) => button.click());
      await returnToWindow(page);
    }
    expect((await requests(page)).filter(request => request.action === action)).toHaveLength(1);
    await page.screenshot({path:testInfo.outputPath(`${resume ? 'setup' : 'removal'}-progress.png`)});
    await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
    await expect(errorNotice).toHaveText(error);
    await expect(errorNotice).toBeVisible();
    await expect(confirm).toHaveText(label);
    await expect(confirm).toHaveAttribute('aria-busy', 'false');
    await expect(confirm).toBeEnabled();
    if (!resume) await expect(cancel).toBeEnabled();
    await expect(page.locator('#health-title')).toHaveText(resume ? 'Background services stopped.' : 'Sensor is running');
    await page.evaluate(() => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.resumeError = undefined;
      mock.removeError = undefined;
    });
    await confirm.click();
    await expect(confirm).toHaveText(working);
    await expect(confirm).toBeDisabled();
    await expect(errorNotice).toBeHidden();
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined;
      win.completeRequest();
    });
    await expect(dialog).toBeHidden();
    await expect(confirm).toHaveText(label);
    await expect(confirm).toHaveAttribute('aria-busy', 'false');
    await expect(page.locator('#health-title')).toHaveText(resume ? 'Sensor is running' : 'Background services stopped.');
    if (!resume) await expect(page.locator('#usage-panel')).toBeHidden();
    expect((await requests(page)).filter(request => request.action === action)).toHaveLength(2);
  });
}

test('all partial removal errors remain readable with keyboard scrolling', async ({page}) => {
  const errors = [
    'The background sensor could not be stopped. '.repeat(8) + 'Check your macOS login session and retry removal.',
    'Your edited coding-agent settings still point to the local receiver. '.repeat(8) + 'Keep your other edits and remove the OpenAIDR exporter manually before retrying.',
  ];
  await boot(page, {status:{desktop_removal:{state:'pending',errors}}});
  const details = page.getByRole('region', {name:'Removal errors'});
  await expect(details).toBeInViewport({ratio:1});
  await expect(details.locator('p')).toHaveText(errors);
  expect(await details.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
  await details.focus();
  await page.keyboard.press('ControlOrMeta+End');
  await expect(details.locator('p').last()).toBeInViewport();
  await expect(page.getByRole('button', {name:'Retry uninstall'})).toBeInViewport({ratio:1});
});

test('simulation controls stay hidden in ordinary builds', async ({page}) => {
  await boot(page, {status:converged});
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expect(page.locator('#collection-guidance')).toContainText('Restart coding-agent sessions after setup or an app update.');
  await expect(page.getByRole('button', {name:'Simulation',exact:true})).toHaveCount(0);
  expect((await requests(page)).some(request => request.action === 'simulation.start')).toBe(false);
});

for (const colorScheme of ['light', 'dark'] as const) {
  test(`simulation start, stop and keyboard controls in ${colorScheme} mode`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme});
    await page.setViewportSize({width:config.app.windows[0].width,height:288});
    await boot(page, {status:{...converged,telemetry:{...converged.telemetry,received:733,forwarded:733,queue_depth:0}},
      simulation:{enabled:true,configured:true,destination:'Local Dev',state:'stopped',enrolled:0,records_sent:0}});
    const trigger = page.getByRole('button', {name:'Simulation',exact:true});
    await expectControlHierarchy(page);
    await trigger.click();
    const panel = page.getByRole('dialog');
    await expect(panel).toBeInViewport({ratio:1});
    await expect(panel.getByText('Local Dev', {exact:true})).toBeVisible();
    await expect(panel.getByRole('button', {name:'Start simulation'})).toBeInViewport({ratio:1});
    await expectControlHierarchy(page);
    const close = panel.getByRole('button', {name:'Close simulation',exact:true});
    await close.focus();
    await page.keyboard.press('Tab');
    await page.keyboard.press('Shift+Tab');
    await expect(close).toBeFocused();
    await expect(close).toHaveCSS('outline-style', 'solid');
    await page.screenshot({path:testInfo.outputPath(`simulation-stopped-${colorScheme}.png`)});
    await panel.getByRole('button', {name:'Start simulation'}).click();
    await expect(panel.getByText('Running', {exact:true})).toBeVisible();
    await expect(page.locator('#sent')).toHaveText('733');
    await expect(page.locator('#delivery')).toHaveText('733');
    await page.keyboard.press('Escape');
    await expect(panel).not.toBeVisible();
    await expect(trigger).toBeFocused();
    await expectControlHierarchy(page);
    expect((await requests(page)).filter(request => request.action === 'simulation.stop')).toHaveLength(0);
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'simulation.status'; });
    await trigger.click();
    await expect.poll(() => page.evaluate(() => typeof (window as unknown as {completeRequest?:() => void}).completeRequest)).toBe('function');
    await panel.getByRole('button', {name:'Stop simulation'}).click();
    await expect(panel.getByText('Stopped', {exact:true})).toBeVisible();
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined;
      win.completeRequest();
    });
    await expect(panel.getByText('Stopped', {exact:true})).toBeVisible();
    await page.evaluate(() => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.simulationError = 'The test workspace could not be reached.';
    });
    await panel.getByRole('button', {name:'Start simulation'}).click();
    await expect(panel.getByRole('alert')).toContainText('test workspace could not be reached');
    await expect(panel.getByRole('button', {name:'Start simulation'})).toBeEnabled();
    await expect(panel.getByRole('button', {name:'Start simulation'})).toBeInViewport({ratio:1});
    expect((await requests(page)).filter(request => request.action === 'setup')).toHaveLength(0);
  });
}

test('simulation requires a configured test workspace', async ({page}) => {
  await boot(page, {status:converged,simulation:{enabled:true,configured:false,state:'stopped',error:'Configure a separate local test workspace in simulation.yaml.'}});
  await page.getByRole('button', {name:'Simulation',exact:true}).click();
  await expect(page.getByRole('button', {name:'Start simulation'})).toBeDisabled();
  await expect(page.getByRole('dialog').getByRole('alert')).toContainText('separate local test workspace');
});

for (const maxWindowHeight of [720,320]) {
  test(`connected dashboard links refresh and stay readable with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const healthy = {...converged,heartbeat:{last_success_at:'2026-10-08T02:50:00Z',error:''},activity:{queue_depth:0},telemetry:{...converged.telemetry,received:11752,forwarded:11240,queue_depth:1}};
    const counts = {tokens:1830000,calls:100,priced_calls:100,cost_usd:1.14};
    await boot(page, {status:healthy,maxWindowHeight,usage:{summary:counts,pending_exports:0,
      by_model:[{name:'gpt-6-astra',...counts}],by_reasoning_effort:[{name:'high',...counts}]}});
    await expect(page.locator('#usage-tokens')).toHaveText('1.83 M');
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    await openSensorStatus(page);
    const panel = page.locator('#health-card');
    const description = page.locator('#health-description');
    for (const name of [undefined, 'OpenSecura test', 'Research <Platform> & Operations', 'A'.repeat(256), '   ', 'Renamed organization']) {
      await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,tenant_name:name});
      await returnToWindow(page);
      const message = `The sensor is running and connected to ${name?.trim() || 'your organization'}.`;
      await expect(description).toHaveText(message);
      await expect(description).not.toHaveAttribute('title');
      const dashboard = panel.getByRole('link', {name:'Open dashboard',exact:true});
      await expect(dashboard).toHaveAttribute('href', `${healthy.server_url}/`);
      await expect(dashboard).toHaveAttribute('title', 'Open dashboard in your browser');
      await expect(description.locator('*')).toHaveCount(0);
      await expect(panel).toBeInViewport({ratio:1});
      expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await description.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
      await panel.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(page.locator('#counter-note')).toBeInViewport({ratio:1});
      await panel.evaluate(node => { node.scrollTop = 0; });
      await expect(page.locator('#close-status')).toBeInViewport({ratio:1});
      if (name === 'OpenSecura test') await page.screenshot({path:testInfo.outputPath('connected-dashboard-link.png')});
    }
    const dashboard = panel.getByRole('link', {name:'Open dashboard',exact:true});
    await dashboard.click();
    await page.locator('#close-status').focus();
    await page.keyboard.press('Tab');
    await expect(dashboard).toBeFocused();
    await expect(dashboard).toHaveCSS('outline-style', 'solid');
    await returnToWindow(page);
    await expect(dashboard).toBeFocused();
    await page.keyboard.press('Enter');
    expect((await requests(page)).filter(request => request.action === 'desktop.dashboard')).toEqual([
      {action:'desktop.dashboard',server_url:`${healthy.server_url}/`},
      {action:'desktop.dashboard',server_url:`${healthy.server_url}/`},
    ]);
    await page.locator('#close-status').click();
    await page.getByRole('button', {name:'Settings',exact:true}).click();
    await expect(page.getByRole('dialog', {name:'Settings'})).toBeVisible();
  });
}

test('dashboard links follow the connected server and handle missing addresses and browser errors', async ({page}) => {
  const healthy = {...converged,tenant_name:'OpenSecura test',heartbeat:{last_success_at:'2026-10-08T02:50:00Z',error:''}};
  await boot(page, {status:healthy,dashboardError:'No browser available'});
  await openSensorStatus(page);
  const description = page.locator('#health-description');
  const dashboard = page.getByRole('link', {name:'Open dashboard',exact:true});
  await dashboard.click();
  await expect(page.locator('#dashboard-error')).toHaveText(`Could not open your browser. Open ${healthy.server_url}/ to view the dashboard.`);
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.dashboardError = undefined; });
  await dashboard.click();
  await expect(page.locator('#dashboard-error')).toBeHidden();
  for (const serverUrl of ['https://other.example:8443/', 'http://localhost:8080', 'http://[::1]:8080']) {
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,server_url:serverUrl});
    await returnToWindow(page);
    await expect(dashboard).toHaveAttribute('href', new URL(serverUrl).href);
    await dashboard.click();
    expect((await requests(page)).filter(request => request.action === 'desktop.dashboard').at(-1)).toEqual({action:'desktop.dashboard',server_url:new URL(serverUrl).href});
  }
  for (const serverUrl of [undefined, '', 'invalid', 'javascript:alert(1)', 'file:///tmp/dashboard', 'https://user:secret@tenant.example', 'https://tenant.example/enroll#token=secret']) {
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,server_url:serverUrl});
    await returnToWindow(page);
    await expect(description).toHaveText('The sensor is running and connected to OpenSecura test.');
    await expect(dashboard).toHaveCount(0);
  }
  await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, healthy);
  await returnToWindow(page);
  await expect(dashboard).toHaveAttribute('href', `${healthy.server_url}/`);
  await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,heartbeat:{last_success_at:null,error:''}});
  await returnToWindow(page);
  await expect(description).toHaveText('The sensor is making its first connection.');
  await expect(dashboard).toHaveAttribute('href', `${healthy.server_url}/`);
  for (const status of [
    {...healthy,disabled:true},
    {...healthy,service:'stopped',running:false},
    {...healthy,heartbeat:{last_success_at:'2026-10-08T02:00:00Z',error:'Connection refused'}},
  ]) {
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, status);
    await returnToWindow(page);
    await expect(dashboard).toHaveAttribute('href', `${healthy.server_url}/`);
    await dashboard.click();
    expect((await requests(page)).filter(request => request.action === 'desktop.dashboard').at(-1)).toEqual({action:'desktop.dashboard',server_url:`${healthy.server_url}/`});
  }
  const opened = (await requests(page)).filter(request => request.action === 'desktop.dashboard').length;
  for (const status of [
    {...healthy,connection_mode:'free'},
    {...healthy,connection_mode:'api_key'},
    {...healthy,enrolled:false},
    {...healthy,desktop_removal:{state:'complete'}},
  ]) {
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, status);
    await returnToWindow(page);
    await expect(page.locator('#dashboard-row')).toBeHidden();
    await expect(page.locator('#dashboard-link')).toHaveCount(0);
  }
  expect((await requests(page)).filter(request => request.action === 'desktop.dashboard')).toHaveLength(opened);
});

async function expectFitsWindow(page: Page) {
  // #app scrolls independently of the document, so document bounds alone miss overflow.
  await expect.poll(() => page.locator('#app').evaluate(node => ({
    horizontalOverflow:node.scrollWidth - node.clientWidth,
    verticalOverflow:node.scrollHeight - node.clientHeight,
    left:node.scrollLeft,top:node.scrollTop,
  }))).toEqual({horizontalOverflow:0,verticalOverflow:0,left:0,top:0});
  // Check the actual dialog scroll containers without duplicating the sizing formula.
  await expect.poll(() => page.locator('dialog[open]').evaluateAll(dialogs => dialogs.flatMap(dialog => {
    const horizontalOverflow = dialog.scrollWidth - dialog.clientWidth, verticalOverflow = dialog.scrollHeight - dialog.clientHeight;
    return horizontalOverflow || verticalOverflow ? [{id:dialog.id,horizontalOverflow,verticalOverflow}] : [];
  }))).toEqual([]);
  // With overlays closed, the window follows the main content down to the native minimum height.
  if (!await page.locator('dialog[open]').count() && !await page.locator('#health-card').evaluate(node => node.classList.contains('status-popover') && !node.hasAttribute('hidden'))) {
    await expect.poll(() => page.evaluate(() => Math.abs(innerHeight - Math.max(160, document.querySelector('main')!.getBoundingClientRect().height)))).toBeLessThanOrEqual(1);
  }
  // Check content bounds outside the agent list, whose scrolling is tested separately.
  await expect.poll(() => page.locator('main *:not(.agent-list *), dialog[open]').evaluateAll(elements => elements.flatMap(element => {
    const closed = element.closest('details:not([open])');
    if (closed && element !== closed && !closed.querySelector(':scope > summary')?.contains(element)) return [];
    const {top, right, bottom, left, width, height} = element.getBoundingClientRect();
    return width && height && (top < -1 || left < -1 || bottom > innerHeight + 1 || right > innerWidth + 1)
      ? [{element:element.id || element.className || element.tagName,top,right,bottom,left}] : [];
  }))).toEqual([]);
  expect(await page.evaluate(() => scrollX === 0 && scrollY === 0 && document.documentElement.scrollWidth <= innerWidth && document.documentElement.scrollHeight <= innerHeight)).toBe(true);
}

for (const maxWindowHeight of [720,320]) {
  test(`restart guidance expires after one minute while usage authentication failures remain visible at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme:maxWindowHeight === 720 ? 'light' : 'dark'});
    await page.clock.install();
    await page.clock.pauseAt(new Date());
    const healthy = {...converged,server_url:'http://localhost:8080',heartbeat:{last_success_at:new Date().toISOString(),error:''},
      telemetry:{...converged.telemetry,codex_available:true,codex_installed:true,codex_current:true,received:724,forwarded:724,queue_depth:0},
      hooks:{opencode:{available:true,installed:true,current:true},hermes:{available:true,installed:true,current:true}}};
    await boot(page, {maxWindowHeight,usage:populatedUsage(),
      status:{...healthy,telemetry:{...healthy.telemetry,claude_current:false}},afterSetup:healthy,
      setup:{restart_required:true,steps:[{step:'telemetry.install',ok:true,agents:['claude']}]}});
    await expect(page.locator('#notice')).toHaveText('Restart Claude Code sessions to apply the new settings.');
    await page.clock.fastForward(15000);
    await expect(page.locator('#notice')).toBeVisible();
    await expect(page.locator('#usage-cost')).toHaveText('$42.18');
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await testInfo.attach('restart-reminder-visible', {body:await page.screenshot(),contentType:'image/png'});
    await page.getByRole('button',{name:'Settings',exact:true}).scrollIntoViewIfNeeded();
    await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeInViewport({ratio:1});
    await page.clock.fastForward(44999);
    await expect(page.locator('#notice')).toBeVisible();
    await page.clock.fastForward(1);
    await expect(page.locator('#notice')).toBeHidden();
    await page.clock.runFor(100);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await app.evaluate(node => { node.scrollTop = 0; });
    await testInfo.attach('restart-reminder-expired', {body:await page.screenshot(),contentType:'image/png'});
    await page.getByRole('button',{name:'Settings',exact:true}).scrollIntoViewIfNeeded();
    await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeInViewport({ratio:1});
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
      {...healthy,telemetry:{...healthy.telemetry,authentication_failed:true,received:100}});
    await returnToWindow(page);
    await expect(page.locator('#sensor-status')).toContainText('Attention');
    await app.evaluate(node => { node.scrollTop = 0; });
    await page.clock.runFor(100);
    await openSensorStatus(page);
    await expect(page.locator('#health-card')).toBeVisible();
    await expect(page.locator('#health-title')).toHaveText('Usage collection needs attention');
    await expect(page.locator('#health-description')).toContainText('Restart running coding-agent sessions');
    await expect(page.locator('#collection-guidance')).toContainText('Each rejection restarts that timer.');
    await page.locator('#health-description').scrollIntoViewIfNeeded();
    await expect(page.locator('#health-description')).toBeInViewport({ratio:1});
    expect(await page.locator('#health-card').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    const dashboard = page.getByRole('link', {name:'Open dashboard',exact:true});
    await expect(dashboard).toHaveAttribute('href', `${healthy.server_url}/`);
    await dashboard.scrollIntoViewIfNeeded();
    await expect(dashboard).toBeInViewport({ratio:1});
    await dashboard.click();
    expect((await requests(page)).filter(r => r.action === 'desktop.dashboard')).toEqual([
      {action:'desktop.dashboard',server_url:`${healthy.server_url}/`},
    ]);
    const rejectedClients = Array.from({length:8}, (_, index) => ({pid:39595 + index,
      process_name:index === 0 ? 'codex' : index === 1 ? 'claude.exe' : 'A long coding agent process name with spaces and <tag> characters',
      started_at:'2026-11-03T17:13:08Z',last_failed_at:'2026-11-04T06:43:47Z',signals:['logs','metrics']}));
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
      {...healthy,telemetry:{...healthy.telemetry,authentication_failed:true,authentication_failures:17,
        authentication_last_failed_at:'2026-11-04T06:43:47Z',authentication_unidentified:true,authentication_clients:rejectedClients}});
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Agent sessions need a restart');
    await expect(page.locator('#health-description')).toContainText('fully quit and reopen');
    await expect(page.locator('#health-description')).toContainText('Starting a new chat may keep the same agent process');
    await expect(page.locator('#telemetry-clients li')).toHaveCount(8);
    await expect(page.locator('#telemetry-clients li').first()).toContainText('Codex · PID 39595');
    await expect(page.locator('#telemetry-clients li').nth(1)).toContainText('Claude Code · PID 39596');
    await expect(page.locator('#telemetry-clients li').last()).toContainText('Started');
    await expect(page.locator('#telemetry-clients tag')).toHaveCount(0);
    await expect(page.locator('#telemetry-auth-summary')).toContainText('17 rejected local reports');
    await expect(page.locator('#telemetry-auth-summary')).toContainText('Last rejection:');
    await expect(page.locator('#collection-guidance')).toContainText('until those processes exit or reconnect successfully');
    await expect(page.locator('#collection-guidance')).toContainText('An additional client could not be identified');
    await page.clock.fastForward(301000);
    await expect(page.locator('#telemetry-clients li')).toHaveCount(8);
    expect(await page.locator('#health-card').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.locator('#health-card').evaluate(node => { node.scrollTop = 0; });
    await page.screenshot({path:testInfo.outputPath('identified-sessions.png')});
    await page.locator('#telemetry-clients li').last().scrollIntoViewIfNeeded();
    await expect(page.locator('#telemetry-clients li').last()).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('usage-authentication-warning.png')});
    const panel = page.locator('#health-card');
    await panel.evaluate(node => { node.scrollTop = node.scrollHeight; });
    await expect(page.locator('#retry')).toBeInViewport({ratio:1});
    await panel.evaluate(node => { node.scrollTop = 0; });
    await expect(page.locator('#close-status')).toBeInViewport({ratio:1});
    // Updated sensors omit the retired telemetry authentication diagnostics.
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
      {...healthy,telemetry:{...healthy.telemetry,received:200}});
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Sensor connected');
    await expect(page.locator('#sensor-status')).toContainText('Connected');
    await expect(page.locator('#telemetry-auth')).toBeHidden();
    await expect(page.locator('#telemetry-clients li')).toHaveCount(0);
    await expect(page.locator('#telemetry-auth-summary')).toBeHidden();
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  });
}

test('restart reminder timeout preserves a later setup message and resets for a new reminder', async ({page}) => {
  await page.clock.install();
  await page.clock.pauseAt(new Date());
  const stale = {...converged,telemetry:{...converged.telemetry,claude_current:false}};
  await boot(page, {status:stale,afterSetup:converged,
    setup:{steps:[{step:'telemetry.install',ok:true,agents:['claude']}],restart_required:true}});
  await expect(page.locator('#notice')).toHaveText('Restart Claude Code sessions to apply the new settings.');
  await page.clock.fastForward(30000);
  await page.evaluate(status => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.status = status;
    mock.pendingAction = 'setup';
    window.dispatchEvent(new Event('focus'));
  }, stale);
  await expect(page.locator('#notice')).toHaveText('Setting up this device…');
  await page.clock.fastForward(60000);
  await expect(page.locator('#notice')).toBeVisible();
  await expect(page.locator('#notice')).toHaveText('Setting up this device…');
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingAction = undefined;
    win.completeRequest();
  });
  await expect(page.locator('#notice')).toHaveText('Restart Claude Code sessions to apply the new settings.');
  await page.clock.fastForward(59999);
  await expect(page.locator('#notice')).toBeVisible();
  await page.clock.fastForward(1);
  await expect(page.locator('#notice')).toBeHidden();
  await returnToWindow(page);
  await expect(page.locator('#notice')).toBeHidden();
  expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(2);
});

for (const maxWindowHeight of [720,240]) {
  test(`first visibility fits setup choices within a ${maxWindowHeight}px work area`, async ({page}) => {
    await page.addInitScript(() => Object.defineProperty(document, 'hidden', {configurable:true,get:() => true}));
    await boot(page, {status:unenrolled,pendingAction:'status',menuBar:{supported:true,enabled:false},maxWindowHeight});
    await expect.poll(() => page.evaluate(() => typeof (window as unknown as {completeRequest?:unknown}).completeRequest)).toBe('function');
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined;
      win.completeRequest();
    });
    await expect(page.locator('#health-title')).toHaveText('Welcome to OpenAIDR');
    await expect(page.locator('#resume-app')).toBeHidden();
    expect((await requests(page)).some(request => request.action === 'desktop.resume')).toBe(false);
    // Let ResizeObserver process the new content while fitting is suspended.
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await page.evaluate(() => {
      Reflect.deleteProperty(document, 'hidden');
      document.dispatchEvent(new Event('visibilitychange'));
    });
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else {
      await expect.poll(() => page.viewportSize()!.height).toBe(maxWindowHeight);
      expect(await page.locator('#app').evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      expect(await page.locator('#app').evaluate(node => node.scrollWidth - node.clientWidth)).toBe(0);
    }
    for (const selector of ['#continue-free','#choose-organization']) {
      if (maxWindowHeight < 720) await page.locator(selector).scrollIntoViewIfNeeded();
      await expect(page.locator(selector)).toBeInViewport({ratio:1});
    }
  });
}

async function expectEnrollmentFeedbackBesideLink(page: Page) {
  await expect(page.locator('#enrollment-link')).toHaveAttribute('aria-describedby', 'link-feedback');
  await expect.poll(() => page.locator('#link-enrollment').evaluate(form => {
    const input = form.querySelector('#enrollment-link')!.getBoundingClientRect();
    const feedback = form.querySelector('#link-feedback')!;
    const bounds = feedback.getBoundingClientRect();
    const certificates = form.querySelector('#certificate-options')!.getBoundingClientRect();
    return {
      belowInput:bounds.top >= input.bottom && bounds.top - input.bottom <= 12,
      aboveCertificates:bounds.bottom <= certificates.top,
      readable:feedback.scrollHeight <= feedback.clientHeight && feedback.scrollWidth <= feedback.clientWidth,
    };
  })).toEqual({belowInput:true,aboveCertificates:true,readable:true});
}

for (const maxWindowHeight of [720,320]) {
  test(`connection modal keeps controls reachable with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const counts = {tokens:436110000,calls:1234,priced_calls:1234,cost_usd:368.13};
    await boot(page, {status:converged, preview, previewError:'Could not verify the enrollment server.', maxWindowHeight, usage:{summary:counts,pending_exports:0,
      series:Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...counts,tokens:i === 29 ? counts.tokens : 0})),
      by_model:[['gpt-6-astra',337.93],['gpt-6.1-sol',29.91],['claude-fable-5-1',.28],['gpt-5.6-luna',.01]].map(([name,cost_usd]) => ({...counts,name,cost_usd})),
      by_reasoning_effort:[['low',7.11],['high',.28],['xhigh',116.99],['unknown',243.75]].map(([name,cost_usd]) => ({...counts,name,cost_usd}))}});
    await expect(page.locator('#usage-tokens')).toHaveText('436 M');
    const mainHeight = await page.locator('main').evaluate(node => node.getBoundingClientRect().height);
    await page.getByRole('button', {name:'Settings', exact:true}).click();
    const dialog = page.getByRole('dialog', {name:'Settings'});
    await expect(dialog).toBeVisible();
    await expect(dialog).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('connection-modal-default.png')});
    await page.getByText('Private server certificate (optional)', {exact:true}).click();
    await expect(page.locator('#link-feedback')).toHaveText('Use the enrollment link from your administrator.');
    await expectEnrollmentFeedbackBesideLink(page);
    await page.getByLabel('Enrollment link', {exact:true}).fill(link);
    await expect(page.locator('#link-feedback')).toHaveText('Could not verify the enrollment server.');
    await expectEnrollmentFeedbackBesideLink(page);
    await expect(page.locator('#link-feedback')).toBeInViewport({ratio:1});
    await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeDisabled();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.previewError = ''; });
    await page.getByLabel('Organization CA certificate', {exact:true}).setInputFiles({name:'organization.pem',mimeType:'application/x-pem-file',buffer:Buffer.from(certificate)});
    await expect(page.locator('#link-preview')).toBeVisible();
    await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeEnabled();
    expect(await page.locator('main').evaluate(node => node.getBoundingClientRect().height)).toBe(mainHeight);
    await expect(dialog).toBeInViewport({ratio:1});
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    const app = page.locator('#app');
    const appScroll = await app.evaluate(node => node.scrollTop);
    if (maxWindowHeight === 320) {
      await expect.poll(() => page.viewportSize()!.height).toBe(320);
      expect(await dialog.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await dialog.hover();
      await page.mouse.wheel(0, 1000);
      await expect.poll(() => dialog.evaluate(node => node.scrollHeight - node.clientHeight - node.scrollTop)).toBeLessThanOrEqual(1);
    } else {
      await expectFitsWindow(page);
      expect(await dialog.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
    }
    await page.getByRole('button', {name:'Connect', exact:true}).focus();
    await expect(page.getByRole('button', {name:'Connect', exact:true})).toBeInViewport({ratio:1});
    await page.getByRole('button', {name:'Done',exact:true}).focus();
    await expect(page.getByRole('button', {name:'Done',exact:true})).toBeInViewport({ratio:1});
    expect(await app.evaluate(node => node.scrollTop)).toBe(appScroll);
    await page.screenshot({path:testInfo.outputPath('connection-modal.png')});
    await page.getByRole('button', {name:'Done',exact:true}).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('button', {name:'Settings', exact:true})).toBeFocused();
    await page.getByRole('button', {name:'Uninstall', exact:true}).click();
    await expect(page.getByRole('dialog', {name:'Uninstall OpenAIDR?'})).toBeVisible();
    await page.getByRole('button', {name:'Cancel',exact:true}).click();
  });
}

test('status fits the window without scrolling or unused space below the footer', async ({ page }, testInfo) => {
  await boot(page, {status: {...converged, telemetry:{...converged.telemetry, queue_depth:0, forwarded:13797, received:13797}}});
  await expect(page).toHaveTitle('OpenAIDR');
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expect(page.locator('#queued')).toHaveText('0');
  await expect(page.locator('#sent')).toHaveText('13,797');
  await expect(page.locator('#delivery')).toHaveText('13,797');
  await expect(page.getByText('Your AI activity,')).toHaveCount(0);
  await expect(page.getByText('Local control center')).toHaveCount(0);
  await expect(page.getByText('This device', {exact:true})).toBeHidden();
  await expect(page.getByText('Sensor ID', {exact:true})).toHaveCount(0);
  await expect(page.getByRole('button', {name:'Check updates',exact:true})).toBeVisible();
  await expect(page.locator('#update-notice')).toBeHidden();
  await expect(page.locator('#notice')).toBeHidden();
  const {width, resizable} = config.app.windows[0];
  expect(resizable).toBe(false);
  await expectFitsWindow(page);
  expect(page.viewportSize()!.width).toBe(width);
  await expect(page.locator('#sensor-status')).toBeInViewport({ratio:1});
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeInViewport({ratio:1});
  expect(await page.locator('#status-footer').evaluate(footer => innerHeight - footer.getBoundingClientRect().bottom)).toBeLessThanOrEqual(12);
  await page.mouse.wheel(0, 500);
  await page.keyboard.press('PageDown');
  await page.evaluate(() => window.scrollTo(100, 500));
  await expectFitsWindow(page);
  expect(await page.locator('#status-footer').evaluate(footer => innerHeight - footer.getBoundingClientRect().bottom)).toBeLessThanOrEqual(12);
  await page.locator('.brand').click();
  await page.screenshot({path:testInfo.outputPath('fixed-desktop.png')});
  await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...converged, telemetry:{...converged.telemetry, queue_depth:1, forwarded:13798, received:13799}});
  await returnToWindow(page);
  await expect(page.locator('#queued')).toHaveText('1');
  await expect(page.locator('#sent')).toHaveText('13,798');
  await expect(page.locator('#delivery')).toHaveText('13,799');
});

for (const [timezoneId, expectedBuild] of [
  ['America/Los_Angeles', 'Built Oct 2, 2026, 1:27:00 AM PDT'],
  ['Asia/Kathmandu', 'Built Oct 2, 2026, 2:12:00 PM GMT+5:45'],
] as const) {
  test.describe(`build information in ${timezoneId}`, () => {
    test.use({timezoneId});

    test('shows source version and local build time without changing on refresh', async ({ page }) => {
      await page.clock.install({time:new Date('2026-10-05T20:00:00Z')});
      await boot(page, {status:converged});
      await expect(page.locator('#health-title')).toHaveText('Sensor is running');
      const build = page.locator('#build-info');
      await expect(build).toHaveText(/^Ver\. \d{4}\.\d{1,2}\.\d{1,2}\+[0-9a-f]{7,40}$/);
      expect(await build.getAttribute('title')).toContain(expectedBuild + ', commit ');
      const expectedVersion = await build.textContent();
      await expectFitsWindow(page);
      await expect(build).toBeInViewport({ratio:1});
      expect(await build.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
      await page.clock.fastForward(60000);
      await returnToWindow(page);
      await expect(build).toHaveText(expectedVersion!);
      await page.reload();
      await expect(build).toHaveText(expectedVersion!);
    });
  });
}

test('first server contact refreshes promptly and then returns to normal polling', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-08T02:50:00Z')});
  await boot(page, {status:{...converged,heartbeat:{last_success_at:null,error:''}},usage:usageTotals(1000)});
  await expect(page.locator('#status-label')).toHaveText('Connecting');
  await expect(page.locator('#usage-tokens')).toHaveText('1 k');
  await page.clock.fastForward(1000);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'status').length).toBe(2);
  await expect(page.locator('#status-label')).toHaveText('Connecting');
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.status.heartbeat = {last_success_at:new Date().toISOString(),error:''};
  });
  await page.clock.fastForward(1000);
  await expect(page.locator('#status-label')).toHaveText('Connected');
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
  const count = (await requests(page)).filter(r => r.action === 'status').length;
  await page.clock.fastForward(1000);
  expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(count);
  await page.clock.fastForward(14000);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'status').length).toBe(count + 1);
  expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(0);
});

test('first contact polling backs off on errors, disabled sensors, and cached update status', async ({page}) => {
  await page.clock.install();
  await boot(page, {status:{...converged,heartbeat:{last_success_at:null,error:''}}});
  for (const state of [
    {label:'Connection lost',fields:{heartbeat:{last_success_at:null,error:'Connection refused'}}},
    {label:'Disabled',fields:{disabled:true}},
    {label:'Updating',fields:{desktop_update:{state:'restarting',latest:'',status_cached:true}}},
  ]) {
    await page.evaluate(fields => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.status = {...mock.status,disabled:false,desktop_update:undefined,heartbeat:{last_success_at:null,error:''},...fields};
    }, state.fields);
    await returnToWindow(page);
    await expect(page.locator('#status-label')).toHaveText(state.label);
    const count = (await requests(page)).filter(r => r.action === 'status').length;
    await page.clock.fastForward(1000);
    expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(count);
    await page.clock.fastForward(14000);
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'status').length).toBe(count + 1);
  }
  expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(0);
});

test('automatic refresh respects visibility, refreshes on return, and coalesces pending reads', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
  await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
  const counts = {tokens:1000,calls:1,priced_calls:1,cost_usd:.01};
  await boot(page, {status:converged,usage:{summary:counts,by_model:[],by_reasoning_effort:[]}});
  await expect(page.locator('#usage-tokens')).toHaveText('1 k');
  await expect(page.getByRole('button', {name:'Refresh',exact:true})).toHaveCount(0);
  await page.clock.fastForward(15000);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'status').length).toBe(2);
  expect((await requests(page)).filter(r => r.action === 'usage.summary' && r.days === 30)).toHaveLength(2);
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {configurable:true,value:true});
    document.dispatchEvent(new Event('visibilitychange'));
    window.dispatchEvent(new Event('focus'));
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.pendingAction = 'status';
    mock.status = {...mock.status,telemetry:{received:43}};
    (mock.usage!.summary as {tokens:number}).tokens = 2000;
  });
  await page.clock.fastForward(45000);
  expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(2);
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {configurable:true,value:false});
    document.dispatchEvent(new Event('visibilitychange'));
    window.dispatchEvent(new Event('focus'));
  });
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','true');
  expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(3);
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingAction = undefined;
    win.completeRequest();
  });
  await expect(page.locator('#delivery')).toHaveText('43');
  await expect(page.locator('#usage-tokens')).toHaveText('2 k');
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    (mock.usage!.summary as {tokens:number}).tokens = 3000;
  });
  await returnToWindow(page);
  await expect(page.locator('#usage-tokens')).toHaveText('2 k');
  expect((await requests(page)).filter(r => r.action === 'usage.summary' && r.days === 30)).toHaveLength(3);
  await page.clock.fastForward(15000);
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
  expect((await requests(page)).filter(r => r.action === 'usage.summary' && r.days === 30)).toHaveLength(4);
  await page.clock.fastForward(45000);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary' && r.days === 30).length).toBe(5);
  await expect(page.locator('#usage-tokens')).toHaveText('3 k');
});

const operationBusy = 'A desktop update or sensor operation is in progress. Try again shortly.';

for (const colorScheme of ['light', 'dark'] as const) for (const maxWindowHeight of [720, 160]) {
  test(`a busy sensor starts with a yellow waiting state and recovers automatically (${colorScheme}, ${maxWindowHeight}px)`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme});
    await page.clock.install();
    await boot(page, {status:converged,statusError:operationBusy,maxWindowHeight,nativeUninstaller:true});
    await expect(page.locator('#health-title')).toHaveText('OpenAIDR is updating.');
    await expect(page.locator('#health-description')).toBeHidden();
    await expect(page.locator('#health-dot')).toHaveCSS('background-color', 'rgb(244, 200, 74)');
    await expect(page.locator('#health-dot .status-idle')).toBeVisible();
    await expect(page.locator('#health-dot .status-error')).toBeHidden();
    for (const id of ['notice', 'health-error', 'sensor-facts', 'stats']) await expect(page.locator(`#${id}`)).toBeHidden();
    const retry = page.getByRole('button', {name:'Check again',exact:true});
    await expect(retry).toBeEnabled();
    const summary = page.locator('#health-card .health-summary');
    await expect(summary).toHaveCSS('background-color', colorScheme === 'light' ? 'rgb(255, 249, 230)' : 'rgb(41, 38, 23)');
    await expect(page.locator('#health-card')).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
    expect(await summary.innerText()).toBe('OpenAIDR is updating.');
    const noticeBounds = (await summary.boundingBox())!;
    expect(noticeBounds.height).toBeLessThanOrEqual(48);
    expect((await retry.boundingBox())!.y).toBeGreaterThan(noticeBounds.y + noticeBounds.height);
    if (maxWindowHeight === 720) {
      await expectFitsWindow(page);
      await page.screenshot({path:testInfo.outputPath(`operation-in-progress-${colorScheme}.png`)});
    } else {
      const app = page.locator('#app');
      await expect.poll(() => page.viewportSize()!.height).toBe(160);
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth && node.scrollHeight > node.clientHeight)).toBe(true);
      await app.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(retry).toBeInViewport({ratio:1});
      await expect(page.locator('#check-update')).toBeInViewport({ratio:1});
      await retry.click();
      await expect(page.locator('#health-title')).toHaveText('OpenAIDR is updating.');
    }
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = ''; });
    await page.clock.fastForward(3000);
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#sensor-status')).toHaveClass(/online/);
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
  });
}

test('a busy sensor keeps a yellow status popover and still reports genuine failures', async ({page}) => {
  await page.clock.install();
  await boot(page, {status:{...converged,telemetry:{...converged.telemetry,forwarded:1234567,received:1234567}},usage:usageTotals(9876543)});
  await expect(page.locator('#sent')).toHaveText('1,234,567');
  await page.evaluate(message => { (window as unknown as {mock:Mock}).mock.statusError = message; }, operationBusy);
  await returnToWindow(page);
  await expect(page.locator('#sensor-status')).toHaveAccessibleName('Sensor status: Updating');
  await expect(page.locator('#sensor-status .status-icon')).toHaveCSS('background-color', 'rgb(244, 200, 74)');
  await openSensorStatus(page);
  await expect(page.locator('#health-title')).toHaveText('OpenAIDR is updating.');
  await expect(page.locator('#health-description')).toBeHidden();
  const noticeBounds = (await page.locator('#health-card .health-summary').boundingBox())!;
  expect((await page.locator('#retry').boundingBox())!.y).toBeGreaterThan(noticeBounds.y + noticeBounds.height);
  await expect(page.locator('#health-error')).toBeHidden();
  await expectFitsWindow(page);
  await page.clock.fastForward(3000);
  await expect(page.locator('#health-title')).toHaveText('OpenAIDR is updating.');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'Cannot open the desktop operation lock.'; });
  await page.clock.fastForward(3000);
  await expect(page.locator('#health-title')).toHaveText('Status unavailable');
  await expect(page.locator('#health-description')).toBeVisible();
  await expect(page.locator('#health-dot')).toHaveClass(/error/);
  await expect(page.locator('#health-error')).toHaveText('Cannot open the desktop operation lock.');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = ''; });
  await page.getByRole('button', {name:'Retry status',exact:true}).click();
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expect(page.locator('#sent')).toHaveText('1,234,567');
});

test('a status failure clears the compact counters and recovers with Retry status', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await boot(page, {status: {...converged, telemetry:{...converged.telemetry, queue_depth:0, forwarded:42, received:42}}});
  await expect(page.locator('#sent')).toHaveText('42');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'Local sensor is unavailable'; });
  await returnToWindow(page);
  await expect(page.locator('#health-title')).toHaveText('Status unavailable');
  await expect(page.locator('#connected-agents')).toHaveText('Unknown');
  await expect(page.locator('#health-dot')).toHaveClass(/error/);
  await expect(page.locator('#notice')).toBeHidden();
  await openSensorStatus(page);
  await expect(page.locator('#health-description')).toHaveText('Could not reach the local sensor.');
  await expect(page.locator('#health-description')).not.toHaveAttribute('title');
  await expect(page.getByRole('button', {name:'Retry status',exact:true})).toBeVisible();
  await expectFitsWindow(page);
  for (const id of ['queued','sent','delivery']) await expect(page.locator(`#${id}`)).toHaveText('N/A');
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeEnabled();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = ''; });
  await page.getByRole('button', {name:'Retry status',exact:true}).click();
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expect(page.locator('#health-description')).not.toHaveAttribute('title');
  await expect(page.locator('#sent')).toHaveText('42');
  await expect(page.locator('#connected-agents')).toHaveText('Claude Code');
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeEnabled();
  expect(errors).toEqual([]);
});

test('sensor forwarding errors show a warning and recover when the error clears', async ({ page }, testInfo) => {
  await boot(page, {status: {...converged, telemetry:{...converged.telemetry, queue_depth:24, received:1234567890, forwarded:1234567866, last_error:'The server could not be reached. Queued records will be retried.'}}});
  await expect(page.locator('#health-title')).toHaveText('Sensor needs attention');
  await expect(page.locator('#health-card')).toBeHidden();
  await openSensorStatus(page, false);
  await expect(page.locator('#health-card #health-title')).toBeVisible();
  await expect(page.locator('#sensor-status')).toBeVisible();
  await expect(page.locator('#health-error')).toContainText('The server could not be reached.');
  await expect(page.locator('#health-dot')).toHaveClass(/warning/);
  await expect(page.locator('#sent')).toHaveText('1,234,567,866');
  await expectFitsWindow(page);
  await page.locator('#sensor-details summary').focus();
  await page.keyboard.press('Enter');
  expect(await page.locator('.stats dd').evaluateAll(values => values.every(value => value.clientHeight === parseFloat(getComputedStyle(value).lineHeight)))).toBe(true);
  await page.locator('#retry').focus();
  await expect(page.locator('#retry')).toBeInViewport({ratio:1});
  await page.locator('#sensor-details summary').focus();
  await page.keyboard.press('Enter');
  await expectFitsWindow(page);
  await page.screenshot({path:testInfo.outputPath('compact-warning.png'),fullPage:true});
  const longError = 'The server could not be reached. Queued records will be retried. '.repeat(30);
  await page.evaluate(last_error => { (window as unknown as {mock:Mock}).mock.status = {enrolled:true,running:true,service:'running',telemetry:{last_error}}; }, longError);
  await returnToWindow(page);
  await expect(page.locator('#health-error')).toHaveText(`Telemetry upload: ${longError}`);
  await expectFitsWindow(page);
  await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, converged);
  await returnToWindow(page);
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expect(page.locator('#health-dot')).toHaveClass(/online/);
  expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(0);
});

test('pending requests show progress and the compact controls work with the keyboard', async ({ page }) => {
  await boot(page, {status: converged, pendingAction:'status'});
  await expect(page.getByRole('button', {name:'Refresh',exact:true})).toHaveCount(0);
  await expect(page.locator('#health-title')).toHaveText('Checking sensor…');
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','true');
  // Both unsupported and idle updater reads keep the loading placeholder at launch size.
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(1);
  expect(await page.evaluate(() => (window as unknown as {ipcCommands:string[]}).ipcCommands)).not.toContain('fit_window');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateStatus = {state:'idle',latest:''}; window.dispatchEvent(new Event('focus')); });
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(2);
  expect(await page.evaluate(() => (window as unknown as {ipcCommands:string[]}).ipcCommands)).not.toContain('fit_window');
  expect(page.viewportSize()!.height).toBe(config.app.windows[0].height);
  const completeRequest = () => page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingAction = undefined;
    win.completeRequest();
  });
  await completeRequest();
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expectFitsWindow(page);
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('tab', {name:'Usage',exact:true})).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('#sensor-status')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#stats')).toBeHidden();
  await page.locator('#sensor-details summary').click();
  await expect(page.locator('#stats')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#stats')).toBeHidden();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('img', {name:'Claude Code',exact:true})).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', {name:'24 hours',exact:true})).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', {name:'30 days',exact:true})).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', {name:'Cost estimate information',exact:true})).toBeFocused();
  await expect(page.locator('#usage-history-note')).toBeVisible();
  const days = page.locator('#usage-chart').getByRole('img');
  await expect(days).toHaveCount(30);
  for (const day of await days.all()) {
    await page.keyboard.press('Tab');
    await expect(day).toBeFocused();
  }
  await page.keyboard.press('Tab');
  await expect(page.locator('#usage-tooltip')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#enrollment-link')).toBeFocused();
  await page.getByRole('button', {name:'Done',exact:true}).click();
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeFocused();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'status'; });
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','true');
  await completeRequest();
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
  await expect(page.locator('#notice')).toBeHidden();
});

test('connection settings open in a modal with focus containment and visible errors', async ({ page }, testInfo) => {
  const enrollError = 'The server certificate could not be verified. Ask your administrator for the organization CA. '.repeat(10);
  await boot(page, {status:converged,preview:{...preview,tenant:{...preview.tenant,name:'Example organization '.repeat(30)},server_url:'https://' + 'long-server-name.'.repeat(30) + 'example'},enrollError});
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expectFitsWindow(page);
  const statusHeight = page.viewportSize()!.height;
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  const dialog = page.getByRole('dialog', {name:'Settings'});
  await expect(dialog).toBeVisible();
  await expect(page.locator('#enrollment-link')).toBeFocused();
  await expect(page.locator('#change-connection')).toHaveAttribute('aria-haspopup', 'dialog');
  await page.locator('#sensor-status').evaluate(node => (node as HTMLElement).focus());
  await expect(page.locator('#enrollment-link')).toBeFocused();
  await page.getByRole('button', {name:'Close Settings'}).focus();
  await page.keyboard.press('Tab');
  await expect(page.locator('#enrollment-link')).toBeFocused();
  await expect(page.getByRole('heading', {name:'Connection',exact:true})).toBeVisible();
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect(page.locator('#link-preview')).toBeVisible();
  await expectFitsWindow(page);
  expect(page.viewportSize()!.height).toBeGreaterThanOrEqual(statusHeight);
  await expect(page.locator('#sensor-status')).toBeInViewport({ratio:1});
  await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
  await expect(page.locator('#connect-card')).toBeInViewport({ratio:1});
  await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeInViewport({ratio:1});
  await expectFitsWindow(page);
  await page.screenshot({path:testInfo.outputPath('connection-long-preview.png')});
  await page.getByRole('button', {name:'Connect',exact:true}).click();
  await expect(dialog.locator('#notice')).toHaveText(enrollError);
  await expect(page.locator('#notice')).toHaveAttribute('title', enrollError);
  await expectFitsWindow(page);
  await page.screenshot({path:testInfo.outputPath('connection-error.png')});
  await returnToWindow(page);
  await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
  await expectFitsWindow(page);
  await page.getByRole('button', {name:'Done',exact:true}).click();
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeFocused();
  await expect(page.locator('#sensor-status')).toBeInViewport({ratio:1});
  await expect(page.locator('#connect-card')).toBeHidden();
  await expectFitsWindow(page);
  expect(page.viewportSize()!.height).toBe(statusHeight);
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await expect(page.locator('#enrollment-link')).toBeFocused();
  await expectFitsWindow(page);
  await page.getByRole('button', {name:'Done',exact:true}).click();
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeFocused();
  await expectFitsWindow(page);
  expect(page.viewportSize()!.height).toBe(statusHeight);
  expect(await page.evaluate(() => [...new Set((window as unknown as {ipcCommands:string[]}).ipcCommands)].sort())).toEqual(['fit_window', 'menu_bar_settings', 'sensor_request']);
});

test('an enrollment link previews the organization and connects once', async ({ page }, testInfo) => {
  await boot(page, {status:unenrolled,preview,afterEnroll:{...enrolled,service:'not installed',running:false},afterSetup:converged});
  await expect(page.getByRole('heading', {name:'Connect your organization'})).toBeVisible();
  await expect(page.locator('#enrollment-link')).toBeFocused();
  await expect(page.getByRole('button', {name:'Advanced setup'})).toHaveCount(0);
  await expect(page.locator('input:visible')).toHaveCount(1);
  const connect = page.getByRole('button', {name:'Connect',exact:true});
  await expect(connect).toBeDisabled();
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect(page.locator('#link-organization')).toHaveText('Example organization');
  await expect(page.locator('#link-server')).toHaveText('https://tenant.example');
  await expect(connect).toBeEnabled();
  expect((await requests(page)).map(r => r.action)).not.toContain('enrollment.connect');
  expect((await requests(page)).map(r => r.action)).not.toContain('setup');
  await expect(page.locator('#connect-card')).toBeInViewport({ratio:1});
  await expectFitsWindow(page);
  await page.screenshot({path:testInfo.outputPath('enrollment-link.png')});
  await connect.click();
  await expect(page.locator('#enrollment-link')).toHaveValue('');
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  await expect(page.locator('#connect-card')).toBeHidden();
  await expectFitsWindow(page);
  const all = await requests(page);
  expect(all.filter(r => r.action === 'enrollment.connect')).toEqual([{action:'enrollment.connect',link,tenant_id:preview.tenant.id}]);
  expect(all.findIndex(r => r.action === 'setup')).toBeGreaterThan(all.findIndex(r => r.action === 'enrollment.connect'));
  expect(await page.evaluate(() => ({local:localStorage.length,session:sessionStorage.length}))).toEqual({local:0,session:0});
});

test('a private CA file is used for preview and connect, then discarded', async ({page}, testInfo) => {
  await boot(page, {status:unenrolled,preview,previewError:'Could not verify the enrollment server.',afterEnroll:converged});
  await page.getByText('Private server certificate (optional)', {exact:true}).click();
  await expect(page.locator('#link-feedback')).toHaveText('Use the enrollment link from your administrator.');
  await expectEnrollmentFeedbackBesideLink(page);
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect(page.locator('#link-feedback')).toContainText('Could not verify');
  await expectEnrollmentFeedbackBesideLink(page);
  await expect(page.locator('#link-feedback')).toBeInViewport({ratio:1});
  await expect(page.locator('#certificate-help')).toContainText('only after you connect');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.previewError = ''; });
  await page.getByLabel('Organization CA certificate', {exact:true}).setInputFiles({name:'organization.pem',mimeType:'application/x-pem-file',buffer:Buffer.from(certificate)});
  await expect(page.locator('#certificate-feedback')).toHaveText('organization.pem selected for https://tenant.example.');
  await expect(page.locator('#link-preview')).toBeVisible();
  expect((await requests(page)).filter(r => r.action === 'enrollment.preview').at(-1)).toEqual({action:'enrollment.preview',link,generation:expect.any(Number),ca_certificate:certificate});
  await expectFitsWindow(page);
  await page.screenshot({path:testInfo.outputPath('private-ca-enrollment.png')});
  await page.getByRole('button', {name:'Connect',exact:true}).click();
  await expect(page.locator('#health-title')).toHaveText('Sensor is running');
  expect((await requests(page)).filter(r => r.action === 'enrollment.connect')).toEqual([{action:'enrollment.connect',link,tenant_id:preview.tenant.id,ca_certificate:certificate}]);
  await expect(page.locator('#enrollment-ca')).toHaveValue('');
  await expect(page.locator('#enrollment-link')).toHaveValue('');
  expect(await page.evaluate(() => ({local:localStorage.length,session:sessionStorage.length}))).toEqual({local:0,session:0});
});

test('removing or changing private CA trust discards pending previews and cancellation clears the file', async ({page}) => {
  await page.clock.install();
  await boot(page, {status:converged,preview});
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await page.clock.fastForward(350);
  await expect(page.locator('#link-preview')).toBeVisible();
  await page.getByText('Private server certificate (optional)', {exact:true}).click();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'enrollment.preview'; });
  const file = page.getByLabel('Organization CA certificate', {exact:true});
  await file.setInputFiles({name:'organization.pem',mimeType:'application/x-pem-file',buffer:Buffer.from(certificate)});
  await page.clock.fastForward(350);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'enrollment.preview').length).toBe(2);
  await page.getByRole('button', {name:'Remove file',exact:true}).click();
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingAction = undefined;
    win.completeRequest();
  });
  await expect(page.locator('#link-preview')).toBeHidden();
  await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeDisabled();
  await page.clock.fastForward(350);
  await expect(page.locator('#link-preview')).toBeVisible();
  expect((await requests(page)).filter(r => r.action === 'enrollment.preview').at(-1)).toEqual({action:'enrollment.preview',link,generation:expect.any(Number)});
  await file.setInputFiles({name:'organization.pem',mimeType:'application/x-pem-file',buffer:Buffer.from(certificate)});
  await page.clock.fastForward(350);
  await expect(page.locator('#link-preview')).toBeVisible();
  const otherLink = link.replace('tenant.example', 'other.example');
  await page.getByLabel('Enrollment link', {exact:true}).fill(otherLink);
  await expect(file).toHaveValue('');
  await page.clock.fastForward(350);
  expect((await requests(page)).filter(r => r.action === 'enrollment.preview').at(-1)).toEqual({action:'enrollment.preview',link:otherLink,generation:expect.any(Number)});
  await file.setInputFiles({name:'another.pem',mimeType:'application/x-pem-file',buffer:Buffer.from(certificate)});
  await page.clock.fastForward(350);
  await page.getByRole('button', {name:'Done',exact:true}).click();
  await expect(file).toHaveValue('');
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await expect(page.locator('#link-preview')).toBeHidden();
  await expect(page.locator('#remove-certificate')).toBeHidden();
  expect((await requests(page)).map(r => r.action)).not.toContain('enrollment.connect');
});

for (const [name, contents, message] of [
  ['oversized', 'x'.repeat(32769), 'at most 32 KiB'],
  ['non-ASCII', 'é', 'ASCII PEM'],
]) {
  test(`a ${name} private CA file invalidates preview before a request`, async ({page}) => {
    await boot(page, {status:unenrolled,preview});
    await page.getByLabel('Enrollment link', {exact:true}).fill(link);
    await expect(page.locator('#link-preview')).toBeVisible();
    const before = (await requests(page)).filter(r => r.action === 'enrollment.preview');
    const invalidations = (await requests(page)).filter(r => r.action === 'enrollment.preview.invalidate').length;
    await page.getByText('Private server certificate (optional)', {exact:true}).click();
    await page.getByLabel('Organization CA certificate', {exact:true}).setInputFiles({name:'invalid.pem',mimeType:'application/x-pem-file',buffer:Buffer.from(contents)});
    await expect(page.locator('#certificate-feedback')).toContainText(message);
    await expect(page.locator('#link-preview')).toBeHidden();
    await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeDisabled();
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'enrollment.preview.invalidate').length).toBeGreaterThan(invalidations);
    expect((await requests(page)).filter(r => r.action === 'enrollment.preview')).toEqual(before);
  });
}

test('delayed invalidation only starts the latest preview with a native generation', async ({page}) => {
  await page.clock.install();
  await boot(page, {status:unenrolled,preview,previewGeneration:41,pendingAction:'enrollment.preview.invalidate'});
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await page.clock.fastForward(350);
  const replacement = link.replace('a'.repeat(43), 'b'.repeat(43));
  await page.getByLabel('Enrollment link', {exact:true}).fill(replacement);
  await page.clock.fastForward(350);
  expect((await requests(page)).filter(r => r.action === 'enrollment.preview')).toHaveLength(0);
  expect((await requests(page)).filter(r => r.action === 'enrollment.preview.invalidate')).toHaveLength(1);
  await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeDisabled();
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeInvalidation:() => void};
    win.mock.pendingAction = undefined;
    win.completeInvalidation();
  });
  await expect(page.locator('#link-preview')).toBeVisible();
  const previews = (await requests(page)).filter(r => r.action === 'enrollment.preview');
  expect(previews).toEqual([{action:'enrollment.preview',link:replacement,generation:expect.any(Number)}]);
  expect(previews[0].generation).toBeGreaterThan(41);
});

test('a late preview response cannot overwrite its replacement', async ({page}) => {
  await boot(page, {status:unenrolled,preview,pendingAction:'enrollment.preview'});
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'enrollment.preview').length).toBe(1);
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock};
    win.mock.pendingAction = undefined;
    win.mock.preview = {...win.mock.preview,tenant:{id:'replacement',name:'Replacement organization'}};
  });
  await page.getByLabel('Enrollment link', {exact:true}).fill(link.replace('a'.repeat(43), 'b'.repeat(43)));
  await expect(page.locator('#link-organization')).toHaveText('Replacement organization');
  await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
  await expect(page.locator('#link-organization')).toHaveText('Replacement organization');
  await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeEnabled();
});

test('failed invalidation blocks preview and a later edit can recover', async ({page}) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await boot(page, {status:unenrolled,preview,invalidationError:'Preview cancellation is unavailable.'});
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect(page.locator('#link-feedback')).toHaveText('Preview cancellation is unavailable.');
  await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeDisabled();
  expect((await requests(page)).filter(r => r.action === 'enrollment.preview')).toHaveLength(0);
  await page.getByLabel('Enrollment link', {exact:true}).fill('');
  await expect(page.locator('#link-feedback')).toHaveText('Use the enrollment link from your administrator.');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.invalidationError = undefined; });
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect(page.locator('#link-preview')).toBeVisible();
  expect(errors).toEqual([]);
});

test('changed or canceled links discard stale previews and secrets', async ({ page }, testInfo) => {
  await boot(page, {status:converged,preview,pendingAction:'enrollment.preview'});
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'enrollment.preview').length).toBe(1);
  await page.getByLabel('Enrollment link', {exact:true}).fill('');
  await page.evaluate(() => {
    const win = window as unknown as {mock:Mock;completeRequest:() => void};
    win.mock.pendingAction = undefined;
    win.completeRequest();
  });
  await expect(page.locator('#link-preview')).toBeHidden();
  await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeDisabled();
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect(page.locator('#link-preview')).toBeVisible();
  await page.screenshot({path:testInfo.outputPath('connection-settings.png')});
  await page.getByRole('button', {name:'Close Settings'}).click();
  await expect(page.locator('#enrollment-link')).toHaveValue('');
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeFocused();
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await expect(page.locator('#link-preview')).toBeHidden();
  await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeDisabled();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'enrollment.preview'; });
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'enrollment.preview').length).toBe(3);
  const invalidations = (await requests(page)).filter(r => r.action === 'enrollment.preview.invalidate').length;
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeFocused();
  await expect(page.locator('#change-connection')).toHaveAttribute('aria-expanded', 'false');
  await expect.poll(async () => (await requests(page)).filter(r => r.action === 'enrollment.preview.invalidate').length).toBeGreaterThan(invalidations);
  await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await expect(page.locator('#enrollment-link')).toHaveValue('');
  await expect(page.locator('#link-preview')).toBeHidden();
  expect((await requests(page)).map(r => r.action)).not.toContain('enrollment.connect');
});

test('unusable links explain the failure and enrollment can be retried with a new link', async ({ page }) => {
  await boot(page, {status:unenrolled,previewError:'This enrollment link is expired. Ask your administrator for a new link.'});
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await expect(page.locator('#link-feedback')).toContainText('expired');
  await expect(page.getByRole('button', {name:'Connect',exact:true})).toBeDisabled();
  expect((await requests(page)).map(r => r.action)).not.toContain('enrollment.connect');
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.previewError = '';
    mock.preview = {server_url:'https://tenant.example',tenant:{id:'01000000-0000-7000-8000-000000000001',name:'Example organization'},auth_mode:'bearer',expires_at:'2099-01-01T00:00:00Z'};
    mock.enrollError = 'Enrollment link already used. Ask your administrator for a new link.';
  });
  await page.getByLabel('Enrollment link', {exact:true}).fill(link.replace('a'.repeat(43), 'b'.repeat(43)));
  await page.getByRole('button', {name:'Connect',exact:true}).click();
  await expect(page.locator('#notice')).toContainText('already used');
  await expect(page.locator('#enrollment-link')).toHaveValue('');
  await expect(page.locator('#connect-card')).toBeVisible();
  expect((await requests(page)).map(r => r.action)).not.toContain('setup');
});

test('a certificate connection switch can retry the same link after an interrupted activation', async ({ page }) => {
  await page.clock.install({time:new Date('2026-10-08T17:00:00Z')});
  const connected = {...converged,heartbeat:{last_success_at:'2026-10-08T17:00:00Z'}};
  const next = {...connected,sensor_id:'new-device',server_url:preview.server_url};
  await boot(page, {status:connected,preview:{...preview,auth_mode:'mtls'},
    enrollError:'The new connection could not be activated. The current connection has been kept.',afterEnroll:next});
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await page.getByRole('button', {name:'Connect',exact:true}).click();
  const dialog = page.getByRole('dialog', {name:'Settings'});
  await expect(dialog.locator('#notice')).toContainText('current connection has been kept');
  await expect(page.locator('#sensor-status')).toContainText('Connected');
  await expect(page.locator('#enrollment-link')).toHaveValue('');
  await expectFitsWindow(page);
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.enrollError = '';
    // A persisted preview permits resuming the already-issued device after expiry.
    mock.preview!.expires_at = '2020-01-01T00:00:00Z';
  });
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await page.getByRole('button', {name:'Connect',exact:true}).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator('#notice')).toBeHidden();
  await expect(page.locator('#health-title')).toHaveText('Sensor connected');
  await expectFitsWindow(page);
  expect((await requests(page)).filter(r => r.action === 'enrollment.connect')).toEqual([
    {action:'enrollment.connect',link,tenant_id:preview.tenant.id},
    {action:'enrollment.connect',link,tenant_id:preview.tenant.id},
  ]);
  expect(await page.evaluate(() => ({local:localStorage.length,session:sessionStorage.length}))).toEqual({local:0,session:0});
});

test.describe('automatic setup', () => {
  for (const [connection, status] of [['first enrollment', unenrolled], ['reconnection', converged]] as const) {
    test(`${connection} shows status progress and recovers when the first refresh fails`, async ({ page }) => {
      await page.clock.install();
      await boot(page, {status,preview,afterEnroll:converged});
      if (status.enrolled) await page.getByRole('button',{name:'Settings',exact:true}).click();
      await page.getByLabel('Enrollment link',{exact:true}).fill(link);
      await page.clock.fastForward(300);
      await expect(page.locator('#link-organization')).toHaveText(preview.tenant.name);
      await page.evaluate(() => {
        const mock = (window as unknown as {mock:Mock}).mock;
        mock.pendingAction = 'status';
        mock.statusError = 'Local sensor is unavailable';
      });
      await page.getByRole('button',{name:'Connect',exact:true}).click();
      await expect(page.locator('#connect-card')).toBeHidden();
      await expect(page.locator('#health-title')).toHaveText('Checking sensor…');
      await expect(page.locator('#health-description')).toContainText('Device connected');
      await expect(page.locator('#stats')).toBeHidden();
      await expect(page.locator('#retry')).toHaveAttribute('aria-busy','true');
      await expectFitsWindow(page);
      await page.evaluate(() => {
        const win = window as unknown as {mock:Mock;completeRequest:() => void};
        win.mock.pendingAction = undefined;
        win.completeRequest();
      });
      await expect(page.locator('#health-title')).toHaveText('Status unavailable');
      if (connection === 'reconnection') await expect(page.locator('#sensor-status')).toBeFocused();
      await openSensorStatus(page);
      await expect(page.locator('#health-card')).toBeVisible();
      await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
      await expect(page.getByRole('button',{name:'Retry status',exact:true})).toBeVisible();
      await expectFitsWindow(page);
      await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = ''; });
      await page.getByRole('button',{name:'Retry status',exact:true}).click();
      await expect(page.locator('#health-title')).toHaveText('Sensor is running');
      await expect(page.locator('#notice')).toBeHidden();
      expect((await requests(page)).filter(r => r.action === 'enrollment.connect')).toHaveLength(1);
    });
  }

  test('a connected sensor shows telemetry failures without a stale setup banner', async ({ page }, testInfo) => {
    const error = "Client error '404 Not Found' for url 'http://localhost:3005/otlp/v1/metrics'";
    await boot(page, {status:converged,preview,afterEnroll:{...converged,telemetry:{...converged.telemetry,received:1849,forwarded:0,queue_depth:337,last_error:error}}});
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    await page.getByLabel('Enrollment link',{exact:true}).fill(link);
    await page.getByRole('button',{name:'Connect',exact:true}).click();
    await expect(page.locator('#health-title')).toHaveText('Sensor needs attention');
    await expect(page.locator('#health-error')).toContainText(error);
    await expect(page.locator('#notice')).toBeHidden();
    await expect(page.locator('#sent')).toHaveText('0');
    await expect(page.locator('#queued')).toHaveText('337');
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(0);
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('telemetry-error.png')});
  });

  test('a restarted connection can finish unpacking before an unreachable service is retried', async ({ page }) => {
    await page.clock.install();
    await boot(page, {status:converged,preview,afterEnroll:{...converged,running:false},afterSetup:converged});
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    await page.getByLabel('Enrollment link',{exact:true}).fill(link);
    await page.clock.fastForward(300);
    await page.getByRole('button',{name:'Connect',exact:true}).click();
    await expect(page.locator('#health-title')).toHaveText('Sensor is starting');
    await expect(page.locator('#notice')).toBeHidden();
    for (let count = 0; count < 7; count++) {
      await page.clock.fastForward(15000);
      await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
    }
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(0);
    await page.clock.fastForward(15000);
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  });

  test('reconnection shows restart progress and retries a failed service start without reusing the link', async ({ page }, testInfo) => {
    await boot(page, {status:converged,preview,usage:usageTotals(300),pendingAction:'enrollment.connect',
      enrollResult:{enrolled:true,service_error:'Device connected, but the background service could not start. Retry setup.'},
      afterEnroll:{...converged,service:'stopped',running:false},afterSetup:converged});
    await expect(page.locator('#usage-tokens')).toHaveText('300');
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    await page.getByLabel('Enrollment link',{exact:true}).fill(link);
    await page.getByRole('button',{name:'Connect',exact:true}).click();
    await expect(page.locator('#notice')).toContainText('Connecting…');
    await expect(page.locator('#enrollment-link')).toHaveValue('');
    await expect(page.getByRole('button',{name:'Connect',exact:true})).toBeDisabled();
    await expect(page.getByRole('button',{name:'Done',exact:true})).toBeDisabled();
    await expect(page.getByRole('button',{name:'Close Settings'})).toBeDisabled();
    await expect(page.locator('#usage-panel [data-days="1"]')).toBeDisabled();
    await expect(page.locator('#usage-panel [data-days="30"]')).toBeDisabled();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog', {name:'Settings'})).toBeVisible();
    await expect(page.locator('#connection-dialog #notice')).toHaveText('Connecting…');
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('reconnecting.png')});
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined;
      win.completeRequest();
    });
    await expect(page.locator('#health-title')).toHaveText('Setup needs attention');
    await expect(page.locator('#health-description')).toContainText('Device connected');
    await expect(page.locator('#connect-card')).toBeHidden();
    await openSensorStatus(page);
    await page.getByRole('button',{name:'Retry setup'}).click();
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    expect((await requests(page)).filter(r => r.action === 'enrollment.connect')).toHaveLength(1);
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  });

  test('enrollment is followed by setup and the window offers no manual service or agent controls', async ({ page }) => {
    await boot(page, {
      status: unenrolled,
      preview,
      afterEnroll: {...enrolled, service:'not installed', running:false, telemetry:{codex_available:false, claude_available:true}},
      afterSetup: converged,
      pendingAction: 'setup',
      setup: {steps:[{step:'service.install',ok:true},{step:'telemetry.install',ok:true,agents:['claude']}], restart_required:true},
    });
    await expect(page.getByRole('heading', {name:'Connect your organization'})).toBeVisible();
    await expect(page.locator('#enrollment-link')).toBeFocused();
    await expect(page.locator('#connect-card')).toBeInViewport({ratio:1});
    await expect(page.locator('#health-title')).toHaveText('Welcome to OpenAIDR');
    await expect(page.locator('#health-description')).toHaveAttribute('title', 'Choose how to get started on this device.');
    await page.getByLabel('Enrollment link', {exact:true}).fill(link);
    await page.getByRole('button',{name:'Connect',exact:true}).click();
    await expect(page.locator('#notice')).toHaveText('Setting up this device…');
    await expect(page.locator('#usage-panel [data-days="1"]')).toBeDisabled();
    await expect(page.locator('#usage-panel [data-days="30"]')).toBeDisabled();
    expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(0);
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined;
      win.completeRequest();
    });
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#notice')).toHaveText('Restart Claude Code sessions to apply the new settings.');
    await openSensorStatus(page);
    await expect(page.locator('#connected-agents')).toHaveText('Claude Code');
    await expect(page.locator('#health-description')).not.toHaveAttribute('title');
    await expect(page.locator('#collection-guidance')).toContainText('Restart coding-agent sessions after setup or an app update.');
    await expect(page.locator('#connect-card')).toBeHidden();
    await expectFitsWindow(page);
    const actions = (await requests(page)).map(r => r.action);
    expect(actions.indexOf('setup')).toBeGreaterThan(actions.indexOf('enrollment.connect'));
    expect(actions.filter(a => a === 'setup')).toHaveLength(1);
    expect(actions).not.toContain('service.install');
    expect(actions).not.toContain('telemetry.install');
    await expect(page.getByRole('button',{name:/install service|^start$|restart|^connect$|disconnect/i})).toHaveCount(0);
  });

  test('drift at launch triggers one setup, a failed step shows why, and retry runs it again', async ({ page }) => {
    await boot(page, {
      status: {...enrolled, service:'stopped', running:false, telemetry:{codex_available:true, claude_available:false}},
      setup: {steps:[{step:'service.restart',ok:false,error:'launchctl kickstart failed',after:'start failed: launchctl start failed'},{step:'telemetry.install',ok:false,error:'invalid TOML.',agents:['codex']},{step:'telemetry.install',ok:true,agents:['claude']}]},
    });
    await expect(page.locator('#health-title')).toHaveText('Setup needs attention');
    await expect(page.locator('#health-description')).toContainText('Restarting the sensor failed: launchctl kickstart failed.');
    await expect(page.locator('#health-description')).toContainText('Connecting Codex failed: invalid TOML. Claude Code telemetry connected. Restart these agents to apply changes.');
    await expect(page.locator('#notice')).toBeHidden();
    await openSensorStatus(page, false);
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeVisible();
    await expectFitsWindow(page);
    await page.locator('#sensor-details summary').focus();
    await page.keyboard.press('Enter');
    await page.locator('#retry').focus();
    await expect(page.locator('#retry')).toBeInViewport({ratio:1});
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
    // Setup pauses while the connection form is open, so Retry is hidden there.
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeHidden();
    await page.getByRole('button',{name:'Done',exact:true}).click();
    await openSensorStatus(page);
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeVisible();
    await openSensorStatus(page);
    await page.getByRole('button',{name:'Retry setup'}).click();
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'setup').length).toBe(2);
  });

  test('missing guardrails stay actionable after failed setup and refresh, then recover on retry', async ({page}, testInfo) => {
    const damaged = {...converged, hooks:{claude:{installed:false,current:false,opted_out:false}}};
    const repaired = {...converged, hooks:{claude:{installed:true,current:true,opted_out:false}}};
    await boot(page, {status:damaged, setup:{steps:[{step:'hooks.install',ok:false,error:'Cannot write agent settings',agents:['claude']}]}});
    await expect(page.locator('#health-title')).toHaveText('Setup needs attention');
    await expect(page.locator('#health-description')).toContainText('Cannot write agent settings');
    await returnToWindow(page);
    await openSensorStatus(page);
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeVisible();
    await expect(page.locator('#health-dot')).toHaveClass(/error/);
    expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(1);
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('guardrails-setup-failed.png')});
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'Sensor unavailable'; });
    await returnToWindow(page);
    await openSensorStatus(page);
    await expect(page.getByRole('button',{name:'Retry status'})).toBeVisible();
    await page.getByRole('button',{name:'Retry status'}).click();
    await expect(page.locator('#health-error')).toHaveText('Sensor unavailable');
    await expect(page.locator('#notice')).toBeHidden();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = ''; });
    await page.getByRole('button',{name:'Retry status'}).click();
    await expect(page.locator('#notice')).toBeHidden();
    await openSensorStatus(page);
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeVisible();
    expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(1);
    await page.evaluate(repaired=>{
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.afterSetup = repaired;
      mock.setup = {steps:[{step:'hooks.install',ok:true,agents:['claude']}],restart_required:true};
    }, repaired);
    await openSensorStatus(page);
    await page.getByRole('button',{name:'Retry setup'}).click();
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#notice')).toHaveText('Restart Claude Code sessions to apply the new settings.');
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeHidden();
    expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(2);
  });

  for (const example of [
    {status:{service:'not installed',foreground:true},guidance:'Stop the manually started sensor'},
    {status:{service:'not installed',foreground:true,settings_stale:true},guidance:'Stop the manually started sensor, then return to this window'},
  ]) test(`failed guardrail repair retains recovery guidance: ${example.guidance}`, async ({page}) => {
    await boot(page, {status:{...converged,...example.status,hooks:{claude:{installed:false,current:false}}},
      setup:{steps:[{step:'hooks.install',ok:false,error:'Cannot write agent settings',agents:['claude']}]}});
    await expect(page.locator('#health-title')).toHaveText('Setup needs attention');
    await expect(page.locator('#health-description')).toContainText('Cannot write agent settings');
    await expect(page.locator('#health-description')).toContainText(example.guidance);
    await openSensorStatus(page);
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeVisible();
    await returnToWindow(page);
    await expect(page.locator('#health-description')).toContainText(example.guidance);
    expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(1);
  });

  for (const condition of ['untrusted', 'previous config', 'hook opt-out', 'telemetry disabled and hook opt-out', 'organization disabled']) {
    test(`guardrail repair respects ${condition}`, async ({page}) => {
      const status = {...converged,disabled:condition==='organization disabled',
        telemetry:{...converged.telemetry,enabled:condition!=='telemetry disabled and hook opt-out',codex_available:true,codex_current:true},
        hooks:{codex:{installed:true,trusted:condition!=='untrusted',current:false,opted_out:condition.includes('hook opt-out')}}};
      await boot(page,{status,afterSetup:{...status,hooks:{codex:{installed:true,trusted:true,current:true}}}});
      const skip = condition.includes('hook opt-out') || condition==='organization disabled';
      if (skip) {
        await expect(page.locator('#health-dot')).not.toHaveClass(/loading/);
        expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(0);
        if (condition.includes('hook opt-out')) await expect(page.locator('#health-description')).toContainText('Codex guardrails are disconnected');
      } else {
        await expect.poll(async()=> (await requests(page)).filter(r=>r.action==='setup').length).toBe(1);
        await expect(page.locator('#health-title')).toHaveText('Sensor is running');
      }
    });
  }

  test('setup results distinguish each agent and capability after a partial failure', async ({page}) => {
    await boot(page,{status:{...converged,telemetry:{...converged.telemetry,codex_available:true},hooks:{codex:{installed:false,current:false}}},setup:{steps:[
      {step:'telemetry.install',ok:true,agents:['codex']},
      {step:'hooks.install',ok:true,agents:['claude']},
      {step:'hooks.install',ok:false,agents:['codex'],error:'Cannot write settings'},
    ]}});
    const message = page.locator('#health-description');
    await expect(message).toContainText('Cannot write settings');
    await expect(message).toContainText('Codex telemetry connected; Claude Code guardrails updated');
    await expect(message).not.toContainText('Codex guardrails updated');
    await expect(message).not.toContainText('Claude Code telemetry connected');
  });

  test('guardrail opt-outs for an uninstalled agent do not warn or trigger setup', async ({page}) => {
    await boot(page,{status:{...converged,telemetry:{...converged.telemetry,codex_available:false},hooks:{codex:{installed:false,current:false,opted_out:true}}}});
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#health-description')).not.toContainText('guardrails are disconnected');
    await expect(page.locator('#health-dot')).toHaveClass(/online/);
    expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(0);
  });

  test('disabled Claude hooks warn without ineffective repair and recover after refresh', async ({page}, testInfo) => {
    await boot(page,{status:{...converged,hooks:{claude:{installed:false,current:false,disabled:true}}}});
    await expect(page.locator('#health-description')).toContainText('Claude Code guardrails are disabled in agent settings. Enable hooks there, then return to this window.');
    await expect(page.locator('#health-dot')).toHaveClass(/warning/);
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeHidden();
    await returnToWindow(page);
    expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(0);
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('claude-hooks-disabled.png')});
    await page.evaluate(status=>{(window as unknown as {mock:Mock}).mock.status=status;}, {...converged,hooks:{claude:{installed:true,current:true}}});
    await returnToWindow(page);
    await expect(page.locator('#health-description')).not.toContainText('guardrails are disabled');
    await expect(page.locator('#health-dot')).toHaveClass(/online/);
    expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(0);
  });

  test('guardrails repair while stale telemetry settings wait for a manual sensor restart', async ({page}) => {
    const status = {...converged,service:'not installed',settings_stale:true,foreground:true,hooks:{claude:{installed:false,current:false}}};
    await boot(page,{status,afterSetup:{...status,hooks:{claude:{installed:true,current:true}}},setup:{steps:[{step:'hooks.install',ok:true,agents:['claude']}]}});
    await expect.poll(async()=> (await requests(page)).filter(r=>r.action==='setup').length).toBe(1);
    await expect(page.locator('#health-title')).toHaveText('Sensor needs a restart');
    await expect(page.locator('#notice')).toHaveText('Restart Claude Code sessions to apply the new settings.');
    await expectFitsWindow(page);
  });

  test('heartbeat and activity upload failures stay visible independently of telemetry', async ({page}, testInfo) => {
    await boot(page,{status:{...converged,heartbeat:{last_success_at:null,error:'Organization connection refused'},activity:{queue_depth:12,last_error:'Activity upload rejected'},telemetry:{...converged.telemetry,queue_depth:0}}});
    await expect(page.locator('#health-title')).toHaveText('Server connection lost');
    await openSensorStatus(page);
    await expect(page.locator('#health-error')).toHaveText('Organization connection: Organization connection refused\nActivity upload: Activity upload rejected');
    await expect(page.locator('#activity-queued')).toHaveText('12');
    await expect(page.locator('#queued')).toHaveText('0');
    expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(0);
    await page.locator('#counter-note').scrollIntoViewIfNeeded();
    await expect(page.locator('#counter-note')).toBeInViewport({ratio:1});
    await page.locator('#sensor-details summary').click();
    await page.locator('#health-card').evaluate(node => { node.scrollTop = 0; });
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('activity-delivery-error.png')});
    const timeout = 'The read operation timed out';
    for (const example of [
      {name:'matching uploads',fields:{telemetry:{...converged.telemetry,last_error:timeout}},expected:`Activity upload, Telemetry upload: ${timeout}`},
      {name:'distinct errors',fields:{heartbeat:{last_success_at:null,error:'403 Forbidden'},telemetry:{...converged.telemetry,last_error:'503 Service Unavailable'}},expected:`Organization connection: 403 Forbidden\nActivity upload: ${timeout}\nTelemetry upload: 503 Service Unavailable`},
      {name:'legacy live error',fields:{live:{last_error:timeout}},expected:`Activity upload, Telemetry upload: ${timeout}`},
      {name:'legacy status send error',fields:{status:{last_send_error:timeout}},expected:`Activity upload, Telemetry upload: ${timeout}`},
    ]) {
      await test.step(example.name,async () => {
        await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...converged,heartbeat:{last_success_at:null,error:''},activity:{queue_depth:12,last_error:timeout},...example.fields});
        await returnToWindow(page);
        await expect(page.locator('#health-error')).toHaveText(example.expected);
        await expect(page.locator('#health-title')).toHaveText('Server connection lost');
        await expect(page.locator('#health-description')).not.toHaveAttribute('title');
      });
    }
    await page.evaluate(status=>{(window as unknown as {mock:Mock}).mock.status=status;}, {...converged,heartbeat:{last_success_at:null,error:''},activity:{queue_depth:12,last_error:''}});
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Waiting for your organization');
    await page.evaluate(status=>{(window as unknown as {mock:Mock}).mock.status=status;}, {...converged,heartbeat:{last_success_at:'2026-10-04T12:00:00Z',error:''},activity:{queue_depth:0,last_error:''}});
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Sensor connected');
    await expect(page.locator('#activity-queued')).toHaveText('0');
    await page.evaluate(()=>{(window as unknown as {mock:Mock}).mock.statusError='Sensor unavailable';});
    await returnToWindow(page);
    await expect(page.locator('#activity-queued')).toHaveText('N/A');
  });

  for (const state of [
    {status:{disabled:true},title:'Sensor disabled by your organization',guidance:'Activity collection is off'},
    {status:{service:'not installed',foreground:true,service_version:'99.0.0'},title:'Sensor version mismatch',guidance:'Stop the manually started sensor'},
    {status:{service:'not installed',foreground:true,telemetry:{enabled:false},heartbeat:{last_success_at:null,error:'First heartbeat failed'}},title:'Sensor is running manually',guidance:'Stop the manually started sensor'},
  ]) {
    test(`delivery errors preserve ${state.title.toLowerCase()} guidance`, async ({page}) => {
      await boot(page,{status:{...converged,...state.status,activity:{queue_depth:12,last_error:'403 Forbidden'}}});
      await expect(page.locator('#health-title')).toHaveText(state.title);
      await expect(page.locator('#health-description')).toContainText(state.guidance);
      await expect(page.locator('#health-error')).toContainText('Activity upload: 403 Forbidden');
      expect((await requests(page)).filter(r=>r.action==='setup')).toHaveLength(0);
      await expectFitsWindow(page);
    });
  }

  test('native update progress continues while sensor reads and setup are pending', async ({page}) => {
    await page.clock.install();
    const downloading = {state:'downloading',latest:'2026.10.8+1234567',downloaded_bytes:1048576,total_bytes:4194304};
    await boot(page, {status:{...converged,desktop_update:{state:'checking',latest:''}},pendingAction:'status',updateStatus:downloading});
    await expect(page.locator('#update-notice')).toHaveText('Downloading update 25%');
    expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(1);
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = 'setup';
      win.mock.status = {...win.mock.status,telemetry:{...win.mock.status.telemetry as object,claude_current:false}};
      win.completeRequest();
    });
    await expect(page.locator('#notice')).toHaveText('Setting up this device…');
    await expect(page.locator('#update-notice')).toHaveText('Downloading update 25%');
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateStatus!.downloaded_bytes = 3145728; });
    await page.clock.fastForward(1000);
    await expect(page.locator('#update-notice')).toHaveText('Downloading update 75%');
    expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(1);
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined;
      win.mock.status = {...win.mock.status,telemetry:{...win.mock.status.telemetry as object,claude_current:true}};
      win.completeRequest();
    });
    await expect(page.locator('#notice')).toBeHidden();
    await expect(page.locator('#update-notice')).toHaveText('Downloading update 75%');
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'Sensor unavailable'; });
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Status unavailable');
    await expect(page.locator('#update-notice')).toHaveText('Downloading update 75%');
  });

  test('native update polling pauses when hidden, stays single-flight and retries quietly', async ({page}) => {
    await page.clock.install();
    const downloading = {state:'downloading',latest:'2026.10.8+1234567',downloaded_bytes:1048576};
    await boot(page, {status:converged,updateStatus:downloading,pendingUpdateStatus:true});
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(1);
    await page.clock.fastForward(5000);
    await returnToWindow(page);
    expect((await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(1);
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeUpdateStatus:() => void};
      Object.defineProperty(document, 'hidden', {configurable:true,value:true});
      document.dispatchEvent(new Event('visibilitychange'));
      win.mock.pendingUpdateStatus = false;
      win.completeUpdateStatus();
    });
    await expect(page.locator('#update-notice')).toHaveText('Downloading update 1.0 MiB');
    await page.clock.fastForward(30000);
    expect((await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(1);
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock};
      win.mock.updateStatusError = 'Cannot read update state';
      Object.defineProperty(document, 'hidden', {configurable:true,value:false});
      document.dispatchEvent(new Event('visibilitychange'));
    });
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(2);
    await expect(page.locator('#update-notice')).toHaveText('Downloading update 1.0 MiB');
    await expect(page.locator('#update-guidance')).toBeHidden();
    await expect(page.locator('#notice')).toBeHidden();
    await page.clock.fastForward(1000);
    expect((await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(2);
    await page.evaluate(() => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.updateStatusError = undefined;
      mock.updateStatus = null;
      mock.status.desktop_update = {state:'downloading',latest:''};
    });
    await page.clock.fastForward(14000);
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(3);
    await expect(page.locator('#update-notice')).toBeHidden();
    await page.clock.fastForward(1000);
    expect((await requests(page)).filter(r => r.action === 'desktop.update.status')).toHaveLength(3);
    await returnToWindow(page);
    await expect(page.locator('#update-notice')).toBeHidden();
  });

  test('native update progress rejects invalid byte totals and clears counts across phases', async ({page}) => {
    await page.clock.install();
    await boot(page, {status:converged,updateStatus:{state:'downloading',latest:'2026.10.8+1234567',downloaded_bytes:2097152}});
    await expect(page.locator('#update-notice')).toHaveText('Downloading update 2.0 MiB');
    for (const total of [null,0,-1,1.5,1048576,2 ** 31,NaN,Infinity,'4194304']) {
      await page.evaluate(total => { (window as unknown as {mock:Mock}).mock.updateStatus!.total_bytes = total; }, total);
      await page.clock.fastForward(1000);
      await expect(page.locator('#update-notice')).toHaveText('Downloading update 2.0 MiB');
    }
    for (const received of [-1,1.5,2 ** 31,NaN,Infinity,'2097152']) {
      await page.evaluate(received => { (window as unknown as {mock:Mock}).mock.updateStatus!.downloaded_bytes = received; }, received);
      await page.clock.fastForward(1000);
      await expect(page.locator('#update-notice')).toHaveText('Downloading update…');
    }
    for (const [state,label] of [['installing','Installing update…'],['restarting','Restarting after update…'],['error','Update needs attention'],['idle','']]) {
      await page.evaluate(state => { (window as unknown as {mock:Mock}).mock.updateStatus = {state,latest:'2026.10.8+1234567',downloaded_bytes:2,total_bytes:4,error:state === 'error' ? 'The current app was kept.' : null}; }, state);
      await page.clock.fastForward(state === 'idle' ? 15000 : 1000);
      await expect(page.locator('#update-notice')).toHaveText(label);
      if (state === 'error') await expect(page.locator('#update-guidance')).toContainText('The current app was kept.');
      else await expect(page.locator('#update-guidance')).toBeHidden();
    }
  });

  test('native update progress ignores replies spanning uninstall and resumes after installation', async ({page}) => {
    await page.clock.install();
    await boot(page, {status:converged,updateStatus:{state:'downloading',latest:'2026.10.8+1234567',downloaded_bytes:1,total_bytes:4},pendingUpdateStatus:true,afterResume:converged});
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await page.getByRole('button', {name:'Uninstall',exact:true}).click();
    await page.getByRole('button', {name:'Uninstall OpenAIDR',exact:true}).click();
    await expect(page.locator('#health-title')).toHaveText('Background services stopped.');
    await expect(page.locator('#update-notice')).toBeHidden();
    await page.getByRole('button', {name:'Reinstall',exact:true}).click();
    await expect(page.locator('#remove-dialog')).toBeHidden();
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeUpdateStatus:() => void};
      win.mock.pendingUpdateStatus = false;
      win.mock.updateStatus = null;
      win.completeUpdateStatus();
    });
    await expect(page.locator('#update-notice')).toBeHidden();
    await page.clock.fastForward(15000);
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'desktop.update.status').length).toBeGreaterThan(1);
    await expect(page.locator('#update-notice')).toBeHidden();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.updateStatus = {state:'checking',latest:''}; });
    await returnToWindow(page);
    await expect(page.locator('#update-notice')).toHaveText('Checking updates…');
  });

  for (const maxWindowHeight of [720,320]) {
    test(`native update download progress fits populated ${maxWindowHeight}px work areas`, async ({page}, testInfo) => {
      const counts = {tokens:30000,calls:30,priced_calls:30,cost_usd:1};
      await boot(page, {status:converged,maxWindowHeight,updateStatus:{state:'downloading',latest:'2026.10.8+1234567',downloaded_bytes:12582912,total_bytes:25165824},usage:{summary:counts,pending_exports:0,
        series:Array.from({length:30},(_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),...counts,tokens:1000})),
        by_model:[{name:'gpt-6.1-sol',...counts}],by_reasoning_effort:[{name:'high',...counts}]}});
      await expect(page.locator('#usage-tokens')).toHaveText('30 k');
      const notice = page.locator('#update-notice');
      await expect(notice).toHaveText('Downloading update 50%');
      await expect(notice).toHaveAttribute('aria-label', 'Downloading update 50% Version 2026.10.8+1234567.');
      await expect(notice).toBeInViewport({ratio:1});
      expect(await notice.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      if (maxWindowHeight === 720) await expectFitsWindow(page);
      else {
        const app = page.locator('#app');
        expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      }
      await page.screenshot({path:testInfo.outputPath('illustrative-live-update-progress.png')});
      const connection = page.getByRole('button', {name:'Settings',exact:true});
      await connection.focus();
      await expect(connection).toBeInViewport({ratio:1});
      await connection.click();
      await expect(page.getByRole('heading', {name:'Connection',exact:true})).toBeVisible();
    });
  }

  test('native update progress refreshes quietly and survives re-enrollment', async ({ page }, testInfo) => {
    await page.clock.install();
    const updating = {state:'downloading', latest:'0.2.0', error:null};
    const healthy = {...converged,telemetry:{...converged.telemetry,received:13797,forwarded:13797,queue_depth:0},update:{latest:'99.0.0',update_available:true}};
    await boot(page, {preview, status:{...healthy,desktop_update:{state:'checking',latest:'',error:null}}, afterEnroll:{...converged,desktop_update:updating}});
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#update-notice')).toHaveText('Checking updates…');
    await expect(page.locator('#notice')).toBeHidden();
    await expect(page.locator('#update-notice')).toBeInViewport({ratio:1});
    await expectFitsWindow(page);
    // Independent updater polling picks up results without a click or an installation request.
    for (const [state,label] of [['downloading','Downloading update…'], ['installing','Installing update…'], ['restarting','Restarting after update…']]) {
      await page.evaluate(desktop_update => { const win = window as unknown as {mock:Mock}; win.mock.status = {...win.mock.status,desktop_update}; }, {...updating,state});
      await page.clock.fastForward(15000);
      await expect(page.locator('#update-notice')).toHaveText(label);
      await expect(page.locator('#update-notice')).toHaveAttribute('title', `${label} Version 0.2.0.`);
      await expect(page.locator('#notice')).toBeHidden();
      await expectFitsWindow(page);
    }
    // During native sensor handoff, cached drift and counters must not trigger setup or appear fresh.
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,running:false,service_outdated:true,telemetry:{...healthy.telemetry,last_error:'Previous sensor error'},desktop_update:{...updating,state:'restarting',status_cached:true}});
    await page.clock.fastForward(15000);
    await expect(page.locator('#health-title')).toHaveText('Updating sensor');
    await expect(page.locator('#connected-agents')).toHaveText('Not checked');
    await expect(page.locator('#health-description')).toHaveText('Showing status from before the update.');
    await expect(page.locator('#delivery')).toHaveText('13,797');
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeHidden();
    await expectFitsWindow(page);
    await page.clock.fastForward(45000);
    expect(new Set((await requests(page)).map(r => r.action))).toEqual(new Set(['enrollment.preview.invalidate', 'status', 'desktop.update.status', 'simulation.status', 'desktop.capabilities', 'usage.summary', 'alerts.list']));
    await expect(page.locator('#health-title')).toHaveText('Updating sensor');
    // These screenshots exercise the real UI with illustrative native IPC data.
    await page.screenshot({path:testInfo.outputPath('illustrative-update-restarting.png')});
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,running:false,desktop_update:{...updating,state:'restarting'}});
    await page.clock.fastForward(15000);
    await expect(page.locator('#health-title')).toHaveText('Sensor is starting');
    expect(new Set((await requests(page)).map(r => r.action))).toEqual(new Set(['enrollment.preview.invalidate', 'status', 'desktop.update.status', 'simulation.status', 'desktop.capabilities', 'usage.summary', 'alerts.list']));
    const longVersion = '0.2.0-alpha.' + '1'.repeat(100);
    const longError = 'The app was updated, but sensor setup needs a retry. '.repeat(20);
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...healthy,desktop_update:{state:'error',latest:longVersion,error:longError}});
    await page.clock.fastForward(15000);
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#update-notice')).toHaveText('Update needs attention');
    const errorDescription = `Update needs attention Version ${longVersion}. ${longError}`;
    await expect(page.locator('#update-notice')).toHaveAttribute('title', errorDescription);
    await expect(page.locator('#update-notice')).toHaveAttribute('aria-label', errorDescription);
    await expect(page.locator('#notice')).toBeHidden();
    await expect(page.locator('#update-notice')).toBeInViewport({ratio:1});
    await expectFitsWindow(page);
    const guidance = page.getByRole('region', {name:'Update details',exact:true});
    await expect(guidance).toContainText(longError);
    expect(await guidance.evaluate(node => node.scrollWidth <= node.clientWidth && node.scrollHeight > node.clientHeight)).toBe(true);
    await guidance.focus();
    await expect(guidance).toBeInViewport({ratio:1});
    await page.keyboard.press('End');
    await page.clock.runFor(500);
    await expect.poll(() => guidance.evaluate(node => node.scrollTop + node.clientHeight >= node.scrollHeight - 1)).toBe(true);
    await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeInViewport({ratio:1});
    await expect(page.getByRole('button', {name:'Uninstall',exact:true})).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('long-update-guidance.png')});
    // A smaller work area must scroll without clipping guidance or controls.
    const fittedViewport = page.viewportSize()!;
    await page.setViewportSize({...fittedViewport,height:320});
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollHeight > node.clientHeight && node.scrollWidth === node.clientWidth)).toBe(true);
    for (const name of ['Settings', 'Uninstall']) {
      const button = page.getByRole('button', {name, exact:true});
      await button.focus();
      await expect(button).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath('update-guidance-controls-small-work-area.png')});
    await app.evaluate(node => { node.scrollTop = 0; });
    await page.setViewportSize(fittedViewport);
    for (const state of ['updated','idle']) {
      await page.evaluate(desktop_update => { const win = window as unknown as {mock:Mock}; win.mock.status = {...win.mock.status,desktop_update}; }, {...updating,state});
      await page.clock.fastForward(15000);
      await expect(page.locator('#update-notice')).toBeHidden();
      await expect(page.locator('#notice')).toBeHidden();
    }
    await page.evaluate(desktop_update => { const win = window as unknown as {mock:Mock}; win.mock.status = {...win.mock.status,desktop_update}; }, updating);
    await page.clock.fastForward(15000);
    await expect(page.locator('#update-notice')).toHaveText('Downloading update…');
    await expect(page.locator('#update-notice')).toHaveAttribute('title', 'Downloading update… Version 0.2.0.');
    let actions = (await requests(page)).map(r => r.action);
    expect(new Set(actions)).toEqual(new Set(['enrollment.preview.invalidate', 'status', 'desktop.update.status', 'simulation.status', 'desktop.capabilities', 'usage.summary', 'alerts.list']));
    await expect(page.locator('#check-update')).toHaveText('Updating...');
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    await expect(page.getByRole('heading',{name:'Connection',exact:true})).toBeVisible();
    await expect(page.locator('#update-notice')).toBeInViewport({ratio:1});
    await expectFitsWindow(page);
    // Re-enrollment needs a stopped sensor; the stopped service must not be restarted while the form is open.
    await page.evaluate(() => { const win = window as unknown as {mock:{status:Record<string, unknown>}}; win.mock.status = {...win.mock.status, service:'stopped', running:false}; });
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Setup paused');
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
    await page.getByLabel('Enrollment link', {exact:true}).fill(link);
    await page.clock.fastForward(300);
    await page.getByRole('button',{name:'Connect',exact:true}).click();
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeFocused();
    await expectFitsWindow(page);
    actions = (await requests(page)).map(r => r.action);
    await expect(page.locator('#update-notice')).toHaveText('Downloading update…');
    expect(actions.filter(a => a === 'enrollment.connect')).toHaveLength(1);
    await expect(page.locator('#notice')).toBeHidden();
    expect(new Set(actions)).toEqual(new Set(['enrollment.preview.invalidate','status','desktop.update.status','simulation.status','desktop.capabilities','enrollment.preview','enrollment.connect','usage.summary','alerts.list']));
    expect(await page.evaluate(() => [...new Set((window as unknown as {ipcCommands:string[]}).ipcCommands)].sort())).toEqual(['fit_window', 'menu_bar_settings', 'sensor_request']);
  });

  test('native update guidance is visible before enrollment and clears after recovery', async ({ page }, testInfo) => {
    await page.clock.install();
    const guidance = 'Move the app to Applications or your home Applications folder to enable automatic updates.';
    await boot(page, {status:{...unenrolled,update:{latest:'99.0.0',update_available:true},desktop_update:{state:'unavailable',latest:'',error:guidance}}});
    await expect(page.getByRole('heading',{name:'Connect your organization'})).toBeVisible();
    await expect(page.locator('#update-notice')).toHaveText('In-app updates unavailable');
    await expect(page.locator('#update-notice')).toHaveAttribute('title', `In-app updates unavailable ${guidance}`);
    await expect(page.locator('#update-guidance')).toContainText(guidance);
    await expect(page.locator('#update-guidance')).toBeInViewport({ratio:1});
    await expect(page.locator('#update-notice')).toBeInViewport({ratio:1});
    await expectFitsWindow(page);
    await page.screenshot({path:testInfo.outputPath('illustrative-update-guidance-unenrolled.png')});
    for (const [state,label] of [['error','Update needs attention'], ['checking','Checking updates…'], ['downloading','Downloading update…']]) {
      await page.evaluate(desktop_update => { const win = window as unknown as {mock:Mock}; win.mock.status = {...win.mock.status,desktop_update}; }, {state,latest:'0.2.0',error:state === 'error' ? 'Cannot check the release server. The current app was kept.' : null});
      await page.clock.fastForward(15000);
      await expect(page.locator('#update-notice')).toHaveText(label);
      if (state === 'error') {
        await expect(page.locator('#update-guidance')).toContainText('Cannot check the release server. The current app was kept.');
        await expect(page.locator('#update-guidance')).not.toContainText('Reopen the app to retry');
        await expect(page.locator('#update-guidance')).toContainText('Contact your administrator');
        await expect(page.locator('#update-guidance')).toBeInViewport({ratio:1});
      } else await expect(page.locator('#update-guidance')).toBeHidden();
      await expect(page.locator('#update-notice')).toBeInViewport({ratio:1});
      await expect(page.locator('#notice')).toBeHidden();
      await expectFitsWindow(page);
    }
    const recovery = 'The app was updated, but sensor status could not be read. Reopen the app to retry.';
    await page.evaluate(error => { (window as unknown as {mock:Mock}).mock.status.desktop_update = {state:'error',latest:'0.2.0',error}; }, recovery);
    await page.clock.fastForward(15000);
    await expect(page.locator('#update-guidance')).toContainText(recovery);
    await expectFitsWindow(page);
    // A development build omits native updater state, even if the sensor has a server-version result.
    await page.evaluate(() => { delete (window as unknown as {mock:Mock}).mock.status.desktop_update; });
    await page.clock.fastForward(15000);
    await expect(page.locator('#update-notice')).toBeHidden();
    await expect(page.locator('#update-guidance')).toBeHidden();
    await expect(page.getByRole('button', {name:'Check updates',exact:true})).toBeVisible();
    expect(new Set((await requests(page)).map(r => r.action))).toEqual(new Set(['enrollment.preview.invalidate', 'status', 'desktop.update.status', 'simulation.status', 'desktop.capabilities']));
    expect(await page.evaluate(() => [...new Set((window as unknown as {ipcCommands:string[]}).ipcCommands)].sort())).toEqual(['fit_window', 'menu_bar_settings', 'sensor_request']);
  });

  test('Done keeps the current connection, clears the form, and resumes setup', async ({ page }) => {
    await boot(page, {preview, status: {...converged, service:'stopped', running:false}, afterSetup: converged, setup: {steps:[{step:'service.start',ok:true}]}});
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    await page.evaluate(() => { const win = window as unknown as {mock:{status:Record<string, unknown>; afterSetup:Record<string, unknown>}}; win.mock.status = {...win.mock.afterSetup, service:'stopped', running:false}; });
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Setup paused');
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
    // The link and its preview are discarded when the change is canceled.
    await page.getByLabel('Enrollment link', {exact:true}).fill(link);
    await expect(page.locator('#link-preview')).toBeVisible();
    await page.getByRole('button',{name:'Done',exact:true}).click();
    await expect(page.locator('#connect-card')).toBeHidden();
    await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeFocused();
    await expect(page.getByRole('button',{name:'Settings',exact:true})).toHaveAttribute('aria-expanded','false');
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'setup').length).toBe(2);
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    await expect(page.locator('#enrollment-link')).toHaveValue('');
    await expect(page.locator('#link-preview')).toBeHidden();
    await expect(page.getByRole('button',{name:'Connect',exact:true})).toBeDisabled();
    expect((await requests(page)).map(r => r.action)).not.toContain('enrollment.connect');
  });

  test('startup checks resume promptly after setup, keep controls available, and defer usage until the sensor answers', async ({ page }) => {
    await page.clock.install({time:new Date('2026-10-07T11:59:00Z')});
    await page.clock.pauseAt(new Date('2026-10-07T12:00:00Z'));
    await boot(page, {
      status: {...converged, service:'stopped', running:false},
      afterSetup: {...converged, running:false},
      setup: {steps:[{step:'service.start',ok:true}]},
    });
    await expect(page.locator('#health-title')).toHaveText('Sensor is starting');
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
    expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(0);
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'status'; });
    await page.clock.fastForward(1000);
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'status').length).toBe(2);
    await expect(page.locator('#retry')).toHaveAttribute('aria-busy','true');
    await expect(page.getByRole('button',{name:'Settings',exact:true})).toBeEnabled();
    await expect(page.getByRole('button',{name:'Uninstall',exact:true})).toBeEnabled();
    await page.clock.fastForward(10000);
    expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(2);
    expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(0);
    await page.evaluate(status => {
      const win = window as unknown as {mock:Mock; completeRequest:() => void};
      win.mock.status = status;
      win.mock.pendingAction = undefined;
      win.completeRequest();
    }, converged);
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').length).toBe(1);
    await page.clock.fastForward(1000);
    expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(2);
    await page.clock.fastForward(14000);
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'status').length).toBe(3);
    await page.evaluate(() => {
      Object.defineProperty(document, 'hidden', {configurable:true, value:true});
      document.dispatchEvent(new Event('visibilitychange'));
    });
    await page.clock.fastForward(15000);
    expect((await requests(page)).filter(r => r.action === 'status')).toHaveLength(3);
    await page.evaluate(() => {
      Object.defineProperty(document, 'hidden', {configurable:true, value:false});
      document.dispatchEvent(new Event('visibilitychange'));
    });
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'status').length).toBe(4);
  });

  test('startup retries remain bounded when a restarted sensor never answers', async ({ page }) => {
    await page.clock.install();
    await boot(page, {
      status: {...converged, running:false},
      setup: {steps:[{step:'service.restart',ok:true,reason:'unreachable'}]},
    });
    await expect(page.locator('#health-title')).toHaveText('Sensor is starting');
    for (let attempt = 1; attempt <= 2; attempt++) {
      await page.clock.fastForward(15000);
      await expect.poll(async () => (await requests(page)).filter(r => r.action === 'setup').length).toBe(attempt);
      await page.clock.fastForward(1000);
      await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
      await expect(page.locator('#health-title')).toHaveText('Sensor is starting');
    }
    await page.clock.fastForward(15000);
    await expect(page.locator('#health-title')).toHaveText('Setup needs attention');
    await expect(page.locator('#health-description')).toContainText('the sensor is not responding');
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(2);
    // Usage has its own refresh timer; only setup retries must stop.
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'usage.summary').length).toBeGreaterThan(0);
    await page.clock.fastForward(15000);
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(2);
  });

  test('a just-started service that has not answered yet gets no agent setup during the grace period', async ({ page }) => {
    await page.clock.install();
    await boot(page, {
      status: {...enrolled, service:'running', running:false, telemetry:{codex_available:false, claude_available:true}},
      afterSetup: converged,
      setup: {steps:[{step:'service.restart',ok:true,reason:'unreachable'}]},
    });
    await expect(page.locator('#health-title')).toHaveText('Sensor is starting');
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
    await returnToWindow(page);
    expect((await requests(page)).filter(r => r.action === 'usage.summary')).toHaveLength(0);
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
    await page.clock.fastForward(14000);
    await returnToWindow(page);
    await expect(page.locator('#retry')).toHaveAttribute('aria-busy','false');
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
    await page.clock.fastForward(1000);
    await expect.poll(async () => (await requests(page)).filter(r => r.action === 'setup').length).toBe(1);
  });

  test('a stopped service is started with the opened app version', async ({ page }) => {
    await boot(page, {status: {...converged, service:'stopped', running:false, service_downgrade:true, recorded_service_version:'0.2.0'},
      afterSetup:converged, setup:{steps:[{step:'service.start',ok:true}]}});
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  });

  test('a sensor disabled from the console gets no agent setup and says so', async ({ page }) => {
    await boot(page, {status: {...enrolled, service:'running', running:true, disabled:true, telemetry:{listen:'127.0.0.1:4318', codex_available:true, claude_available:false}}});
    await expect(page.locator('#health-title')).toHaveText('Sensor disabled by your organization');
    await returnToWindow(page);
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
  });

  test('an agent disconnected from the command line stays disconnected', async ({ page }) => {
    await boot(page, {status: {...converged, telemetry:{...converged.telemetry, codex_available:true, codex_opted_out:true}}});
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#health-description')).toContainText('Codex telemetry is disconnected.');
    await returnToWindow(page);
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
  });

  test('an agent whose settings no longer match the desired values is configured again', async ({ page }) => {
    await boot(page, {
      status: {...converged, telemetry:{...converged.telemetry, claude_current:false}},
      afterSetup: converged,
      setup: {steps:[{step:'telemetry.install',ok:true,agents:['claude']}]},
    });
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#notice')).toHaveText('Restart Claude Code sessions to apply the new settings.');
    await expect(page.locator('#connected-agents')).toHaveText('Claude Code');
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  });

  test('a service that launchd reports running but that does not answer is restarted after a grace period', async ({ page }) => {
    await page.clock.install();
    await boot(page, {
      status: {...converged, running:false},
      afterSetup: converged,
      setup: {steps:[{step:'service.restart',ok:true,reason:'unreachable'}]},
    });
    await expect(page.locator('#health-title')).toHaveText('Sensor is starting');
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
    await page.clock.fastForward(15000);
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#notice')).toBeHidden();
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  });

  test('a sensor started by hand in the foreground is left alone and labeled', async ({ page }) => {
    await boot(page, {status: {...converged, service:'not installed', foreground:true}});
    await expect(page.locator('#health-title')).toHaveText('Sensor is running manually');
    await expect(page.locator('#health-description')).toContainText('Stop the manually started sensor, then return to this window');
    await expect(page.locator('#health-dot')).not.toHaveClass(/online/);
    await returnToWindow(page);
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
  });

  test('a foreground sensor on previous settings is asked for a restart and its agents wait', async ({ page }) => {
    await boot(page, {status: {...enrolled, service:'not installed', running:true, foreground:true, settings_stale:true, telemetry:{listen:'127.0.0.1:4318', codex_available:false, claude_available:true}}});
    await expect(page.locator('#health-title')).toHaveText('Sensor needs a restart');
    await expect(page.locator('#health-description')).toContainText('manually started sensor is using old settings');
    await returnToWindow(page);
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
  });

  for (const previous of ['2026.10.19+73302c5', '2026.10.21+aaaaaaa', '2026.10.20+aaaaaaa', '']) {
    test(`desktop setup replaces sensor ${previous || 'with unknown version'} with the exact app version`, async ({page}) => {
      const version = '2026.10.20+c3eb326';
      await boot(page, {status:{...converged,version,service_version:previous,service_newer:true,settings_stale:true},
        afterSetup:{...converged,version,service_version:version},setup:{steps:[{step:'service.restart',ok:true}]}});
      await expect(page.locator('#health-title')).toHaveText('Sensor is running');
      expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
    });
  }

  for (const maxWindowHeight of [720, 320]) {
    test(`a persistent version mismatch is visible and recoverable at ${maxWindowHeight}px`, async ({page}, testInfo) => {
      await page.clock.install();
      await boot(page, {maxWindowHeight,status:{...converged,version:'2026.10.20+c3eb326',service_version:'2026.10.21+aaaaaaa',service_newer:true,
        telemetry:{...converged.telemetry,received:12043,forwarded:12040,queue_depth:3},activity:{queue_depth:2}},
        setup:{steps:[{step:'service.restart',ok:true}]}});
      await returnToWindow(page);
      await returnToWindow(page);
      await expect(page.locator('#health-title')).toHaveText('Setup needs attention');
      await expect(page.locator('#health-description')).toContainText('2026.10.21+aaaaaaa');
      await expect(page.locator('#health-dot')).not.toHaveClass(/online/);
      await openSensorStatus(page, false);
      const panel = page.locator('#health-card');
      expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      if (maxWindowHeight === 320) expect(await panel.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      else expect(await panel.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
      await page.locator('#sensor-details summary').focus();
      await page.keyboard.press('Enter');
      await page.locator('#retry').focus();
      await expect(page.getByRole('button',{name:'Retry setup'})).toBeInViewport({ratio:1});
      await page.screenshot({path:testInfo.outputPath('version-mismatch.png'),animations:'disabled'});
    });
  }

  test('a receiver still running previous telemetry settings is restarted', async ({ page }) => {
    await boot(page, {
      status: {...converged, settings_stale:true},
      afterSetup: converged,
      setup: {steps:[{step:'service.restart',ok:true,reason:'settings'}]},
    });
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#notice')).toBeHidden();
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
  });

  test('a running service on an older version is restarted and a recovered start is not a failure', async ({ page }) => {
    await boot(page, {
      status: {...converged, service_version:'0.0.9', service_outdated:true},
      afterSetup: {...converged, service_version:'0.1.0'},
      setup: {steps:[{step:'service.restart',ok:true,running:'0.0.9',installed:'0.1.0'}]},
    });
    await expect(page.locator('#health-title')).toHaveText('Sensor is running');
    await expect(page.locator('#notice')).toBeHidden();
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(1);
    await expect(page.getByRole('button',{name:'Retry setup'})).toBeHidden();
  });

  test('telemetry disabled in the sensor settings is shown, even for a previously configured agent, and never triggers agent setup', async ({ page }) => {
    await boot(page, {status: {...enrolled, service:'running', running:true, telemetry:{enabled:false, codex_available:true, claude_available:true, claude_installed:true, claude_current:false, listen:'127.0.0.1:4318'}}});
    await expect(page.locator('#health-title')).toHaveText('Telemetry is disabled');
    await expect(page.locator('#health-description')).toContainText('Guardrails can still collect activity.');
    await expect(page.locator('#health-dot')).not.toHaveClass(/online/);
    await returnToWindow(page);
    expect((await requests(page)).map(r => r.action)).not.toContain('setup');
  });
});


const securityAlert: AlertFixture = {id:'01000000-0000-7000-8000-000000000042',title:'Upgrade LiteLLM',
  message:'Your security team requires a newer version of the LiteLLM Python package. Activate the project environment before upgrading, then restart your application.',
  command:'python -m pip install --upgrade "litellm==1.106.2"',installed_version:'1.105.0',required_version:'1.106.2',
  sender_name:'Sam Kim · Security team',created_at:'2026-10-22T09:41:00Z',expires_at:'2099-11-21T09:41:00Z',received_at:null,acknowledged_at:null};

test('endpoint alerts hide empty and expired inboxes while keeping fetch errors reachable', async ({page}) => {
  await page.clock.install({time:new Date('2026-10-23T12:00:00Z')});
  await boot(page, {status:converged,alerts:[]});
  const trigger = page.locator('#open-alerts');
  await expect.poll(async () => (await requests(page)).filter(row => row.action === 'alerts.list').length).toBe(1);
  await expect(trigger).toBeHidden();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.alertsError = 'Could not read alerts. Try again.'; });
  await page.clock.fastForward(60000);
  await expect(trigger).toBeVisible();
  await expect(trigger).toHaveText('Alerts');
  await expect(trigger).not.toHaveCSS('background-color', 'rgb(135, 36, 32)');
  await trigger.click();
  await expect(page.locator('#alerts-error')).toHaveText('Could not read alerts. Try again.');
  await expect(page.locator('#alerts-empty')).toBeHidden();
  await page.evaluate(alert => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.alertsError = '';
    mock.alerts = [{...alert,received_at:'2026-10-23T12:00:00Z',expires_at:'2026-10-23T12:02:00Z'},
      {...alert,id:'expired',expires_at:'2026-10-22T12:00:00Z'}];
  }, securityAlert);
  await page.getByRole('button', {name:'Refresh',exact:true}).click();
  await expect(trigger).toHaveText('Alerts (1)');
  await expect(trigger).toHaveCSS('background-color', 'rgb(135, 36, 32)');
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
  await page.clock.fastForward(60000);
  await expect(trigger).toBeHidden();
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.alertsError = 'Connection unavailable.'; });
  await page.clock.fastForward(60000);
  await trigger.click();
  await expect(page.locator('#alerts-error')).toHaveText('Connection unavailable.');
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.alertsError = ''; delete mock.alerts;
  });
  await page.getByRole('button', {name:'Refresh',exact:true}).click();
  await expect(trigger).toBeHidden();
  await expect(page.locator('#alerts-error')).toBeHidden();
});

test('endpoint alerts copy, native notification, acknowledgement retry, and retained inbox', async ({page}) => {
  await page.addInitScript(() => Object.defineProperty(navigator, 'clipboard', {value:{writeText:async(text:string) => { (window as unknown as {copied:string}).copied = text; }}}));
  await boot(page, {status:converged,alerts:[securityAlert],acknowledgeError:'Connection unavailable. Try again.'});
  const dialog = page.locator('#endpoint-alert');
  const trigger = page.locator('#open-alerts');
  await expect(dialog).toBeVisible();
  await expect(page.locator('#endpoint-alert-title')).toBeFocused();
  await expect(trigger).toHaveText('Alerts (1)');
  await expect(trigger).toHaveCSS('background-color', 'rgb(135, 36, 32)');
  await expect(trigger.locator('svg')).toHaveAttribute('aria-hidden', 'true');
  await expect(trigger.locator('svg')).toHaveCSS('color', 'rgb(255, 255, 255)');
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
  await expect(trigger).toHaveText('Alerts (1)');
  await trigger.click();
  await page.getByRole('button', {name:/Upgrade LiteLLM.*Not acknowledged/}).click();
  await expect(dialog.getByText('Update required', {exact:true})).toHaveCount(0);
  await expect(dialog.getByText('Need help with this update?')).toHaveCount(0);
  await expect.poll(async () => (await requests(page)).filter(row => row.action === 'alerts.received').length).toBe(1);
  await expect.poll(() => page.evaluate(() => (window as unknown as {notifications:unknown[]}).notifications.length)).toBe(1);
  await dialog.getByRole('button', {name:'Copy command'}).click();
  expect(await page.evaluate(() => (window as unknown as {copied:string}).copied)).toBe(securityAlert.command);
  await page.evaluate(() => { navigator.clipboard.writeText = async () => { throw new Error('Denied'); }; });
  await page.locator('#copy-alert-command').click();
  await expect(page.locator('#alert-copy-status')).toContainText('Command selected');
  expect(await page.evaluate(() => getSelection()?.toString())).toBe(securityAlert.command);
  await dialog.getByRole('button', {name:'Acknowledge',exact:true}).click();
  await expect(dialog.getByRole('alert')).toHaveText('Connection unavailable. Try again.');
  await expect(trigger).toHaveAccessibleName('Alerts, 1 awaiting acknowledgment');
  await expect(trigger).toHaveCSS('background-color', 'rgb(135, 36, 32)');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.acknowledgeError = ''; });
  await dialog.getByRole('button', {name:'Acknowledge',exact:true}).click();
  await expect(page.locator('#alert-receipt-note')).toContainText('Receipt acknowledged');
  await dialog.getByRole('button', {name:'Done',exact:true}).click();
  await expect(page.locator('#alerts-inbox')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#alerts-inbox')).toBeHidden();
  await expect(trigger).toBeFocused();
  await expect(trigger).toHaveAccessibleName('Alerts');
  await expect(trigger).toHaveText('Alerts');
  await expect(trigger).not.toHaveCSS('background-color', 'rgb(135, 36, 32)');
  await trigger.click();
  await page.getByRole('button', {name:/Upgrade LiteLLM.*Acknowledged/}).click();
  await expect(dialog.getByRole('button', {name:'Done',exact:true})).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', {name:'Alerts',exact:true})).toBeVisible();
  await page.keyboard.press('Escape');
  await page.evaluate(() => (window as unknown as {notificationAction:(extra:unknown) => void}).notificationAction({scope:'a'.repeat(64),alert_id:'01000000-0000-7000-8000-000000000042'}));
  await expect(dialog).toBeVisible();
  expect((await requests(page)).some(row => row.action === 'alerts.focus')).toBe(true);
  await page.keyboard.press('Escape');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.status = {enrolled:false}; });
  await returnToWindow(page);
  await expect(page.locator('#open-alerts')).toBeHidden();
  await expect(dialog).toBeHidden();
});

for (const maxWindowHeight of [720,320]) for (const colorScheme of ['light','dark'] as const) {
  test(`endpoint alert layout ${colorScheme} ${maxWindowHeight} and plain text content`, async ({page}, testInfo) => {
    await page.clock.install({time:new Date('2026-10-07T12:00:00Z')});
    await page.emulateMedia({colorScheme});
    const counts = {tokens:485330000,cached_input_tokens:475288000,uncached_input_tokens:8712000,output_tokens:1330000,calls:100,priced_calls:100,cost_usd:337.34};
    const breakdown = [
      {application:'codex',model:'gpt-6-astra',reasoning_effort:'xhigh',share:.75},
      {application:'claude_code',model:'claude-opus-5-5',reasoning_effort:'medium',share:.12},
      {application:'codex',model:'gpt-6.1-sol',reasoning_effort:'low',share:.09},
      {application:'claude_code',model:'claude-fable-5-1',reasoning_effort:'high',share:.04},
    ].map(({share,...row}) => ({...row,tokens:Math.round(counts.tokens * share),calls:100 * share,priced_calls:100 * share,cost_usd:counts.cost_usd * share}));
    const series = Array.from({length:30}, (_,i) => ({date:new Date(Date.UTC(2026,8,8+i)).toISOString().slice(0,10),
      ...(i === 29 ? {...counts,breakdown} : {tokens:0,calls:0,priced_calls:0,cost_usd:null})}));
    const alerts = [securityAlert,
      {...securityAlert,id:'credential-review',title:'Review exposed credentials',received_at:'2026-10-22T12:00:00Z'},
      {...securityAlert,id:'extension-review',title:'Review browser extensions',received_at:'2026-10-22T12:00:00Z'}];
    await boot(page, {status:{...converged,heartbeat:{last_success_at:'2026-10-07T11:59:00Z',error:''}},alerts,maxWindowHeight,notificationPermission:'denied',
      usage:{summary:counts,series,breakdown,pending_exports:0,
        by_model:breakdown.map(row => ({...row,name:row.model})),by_reasoning_effort:breakdown.map(row => ({...row,name:row.reasoning_effort}))}});
    const dialog = page.locator('#endpoint-alert');
    await expect(dialog).toBeVisible();
    await page.keyboard.press('Escape');
    const trigger = page.locator('#open-alerts');
    const app = page.locator('#app');
    await expect(trigger).toBeFocused();
    await expect(trigger).toHaveText('Alerts (3)');
    await expect(trigger).toHaveCSS('background-color', 'rgb(135, 36, 32)');
    await expect(trigger).toHaveCSS('color', 'rgb(255, 255, 255)');
    await trigger.hover();
    await expect(trigger).toHaveCSS('background-color', 'rgb(135, 36, 32)');
    expect(await trigger.evaluate(node => {
      const icon = node.querySelector('svg')!.getBoundingClientRect(), label = node.querySelector('span')!.getBoundingClientRect();
      return icon.width === 16 && icon.height === 16 && icon.right < label.left;
    })).toBe(true);
    for (const button of await page.locator('#header-actions button').all()) {
      await expect(button).toBeInViewport({ratio:1});
      expect(await button.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    }
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else {
      expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await page.getByRole('button', {name:'Settings',exact:true}).scrollIntoViewIfNeeded();
      await expect(page.getByRole('button', {name:'Settings',exact:true})).toBeInViewport({ratio:1});
      await trigger.scrollIntoViewIfNeeded();
      await expect(trigger).toBeInViewport({ratio:1});
    }
    await page.getByRole('heading', {name:'Your usage'}).click();
    await page.screenshot({path:testInfo.outputPath('alerts-pending.png'),animations:'disabled'});
    await trigger.click();
    await page.getByRole('button', {name:/Upgrade LiteLLM.*Not acknowledged/}).click();
    await expect(page.locator('#acknowledge-alert')).toBeInViewport({ratio:1});
    await dialog.screenshot({path:testInfo.outputPath('endpoint-alert-popup.png')});
    const scroll = dialog.locator('.endpoint-alert-scroll');
    await expect.poll(() => scroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(maxWindowHeight === 320);
    expect(await scroll.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.locator('#copy-alert-command').focus();
    await expect(page.locator('#copy-alert-command')).toBeInViewport({ratio:1});
    await scroll.evaluate(node => { node.scrollTop = node.scrollHeight; });
    await expect(dialog.locator('.alert-source')).toBeInViewport({ratio:1});
    await dialog.getByRole('button', {name:'Acknowledge',exact:true}).click();
    await expect(dialog.getByRole('button', {name:'Done',exact:true})).toBeInViewport({ratio:1});
    await page.screenshot({path:`test-results/endpoint-alert-${colorScheme}-${maxWindowHeight}.png`});
    await page.keyboard.press('Escape');
    await expect(page.locator('#alerts-inbox')).toBeVisible();
    for (const [index, alert] of alerts.slice(1).entries()) {
      await expect(trigger).toHaveText(`Alerts (${2 - index})`);
      await expect(trigger).toHaveCSS('background-color', 'rgb(135, 36, 32)');
      await page.getByRole('button', {name:new RegExp(alert.title)}).click();
      await dialog.getByRole('button', {name:'Acknowledge',exact:true}).click();
      await expect(dialog.getByRole('button', {name:'Done',exact:true})).toBeVisible();
      await page.keyboard.press('Escape');
      await expect(page.locator('#alerts-inbox')).toBeVisible();
    }
    await page.keyboard.press('Escape');
    await expect(page.locator('#alerts-inbox')).toBeHidden();
    await expect(trigger).toHaveText('Alerts');
    await expect(trigger).not.toHaveCSS('background-color', 'rgb(135, 36, 32)');
    await page.screenshot({path:testInfo.outputPath('alerts-acknowledged.png'),animations:'disabled'});
    await trigger.click();
    await expect(page.locator('#alerts-notification-status')).toHaveText('System notifications are off. Alerts remain available here.');
    await page.evaluate(() => {
      const row = (window as unknown as {mock:Mock}).mock.alerts![0];
      row.title = '<img src=x onerror=alert(1)>';
      row.message = ('Long remediation instruction <script>alert(1)</script> ').repeat(30);
      row.command = 'a'.repeat(1900);
    });
    await page.getByRole('button', {name:'Refresh',exact:true}).click();
    await page.getByRole('button', {name:/<img src=x/}).click();
    await expect(page.locator('#endpoint-alert-title')).toHaveText('<img src=x onerror=alert(1)>');
    await expect(dialog.locator('img,script')).toHaveCount(0);
    await expect(page.locator('#acknowledge-alert')).toBeInViewport({ratio:1});
    expect(await scroll.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.locator('#alert-command').focus();
    await expect(page.locator('#alert-command')).toBeInViewport();
    await page.keyboard.press('Escape');
    await expect(page.locator('#alerts-inbox')).toBeVisible();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.alerts = []; });
    await page.getByRole('button', {name:'Refresh',exact:true}).click();
    await expect(trigger).toBeHidden();
    await page.keyboard.press('Escape');
    await expect(page.locator('#alerts-inbox')).toBeHidden();
    await page.screenshot({path:testInfo.outputPath('alerts-empty.png'),animations:'disabled'});
  });
}

for (const maxWindowHeight of [720, 320]) {
  test(`Hermes approval remains visible without repeated setup in a ${maxWindowHeight}px work area`, async ({page}) => {
    const hermes = {available:true,installed:true,current:false,approval_pending:true};
    const status = {...converged,hooks:{...converged.hooks,hermes}};
    await boot(page,{status,maxWindowHeight,usage:usageTotals(279440000)});
    await expect(page.locator('#status-label')).toHaveText('Attention');
    await openSensorStatus(page);
    await expect(page.locator('#health-description')).toContainText('Hermes Agent guardrails need approval.');
    await expect(page.locator('#connected-agents')).not.toContainText('Hermes Agent');
    expect((await requests(page)).filter(r => r.action === 'setup')).toHaveLength(0);
    const panel = page.locator('#health-card');
    expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.locator('#retry').focus();
    await expect(page.locator('#retry')).toBeInViewport({ratio:1});
    await page.keyboard.press('Escape');
    await page.evaluate(() => {
      const hooks = (window as unknown as {mock:Mock}).mock.status.hooks as Record<string,Record<string,boolean>>;
      hooks.hermes.current = true;
      hooks.hermes.approval_pending = false;
    });
    await returnToWindow(page);
    await openSensorStatus(page);
    await expect(page.locator('#connected-agents')).toContainText('Hermes Agent');
    await expect(page.locator('#health-description')).not.toContainText('need approval');
  });
}

for (const maxWindowHeight of [720, 320]) {
  test(`usage notices stay compact and controls remain reachable at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    await page.clock.install();
    await page.emulateMedia({colorScheme:maxWindowHeight === 720 ? 'light' : 'dark'});
    const ready = {...freeStatus(),telemetry:{...freeStatus().telemetry,codex_available:true,codex_installed:true,codex_current:true},
      hooks:{hermes:{available:true,installed:true,current:true}}};
    const counts = {tokens:937160000,cached_input_tokens:919105000,uncached_input_tokens:15895000,output_tokens:2160000,
      calls:2840,priced_calls:2840,cost_usd:807.08};
    const share = (fraction:number) => Object.fromEntries(Object.entries(counts).map(([key,value]) => [key,value * fraction]));
    const breakdown = (fraction:number) => [
      {application:'codex',model:'gpt-6-astra',reasoning_effort:'xhigh',...share(fraction * .99)},
      {application:'claude_code',model:'claude-opus-5-5',reasoning_effort:'high',...share(fraction * .01)},
    ];
    const weights = [2,24,14,7,0,2,0,2,6,30,11,0,0,0,0,0,1,13,7,2,15,17,3,16,7];
    const total = weights.reduce((sum,value) => sum + value, 0);
    const usage = {summary:counts,pending_exports:0,
      series:weights.map((weight,index) => ({date:new Date(Date.UTC(2026,9,6,12+index)).toISOString(),...share(weight / total),breakdown:breakdown(weight / total)})),
      by_model:['gpt-6-astra','gpt-6.1-sol','claude-fable-5-1','claude-opus-5-5'].map((name,index) => ({name,...share([.89,.1,.007,.003][index])})),
      by_reasoning_effort:['xhigh','low','high','max'].map((name,index) => ({name,...share([.88,.1,.01,.01][index])})),
      history_recovery:{recovered_calls:0,unreconciled_records:1},breakdown:breakdown(1)};
    await boot(page, {status:{...ready,telemetry:{...ready.telemetry,claude_current:false}},afterSetup:ready,maxWindowHeight,
      usageByDays:{1:usage,30:{...usage,series:Array.from({length:30}, (_,index) => ({date:new Date(Date.UTC(2026,8,8+index)).toISOString().slice(0,10),...share(index === 29 ? 1 : 0)}))}},
      setup:{restart_required:true,steps:[{step:'hooks.install',ok:true,agents:['codex','claude','opencode','hermes']}]}});
    await expect(page.locator('#usage-cost')).toHaveText('$807.08');
    await page.getByRole('button', {name:'24 hours',exact:true}).click();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.usageError = 'Could not read usage stored on this device. Try again later.'; });
    await page.clock.fastForward(10001);
    await expect(page.locator('#usage-message')).toContainText('Showing previously loaded usage.');
    await expect(page.locator('#usage-legend')).toHaveText('CodexClaude Code');
    const app = page.locator('#app');
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.screenshot({path:testInfo.outputPath(`compact-usage-notices-${maxWindowHeight}.png`),animations:'disabled'});
    const cloud = page.locator('#cloud-credit');
    await expect(cloud).toBeHidden();
    await returnToWindow(page);
    await expect(cloud).toBeHidden();
    await expect(page.locator('#notice')).toHaveText('Restart coding-agent sessions to apply the new settings.');
    for (const control of [page.getByRole('button', {name:'30 days',exact:true}),page.getByRole('button', {name:'Settings',exact:true})]) {
      await control.focus();
      await expect(control).toBeInViewport({ratio:1});
    }
    for (const id of ['usage-models','usage-efforts']) {
      const last = page.locator(`#${id} .usage-row`).last();
      await last.scrollIntoViewIfNeeded();
      await expect(last).toBeInViewport({ratio:1});
    }
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  });
}

for (const maxWindowHeight of [720, 240]) {
  test(`cloud protection notices and recovery fit a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const credit = {schema_version:1,state:'exhausted',checked_at:Date.now()/1000,guardrail_configured:true,guardrail_available:false,credit_status:null,credits_per_usd:'100',reset_at:'2026-11-01T00:00:00Z'};
    const status = {...converged, control_ready:true, heartbeat:{last_success_at:new Date().toISOString(),error:''}, cloud_protection:credit,
      hooks:{codex:guardrailStatus().hooks.codex,claude:guardrailStatus().hooks.claude}};
    await boot(page, {status,maxWindowHeight,usage:populatedUsage(),guardrails:guardrailActivity()});
    const notice = page.locator('#cloud-credit');
    await expect(notice).toBeVisible();
    await expect(notice).toContainText('Cloud guardrails inactive');
    await expect(notice.locator('p')).toBeVisible();
    await expect(notice).toContainText('Local rules and collection remain available.');
    await expect(notice).toContainText('Free protection resets');
    await expect(notice).not.toContainText('$');
    await expect.poll(() => page.evaluate(() => (window as unknown as {notifications:unknown[]}).notifications.length)).toBe(1);
    await returnToWindow(page);
    expect(await page.evaluate(() => (window as unknown as {notifications:unknown[]}).notifications.length)).toBe(1);
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else {
      expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await page.locator('#change-connection').focus();
      await expect(page.locator('#change-connection')).toBeInViewport({ratio:1});
      await notice.scrollIntoViewIfNeeded();
      await expect(notice).toBeInViewport();
    }
    await page.screenshot({path:testInfo.outputPath(`cloud-protection-exhausted-${maxWindowHeight}.png`),animations:'disabled'});
    for (const connection_mode of ['organization','api_key','free']) {
      await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
        {...status,connection_mode,cloud_protection:{...credit,state:'active',guardrail_available:true}});
      await returnToWindow(page);
      await expect(notice).toBeHidden();
      await expect(page.locator('#status-label')).toHaveText('Connected');
    }
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    await expect(page.locator('#guardrails-mode')).toHaveText('Monitoring (Shadow)');
    await expect(page.locator('#guardrails-policy')).toHaveText('Actions continue');
    await expect(page.locator('#guardrails-completed')).toHaveText('1,240');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight)).toBe(true);
    if (maxWindowHeight === 720) {
      await expect(page.locator('#sensor-status')).toBeInViewport({ratio:1});
      await expect(page.locator('#guardrails-mode')).toBeInViewport({ratio:1});
    } else expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await page.locator('#guardrails-view').focus();
    await expect(page.locator('#guardrails-view')).toBeInViewport({ratio:1});
    await page.locator('#agent-reinstall').focus();
    await expect(page.locator('#agent-reinstall')).toBeInViewport({ratio:1});
    await page.locator('#change-connection').focus();
    await expect(page.locator('#change-connection')).toBeInViewport({ratio:1});
    await app.evaluate(node => { node.scrollTop = 0; });
    await page.screenshot({path:testInfo.outputPath(`cloud-protection-active-${maxWindowHeight}.png`),animations:'disabled'});
    await page.getByRole('tab', {name:'Usage',exact:true}).click();
    await openSensorStatus(page);
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = 'Local sensor unavailable'; });
    await returnToWindow(page);
    await expect(page.locator('#health-title')).toHaveText('Status unavailable');
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.statusError = ''; });
    await returnToWindow(page);
    await page.keyboard.press('Escape');
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
      {...status,cloud_protection:{...credit,state:'unavailable'}});
    await returnToWindow(page);
    await expect(notice).toBeVisible();
    await expect(notice).toContainText('Cloud protection is unavailable.');
    await expect(notice.locator('p')).toBeVisible();
    await expect.poll(() => page.evaluate(() => (window as unknown as {notifications:unknown[]}).notifications.length)).toBe(2);
    for (const unsafe of [
      {state:'active',remaining_nanos:1500000000,allowance_nanos:2000000000},
      {...credit,state:'active',guardrail_available:false},
      {...credit,state:'active',guardrail_available:true,credit_status:'unavailable'},
      {...credit,state:'active',guardrail_available:true,credit_status:'unconfigured'},
      {...credit,state:'active',guardrail_available:true,credit_status:'exhausted'},
      {...credit,state:'active',guardrail_available:true,model:'private-provider-model',usage:{tokens:123}},
      {...credit,state:'active',guardrail_available:true,checked_at:null},
      {...credit,state:'active',guardrail_available:true,checked_at:0},
    ]) {
      await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, {...status,cloud_protection:unsafe});
      await returnToWindow(page);
      await expect(notice).toBeVisible();
      await expect(notice).toContainText('Cloud protection is unavailable.');
      await expect(notice).not.toContainText('$');
    }
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
      {...status,cloud_protection:{...credit,credit_status:'exhausted'}});
    await returnToWindow(page);
    await expect(notice).toContainText('Service credits are exhausted');
    await expect(notice).not.toContainText('resets');
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
      {...status,cloud_protection:{...credit,state:'connecting'}});
    await returnToWindow(page);
    await expect(notice).toBeVisible();
    await expect(notice).toContainText('Connecting cloud protection');
    // An older bridge has no versioned status. Never display its private balance.
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
      {...converged,cloud_credit:{state:'active',checked_at:Date.now()/1000,remaining_nanos:1.5e9,allowance_nanos:2e9}});
    await returnToWindow(page);
    await expect(notice).toBeHidden();
  });
}

test('cloud connection grace requires recent contact and preserves actionable failures', async ({page}) => {
  const now = new Date('2026-11-04T12:00:00Z');
  await page.clock.setFixedTime(now);
  const ready = {...freeStatus(),heartbeat:{last_success_at:now.toISOString(),error:''},
    cloud_protection:{...freeStatus().cloud_protection,checked_at:now.getTime()/1000}};
  const heartbeat = {...ready.heartbeat,error:'Intelligence service unavailable'};
  const unavailable = {...ready.cloud_protection,state:'unavailable',guardrail_configured:false,guardrail_available:false,credit_status:null};
  await boot(page,{status:ready});
  for (const example of [
    {name:'free service failure',fields:{},deferred:true},
    {name:'API key service failure',fields:{connection_mode:'api_key'},deferred:true},
    {name:'network timeout',fields:{heartbeat:{...heartbeat,error:'The read operation timed out'}},deferred:true},
    {name:'no previous contact',fields:{heartbeat:{...heartbeat,last_success_at:null}}},
    {name:'old contact',fields:{heartbeat:{...heartbeat,last_success_at:new Date(now.getTime() - 180000).toISOString()}}},
    {name:'invalid contact',fields:{heartbeat:{...heartbeat,last_success_at:'invalid'}}},
    {name:'future contact',fields:{heartbeat:{...heartbeat,last_success_at:new Date(now.getTime() + 1000).toISOString()}}},
    {name:'authentication failure',fields:{heartbeat:{...heartbeat,error:'401 Unauthorized'}}},
    {name:'authorization failure',fields:{heartbeat:{...heartbeat,error:'403 Forbidden'}}},
    {name:'certificate failure',fields:{heartbeat:{...heartbeat,error:'[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed'}}},
    {name:'unknown failure',fields:{heartbeat:{...heartbeat,error:'Unexpected service response'}}},
    {name:'other upload failure',fields:{activity:{queue_depth:1,last_error:'403 Forbidden'}}},
  ]) {
    await test.step(example.name,async () => {
      await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },ready);
      await returnToWindow(page);
      await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
        {...ready,heartbeat,cloud_protection:unavailable,...example.fields});
      await returnToWindow(page);
      await expect(page.locator('#status-label')).toHaveText(example.deferred ? 'Connected' : 'Connection lost');
      await expect(page.locator('#cloud-credit')).toBeVisible({visible:!example.deferred});
      await openSensorStatus(page,false);
      await expect(page.locator('#health-error')).toBeVisible({visible:!example.deferred});
    });
  }
  for (const cloud_protection of [
    {...unavailable,state:'exhausted',credit_status:'exhausted'},
    {...unavailable,credit_status:'exhausted'},
    {...unavailable,credit_status:'unconfigured'},
    {...unavailable,checked_at:null},
    {...unavailable,checked_at:now.getTime()/1000 - 181},
    {state:'unavailable'},
  ]) {
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; },
      {...ready,heartbeat,cloud_protection});
    await returnToWindow(page);
    await expect(page.locator('#cloud-credit')).toBeVisible();
  }
});

for (const maxWindowHeight of [720,320]) {
  test(`transient cloud errors recover quietly and persistent errors appear at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    const now = new Date('2026-11-04T12:00:00Z');
    await page.clock.install({time:now});
    await page.clock.pauseAt(new Date(now.getTime() + 1000));
    const ready = {...freeStatus(),heartbeat:{last_success_at:now.toISOString(),error:''},
      cloud_protection:{...freeStatus().cloud_protection,checked_at:now.getTime()/1000}};
    await boot(page,{status:ready,maxWindowHeight,usage:populatedUsage()});
    await expect(page.locator('#status-label')).toHaveText('Connected');
    await openSensorStatus(page,false);
    const panel = page.locator('#health-card');
    const cloud = page.locator('#cloud-credit');
    const notifications = () => page.evaluate(() => (window as unknown as {notifications:unknown[]}).notifications.length);
    const fail = async () => {
      await page.evaluate(() => {
        const status = (window as unknown as {mock:Mock}).mock.status;
        status.heartbeat = {...status.heartbeat as object,error:'Intelligence service unavailable'};
        status.cloud_protection = {...status.cloud_protection as object,state:'unavailable',checked_at:Date.now()/1000,
          guardrail_configured:false,guardrail_available:false,credit_status:null};
      });
      await returnToWindow(page);
    };
    const recover = async () => {
      await page.evaluate(ready => {
        (window as unknown as {mock:Mock}).mock.status = {...ready,heartbeat:{last_success_at:new Date().toISOString(),error:''},
          cloud_protection:{...ready.cloud_protection,checked_at:Date.now()/1000}};
      },ready);
      await returnToWindow(page);
    };
    await fail();
    await expect(page.locator('#status-label')).toHaveText('Connected');
    await expect(panel).toHaveClass(/compact-status/);
    await expect(page.locator('#health-error')).toBeHidden();
    await expect(cloud).toBeHidden();
    await page.clock.fastForward(5000);
    await recover();
    await page.clock.fastForward(15000);
    await expect(cloud).toBeHidden();
    expect(await notifications()).toBe(0);
    await page.screenshot({path:testInfo.outputPath('cloud-transient-recovered.png')});

    await fail();
    await page.clock.fastForward(14999);
    await returnToWindow(page);
    await expect(page.locator('#status-label')).toHaveText('Connected');
    await expect(cloud).toBeHidden();
    expect(await notifications()).toBe(0);
    await page.clock.fastForward(1);
    await returnToWindow(page);
    await expect(page.locator('#status-label')).toHaveText('Connection lost');
    await expect(page.locator('#health-title')).toHaveText('Server connection lost');
    await expect(page.locator('#health-error')).toHaveText('Cloud service connection: Intelligence service unavailable');
    await expect(cloud).toContainText('Cloud protection is unavailable.');
    await expect.poll(notifications).toBe(1);
    await returnToWindow(page);
    expect(await notifications()).toBe(1);
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else expect(await panel.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await page.locator('#retry').focus();
    await expect(page.locator('#retry')).toBeInViewport({ratio:1});
    await page.locator('#close-status').focus();
    await expect(page.locator('#close-status')).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath('cloud-persistent-failure.png')});
    await recover();
    await expect(page.locator('#status-label')).toHaveText('Connected');
    await expect(cloud).toBeHidden();
    await expect(page.locator('#health-error')).toBeHidden();
    await fail();
    await expect(page.locator('#status-label')).toHaveText('Connected');
    await expect(cloud).toBeHidden();
    expect(await notifications()).toBe(1);
  });

  test(`free onboarding choices work side by side in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await page.emulateMedia({colorScheme:'light'});
    await boot(page, {status:unenrolled,setupChoices:true,preview,maxWindowHeight});
    await expect(page.getByRole('heading', {name:'Welcome to OpenAIDR'})).toBeVisible();
    const cards = await page.locator('.setup-choice').evaluateAll(nodes => nodes.map(node => {
      const {x,y,width,height} = node.getBoundingClientRect(); return {x,y,width,height};
    }));
    expect(cards).toHaveLength(2);
    expect(cards[0].y).toBe(cards[1].y);
    expect(cards[0].width).toBe(cards[1].width);
    expect(cards[0].height).toBe(cards[1].height);
    expect(cards[0].x + cards[0].width).toBeLessThan(cards[1].x);
    const buttons = await page.locator('.setup-choice-actions > .button').evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().y));
    expect(buttons[0]).toBe(buttons[1]);
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else expect(await page.locator('#app').evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await page.screenshot({path:testInfo.outputPath('free-onboarding.png'),animations:'disabled'});
    for (const id of ['continue-free','choose-organization','data-use','change-connection','check-update','show-about']) {
      await page.locator('#' + id).focus();
      await expect(page.locator('#' + id)).toBeInViewport({ratio:1});
    }
    await page.getByRole('button', {name:'How your data is used'}).click();
    const dialog = page.getByRole('dialog', {name:'How your data is used'});
    await expect(dialog).toContainText('without retaining it');
    await expect(dialog).toContainText('Shadow mode');
    await dialog.getByRole('button', {name:'Done',exact:true}).focus();
    await expect(dialog.getByRole('button', {name:'Done',exact:true})).toBeInViewport({ratio:1});
    await dialog.getByRole('button', {name:'Done',exact:true}).click();
    await expect(page.locator('#data-use')).toBeFocused();
    await page.getByRole('button', {name:'Connect organization',exact:true}).click();
    await expect(page.getByLabel('Enrollment link', {exact:true})).toBeFocused();
    await expect(page.locator('#setup-choices')).toBeHidden();
    const back = page.getByRole('button', {name:'Back',exact:true});
    await expect.poll(() => page.locator('#connect-card').evaluate(card => {
      const title = card.querySelector('#connection-title')!.getBoundingClientRect();
      const back = card.querySelector('#back-to-choices')!.getBoundingClientRect();
      return {
        sameRow:Math.abs(title.y + title.height / 2 - back.y - back.height / 2) <= 1,
        afterTitle:back.left > title.right,
        rightAligned:Math.abs(back.right - card.getBoundingClientRect().right) <= 1,
      };
    })).toEqual({sameRow:true,afterTitle:true,rightAligned:true});
    await page.getByLabel('Enrollment link', {exact:true}).fill(link);
    await expect(page.locator('#link-organization')).toHaveText(preview.tenant.name);
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else expect(await page.locator('#app').evaluate(node => node.scrollHeight > node.clientHeight && node.scrollWidth === node.clientWidth)).toBe(true);
    for (const id of ['connect-link','choose-local-runtime','show-about','back-to-choices']) {
      await page.locator('#' + id).focus();
      await expect(page.locator('#' + id)).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath('organization-heading-back.png'),animations:'disabled'});
    await back.click();
    await expect(page.locator('#setup-choices')).toBeVisible();
    await expect(page.locator('#choose-organization')).toBeFocused();
    expect((await requests(page)).filter(row => row.action === 'free.connect' || row.action === 'enrollment.connect')).toEqual([]);
  });
}

function freeStatus() {
  return {...converged,connection_mode:'free',tenant_name:'Free plan',server_url:'https://api.opensecura.ai',
    heartbeat:{last_success_at:new Date().toISOString(),error:''},
    telemetry:{...converged.telemetry,processed_locally:42,forwarded:0,received:42},
    cloud_protection:{schema_version:1,state:'active',checked_at:Date.now()/1000,guardrail_configured:true,
      guardrail_available:true,credit_status:'disabled',credits_per_usd:'100',reset_at:null}};
}

test('Continue for free retries failures then enrolls once and automatically sets up the sensor', async ({page}) => {
  const ready = freeStatus();
  await boot(page, {status:unenrolled,setupChoices:true,freeError:'Free setup is rate limited. Wait and try again with the same installation.',
    afterEnroll:{...ready,service:'not installed',running:false},afterSetup:ready,usage:populatedUsage()});
  await page.getByRole('button', {name:'Continue for free',exact:true}).click();
  await expect(page.locator('#notice')).toContainText('rate limited');
  await expect(page.locator('#continue-free')).toBeEnabled();
  expect((await requests(page)).filter(row => row.action === 'setup')).toHaveLength(0);
  await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.freeError = ''; mock.pendingAction = 'free.connect'; });
  await page.getByRole('button', {name:'Continue for free',exact:true}).click();
  await expect(page.locator('#continue-free')).toBeDisabled();
  await expect(page.locator('#choose-organization')).toBeDisabled();
  expect((await requests(page)).filter(row => row.action === 'free.connect')).toHaveLength(2);
  await page.evaluate(() => { const win = window as unknown as {mock:Mock;completeRequest:() => void}; win.mock.pendingAction = undefined; win.completeRequest(); });
  await expect(page.getByRole('tab', {name:'Usage',exact:true})).toBeVisible();
  await expect(page.locator('#setup-choices')).toBeHidden();
  await expect.poll(async () => (await requests(page)).filter(row => row.action === 'setup').length).toBe(1);
  await expect(page.locator('#cloud-credit')).toBeHidden();
  await openSensorStatus(page);
  await expect(page.locator('#health-description')).toContainText('Connected to the free service');
  await expect(page.locator('#processed-label')).toHaveText('Processed locally');
  await expect(page.locator('#sent')).toHaveText('42');
  await expect(page.locator('#dashboard-link')).toHaveCount(0);
  const calls = await requests(page);
  expect(calls.filter(row => ['enrollment.preview','enrollment.connect'].includes(row.action))).toEqual([]);
  expect(calls.filter(row => row.action === 'free.connect')).toEqual([{action:'free.connect'},{action:'free.connect'}]);
});

test('persisted free setup resumes without enrollment and offers organization switching in Settings', async ({page}) => {
  const status = freeStatus();
  await boot(page, {status,guardrails:guardrailActivity(),usage:populatedUsage(),preview,afterEnroll:converged});
  await expect(page.locator('#setup-choices')).toBeHidden();
  await expect(page.getByRole('tab', {name:'Usage',exact:true})).toBeVisible();
  await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
  await expect(page.locator('#cloud-credit')).toBeHidden();
  await expect(page.locator('#guardrails-mode')).toHaveText('Monitoring (Shadow)');
  await expect(page.locator('#guardrails-policy')).toHaveText('Actions continue');
  await expect(page.locator('#guardrails-completed')).toHaveText('1,240');
  await expect(page.locator('#guardrails-deny')).toBeDisabled();
  await page.locator('#guardrails-view').click();
  await expect(page.locator('#guardrails-recent')).toContainText('Response: allow');
  expect((await requests(page)).filter(row => row.action === 'free.connect')).toEqual([]);
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await page.getByLabel('Enrollment link', {exact:true}).fill(link);
  await page.getByRole('button', {name:'Connect',exact:true}).click();
  await expect(page.getByRole('dialog', {name:'Settings',exact:true})).toBeHidden();
  await expect(page.locator('#guardrails-policy')).toHaveText('Organization policy · Actions continue');
  await expect(page.locator('#guardrails-deny')).toBeEnabled();
  expect((await requests(page)).filter(row => row.action === 'enrollment.connect')).toHaveLength(1);
});

for (const state of ['unavailable','exhausted']) {
  test(`free ${state} protection is explicit and does not claim a local policy fallback`, async ({page}) => {
    const status = freeStatus();
    status.cloud_protection = {...status.cloud_protection,state,guardrail_available:false,credit_status:state};
    await boot(page, {status,usage:populatedUsage()});
    await expect(page.locator('#cloud-credit')).toContainText('Cloud guardrails inactive');
    await expect(page.locator('#cloud-credit')).toContainText('Actions continue.');
    await expect(page.locator('#cloud-credit')).not.toContainText('Local rules');
    await expect.poll(() => page.evaluate(() => (window as unknown as {notifications:unknown[]}).notifications.length)).toBe(1);
    await page.evaluate(status => { (window as unknown as {mock:Mock}).mock.status = status; }, freeStatus());
    await returnToWindow(page);
    await expect(page.locator('#cloud-credit')).toBeHidden();
    expect((await requests(page)).filter(row => row.action === 'free.connect')).toEqual([]);
  });
}

for (const maxWindowHeight of [720,320]) {
  test(`Cloud check failure reasons stay safe and reachable in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const activity = guardrailActivity();
    const reasons = ['timeout','evidence_unavailable','service_unavailable','outcome_unknown','private-secret-<script>alert(1)</script>',undefined];
    const recent = activity.recent.map((check, index) => index < reasons.length
      ? {...check,status:'unavailable',evaluated_decision:null,returned_decision:null,failure_reason:reasons[index]}
      : {...check,failure_reason:'timeout'});
    activity.summary.unavailable = activity.by_mode.shadow.unavailable = reasons.length;
    const status = {...freeStatus(),hooks:guardrailStatus().hooks,connection_mode:maxWindowHeight === 720 ? 'free' : 'api_key'};
    await boot(page, {status,guardrails:{...activity,recent},usage:populatedUsage(),maxWindowHeight});
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight)).toBe(true);
    await page.locator('#agent-reinstall').focus();
    await expect(page.locator('#agent-reinstall')).toBeInViewport({ratio:1});
    await page.locator('#guardrails-view').click();
    const rows = page.locator('.guardrail-activity-row');
    await expect(rows).toHaveCount(20);
    for (const [index, text] of ['Check timed out.','Required evidence was unavailable.','The service was unavailable.',
      'No completion result was recorded.','Reason not recorded.','Reason not recorded.'].entries()) {
      await expect(rows.nth(index)).toContainText(text);
      await rows.nth(index).scrollIntoViewIfNeeded();
      await expect(rows.nth(index)).toBeInViewport({ratio:1});
    }
    await expect(page.locator('#guardrails-recent')).not.toContainText('private-secret');
    await expect(page.locator('#guardrails-recent script')).toHaveCount(0);
    await expect(rows.nth(6)).not.toContainText('Check timed out.');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await rows.last().scrollIntoViewIfNeeded();
    await expect(rows.last()).toBeInViewport({ratio:1});
    expect(await app.evaluate(node => node.scrollTop > 0)).toBe(true);
    await page.locator('#agent-reinstall').focus();
    await expect(page.locator('#agent-reinstall')).toBeInViewport({ratio:1});
    await rows.first().scrollIntoViewIfNeeded();
    await page.screenshot({path:testInfo.outputPath('cloud-check-failure-reasons.png'),animations:'disabled'});
    await testInfo.attach('Cloud check failure reasons', {path:testInfo.outputPath('cloud-check-failure-reasons.png'),contentType:'image/png'});
    await page.locator('#guardrails-view').click();
    await expect(page.locator('#guardrails-activity')).toBeHidden();
  });
}


for (const maxWindowHeight of [720,320]) {
  test(`rate-limited setup accepts an API key in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const ready = {...freeStatus(),connection_mode:'api_key',cloud_protection:null};
    await boot(page, {status:unenrolled,setupChoices:true,maxWindowHeight,
      freeError:'Free setup is rate limited. Wait and try again with the same installation.',
      apiKeyError:'The API key was rejected. Check the key and try again.',
      afterEnroll:{...ready,service:'not installed',running:false},afterSetup:ready,usage:populatedUsage()});
    await expect(page.getByRole('button', {name:'Use an API key',exact:true})).toBeHidden();
    await page.getByRole('button', {name:'Continue for free',exact:true}).click();
    const trigger = page.getByRole('button', {name:'Use an API key',exact:true});
    await expect(trigger).toBeVisible();
    await trigger.focus(); await expect(trigger).toBeInViewport({ratio:1});
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await trigger.click();
    const dialog = page.getByRole('dialog', {name:'Connect with an API key',exact:true});
    const input = dialog.getByLabel('OpenSecura API key', {exact:true});
    const connect = dialog.getByRole('button', {name:'Connect',exact:true});
    await expect(input).toBeFocused(); await expect(input).toHaveAttribute('type','password');
    await expect(connect).toBeDisabled();
    await input.fill('synthetic-rejected-key'); await connect.click();
    await expect(dialog.getByRole('alert')).toContainText('API key was rejected');
    await expect(input).toHaveValue(''); await expect(input).toBeFocused();
    expect((await requests(page)).filter(row => row.action === 'setup')).toEqual([]);
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    for (const control of [input,dialog.getByRole('button', {name:'Cancel',exact:true})]) {
      await control.focus(); await expect(control).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath('api-key-error.png'),animations:'disabled'});
    await input.fill('discard-on-close'); await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden(); await expect(page.locator('#api-key')).toHaveValue(''); await expect(trigger).toBeFocused();
    await trigger.click();
    const key = 'oasc_' + 'a'.repeat(32) + '.' + 'k'.repeat(43);
    await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.apiKeyError = ''; mock.pendingAction = 'api-key.connect'; });
    await input.fill(key); await connect.focus(); await expect(connect).toBeInViewport({ratio:1});
    await connect.click();
    await expect(connect).toBeDisabled(); await expect(input).toHaveValue('');
    await expect(dialog.getByRole('button', {name:'Cancel',exact:true})).toBeDisabled();
    await page.keyboard.press('Escape'); await expect(dialog).toBeVisible();
    await page.evaluate(() => { const win = window as unknown as {mock:Mock;completeRequest:() => void}; win.mock.pendingAction = undefined; win.completeRequest(); });
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('tab', {name:'Usage',exact:true})).toBeVisible();
    await expect.poll(async () => (await requests(page)).filter(row => row.action === 'setup').length).toBe(1);
    await page.getByRole('tab', {name:'Guardrails',exact:true}).click();
    await expect(page.locator('#guardrails-policy')).toHaveText('API key · Actions continue');
    await expect(page.locator('#guardrails-deny')).toBeDisabled();
    await openSensorStatus(page);
    await expect(page.locator('#health-description')).toContainText('Connected with your API key');
    await expect(page.locator('#processed-label')).toHaveText('Processed locally');
    expect(await page.locator('body').textContent()).not.toContain(key);
    expect(await page.evaluate(() => JSON.stringify([localStorage,sessionStorage]))).not.toContain(key);
    expect((await requests(page)).filter(row => row.action === 'free.connect')).toHaveLength(1);
    expect((await requests(page)).filter(row => row.action === 'api-key.connect')).toHaveLength(2);
  });
}


for (const maxWindowHeight of [720, 320]) {
  test(`Connected free credits and guardrail actions fit in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const now = new Date('2026-11-04T08:00:00Z');
    await page.clock.setFixedTime(now);
    await page.emulateMedia({colorScheme:maxWindowHeight === 720 ? 'light' : 'dark'});
    const start = new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate()));
    start.setUTCDate(start.getUTCDate() - (start.getUTCDay() + 6) % 7);
    const usage = {status:'active',allowance:'200',used:'43.21',reserved:'6.79',available:'150',
      starts_at:start.toISOString(),resets_at:new Date(start.getTime()+7*86400000).toISOString(),checked_at:now.toISOString()};
    const status = {...guardrailStatus(),connection_mode:'free',heartbeat:{last_success_at:now.toISOString(),error:''},
      cloud_protection:{schema_version:1,state:'unavailable',checked_at:Date.now()/1000,guardrail_configured:true,guardrail_available:false,credit_status:'active',credits_per_usd:'100',reset_at:usage.resets_at}};
    await boot(page, {status,freeUsage:usage,guardrails:guardrailActivity(),usage:populatedUsage(),maxWindowHeight});
    await page.locator('#guardrails-tab').click();
    await expect(page.locator('#guardrails-panel #free-plan')).toHaveCount(0);
    await openSensorStatus(page, false);
    const card = page.locator('#free-plan');
    await expect(card).toContainText('43.21 of 200 credits used');
    await expect(card).not.toContainText('monthly');
    await expect(page.locator('#free-plan-reset')).toHaveText('Resets in 4 days, 16 hours');
    await expect(card).not.toContainText('Reserved');
    await expect(card).not.toContainText('Available');
    await expect(page.locator('#free-plan-details')).toBeHidden();
    expect(await page.locator('#free-plan-progress').evaluate(node => (node as HTMLProgressElement).position)).toBeCloseTo(43.21 / 200);
    expect(await page.locator('#health-card').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await page.locator('#app').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await expect(page.locator('#sensor-details')).not.toHaveAttribute('open', '');
    await page.screenshot({path:testInfo.outputPath(`free-plan-${maxWindowHeight}.png`),animations:'disabled'});
    await page.locator('#free-plan-toggle').click();
    await expect(page.locator('#free-plan-toggle')).toHaveAttribute('aria-expanded','true');
    const resetLabel = await page.evaluate(value => new Date(value).toLocaleString('en-US', {month:'short',day:'numeric',hour:'numeric',minute:'2-digit',timeZone:'UTC',timeZoneName:'short'}), usage.resets_at);
    await expect(page.locator('#free-plan-reset-at')).toContainText(resetLabel);
    await expect(page.locator('#free-plan-checked')).toBeVisible();
    await page.locator('#free-plan-refresh').focus();
    await page.locator('#free-plan-refresh').scrollIntoViewIfNeeded();
    await expect(page.locator('#free-plan-refresh')).toBeInViewport({ratio:1});
    for (const [hours,label] of [[49,'2 days, 1 hour'],[24,'1 day'],[8,'8 hours'],[1,'1 hour'],[0.5,'less than 1 hour']] as const) {
      await page.evaluate(({usage,hours}) => { (window as unknown as {mock:Mock}).mock.freeUsage = {...usage,resets_at:new Date(Date.now()+hours*3600000).toISOString()}; },{usage,hours});
      await page.locator('#free-plan-refresh').click();
      await expect(page.locator('#free-plan-reset')).toHaveText(`Resets in ${label}`);
    }
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.freeUsageError = 'Offline'; });
    await page.locator('#free-plan-refresh').click();
    await expect(card).toContainText('Usage unavailable');
    await expect(page.locator('#free-plan-data')).toBeHidden();
    await expect(page.locator('#free-plan-metadata')).toBeHidden();
    await page.evaluate(usage => {
      const mock = (window as unknown as {mock:Mock}).mock;
      mock.freeUsageError = undefined;
      mock.freeUsage = {...usage,status:'exhausted',used:'200',reserved:'0',available:'0'};
    }, usage);
    await page.locator('#free-plan-refresh').click();
    await expect(card).toContainText('200 of 200 credits used');
    await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.freeUsage = {...usage,status:'exhausted',reserved:'156.79',available:'0'}; }, usage);
    await page.locator('#free-plan-refresh').click();
    await expect(card).toContainText('43.21 of 200 credits used');
    expect(await page.locator('#free-plan-progress').evaluate(node => (node as HTMLProgressElement).position)).toBeCloseTo(43.21 / 200);
    await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.freeUsage = {...usage,
      starts_at:new Date(Date.UTC(new Date().getUTCFullYear(),new Date().getUTCMonth(),1)).toISOString(),
      resets_at:new Date(Date.UTC(new Date().getUTCFullYear(),new Date().getUTCMonth()+1,1)).toISOString()}; }, usage);
    await page.locator('#free-plan-refresh').click();
    await expect(card).toContainText('43.21 of 200 credits used');
    await expect(card).not.toContainText('weekly');
    await page.evaluate(usage => { (window as unknown as {mock:Mock}).mock.freeUsage = {...usage,used:'-1'}; }, usage);
    await page.locator('#free-plan-refresh').click();
    await expect(card).toContainText('Usage unavailable');
    await expect(page.locator('#free-plan-data')).toBeHidden();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.freeUsage = undefined; });
    await page.locator('#free-plan-refresh').click();
    await expect(card).toContainText('Credits are not enabled');
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.status.connection_mode = 'organization'; });
    await returnToWindow(page);
    await expect(page.locator('#credit-title')).toHaveText('Enterprise · Paid');
    await expect(page.locator('#free-plan-data')).toBeHidden();
    await page.keyboard.press('Escape');
    await page.locator('#guardrails-tab').click();
    const actionsBox = (await page.locator('.guardrail-summary').boundingBox())!;
    expect(actionsBox.width).toBeGreaterThan(500);
    await page.locator('#agent-reinstall').focus();
    await expect(page.locator('#agent-reinstall')).toBeInViewport({ratio:1});
  });
}

test('Connected credits discard an in-flight response after the connection changes', async ({page}) => {
  const now = new Date('2026-11-04T08:00:00Z');
  await page.clock.install({time:now});
  const status = {...converged,connection_mode:'api_key',heartbeat:{last_success_at:now.toISOString(),error:''}};
  const usage = {status:'active',used:'14.18',available:'985.82',starts_at:'2026-11-01T00:00:00Z',checked_at:now.toISOString()};
  await boot(page, {status,freeUsage:usage,creditPlan:'paid',pendingAction:'credits.summary'});
  await openSensorStatus(page, false);
  await expect.poll(async () => (await requests(page)).filter(row => row.action === 'credits.summary').length).toBe(1);
  await page.evaluate(usage => { const mock = (window as unknown as {mock:Mock}).mock;
    mock.status = {...mock.status,sensor_id:'replacement-sensor'}; mock.freeUsage = {...usage,used:'777',available:'223'};
  }, usage);
  await returnToWindow(page);
  await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
  await expect.poll(async () => (await requests(page)).filter(row => row.action === 'credits.summary').length).toBe(2);
  await expect(page.locator('#free-plan-data')).toBeHidden();
  await expect(page.locator('#free-plan-message')).toHaveText('Loading credit usage…');
  await expect(page.locator('#free-plan-details')).toBeHidden();
  await page.evaluate(() => { const win = window as unknown as {mock:Mock;completeRequest:() => void}; win.mock.pendingAction = undefined; win.completeRequest(); });
  await expect(page.locator('#free-plan-total')).toHaveText('777/223 credits used/available');
});

for (const maxWindowHeight of [720, 320]) {
  for (const variant of [
    {name:'personal-paid', mode:'api_key', plan:'paid', title:'Personal · Paid', used:'14.18', available:'985.82'},
    {name:'enterprise-free', mode:'organization', plan:'free', title:'Enterprise · Free', used:'14.18', available:'185.82'},
    {name:'enterprise-paid', mode:'organization', plan:'paid', title:'Enterprise · Paid', used:'139.50', available:'24860.50'},
  ] as const) test(`Connected ${variant.name} credits fit in a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const now = new Date('2026-11-04T08:00:00Z');
    await page.clock.install({time:now});
    await page.emulateMedia({colorScheme:maxWindowHeight === 720 ? 'light' : 'dark'});
    const free = variant.plan === 'free', enterprise = variant.mode === 'organization';
    const usage = {status:'active',used:variant.used,available:variant.available,checked_at:now.toISOString(),
      starts_at:'2026-11-01T00:00:00Z',...(free ? {allowance:'200',reserved:'0',resets_at:'2026-11-09T00:00:00Z'} : {})};
    const status = {...converged,connection_mode:variant.mode,tenant_name:'Acme',heartbeat:{last_success_at:now.toISOString(),error:''},
      activity:{queue_depth:0},telemetry:{...converged.telemetry,received:1232,forwarded:1232,queue_depth:0}};
    await boot(page, {status,freeUsage:usage,creditPlan:variant.plan,guardrails:guardrailActivity(),usage:populatedUsage(),maxWindowHeight});
    await page.locator('#guardrails-tab').click();
    await expect(page.locator('#guardrails-panel #free-plan')).toHaveCount(0);
    await openSensorStatus(page, false);
    const panel = page.locator('#health-card');
    await expect(page.locator('#credit-title')).toHaveText(variant.title);
    await expect(page.locator('#free-plan-total')).toHaveText(free ? '14.18 of 200 credits used' : `${Number(variant.used).toLocaleString('en-US')}/${Number(variant.available).toLocaleString('en-US')} credits used/available`);
    await expect(page.locator('#health-description')).toBeHidden();
    await expect(page.locator('#sensor-details')).not.toHaveAttribute('open', '');
    await expect(page.locator('#free-plan-details')).toBeHidden();
    await expect(panel.getByText('Last successful contact', {exact:true})).toHaveCount(0);
    await expect(panel.getByText('Cloud guardrails', {exact:true})).toHaveCount(0);
    if (enterprise) {
      await expect(page.locator('#credit-owner')).toHaveText('Acme · Shared organization credits');
      await page.locator('#dashboard-link').click();
      expect((await requests(page)).filter(row => row.action === 'desktop.dashboard')).toHaveLength(1);
    } else await expect(page.locator('#dashboard-link')).toHaveCount(0);
    if (!free) {
      await expect(page.locator('#free-plan-progress')).toBeHidden();
      await expect(page.locator('#free-plan-reset')).toBeHidden();
      const rows = await page.locator('#free-plan-total').evaluate(node => Array.from(node.children).map(child => {
        const range = document.createRange(); range.selectNodeContents(child);
        return Array.from(range.getClientRects()).map(box => ({top:box.top,bottom:box.bottom}));
      }));
      expect(rows.every(rects => rects.length === 1)).toBe(true);
      expect(Math.min(...rows.map(rects => rects[0].bottom))).toBeGreaterThan(Math.max(...rows.map(rects => rects[0].top)));
      await expect(page.locator('#free-plan-total')).toHaveAccessibleName(/credits used this month \(UTC\);.*credits available/);
    }
    expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await expect(panel).toBeInViewport({ratio:1});
    await page.screenshot({path:testInfo.outputPath(`${variant.name}-${maxWindowHeight}.png`),animations:'disabled'});
    await page.locator('#free-plan-toggle').click();
    await page.locator('#free-plan-refresh').focus();
    await expect(page.locator('#free-plan-refresh')).toBeInViewport({ratio:1});
    if (!free) await expect(page.locator('#free-plan-period')).toContainText('Used this month (UTC)');
    await page.locator('#sensor-details summary').focus();
    await page.keyboard.press('Enter');
    await page.locator('#counter-note').scrollIntoViewIfNeeded();
    await expect(page.locator('#counter-note')).toBeInViewport({ratio:1});
    await expect(page.locator('#delivery')).toHaveText('1,232');
    await page.locator('#free-plan-refresh').click();
    await page.locator('#sensor-details summary').click();
    await page.locator('#free-plan-toggle').click();
    await expect(page.locator('#free-plan-details')).toBeHidden();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.freeUsageError = 'Offline'; });
    await page.clock.runFor(60001);
    await expect(page.locator('#free-plan-data')).toBeHidden();
    await expect(page.locator('#free-plan-message')).toContainText('Usage unavailable');
    await expect(page.locator('#free-plan-details')).toBeVisible();
    await expect(page.locator('#free-plan-toggle')).toHaveAttribute('aria-expanded', 'true');
    await page.locator('#free-plan-refresh').focus();
    await expect(page.locator('#free-plan-refresh')).toBeInViewport({ratio:1});
    expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.screenshot({path:testInfo.outputPath(`credit-recovery-${variant.name}-${maxWindowHeight}.png`),animations:'disabled'});
    await page.evaluate(usage => { const mock = (window as unknown as {mock:Mock}).mock;
      mock.freeUsageError = ''; mock.freeUsage = {...usage,checked_at:new Date().toISOString()};
      mock.creditIdentity = {sensor_id:'another-sensor',server_url:mock.status.server_url!};
    }, usage);
    await page.locator('#free-plan-refresh').click();
    await expect(page.locator('#free-plan-data')).toBeHidden();
    await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.creditIdentity = undefined; });
    await page.locator('#free-plan-refresh').click();
    await expect(page.locator('#free-plan-data')).toBeVisible();
    await page.locator('#free-plan-toggle').click();
    await expect(page.locator('#free-plan-details')).toBeHidden();
    await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.pendingAction = 'credits.summary'; });
    await page.clock.runFor(180001);
    await expect(page.locator('#free-plan-message')).toHaveText('Usage unavailable. Refresh to check your current balance.');
    await expect(page.locator('#free-plan-details')).toBeVisible();
    await expect(page.locator('#free-plan-toggle')).toHaveAttribute('aria-expanded', 'true');
    await page.evaluate(() => { const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = undefined; win.mock.freeUsage = {...win.mock.freeUsage,checked_at:new Date().toISOString()}; win.completeRequest();
    });
    await expect(page.locator('#free-plan-refresh')).toBeEnabled();
    await page.locator('#free-plan-refresh').focus();
    await expect(page.locator('#free-plan-refresh')).toBeInViewport({ratio:1});
    await page.locator('#free-plan-refresh').click();
    await expect(page.locator('#free-plan-data')).toBeVisible();
    if (!free) {
      await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.freeUsage = {...mock.freeUsage,used:'1234567.89',available:'8765432.11',checked_at:new Date().toISOString()}; });
      await page.locator('#free-plan-refresh').click();
      await expect(page.locator('#free-plan-total')).toHaveText('1.23M/8.77M credits used/available');
      await expect(page.locator('#free-plan-total')).toHaveAccessibleName('1,234,567.89 credits used this month (UTC); 8,765,432.11 credits available');
      expect(await panel.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      await page.clock.setSystemTime(new Date('2026-12-01T00:00:01Z'));
      await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.freeUsage = {...mock.freeUsage,checked_at:'2026-11-30T23:59:59Z'}; });
      await page.locator('#free-plan-refresh').click();
      await expect(page.locator('#free-plan-data')).toBeHidden();
    }
    await page.keyboard.press('Escape');
    const count = (await requests(page)).filter(row => row.action === 'credits.summary').length;
    await page.clock.runFor(120000);
    expect((await requests(page)).filter(row => row.action === 'credits.summary')).toHaveLength(count);
  });
}

for (const maxWindowHeight of [720,320]) {
  test(`local runtime setup fits a ${maxWindowHeight}px work area and connects without a link`, async ({page}, testInfo) => {
    await boot(page, {status:unenrolled,maxWindowHeight,pendingAction:'local-runtime.prepare',afterEnroll:{...converged,server_url:'http://localhost:8080'}});
    const cards = await page.locator('.connection-option').evaluateAll(nodes => nodes.map(node => {
      const {x,y,width,height} = node.getBoundingClientRect(); return {x,y,width,height};
    }));
    expect(cards[0].y).toBe(cards[1].y);
    expect(cards[0].width).toBe(cards[1].width);
    expect(cards[0].height).toBe(cards[1].height);
    expect(cards[0].x + cards[0].width).toBeLessThan(cards[1].x);
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
    await expect(page.locator('#health-card')).toBeHidden();
    await page.screenshot({path:testInfo.outputPath('local-runtime-options.png')});
    await page.getByRole('button',{name:'Set up local runtime'}).click();
    await expect(page.getByText('Installed and running',{exact:true})).toBeVisible();
    await expectControlHierarchy(page);
    await expect(page.locator('#local-message')).toContainText('Preparing the runtime');
    await expect(page.locator('#local-start')).toBeHidden();
    await expect(page.locator('#local-back')).toBeDisabled();
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = ''; win.completeRequest();
    });
    await expect(page.getByRole('heading',{name:'Your local runtime is connected'})).toBeVisible();
    await expect(page.locator('#local-runtime-view')).toContainText('Restart running coding-agent sessions');
    await expectControlHierarchy(page);
    expect((await requests(page)).filter(item => item.action.startsWith('local-runtime.')).map(item => item.action)).toEqual([
      'local-runtime.check','local-runtime.prepare','local-runtime.start','local-runtime.connect','local-runtime.check',
    ]);
    expect((await requests(page)).some(item => item.action === 'enrollment.connect')).toBe(false);
    expect((await requests(page)).some(item => item.action === 'local-runtime.credentials')).toBe(false);
    const executable = testInfo.outputPath('dashboard-handoff');
    execFileSync('rustc', ['--edition=2021', 'tests/local-dashboard-handoff.rs', '-o', executable]);
    const session = 'oass_' + 'a'.repeat(43);
    const backend = createServer((request,response) => {
      response.setHeader('Content-Type', 'text/plain');
      response.end(request.headers.cookie === `openaidr_session=${session}` ? 'Local dashboard' : 'Sign in required');
    });
    backend.listen(0, '127.0.0.1');
    await once(backend, 'listening');
    const port = (backend.address() as {port:number}).port;
    const origin = `http://localhost:${port}/`;
    const native = spawn(executable, [String(port)]);
    try {
      const [output] = await once(native.stdout, 'data');
      const handoff = output.toString().trim();
      expect(handoff).not.toContain(session);
      await page.evaluate(handoff => { (window as unknown as {mock:Mock}).mock.dashboardHandoff = handoff; }, handoff);
      await page.exposeFunction('openNativeDashboard', async (url:string) => {
        const browserPage = await page.context().newPage();
        await browserPage.goto(url);
      });
      const popup = page.context().waitForEvent('page');
      await page.getByRole('button',{name:'Open dashboard',exact:true}).click();
      const dashboard = await popup;
      await expect(dashboard).toHaveURL(origin);
      await expect(dashboard.getByText('Local dashboard',{exact:true})).toBeVisible();
      expect(await dashboard.evaluate(() => document.cookie)).toBe('');
      const cookies = await page.context().cookies(origin);
      expect(cookies.find(cookie => cookie.name === 'openaidr_session')).toMatchObject({httpOnly:true,sameSite:'Lax',path:'/'});
      await dashboard.close();
    } finally { native.kill(); backend.close(); }
    expect((await requests(page)).at(-1)?.action).toBe('desktop.dashboard');
    await page.getByRole('button',{name:'Show dashboard sign-in'}).click();
    await expect(page.locator('#local-sign-in')).toContainText('sample-password-only');
    await page.getByRole('button',{name:'Hide dashboard sign-in'}).click();
    await expect(page.locator('#local-sign-in')).toBeEmpty();
    await page.locator('#local-done').click();
    await expect(page.locator('#local-runtime-view')).toBeHidden();
  });
}

for (const dockerAction of ['install','start'] as const) {
for (const maxWindowHeight of [720,320]) {
  test(`local runtime automatically runs Docker ${dockerAction} within a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    await boot(page, {status:unenrolled,maxWindowHeight,pendingAction:'local-runtime.docker-setup',
      localRuntime:{docker_ready:false,docker_action:dockerAction,existing:false,managed:false,connected:false,server_url:'http://localhost:8080'}});
    await page.getByRole('button',{name:'Set up local runtime'}).click();
    await expect(page.locator('#local-message')).toContainText(dockerAction === 'install' ? 'Approve the macOS prompt' : 'Starting Docker');
    await expect(page.locator('#local-start')).toBeHidden();
    await expect(page.locator('#local-check')).toBeHidden();
    await expect(page.locator('#local-back')).toBeDisabled();
    const progress = page.locator('#local-progress');
    await expect(progress.locator('.active')).toHaveText('Prepare Docker');
    const app = page.locator('#app');
    await expect.poll(() => app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (maxWindowHeight === 720) {
      await expect.poll(() => app.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
      await expect(progress).toBeInViewport({ratio:1});
    } else {
      await expect.poll(() => app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await progress.scrollIntoViewIfNeeded();
      await expect(progress).toBeInViewport({ratio:1});
    }
    await page.screenshot({path:testInfo.outputPath(`docker-${dockerAction}.png`)});
    expect((await requests(page)).some(item => item.action === 'local-runtime.prepare')).toBe(false);
    await returnToWindow(page);
    expect((await requests(page)).filter(item => item.action === 'local-runtime.docker-setup')).toHaveLength(1);
    await page.evaluate(() => {
      const win = window as unknown as {mock:Mock;completeRequest:() => void};
      win.mock.pendingAction = ''; win.completeRequest();
    });
    await expect(page.getByRole('heading',{name:'Your local runtime is connected'})).toBeVisible();
    expect((await requests(page)).filter(item => item.action.startsWith('local-runtime.') || item.action === 'setup').map(item => item.action)).toEqual([
      'local-runtime.check','local-runtime.docker-setup','local-runtime.prepare','local-runtime.start','local-runtime.connect','setup','local-runtime.check',
    ]);
    await page.getByRole('button',{name:'Open dashboard',exact:true}).scrollIntoViewIfNeeded();
    await expect(page.getByRole('button',{name:'Open dashboard',exact:true})).toBeInViewport({ratio:1});
  });
}
}

test('local runtime retries Docker setup and requests authorization for an existing runtime', async ({page}) => {
  await boot(page, {status:unenrolled,localDockerError:'Docker setup was cancelled. Retry setup to continue.',
    localRuntime:{docker_ready:false,docker_action:'start',existing:false,managed:false,connected:false,server_url:'http://localhost:8080'}});
  await page.getByRole('button',{name:'Set up local runtime'}).click();
  const start = page.getByRole('button',{name:'Retry setup',exact:true});
  await expect(page.locator('#local-message')).toContainText('Docker setup was cancelled');
  await expect(start).toBeEnabled();
  expect((await requests(page)).some(item => item.action === 'local-runtime.prepare' || item.action === 'local-runtime.connect')).toBe(false);
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.localDockerError = ''; mock.localRuntime!.existing = true;
  });
  await start.click();
  await expect(page.getByLabel('Local administrator password')).toBeFocused();
  await expect(page.getByRole('button',{name:'Connect this device'})).toBeDisabled();
  expect((await requests(page)).some(item => item.action === 'local-runtime.connect')).toBe(false);
  await page.getByLabel('Local administrator password').fill('existing-runtime-password');
  await page.getByRole('button',{name:'Connect this device'}).click();
  await expect(page.getByRole('heading',{name:'Your local runtime is connected'})).toBeVisible();
  expect((await requests(page)).some(item => item.action === 'local-runtime.prepare')).toBe(false);
  expect((await requests(page)).filter(item => item.action === 'local-runtime.connect')).toEqual([
    {action:'local-runtime.connect',password:'existing-runtime-password'},
  ]);
  expect(await page.locator('body').textContent()).not.toContain('existing-runtime-password');
});

test('local runtime prerequisites and a failed setup can be retried', async ({page}) => {
  const localRuntime = {docker_ready:false,existing:false,managed:false,connected:false,server_url:'http://localhost:8080'};
  await boot(page, {status:unenrolled,localRuntime,localRuntimeError:'Docker stopped. Saved data is kept.'});
  await page.getByRole('button',{name:'Set up local runtime'}).click();
  await expect(page.getByRole('button',{name:'Check again'})).toBeEnabled();
  await expect(page.locator('#local-start')).toBeHidden();
  expect((await requests(page)).filter(item => item.action.startsWith('local-runtime.')).map(item => item.action)).toEqual(['local-runtime.check']);
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.localRuntime!.docker_ready = true; });
  await page.getByRole('button',{name:'Check again'}).click();
  await expect(page.locator('#local-message')).toHaveText('Docker stopped. Saved data is kept.');
  await expect(page.getByRole('button',{name:'Retry setup',exact:true})).toBeEnabled();
  expect((await requests(page)).some(item => item.action === 'local-runtime.connect')).toBe(false);
  await page.locator('#local-back').click();
  await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.localRuntime!.existing = true; mock.localRuntimeError = ''; });
  await page.getByRole('button',{name:'Set up local runtime'}).click();
  await expect(page.getByRole('button',{name:'Connect this device'})).toBeDisabled();
  await page.getByLabel('Local administrator password').fill('existing-runtime-password');
  await expect(page.getByRole('button',{name:'Connect this device'})).toBeEnabled();
  expect((await requests(page)).some(item => item.action === 'local-runtime.connect')).toBe(false);
  await page.getByRole('button',{name:'Connect this device'}).click();
  await expect(page.getByRole('heading',{name:'Your local runtime is connected'})).toBeVisible();
});

for (const state of ['pending','complete']) for (const maxWindowHeight of [720,320]) {
  test(`uninstall from local runtime setup shows ${state} removal at ${maxWindowHeight}px`, async ({page}, testInfo) => {
    const error = 'The sensor is still stopping. Retry removal shortly.';
    await boot(page, {status:unenrolled,maxWindowHeight,pendingAction:'desktop.remove',
      localRuntime:{docker_ready:false,existing:false,managed:false,connected:false,server_url:'http://localhost:8080'},
      afterRemove:{desktop_removal:{state,errors:state === 'pending' ? [error] : [],retained_data:'/Users/example/Library/Application Support/OpenAIDR/data'}}});
    await page.getByRole('button',{name:'Set up local runtime'}).click();
    await expect(page.locator('#local-start')).toBeDisabled();
    await page.getByRole('button',{name:'Uninstall',exact:true}).click();
    const dialog = page.getByRole('dialog',{name:'Uninstall OpenAIDR?'});
    await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
    await expect(page.locator('#local-runtime-view')).toBeVisible();
    expect((await requests(page)).some(item => item.action === 'desktop.remove')).toBe(false);
    await page.getByRole('button',{name:'Uninstall',exact:true}).click();
    await dialog.getByRole('button',{name:'Uninstall OpenAIDR',exact:true}).click();
    await expect(dialog.locator('#confirm-remove')).toHaveText('Uninstalling…');
    await page.evaluate(() => (window as unknown as {completeRequest:() => void}).completeRequest());
    await expect(dialog).toBeHidden();
    await expect(page.locator('#local-runtime-view')).toBeHidden();
    await expect(page.locator('#connect-card')).toBeHidden();
    await expect(page.locator('#health-title')).toHaveText(state === 'complete' ? 'Background services stopped.' : 'Removal needs attention');
    if (state === 'pending') {
      await expect(page.getByRole('region',{name:'Removal errors'})).toHaveText(error);
      await expect(page.locator('#trash-app')).toBeHidden();
    }
    const action = page.getByRole('button',{name:state === 'complete' ? 'Move app to Trash' : 'Retry uninstall',exact:true});
    if (maxWindowHeight === 720) await expectFitsWindow(page);
    else {
      const app = page.locator('#app');
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      await action.scrollIntoViewIfNeeded();
    }
    await expect(action).toBeInViewport({ratio:1});
    await expect(action).toBeEnabled();
    await page.screenshot({path:testInfo.outputPath('local-runtime-removal.png')});
    await returnToWindow(page);
    await expect(page.locator('#local-runtime-view')).toBeHidden();
    expect((await requests(page)).filter(item => item.action === 'desktop.remove')).toHaveLength(1);
    expect((await requests(page)).some(item => ['setup','local-runtime.prepare','local-runtime.connect'].includes(item.action))).toBe(false);
    if (state === 'complete') {
      await action.click();
      expect((await requests(page)).filter(item => item.action === 'desktop.trash')).toEqual([{action:'desktop.trash'}]);
    }
  });
}

test('closing Settings dismisses local setup and permits opening it again', async ({page}) => {
  await boot(page, {status:converged});
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByRole('button',{name:'Set up local runtime'}).click();
  await expect(page.getByRole('heading',{name:'Your local runtime is connected'})).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#connection-dialog')).not.toBeVisible();
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await expect(page.locator('.connection-option').first()).toBeVisible();
  await expect(page.locator('#local-runtime-view')).toBeHidden();
});

function postureFixture(local = false) {
  const item = (id:string,name:string,kind:string,attention = false) => ({id,name,kind,source:'Organization inventory',path:`/Users/example/Projects/website/${id}`,
    version:'1.2.3' as string|null,publisher:'Publisher' as string|null,scope:'User',last_seen_at:'2026-11-04T19:51:00Z',root_status:'ok',product:null as string|null,attention,
    approval_status:attention ? 'unapproved' : 'approved',assessment_status:'complete',findings:attention ? [{title:'Review changed configuration',detail:'The installed configuration differs from the previously reviewed version.'}] : [],findings_truncated:false,metadata:{} as Record<string,unknown>});
  const apps = [item('cursor','Cursor','AI editor',true),item('codex','Codex','Coding agent'),item('claude','Claude Code','Coding agent'),item('hermes','Hermes','AI agent')];
  apps.forEach((asset,i) => { asset.product = ['cursor','codex','claude-code','hermes'][i]; asset.findings = []; asset.assessment_status = 'unsupported'; });
  const components = ['Filesystem MCP','GitHub MCP','Playwright MCP','Context7 MCP','Linear MCP','Slack MCP','Git tools'].map((name,i) => ({...item(`component-${i}`,name,'MCP server'),approval_status:'unavailable',assessment_status:'unsupported'}));
  components.push({...item('example-parser','Example parser','Package',true),approval_status:'unavailable',findings:[{title:'Dependency advisory reported',detail:'The installed version matches a retained advisory.'}]});
  const skills = ['deploy-preview','code-review','test-runner','frontend-design','release-notes','commit-helper','api-docs','debugging'].map((name,i) => item(name,name,'Skill',i === 0));
  if (local) {
    for (const asset of [...apps,...components,...skills]) {
      asset.source = 'Local inventory'; asset.approval_status = 'unavailable'; asset.attention = false; asset.findings = [];
      if (asset.kind === 'Package' || asset.kind === 'Skill') asset.assessment_status = 'disabled';
    }
    skills[0].root_status = 'partial'; skills[0].attention = true;
  }
  return {supported:true,schema_version:1,...(local ? {source:'local'} : {}),assessments:local ? {enabled:false,state:'disabled',billing:{status:'active',available:'162.47',reserved:'0.5',used:'37.53',resets_at:'2026-12-01T00:00:00Z',checked_at:'2026-11-04T19:50:00Z'},usage:{credits_charged:'4.02',credits_reserved:'0.01',unknown_attempts:1}} : undefined,collected_at:'2026-11-04T19:50:00Z',groups:{apps:{items:apps,total:apps.length,truncated:false},components:{items:components,total:components.length,truncated:false},skills:{items:skills,total:skills.length,truncated:false}},coverage:{status:local ? 'partial' : 'complete',sources:[{source:'AI inventory',status:local ? 'partial' : 'ok',collected_at:'2026-11-04T19:50:00Z',message:local ? 'Some skill files could not be read.' : ''}]}};
}

test('Posture navigates real app pages, searches loaded assets, and preserves finding text', async ({page}) => {
  await page.clock.install();
  const posture = postureFixture();
  const evidence = '<img src=x onerror="window.postureInjected=true">';
  posture.groups.skills.items[0].findings = [{title:'Changed instructions',detail:evidence}];
  posture.groups.skills.items[0].findings_truncated = true;
  posture.groups.skills.items[0].metadata = {source_url:'javascript:alert(1)',description:evidence};
  await boot(page,{status:guardrailStatus(),posture});
  expect((await requests(page)).some(request => request.action === 'posture.summary')).toBe(false);
  await page.getByRole('tab',{name:'Usage',exact:true}).focus(); await page.keyboard.press('End');
  await expect(page.getByRole('tab',{name:'Posture',exact:true})).toBeFocused();
  await expect(page.locator('.posture-stat strong')).toHaveText(['4','8','8']);
  await expect(page.locator('#posture-attention .posture-row-copy small')).toHaveText(['Awaiting review','Dependency advisory reported','Changed instructions']);
  await expect(page.locator('#posture-configure')).toBeHidden();
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.locator('.posture-stat strong')).toHaveText(['4','8','8']);
  for (const tab of ['apps','components','skills','overview']) {
    await page.locator(`#posture-${tab}-tab`).click();
    await expect(page.locator(`#posture-${tab}-tab`)).toHaveAttribute('aria-selected','true');
  }
  await page.getByRole('button',{name:'View AI Apps',exact:true}).click();
  await expect(page.locator('#posture-rows .posture-row')).toHaveCount(4);
  await expect(page.getByRole('searchbox')).toHaveAttribute('placeholder','Search apps');
  await expect(page.locator('#posture-rows .posture-row-copy small').first()).toHaveText('1.2.3 · Publisher');
  await page.locator('#posture-rows .posture-row').first().click();
  await expect(page.locator('.posture-facts')).toContainText('KindAI editor');
  await expect(page.locator('.posture-facts')).toContainText('SourceOrganization inventory');
  await expect(page.locator('.posture-facts')).toContainText('Version1.2.3');
  await page.getByRole('button',{name:'Close asset details'}).click();
  await page.getByRole('checkbox',{name:'Needs attention',exact:true}).check();
  await expect(page.locator('#posture-rows .posture-row')).toHaveCount(1);
  await page.getByRole('checkbox',{name:'Needs attention',exact:true}).uncheck();
  await page.getByRole('searchbox',{name:'Search loaded assets'}).fill('codex');
  await expect(page.locator('#posture-rows .posture-row')).toHaveCount(1);
  await page.getByRole('searchbox',{name:'Search loaded assets'}).fill('no-match');
  await expect(page.locator('#posture-rows')).toContainText('No matching assets');
  await page.getByRole('tab',{name:'Supply Chain',exact:true}).click();
  await expect(page.getByRole('searchbox')).toHaveAttribute('placeholder','Search components');
  await expect(page.locator('#posture-rows .posture-row-copy small').first()).toHaveText('MCP server · 1.2.3 · Publisher');
  await expect(page.locator('#posture-rows .posture-badge')).toHaveText(Array(6).fill('Not assessed'));
  await page.getByRole('button',{name:'Next asset page'}).click();
  await expect(page.locator('#posture-result')).toHaveText('7–8 of 8 components');
  await page.getByRole('button',{name:'Previous asset page'}).click();
  await expect(page.locator('#posture-result')).toHaveText('1–6 of 8 components');
  await page.getByRole('button',{name:'Next asset page'}).click();
  await page.getByRole('button',{name:/Example parser/}).click();
  await expect(page.getByRole('dialog')).toContainText('1 finding');
  await expect(page.getByRole('dialog')).toContainText('Assessment: Complete');
  await page.getByRole('button',{name:'Close asset details'}).click();
  await page.getByRole('tab',{name:'AI Skills',exact:true}).click();
  await expect(page.getByRole('searchbox')).toHaveAttribute('placeholder','Search skills');
  await expect(page.locator('#posture-rows .posture-row-copy small').first()).toHaveText('1.2.3 · Publisher');
  await page.locator('#posture-rows .posture-row').first().click();
  await expect(page.getByRole('dialog',{name:'deploy-preview'})).toContainText(evidence);
  await expect(page.getByRole('dialog')).toContainText('Additional findings are available in the dashboard.');
  await expect(page.getByRole('dialog').locator('a, img')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as {postureInjected?:boolean}).postureInjected)).toBeUndefined();
  await page.locator('#posture-done').click();
  await expect(page.locator('#posture-rows .posture-row').first()).toBeFocused();
  await page.locator('#posture-rows .posture-row').first().click();
  await page.evaluate(async () => {
    const dialog = document.getElementById('posture-detail') as HTMLDialogElement;
    const closed = new Promise<void>(resolve => dialog.addEventListener('close',() => resolve(),{once:true}));
    dialog.close(); document.getElementById('posture-tab')!.focus();
    await closed;
  });
  await expect(page.getByRole('tab',{name:'Posture',exact:true})).toBeFocused();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab',{name:'Usage',exact:true})).toBeFocused();
  const reads = (await requests(page)).filter(request => request.action === 'posture.summary').length;
  await page.clock.runFor(31000);
  expect((await requests(page)).filter(request => request.action === 'posture.summary')).toHaveLength(reads);
});

for (const local of [false,true]) for (const colorScheme of ['light','dark'] as const) for (const maxWindowHeight of [720,320]) {
  test(`Posture layout fits ${colorScheme} at ${maxWindowHeight}px with populated ${local ? 'local' : 'organization'} inventory`, async ({page},testInfo) => {
    await page.emulateMedia({colorScheme});
    const posture = postureFixture(local);
    if (!local) {
      const apps = posture.groups.apps.items;
      posture.groups.apps = {items:Array.from({length:7},(_,i) => ({...apps[i%apps.length],id:`app-${i}`,attention:true,approval_status:'approved'})),total:7,truncated:false};
      const component = posture.groups.components.items[0];
      posture.groups.components = {items:Array.from({length:200},(_,i) => ({...component,id:`component-${i}`,name:`${component.name} ${i+1}`,attention:true})),total:474,truncated:true};
      const skill = {...posture.groups.skills.items[0],version:null,publisher:null,source:'openaidr-skills'};
      posture.groups.skills = {items:Array.from({length:159},(_,i) => ({...skill,id:`skill-${i}`,name:i ? `code-review-${i}` : skill.name})),total:159,truncated:false};
      posture.coverage.status = 'partial'; posture.coverage.sources[0].status = 'partial';
      posture.coverage.sources[0].message = 'Some inventory sources could not be read.';
    }
    posture.groups.skills.items[0].path = '/Users/example/Projects/customer-website/.claude/skills/deploy-preview/SKILL.md';
    await boot(page,{status:local ? freeStatus() : guardrailStatus(),posture,maxWindowHeight});
    await page.getByRole('tab',{name:'Posture',exact:true}).click();
    await expect(page.locator('.posture-stat')).toHaveCount(3);
    const app = page.locator('#app');
    for (const name of ['Overview','AI Apps','Supply Chain','AI Skills']) {
      await page.getByRole('tab',{name,exact:true}).click();
      await expect(page.locator('.posture-heading p')).toHaveCount(0);
      if (name === 'Overview' && !local) {
        await expect(page.locator('.posture-stat strong')).toHaveText(['7','474','159']);
        await expect(page.locator('#posture-attention-count')).toHaveText('366 loaded');
        await expect(page.locator('#posture-attention .posture-row-copy small')).toHaveCount(0);
      }
      if (local && name === 'Overview') {
        await page.getByRole('button',{name:'Enable automatic checks'}).scrollIntoViewIfNeeded();
        await expect(page.getByRole('button',{name:'Enable automatic checks'})).toBeInViewport({ratio:1});
        await expect(page.locator('#posture-checks')).toContainText('162.47 credits');
      }
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await page.locator('#posture-page *').evaluateAll(nodes => nodes.filter(node => {
        const bounds = node.getBoundingClientRect(); return bounds.width && bounds.height && (bounds.left < 0 || bounds.right > innerWidth || node.scrollWidth > node.clientWidth+1);
      }).map(node => node.id || node.className))).toEqual([]);
      if (maxWindowHeight === 720) {
        await expect(page.locator('#status-footer')).toBeInViewport({ratio:1});
        expect(await app.evaluate(node => node.scrollHeight <= node.clientHeight+1)).toBe(true);
        if (!local) expect(await page.locator('main').evaluate(node => node.getBoundingClientRect().height)).toBeLessThanOrEqual(name === 'Overview' ? 580 : 640);
        await page.screenshot({path:testInfo.outputPath(`posture-${name.replaceAll(' ','-')}-${colorScheme}.png`),animations:'disabled'});
      } else {
        if (name !== 'Overview') {
          const next = page.getByRole('button',{name:'Next asset page'});
          await next.scrollIntoViewIfNeeded();
          await expect(next).toBeInViewport({ratio:1});
          if (name === 'AI Apps' && local) await expect(next).toBeDisabled();
          else {
            await next.click();
            await expect(page.locator('#posture-page-number')).toContainText('2 /');
            await page.getByRole('button',{name:'Previous asset page'}).click();
          }
        }
        await page.locator('#show-about').scrollIntoViewIfNeeded();
        await expect(page.locator('#show-about')).toBeInViewport({ratio:1});
        expect(await app.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
      }
      if (name === 'Overview') {
        const summary = page.locator('#posture-coverage-details summary');
        await summary.scrollIntoViewIfNeeded();
        await expect(summary).toBeInViewport({ratio:1});
        if (!local) {
          await expect(summary).toContainText('Supply Chain: 200 of 474 loaded');
          await expect(summary).toHaveAccessibleDescription('Collection incomplete Supply Chain: 200 of 474 loaded');
        }
        await expect(page.locator('#posture-collected')).toBeHidden();
        await summary.focus(); await page.keyboard.press('Enter');
        await expect(page.locator('#posture-collected')).toBeVisible();
        await expect(page.locator('#posture-sources')).toContainText(local ? 'Some skill files could not be read.' : 'Some inventory sources could not be read.');
        await page.locator('#posture-sources').scrollIntoViewIfNeeded();
        await expect(page.locator('#posture-sources')).toBeInViewport({ratio:1});
        expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        await summary.focus(); await page.keyboard.press('Enter');
        await expect(page.locator('#posture-sources')).toBeHidden();
      } else if (!local) {
        await expect(page.locator('#posture-loaded')).toHaveText('Supply Chain: 200 of 474 loaded');
        if (name === 'Supply Chain') await expect(page.locator('#posture-result')).toHaveText('1–6 of 200 loaded components');
        if (name === 'AI Skills') {
          await expect(page.locator('#posture-result')).toHaveText('1–6 of 159 skills');
          await expect(page.locator('#posture-rows .posture-row-copy small').first()).toHaveText('openaidr-skills');
        }
      }
    }
    await page.locator('#posture-rows .posture-row').first().click();
    const dialog = page.getByRole('dialog',{name:'deploy-preview'});
    await expect(dialog).toBeInViewport({ratio:1});
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.getByRole('button',{name:'Done',exact:true}).focus();
    await expect(page.getByRole('button',{name:'Done',exact:true})).toBeInViewport({ratio:1});
    await page.keyboard.press('Enter'); await expect(dialog).toBeHidden();
    expect(await page.locator('#posture-page img').evaluateAll(images => images.every(image => image.complete && image.naturalWidth > 0))).toBe(true);
  });
}

for (const connection_mode of ['free','api_key']) {
  test(`Posture shows local inventory for offline ${connection_mode} connections without organization reviews`, async ({page}) => {
    const status = {...freeStatus(),connection_mode,heartbeat:{last_success_at:'2026-11-01T00:00:00Z',error:'Cloud unavailable'},cloud_protection:null};
    await boot(page,{status,posture:postureFixture(true)});
    await page.getByRole('tab',{name:'Posture',exact:true}).click();
    await expect(page.locator('.posture-stat strong')).toHaveText(['4','8','8']);
    await expect(page.locator('#posture-note')).toContainText('Collection alone does not assess security.');
    for (const [name,label] of [['AI Apps','Not assessed'],['Supply Chain','Not assessed'],['AI Skills','Disabled']]) {
      await page.getByRole('tab',{name,exact:true}).click();
      await expect(page.locator('#posture-review-column')).toHaveText('Assessment');
      await expect(page.locator('#posture-rows .posture-badge').first()).toHaveText(label);
      await page.locator('#posture-rows .posture-row').first().click();
      await expect(page.getByRole('dialog')).toContainText(`Assessment: ${label}`);
      await expect(page.getByRole('dialog')).not.toContainText(/organization|administrator|dashboard/i);
      await page.getByRole('button',{name:'Done',exact:true}).click();
    }
    await page.getByRole('button',{name:'Refresh',exact:true}).click();
    await expect(page.locator('#posture-content')).toBeVisible();
    expect((await requests(page)).filter(row => row.action.startsWith('posture.'))).toEqual([{action:'posture.summary'},{action:'posture.summary'}]);
  });
}

test('Posture distinguishes truncated, partial, empty, unavailable, and failed data', async ({page}) => {
  const posture = postureFixture(); posture.groups.apps.total = 250; posture.groups.apps.truncated = true;
  posture.coverage.status = 'partial'; posture.coverage.sources[0].status = 'error'; posture.coverage.sources[0].message = 'A source could not be read.';
  await boot(page,{status:guardrailStatus(),posture});
  await page.getByRole('tab',{name:'Posture',exact:true}).click();
  await expect(page.locator('#posture-note')).toContainText('AI Apps: 4 of 250 loaded');
  await expect(page.locator('#posture-attention-count')).toHaveText('3 loaded');
  await expect(page.locator('#posture-coverage-title')).toHaveText('Collection incomplete');
  await expect(page.locator('#posture-loaded')).toBeVisible();
  await expect(page.locator('#posture-loaded')).toHaveText('AI Apps: 4 of 250 loaded');
  await page.locator('#posture-coverage-details summary').click();
  await expect(page.locator('#posture-sources')).toContainText('A source could not be read.');
  await expect(page.locator('#posture-note')).toBeVisible();
  await expect(page.locator('#posture-note')).toContainText('Search and attention counts cover loaded records only.');
  await expect(page.locator('#posture-note')).toContainText('Organization approval is separate from security assessment.');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.postureError = 'Server could not be reached.'; });
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.locator('#posture-message')).toContainText('Showing previously loaded posture. Server could not be reached.');
  await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.postureError = ''; mock.posture = {supported:false,reason:'connection_mode'}; });
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.locator('#posture-content')).toBeHidden();
  await expect(page.locator('#posture-message')).toContainText('Update OpenAIDR to view local posture');
  await page.evaluate(() => { (window as unknown as {mock:Mock}).mock.posture = {supported:false,reason:'server_unavailable'}; });
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.locator('#posture-message')).toContainText('Ask your administrator to update it');
  const empty = postureFixture(); Object.values(empty.groups).forEach(group => { group.items = []; group.total = 0; }); empty.coverage.status = 'unavailable';
  await page.evaluate(value => { (window as unknown as {mock:Mock}).mock.posture = value; },empty);
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.locator('#posture-coverage-title')).toHaveText('Collection unavailable');
  await expect(page.locator('#posture-loaded')).toBeHidden();
  await page.getByRole('tab',{name:'AI Apps',exact:true}).click();
  await expect(page.locator('#posture-rows')).toContainText('No assets have been reported');
});

test('Posture rejects a mismatched response and discards late responses after enrollment changes', async ({page}) => {
  const posture = postureFixture();
  await boot(page,{status:guardrailStatus(),posture:{...posture,sensor_id:'other-device'}});
  await page.getByRole('tab',{name:'Posture',exact:true}).click();
  await expect(page.locator('#posture-message')).toHaveText('Posture response does not match this device.');
  await expect(page.locator('#posture-content')).toBeHidden();
  await page.evaluate(value => { const mock = (window as unknown as {mock:Mock}).mock; mock.posture = value; mock.pendingAction = 'posture.summary'; },posture);
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect.poll(async () => (await requests(page)).filter(request => request.action === 'posture.summary').length).toBe(2);
  await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.status = {...mock.status,sensor_id:'new-device',server_url:'https://new.example'}; mock.posture = {supported:false,reason:'server_unavailable'}; });
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.locator('#posture-message')).toHaveText('Loading posture…');
  await page.evaluate(() => { const win = window as unknown as {mock:Mock;completeRequest:() => void}; win.mock.pendingAction = ''; win.completeRequest(); });
  await expect(page.locator('#posture-message')).toContainText('Ask your administrator to update it');
  await expect(page.locator('#posture-content')).toBeHidden();
  await page.evaluate(() => { const mock = (window as unknown as {mock:Mock}).mock; mock.posture = {supported:true,schema_version:1,groups:{},coverage:{}}; });
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.locator('#posture-message')).toContainText('Posture data is unavailable');
});

test('Posture automatic checks require explicit consent and distinguish account credits from local receipts', async ({page}) => {
  const posture = postureFixture(true);
  posture.groups.skills.items[0].assessment_status = 'partial';
  posture.groups.skills.items[0].metadata = {assessment_scope:'Instruction and content AI review only. Static scanning is not included.',assessment_coverage:'Skill reviewed in one billed request.',assessment_prepared_at:1793821800};
  await boot(page,{status:freeStatus(),posture});
  await page.getByRole('tab',{name:'Posture',exact:true}).click();
  await expect(page.locator('#posture-check-state')).toHaveText('Paused');
  await expect(page.locator('#posture-checks')).toContainText('Sends package identifiers and skill content');
  await expect(page.locator('#posture-checks')).toContainText('One billed request per skill');
  await expect(page.locator('#posture-credit-available')).toHaveText('162.47 credits');
  await expect(page.locator('#posture-credit-charged')).toHaveText('4.02 credits');
  expect((await requests(page)).some(row => row.action === 'posture.configure')).toBe(false);
  await page.locator('#posture-credit-details summary').click();
  await expect(page.locator('#posture-credit-details')).toContainText('Posture reserved: 0.01 credits. Unconfirmed checks: 1.');
  await expect(page.locator('#posture-credit-details')).toContainText('Unconfirmed charges are excluded');
  await page.getByRole('button',{name:'Enable automatic checks'}).click();
  await expect(page.getByRole('button',{name:'Pause checks'})).toBeEnabled();
  await page.getByRole('button',{name:'Pause checks'}).click();
  await expect(page.locator('#posture-check-message')).toHaveText('Paused. Admitted checks may finish.');
  expect((await requests(page)).filter(row => row.action === 'posture.configure')).toEqual([
    {action:'posture.configure',automatic:true,scope:'a'.repeat(64)}, {action:'posture.configure',automatic:false,scope:'a'.repeat(64)},
  ]);
  await page.getByRole('tab',{name:'AI Skills',exact:true}).click();
  await page.locator('#posture-rows .posture-row').first().click();
  await expect(page.getByRole('dialog')).toContainText('Assessment: Partial');
  await expect(page.getByRole('dialog')).toContainText('Static scanning is not included.');
  await expect(page.getByRole('dialog')).toContainText('Skill reviewed in one billed request.');
  await expect(page.getByRole('dialog')).toContainText('Prepared');
  await page.keyboard.press('Escape');
  await page.getByRole('tab',{name:'Overview',exact:true}).click();
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.posture!.assessments = {enabled:true,state:'unavailable',billing:null,usage:null};
    mock.postureConfigureError = 'The Posture connection changed. Refresh before changing assessments.';
  });
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.locator('#posture-credit-available')).toHaveText('Unavailable');
  await expect(page.locator('#posture-credit-charged')).toHaveText('Unavailable');
  await page.getByRole('button',{name:'Pause checks'}).click();
  await expect(page.locator('#posture-check-message')).toContainText('connection changed');
  await expect(page.getByRole('button',{name:'Pause checks'})).toBeEnabled();
});

test('Posture discards a late consent response and old billing when the connection changes', async ({page}) => {
  await boot(page,{status:freeStatus(),posture:postureFixture(true),pendingAction:'posture.configure'});
  await page.getByRole('tab',{name:'Posture',exact:true}).click();
  await page.getByRole('button',{name:'Enable automatic checks'}).click();
  await expect(page.getByRole('button',{name:'Saving…',exact:true})).toBeDisabled();
  await expect(page.getByRole('button',{name:'Refresh',exact:true})).toBeDisabled();
  await page.evaluate(() => {
    const mock = (window as unknown as {mock:Mock}).mock;
    mock.status = {...mock.status,sensor_id:'another-device'};
    mock.posture = {...mock.posture,scope:'b'.repeat(64),assessments:{enabled:false,state:'disabled',billing:null,usage:null}};
    window.dispatchEvent(new Event('focus'));
  });
  await expect(page.locator('#posture-content')).toBeHidden();
  await page.evaluate(() => { const win = window as unknown as {mock:Mock;completeRequest:() => void}; win.mock.pendingAction = ''; win.completeRequest(); });
  await expect(page.getByRole('button',{name:'Enable automatic checks'})).toBeEnabled();
  await expect(page.locator('#posture-check-state')).toHaveText('Paused');
  await expect(page.locator('#posture-check-message')).toBeEmpty();
  await expect(page.locator('#posture-credit-available')).toHaveText('Unavailable');
  await expect(page.locator('#posture-credit-charged')).toHaveText('Unavailable');
  expect((await requests(page)).filter(row => row.action === 'posture.configure')).toEqual([{action:'posture.configure',automatic:true,scope:'a'.repeat(64)}]);
});


for (const maxWindowHeight of [720, 420]) test(`enterprise enrollment and Settings fit a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
  test.skip(process.env.OPENAIDR_DESKTOP_EDITION !== 'enterprise', 'Enterprise build only');
  await boot(page, {status:unenrolled, preview, afterEnroll:converged, maxWindowHeight});
  await expect(page.locator('#resume-app')).toBeHidden();
  for (const selector of ['#continue-free', '#use-api-key', '#api-key-dialog', '#choose-local-runtime', '#local-runtime-view', '#back-to-choices']) {
    await expect(page.locator(selector)).toHaveCount(0);
  }
  await expect(page.locator('#enrollment-link')).toBeVisible();
  const layout = await page.evaluate(readFileSync(new URL('../e2e/startup-layout.js', import.meta.url), 'utf8')) as {edition:string;controls:{selector:string}[]};
  expect(layout.edition).toBe('enterprise');
  expect(layout.controls.map(control => control.selector)).toEqual(['#enrollment-link', '#connect-link']);
  await page.locator('#enrollment-link').fill(link);
  await expect(page.locator('#link-organization')).toHaveText('Example organization');
  await expect(page.locator('#connect-link')).toBeEnabled();
  const app = page.locator('#app');
  expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  if (maxWindowHeight === 720) expect(await app.evaluate(node => node.scrollHeight <= node.clientHeight + 1)).toBe(true);
  else {
    expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await page.locator('#connect-link').scrollIntoViewIfNeeded();
    await expect(page.locator('#connect-link')).toBeInViewport();
  }
  await page.screenshot({path:testInfo.outputPath('enterprise-enrollment.png')});
  await page.locator('#connect-link').click();
  await expect(page.locator('#connect-card')).toBeHidden();
  await page.locator('#change-connection').click();
  await expect(page.locator('#connection-dialog')).toBeVisible();
  await expect(page.locator('#enrollment-link')).toBeVisible();
  await expect(page.locator('#choose-local-runtime')).toHaveCount(0);
  await page.getByRole('button', {name:'Done',exact:true}).click();
  const requests = await page.evaluate(() => (window as unknown as {requests:Requests}).requests);
  expect(requests.some(request => request.action === 'enrollment.connect')).toBe(true);
  expect(requests.some(request => request.action === 'desktop.resume')).toBe(false);
  expect(requests.some(request => request.action.startsWith('local-runtime.') || request.action === 'free.connect' || request.action === 'api-key.connect')).toBe(false);
});

for (const connection_mode of ['free','api_key','organization']) test(`enterprise requires enrollment over an existing ${connection_mode} personal installation`, async ({page}) => {
  test.skip(process.env.OPENAIDR_DESKTOP_EDITION !== 'enterprise', 'Enterprise build only');
  await boot(page, {status:{...enrolled,connection_mode,enterprise_enrollment_required:true}});
  await expect(page.locator('#enrollment-link')).toBeVisible();
  const requests = await page.evaluate(() => (window as unknown as {requests:Requests}).requests);
  expect(requests.some(request => request.action === 'setup')).toBe(false);
});
