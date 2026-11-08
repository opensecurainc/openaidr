import {test, expect, request, chromium, type Browser, type APIRequestContext, type Page, type TestInfo} from '@playwright/test';
import {spawn, execFileSync, type ChildProcess} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import {NativeUI} from './native-ui';
import {exerciseAppAlerts, exerciseAppControls} from './native-flows';
import {dashboardFixtures, walkDashboard} from './dashboard';

const root = path.resolve(import.meta.dirname, '../../..');
const origin = 'http://127.0.0.1:8080';
const codex = process.env.E2E_CODEX_JS || '';
const stateRoot = path.join(process.env.LOCALAPPDATA || os.tmpdir(), 'OpenAIDR/data');
let appPage: Page;
let webview: Browser | undefined;
let native: NativeUI;
let appProcess: ChildProcess;
let installer = '';
let appRemoved = false;
const terminalPids: number[] = [];
const apiKey = process.env.E2E_OPENAI_API_KEY || '';
const secrets = [apiKey].filter(Boolean);
const cleanEnv = {...process.env};
for (const key of ['E2E_CLAUDE_TOKEN', 'E2E_OPENAI_API_KEY', 'OPENAI_API_KEY', 'CODEX_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN']) delete cleanEnv[key];
let temporary = '';
let app = '';
let sensor = '';
let sensorId = '';
let api: APIRequestContext;
let expectedBuild: Record<string, unknown>;
let restoreWebviewPolicy: (() => void) | undefined;
const processes: {name: string; process: ChildProcess; expectedExit?: boolean}[] = [];
const browserErrors: string[] = [];

function redact(value: string): string {
  for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) value = value.split(secret).join('[REDACTED]');
  return value.replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|oa(?:et|st)_[A-Za-z0-9_-]{20,})/g, '[REDACTED]');
}

function command(file: string, args: string[], options: {input?: string; env?: NodeJS.ProcessEnv; cwd?: string; timeout?: number; stdio?: 'ignore'} = {}): string {
  try {
    const env = {...(options.env || cleanEnv)};
    // pwsh 7 module paths break Windows PowerShell 5.1 auto-loading through Node.
    if (path.basename(file).toLowerCase() === 'powershell.exe') {
      for (const key of Object.keys(env)) if (key.toLowerCase() === 'psmodulepath') delete env[key];
    }
    return (execFileSync(file, args, {encoding: 'utf8', timeout: 30_000,
      maxBuffer: 8 * 1024 * 1024, ...options, env}) || '').trim();
  } catch (error) {
    throw new Error(redact(String(error)));
  }
}

function start(name: string, file: string, args: string[], env = cleanEnv) {
  const log = fs.openSync(path.join(temporary, `${name}.log`), 'a');
  const child = spawn(file, args, {cwd: root, env, stdio: ['ignore', log, log], windowsHide: false});
  fs.closeSync(log);
  child.on('error', error => fs.appendFileSync(path.join(temporary, `${name}.log`), redact(String(error))));
  processes.push({name, process: child});
  return child;
}

async function attach(info: TestInfo, name: string, value: unknown) {
  await info.attach(name, {body: redact(typeof value === 'string' ? value : JSON.stringify(value, null, 2)), contentType: 'text/plain'});
}

function bridge(action: string, params = {}): any {
  const response = JSON.parse(command(sensor, ['desktop-bridge'], {input: JSON.stringify({action, params}), timeout: 60_000}));
  if (!response.ok) throw new Error(redact(`Sensor ${action}: ${JSON.stringify(response.error)}`));
  return response.data;
}

async function apiCall(route: string, method = 'GET', data?: unknown): Promise<any> {
  // The dashboard server drops idle keep-alive sockets after five seconds, and installing the app
  // leaves the connection idle longer than that. Playwright retries only ECONNRESET here.
  try {
    const response = await api.fetch(`/api/v1/${route}`, {method, data, maxRetries: 2});
    if (!response.ok()) throw new Error(`Backend ${method} ${route} returned HTTP ${response.status()}`);
    return response.status() === 204 ? null : response.json();
  } catch (error) { throw new Error(redact(String(error))); }
}

function collectCredentials() {
  const file = path.join(stateRoot, 'sensor.yaml');
  if (!fs.existsSync(file)) return;
  const values = JSON.parse(command('python', ['-c',
    'import json,pathlib,sys,yaml; c=yaml.safe_load(pathlib.Path(sys.argv[1]).read_text()); print(json.dumps([c.get("sensor_token",""),c.get("telemetry",{}).get("local_token","")]))', file]));
  secrets.push(...values.filter(Boolean));
}

async function waitHttp(url: string) {
  await expect.poll(async () => {
    try { return (await fetch(url, {signal: AbortSignal.timeout(2000)})).ok; } catch { return false; }
  }, {timeout: 60_000, intervals: [500, 1000], message: `Service ready: ${url}`}).toBe(true);
}

function powershell(script: string): string {
  return command('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
}

function quote(value: string): string { return "'" + value.replaceAll("'", "''") + "'"; }

function configureWebviewPolicy(profile: string): () => void {
  // Elevated WebView2 hosts ignore browser-argument environment overrides.
  // Scope the hosted-runner policy to this executable and refuse existing values.
  const registry = 'SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2';
  const entries = [
    ['AdditionalBrowserArguments', '--remote-debugging-port=9222 --remote-debugging-address=127.0.0.1'],
    ['UserDataFolder', profile],
  ];
  const keys = entries.map(([name]) => quote(`${registry}\\${name}`)).join(', ');
  powershell(`$ErrorActionPreference = 'Stop'; foreach ($path in @(${keys})) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path);
    if ($key) { try {
      if ($key.GetValueNames() -contains 'openaidr-desktop.exe') { throw 'Existing OpenAIDR WebView2 policy must not be overwritten.' }
    } finally { $key.Dispose() } }
  }`);
  const restore = () => powershell(`$ErrorActionPreference = 'Stop'; foreach ($path in @(${keys})) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $true);
    if ($key) { try { $key.DeleteValue('openaidr-desktop.exe', $false) } finally { $key.Dispose() } }
  }`);
  try {
    powershell(`$ErrorActionPreference = 'Stop'; ` + entries.map(([name, value]) => `
      $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(${quote(`${registry}\\${name}`)});
      try { $key.SetValue('openaidr-desktop.exe', ${quote(value)}, [Microsoft.Win32.RegistryValueKind]::String) }
      finally { $key.Dispose() }
    `).join('\n'));
  } catch (error) {
    restore();
    throw error;
  }
  return restore;
}

async function launchApp() {
  appProcess = start('app', app, []);
  await waitHttp('http://127.0.0.1:9222/json/version');
  webview = await chromium.connectOverCDP('http://127.0.0.1:9222');
  await expect.poll(() => webview!.contexts()[0]?.pages().length || 0).toBeGreaterThan(0);
  appPage = webview.contexts()[0].pages()[0];
  appPage.on('pageerror', error => browserErrors.push(redact(error.message)));
  appPage.on('console', message => { if (message.type() === 'error') browserErrors.push(redact(message.text())); });
  if (!native) native = new NativeUI(redact, {
    evaluate: (script, args) => appPage.evaluate(({script, args}) => new Function(script).apply(null, args), {script, args}),
    click: selector => appPage.locator(selector).click(),
    fill: (selector, value) => appPage.locator(selector).fill(value),
  }, {
    '#resume-app': 'Windows reinstalls with NSIS; the native uninstaller closes the app.',
    '#trash-app': 'Windows removes the package with NSIS; Move app to Trash is macOS only.',
  });
  await expect(appPage.locator('#app')).toBeVisible();
  await native.connect();
  const capabilities = await native.evaluate("return window.__TAURI_INTERNALS__.invoke('sensor_request', {request:{action:'desktop.capabilities'}});");
  expect(capabilities).toMatchObject({removal_supported: true, native_uninstaller: true});
  await native.visible('#resume-app', false);
  await native.visible('#trash-app', false);
  appRemoved = false;
}

function retainedFiles(): Record<string, string> {
  const files = [path.join(stateRoot, 'sensor.yaml'), path.join(stateRoot, 'e2e-retained-data.txt'),
    path.join(os.homedir(), '.codex/config.toml'), path.join(os.homedir(), '.codex/hooks.json')];
  return Object.fromEntries(files.map(file => {
    expect(fs.existsSync(file), `Retained configuration exists: ${file}`).toBe(true);
    return [file, createHash('sha256').update(fs.readFileSync(file)).digest('hex')];
  }));
}

function removalState() {
  const installed = path.dirname(app);
  const state = JSON.parse(powershell(`$ErrorActionPreference = 'Stop';
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    $tasks = @(@('OpenAIDR ', 'OpenAIDR Sensor ', 'OpenAIDR update ') | ForEach-Object {
      Get-ScheduledTask -TaskName ($_ + $sid) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TaskName
    });
    $roots = @(${quote(installed + path.sep)}, ${quote(path.join(stateRoot, 'runtime') + path.sep)});
    $owned = @(Get-CimInstance Win32_Process | Where-Object {
      $executable = $_.ExecutablePath;
      $executable -and @($roots | Where-Object { $executable.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count
    } | Select-Object ProcessId, Name);
    @{tasks=$tasks; processes=$owned; registered=(Test-Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OpenAIDR')} | ConvertTo-Json -Depth 4 -Compress`));
  return {...state, package_removed: !fs.existsSync(installed),
    runtime_removed: !fs.readdirSync(stateRoot).some(name => name === 'runtime' || name.startsWith('runtime.remove-')),
    recovery_disabled: fs.existsSync(path.join(stateRoot, 'desktop-update/removed'))};
}

async function openUninstaller(info: TestInfo, name: string) {
  const uninstaller = path.join(path.dirname(app), 'uninstall.exe');
  const digest = createHash('sha256').update(fs.readFileSync(uninstaller)).digest('hex');
  const startedAfter = new Date(Date.now() - 1000).toISOString();
  await native.healthy();
  await native.click('#remove-app');
  await native.text('#confirm-remove', 'Open uninstaller');
  await screenshot(info, 'OpenAIDR', `${name}-confirmation`);
  processes.find(item => item.process === appProcess)!.expectedExit = true;
  let responseError = '';
  try { await native.click('#confirm-remove'); }
  catch (error) { responseError = redact(String(error)); }
  await expect.poll(() => appProcess.exitCode, {timeout: 30_000, message: 'The app exits after opening NSIS'}).toBe(0);
  try { if (webview) await webview.close(); } catch { /* The confirmed app exit already closed CDP. */ }
  webview = undefined;
  const invoke = (operation: string, processId = 0) => JSON.parse(command('powershell.exe', ['-NoProfile', '-File',
    path.join(root, 'scripts/e2e_installer_windows.ps1'), '-UninstallerPath', uninstaller,
    '-UninstallerHash', digest, '-StartedAfter', startedAfter, '-Operation', operation,
    '-WindowProcessId', String(processId), '-TimeoutSeconds', '60'], {timeout: 180_000}));
  const window = invoke('Inspect');
  terminalPids.push(window.process_id);
  await attach(info, `${name}: native uninstaller`, {window, app_exit_code: appProcess.exitCode,
    ...(responseError ? {driver_response_after_exit: responseError} : {})});
  await screenshot(info, window.title, `${name}-wizard`);
  return {
    invoke: (operation: string) => invoke(operation, window.process_id),
    title: window.title,
    async closed() {
      await expect.poll(() => powershell(`$ErrorActionPreference = 'Stop'; Get-Process | Where-Object Id -EQ ${window.process_id} | Measure-Object | Select-Object -ExpandProperty Count`),
        {timeout: 30_000, message: 'The owned NSIS wizard exits'}).toBe('0');
      terminalPids.splice(terminalPids.indexOf(window.process_id), 1);
    },
  };
}

async function screenshot(info: TestInfo, owner: string, name: string, expectedText?: string) {
  if (expectedText) await expect(appPage.locator(expectedText === 'Codex' ? '#usage-legend' : 'body'))
    .toContainText(expectedText, {timeout: 90_000});
  if (owner === 'OpenAIDR' && appPage) {
    await appPage.locator('input[type="password"], #enrollment-link').evaluateAll(inputs => {
      for (const input of inputs) (input as HTMLInputElement).value = '';
    });
  }
  const file = info.outputPath(`${name}.png`);
  await expect.poll(() => {
    try {
      command('powershell.exe', ['-NoProfile', '-File', path.join(root, 'scripts/e2e_window_windows.ps1'),
        '-WindowTitle', owner, '-OutputPath', file]);
      return fs.statSync(file).size > 1000;
    } catch { return false; }
  }, {timeout: 20_000, message: `A rendered native ${owner} window must be available`}).toBe(true);
  await info.attach(`${name} (${new Date().toISOString()})`, {path: file, contentType: 'image/png'});
}

async function dashboard(page: Page, info: TestInfo, route: string, name: string, ready: () => Promise<void>) {
  const state = await api.storageState();
  await page.context().addCookies(state.cookies);
  await page.goto(origin + route);
  await expect(page.getByRole('main')).toBeVisible();
  await expect(page.getByRole('heading', {name: 'Sign in', exact: true})).toHaveCount(0);
  await ready();
  await page.screenshot({path: info.outputPath(`${name}.png`), fullPage: true});
  await info.attach(`${name} (${new Date().toISOString()})`, {path: info.outputPath(`${name}.png`), contentType: 'image/png'});
}

test.describe('Windows installed application', () => {
  test.describe.configure({mode: 'serial'});

  test.beforeEach(async ({page}) => {
    browserErrors.length = 0;
    page.on('pageerror', error => browserErrors.push(redact(error.message)));
    page.on('console', message => { if (message.type() === 'error') browserErrors.push(redact(message.text())); });
    page.on('response', response => {
      if (response.url().startsWith(origin) && response.status() >= 500)
        browserErrors.push(`HTTP ${response.status()} ${new URL(response.url()).pathname}`);
    });
  });

  test.afterEach(async ({page}, info) => {
    if (info.status === 'skipped') return;
    const runtimeErrors: string[] = [];
    if (temporary) {
      collectCredentials();
      for (const name of ['backend', 'intelligence', 'dashboard', 'app', 'postgres']) {
        const file = path.join(temporary, `${name}.log`);
        if (fs.existsSync(file)) {
          const log = fs.readFileSync(file, 'utf8');
          await attach(info, `${name}.log`, log);
          if (/^ERROR[: ]|^Traceback \(most recent call last\):|^thread .* panicked at/m.test(log))
            runtimeErrors.push(`${name} logged an error, traceback, or panic`);
        }
      }
      for (const name of ['sensor.log', 'sensor.err.log']) {
        const file = path.join(stateRoot, 'data', name);
        if (fs.existsSync(file)) await attach(info, name, fs.readFileSync(file, 'utf8'));
      }
    }
    for (const {name, process: child, expectedExit} of processes) {
      if (expectedExit) continue;
      if (!child.pid || child.exitCode !== null || child.signalCode !== null) runtimeErrors.push(`${name} process exited`);
    }
    if (sensor && fs.existsSync(sensor)) {
      try { await attach(info, 'Sensor status', bridge('status')); }
      catch (error) { await attach(info, 'Sensor status error', String(error)); }
    }
    if (info.status !== info.expectedStatus) {
      try { if (app) await screenshot(info, 'OpenAIDR', 'app-at-failure'); }
      catch (error) { await attach(info, 'App capture failure', String(error)); }
      try {
        await info.attach('Dashboard at failure', {body: await page.screenshot({fullPage: true}), contentType: 'image/png'});
      } catch (error) { await attach(info, 'Dashboard capture failure', String(error)); }
    }
    await attach(info, 'Browser errors', browserErrors);
    await attach(info, 'Runtime errors', runtimeErrors);
    if (native) await native.coverage(info);
    if (info.status === 'passed') {
      if (native && !appRemoved) await native.healthy();
      expect(browserErrors, 'Dashboard must have no browser errors or HTTP 5xx responses').toEqual([]);
      expect(runtimeErrors, 'App, backend, and dashboard must stay healthy').toEqual([]);
    }
  });

  test.afterAll(async () => {
    if (!temporary) return;
    try {
      if (webview) await webview.close();
    } finally {
      // Close the app before its sensor, so automatic setup cannot restart it.
      for (const pid of [...terminalPids, ...processes.reverse().flatMap(({process: child}) =>
        child.pid && child.exitCode === null && child.signalCode === null ? [child.pid] : [])]) {
        try { command('taskkill.exe', ['/PID', String(pid), '/T', '/F']); } catch { /* Already exited. */ }
      }
      try {
        if (sensor && fs.existsSync(sensor) && bridge('status').service !== 'not installed') command(sensor, ['stop']);
      } finally {
        try {
          try { if (restoreWebviewPolicy) restoreWebviewPolicy(); }
          finally { if (api) await api.dispose(); }
        } finally {
          try {
            const pg = path.join(temporary, 'postgres');
            if (fs.existsSync(path.join(pg, 'postmaster.pid')))
              command('pg_ctl', ['-D', pg, '-m', 'immediate', 'stop'], {stdio: 'ignore'});
          } finally { fs.rmSync(temporary, {recursive: true, force: true, maxRetries: 5, retryDelay: 200}); }
        }
      }
    }
  });

  test('Install NSIS, enroll the packaged sensor, and connect the app', async ({page}, info) => {
    expect(process.platform).toBe('win32');
    expect(process.env.GITHUB_ACTIONS, 'This suite changes the test account and must run in a disposable hosted VM').toBe('true');
    expect(process.env.RUNNER_ENVIRONMENT).toBe('github-hosted');
    expect(process.env.E2E_BUILD_OUTCOME, 'The app and dashboard build must succeed first').toBe('success');
    expect(Boolean(apiKey), 'Missing Codex credentials').toBe(true);
    expect(fs.existsSync(path.join(process.env.LOCALAPPDATA!, 'OpenAIDR')), 'The VM must not contain a previous installation').toBe(false);
    expect(fs.existsSync(path.join(process.env.LOCALAPPDATA!, 'OpenAIDR Sensor')), 'The VM must not contain a legacy installation').toBe(false);
    temporary = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP!, 'openaidr-private-'));
    const sid = powershell('[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value');
    command('icacls.exe', [temporary, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`]);
    const password = randomUUID();
    secrets.push(password);
    const env: NodeJS.ProcessEnv = {...cleanEnv, OPENAIDR_DATABASE_URL: 'postgresql://e2e@127.0.0.1:55432/openaidr',
      OPENAIDR_LISTEN: '127.0.0.1:8081', OPENAIDR_PUBLIC_URL: origin,
      OPENAIDR_SERVICES: 'ingest,api,detect', OPENAIDR_REQUIRE_TENANT: 'true', OPENAIDR_AUTH_MODE: 'local'};
    await test.step('Start an isolated database, real backend, and built dashboard', async () => {
      const pg = path.join(temporary, 'postgres');
      command('initdb', ['-D', pg, '-U', 'e2e', '--auth=trust', '--no-locale', '--encoding=UTF8']);
      // The Windows launcher retains inherited pipes after PostgreSQL is ready.
      command('pg_ctl', ['-D', pg, '-l', path.join(temporary, 'postgres.log'), '-o', '-h 127.0.0.1 -p 55432 -c timezone=UTC', '-w', 'start'], {stdio: 'ignore'});
      command('createdb', ['-h', '127.0.0.1', '-p', '55432', '-U', 'e2e', 'openaidr']);
      const tenant = JSON.parse(command('openaidr-server', ['tenant', 'bootstrap', '--name', 'OpenAIDR E2E',
        '--slug', 'windows-e2e', '--max-uses', '1', '--json'], {env, timeout: 120_000}));
      secrets.push(tenant.enrollment_token);
      env.OPENAIDR_TENANT_ID = tenant.tenant_id;
      const intelligenceScript = path.join(root, 'scripts/e2e_intelligence.py');
      const intelligenceDirectory = path.join(temporary, 'intelligence');
      const connection = JSON.parse(command('python', [intelligenceScript, 'prepare', intelligenceDirectory, tenant.tenant_id]));
      secrets.push(connection.api_key);
      Object.assign(env, {OPENAIDR_INTELLIGENCE_ORIGIN: connection.origin,
        OPENAIDR_INTELLIGENCE_API_KEY: connection.api_key, OPENAIDR_INTELLIGENCE_CA_FILE: connection.ca_file});
      start('intelligence', 'python', [intelligenceScript, 'serve', intelligenceDirectory]);
      command('openaidr-server', ['tenant', 'user', 'create', '--name', 'E2E Owner', '--email', 'e2e@example.test',
        '--password-stdin'], {env, input: password});
      start('backend', 'openaidr-server', ['serve'], env);
      await waitHttp('http://127.0.0.1:8081/readyz');
      start('dashboard', 'node', [path.join(root, 'apps/dashboard/.next/standalone/apps/dashboard/server.js')],
        {...cleanEnv, PORT: '8080', HOSTNAME: '127.0.0.1'});
      await waitHttp(origin + '/login');
      api = await request.newContext({baseURL: origin, extraHTTPHeaders: {'X-OpenAIDR-CSRF': '1', Origin: origin}});
      await apiCall('auth/login', 'POST', {email: 'e2e@example.test', password});
      for (const cookie of (await api.storageState()).cookies) secrets.push(cookie.value);
      await expect.poll(async () => {
        try { return (await apiCall('settings/intelligence/check', 'POST', {})).tenant_id; }
        catch { return ''; }
      }, {timeout: 30_000, intervals: [500, 1000], message: 'Backend authenticates to the local Intelligence service over verified TLS'}).toBe(tenant.tenant_id);
    });
    await test.step('Install the unsigned NSIS package and launch its native WebView2 app', async () => {
      const directory = path.join(root, 'apps/desktop/src-tauri/target/release/bundle/nsis');
      const installers = fs.readdirSync(directory).filter(name => name.endsWith('-setup.exe'));
      expect(installers).toHaveLength(1);
      installer = path.join(directory, installers[0]);
      command(installer, ['/S'], {timeout: 120_000});
      const installed = path.join(process.env.LOCALAPPDATA!, 'OpenAIDR/app');
      app = path.join(installed, 'openaidr-desktop.exe');
      sensor = path.join(installed, 'runtime/openaidr.exe');
      expect(fs.existsSync(app)).toBe(true);
      const build = JSON.parse(command(sensor, ['build-info']));
      expectedBuild = JSON.parse(fs.readFileSync(path.join(root, 'build/desktop/_build.json'), 'utf8'));
      expect(build.source_commit).toBe(process.env.GITHUB_SHA);
      expect(build).toEqual(expectedBuild);
      expect(installers[0]).toContain(String(expectedBuild.version));
      const desktopBuild = JSON.parse(command(app, ['--update-build-info']));
      expect(desktopBuild).toEqual(expectedBuild);
      restoreWebviewPolicy = configureWebviewPolicy(path.join(temporary, 'webview2'));
      await launchApp();
      await screenshot(info, 'OpenAIDR', 'app-before-enrollment', build.desktop_edition === 'enterprise' ? 'Connect your organization' : 'Continue without');
      await attach(info, 'Build and environment', {build,
        Windows: powershell('[System.Environment]::OSVersion.VersionString'),
        dashboard_branding: 'Neutral E2E palette; private marks omitted',
        codex: command(process.execPath, [codex, '--version']), selected: 'codex'});
    });
    await test.step('Connect in the installed app and verify live hooks and its Scheduled Task', async () => {
      const enrollment = await apiCall('sensors/enrollment-links', 'POST', {label: 'Windows E2E', expires_in_hours: 1, max_uses: 1});
      secrets.push(enrollment.enrollment_url, enrollment.enrollment_url.split('token=')[1]);
      try {
        await native.chooseOrganization();
        await native.fill('#enrollment-link', enrollment.enrollment_url);
        await native.click('#connect-link');
        await native.text('#health-title', 'Sensor connected');
      } catch (error) { throw new Error(redact(String(error))); }
      sensorId = bridge('status').sensor_id;
      // The native window also runs setup. Poll it instead of racing that mutation.
      await expect.poll(() => {
        const status = bridge('status');
        return status.running && status.control_ready && status.service === 'running'
          && status.service_version === expectedBuild.version && Boolean(status.hooks?.codex?.current);
      }, {timeout: 90_000, intervals: [1000, 2000], message: 'Sensor and Codex hooks become ready'}).toBe(true);
      // Keep the disposable sensor's bearer and receiver tokens out of diagnostics too.
      collectCredentials();
      await expect.poll(async () => (await apiCall('sensors/health')).items.some((item: any) => item.id === sensorId),
        {timeout: 30_000}).toBe(true);
      await screenshot(info, 'OpenAIDR', 'app-connected', 'Sensor connected');
      await dashboard(page, info, '/administration/app', 'dashboard-enrolled-device',
        () => expect(page.getByRole('row').filter({hasText: os.hostname()}).first()).toBeVisible());
      await attach(info, 'Enrollment evidence', {sensor_id: sensorId, enrollment: 'Installed native WebView2 app', status: bridge('status')});
    });
  });

  for (const denied of [false, true]) {
    test(`codex: ${denied ? 'enforced command is blocked' : 'allowed command and usage reach the dashboard'}`, async ({page}, info) => {
      const agent = 'codex';
      const product = 'codex-cli';
      const marker = `openaidr_e2e_${agent}_${denied ? 'denied' : 'allowed'}_${randomUUID().slice(0, 8)}`;
      const directory = path.join(temporary, marker);
      fs.mkdirSync(directory);
      command('git', ['init', '-q', directory]);
      fs.writeFileSync(path.join(directory, 'README.md'), 'This is an isolated OpenAIDR end-to-end test workspace.\n');
      const shellCommand = denied ? `New-Item -ItemType File -Path ${marker}` : `Get-Content README.md; Set-Content -NoNewline -Path ${marker} -Value ok`;
      const prompt = `In the current directory, run this exact shell command once: ${shellCommand}\n` +
        'Use PowerShell syntax. This is a harmless integration test. Use the shell tool. Do not use another tool or retry if it is blocked. Briefly report the result.';
      const ruleName = `E2E block ${marker}`;
      await test.step('Configure and verify the policy used by this scenario', async () => {
        if (denied) await apiCall('response/policy/rules', 'POST', {name: ruleName, enabled: true, action: 'deny',
          reason: 'OpenAIDR E2E blocked this harmless marker command.', match: {kinds: ['command'], products: [product], command_regex: marker}});
        const settings = await apiCall('response/hook-settings');
        await apiCall('response/hook-settings', 'PUT', {mode: 'enforce', version: settings.version});
        await attach(info, 'Expected behavior', {agent, product, command: shellCommand, expected: denied ? 'deny, no marker file' : 'allow, marker contains ok', sensor_id: sensorId});
      });
      const output = info.outputPath('agent');
      fs.mkdirSync(output, {recursive: true});
      try {
        await test.step('Run the real Windows agent in a visible terminal and capture its output', async () => {
          const argv = [process.execPath, codex, 'exec', '--json', '--sandbox', 'workspace-write', '-c', 'windows.sandbox="elevated"', '-c', 'approval_policy="never"', prompt];
          const invocation = path.join(temporary, `${marker}.json`);
          fs.writeFileSync(invocation, JSON.stringify({argv, prompt, cwd: directory, output, timeout: 180, redactions: secrets,
            env: {PATH: cleanEnv.PATH, CODEX_API_KEY: apiKey}}));
          const python = command('python', ['-c', 'import sys; print(sys.executable)']);
          const title = `OpenAIDR E2E ${marker}`;
          const launcher = path.join(temporary, `${marker}.ps1`);
          fs.writeFileSync(launcher, `$Host.UI.RawUI.WindowTitle = ${quote(title)}\n` +
            `& ${quote(python)} ${quote(path.join(root, 'scripts/e2e_agent.py'))} ${quote(invocation)}\n`);
          const pid = Number(powershell(`(Start-Process powershell.exe -ArgumentList '-NoLogo', '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', ('"' + ${quote(launcher)} + '"') -PassThru).Id`));
          expect(pid).toBeGreaterThan(0);
          terminalPids.push(pid);
          await screenshot(info, title, 'agent-started');
          await expect.poll(() => fs.existsSync(path.join(output, 'result.json')), {timeout: 195_000, intervals: [1000], message: 'Agent completes within its deadline'}).toBe(true);
          await screenshot(info, title, 'agent-finished');
          const result = JSON.parse(fs.readFileSync(path.join(output, 'result.json'), 'utf8'));
          await attach(info, 'Agent process result', result);
          expect(result.timed_out).toBe(false);
          expect(result.returncode, 'The agent must complete without an authentication, CLI, or runtime failure').toBe(0);
        });
        await test.step('Correlate the real tool call, hook delivery, and filesystem effect', async () => {
          const events = fs.readFileSync(path.join(output, 'agent.jsonl'), 'utf8').split('\n').flatMap(line => {
            try { return [JSON.parse(line)]; } catch { return []; }
          });
          const sessions = new Set(events.map(event => event.thread_id).filter(Boolean));
          expect(sessions.size, 'Agent must identify its actual session').toBeGreaterThan(0);
          expect(events.some(event => event.type === 'turn.completed'),
            'Agent must emit a successful terminal result').toBe(true);
          expect(events.some(event => event.type === 'turn.failed' || event.type === 'error'),
            'Agent stream must not report a failed run').toBe(false);
          let evidence: any;
          await expect.poll(async () => {
            const {items} = await apiCall('hook-decisions?limit=100');
            evidence = items.find((item: any) => item.sensor_id === sensorId && item.product === product &&
              sessions.has(item.session_id) && item.hook_event === 'PreToolUse' && JSON.stringify(item.actions).includes(marker) &&
              item.returned_decision === (denied ? 'deny' : 'allow') && item.delivery_status === 'delivered');
            return Boolean(evidence);
          }, {timeout: 60_000, intervals: [1000, 2000], message: 'Backend confirms the matching hook decision was delivered'}).toBe(true);
          expect(evidence.delivered_decision).toBe(denied ? 'deny' : 'allow');
          if (denied) {
            expect(evidence.rule_name).toBe(ruleName);
            expect(fs.existsSync(path.join(directory, marker)), 'A denied command must not create its marker').toBe(false);
          } else expect(fs.readFileSync(path.join(directory, marker), 'utf8')).toBe('ok');
          await attach(info, 'Correlated backend hook decision', evidence);
        });
        await test.step('Verify telemetry and capture the app and dashboard', async () => {
          if (!denied) {
            let usage: any;
            await expect.poll(() => {
              usage = bridge('usage.summary', {days: 30});
              return usage.breakdown?.some((row: any) => row.application === 'codex' && row.tokens > 0);
            }, {timeout: 60_000, intervals: [2000], message: 'App records token usage for this agent'}).toBe(true);
            await attach(info, 'App usage', usage);
            await expect.poll(async () => (await apiCall('telemetry/overview')).devices.some((device: any) => device.id === sensorId && device.exports > 0),
              {timeout: 60_000, intervals: [2000], message: 'Backend receives device telemetry'}).toBe(true);
          }
          const status = bridge('status');
          expect(status.running).toBe(true);
          expect(status.heartbeat?.error || '').toBe('');
          expect(status.activity?.last_error || '').toBe('');
          expect(status.telemetry?.last_error || '').toBe('');
          await screenshot(info, 'OpenAIDR', 'app-after-agent', 'Codex');
          await dashboard(page, info, denied ? '/guardrail/configuration' : '/administration/app', 'dashboard-after-agent',
            () => denied ? expect(page.getByText(ruleName, {exact: true})).toBeVisible()
              : expect(page.getByRole('row').filter({hasText: os.hostname()}).first()).toBeVisible());
          await attach(info, 'Backend telemetry overview', await apiCall('telemetry/overview'));
        });
      } finally {
        const transcript = path.join(output, 'agent.jsonl');
        if (fs.existsSync(transcript)) await attach(info, 'Complete agent JSON stream', fs.readFileSync(transcript, 'utf8'));
        if (denied) {
          const policy = await apiCall('response/policy');
          for (const rule of policy.rules.filter((item: any) => item.name === ruleName)) await apiCall(`response/policy/rules/${rule.id}`, 'DELETE');
        }
      }
    });
  }

  test('Every dashboard page and detail route fully loads', async ({page}, info) => {
    test.setTimeout(12 * 60_000);
    const details = await dashboardFixtures({apiCall, sensorId, secrets, backendOrigin: 'http://127.0.0.1:8081',
      seedDetails: input => JSON.parse(command('python', [path.join(root, 'scripts/e2e_dashboard_fixture.py'),
        'postgresql://e2e@127.0.0.1:55432/openaidr', path.join(temporary, 'intelligence/connection.json')], {input: JSON.stringify(input)}))});
    await page.context().addCookies((await api.storageState()).cookies);
    await walkDashboard(page, info, origin, details);
  });

  test('Native app controls and the Windows tray preference work with real sensor state', async ({}, info) => {
    const publicCertificate = command('python', ['-c',
      'import certifi; print(open(certifi.where()).read().split("-----END CERTIFICATE-----")[0]+"-----END CERTIFICATE-----")']);
    await exerciseAppControls({native, sensorId, sensorStatus: () => bridge('status'), publicCertificate,
      screenshot: name => screenshot(info, 'OpenAIDR', name)});
    await test.step('The system tray preference persists through the native command', async () => {
      await native.click('#change-connection');
      await native.visible('#connection-dialog');
      await expect(appPage.getByRole('checkbox', {name: 'Show in system tray'})).toBeVisible();
      const preferences = path.join(process.env.APPDATA!, 'com.opensecura.openaidr.sensor/desktop-preferences.json');
      for (const enabled of [true, false]) {
        await native.click('#show-menu-bar');
        await native.wait('const input = document.querySelector("#show-menu-bar"); return !input.disabled && input.checked === arguments[0];', [enabled]);
        expect(JSON.parse(fs.readFileSync(preferences, 'utf8')).show_in_menu_bar).toBe(enabled);
      }
      await screenshot(info, 'OpenAIDR', 'app-system-tray-preference');
      await native.click('#cancel-change');
      await native.visible('#connection-dialog', false);
    });
  });

  test('Native alert controls acknowledge a real backend alert', async ({}, info) => {
    await exerciseAppAlerts({native, apiCall, sensorId, alertCommand: 'Write-Output "E2E instructions only"',
      screenshot: name => screenshot(info, 'OpenAIDR', name)});
  });

  test('Native NSIS cancellation, uninstall, reinstall, and final removal preserve enrollment', async ({}, info) => {
    test.setTimeout(8 * 60_000);
    fs.writeFileSync(path.join(stateRoot, 'e2e-retained-data.txt'), 'Retain disposable user data across native package removal.\n');
    await native.click('#remove-app');
    await native.click('#cancel-remove');
    await native.visible('#remove-dialog', false);
    const beforeCancel = retainedFiles();
    await test.step('Cancelling the real NSIS wizard keeps the installation and running sensor', async () => {
      const wizard = await openUninstaller(info, 'uninstall-cancel');
      await attach(info, 'NSIS cancellation', wizard.invoke('Cancel'));
      await wizard.closed();
      expect(fs.existsSync(app)).toBe(true);
      expect(retainedFiles()).toEqual(beforeCancel);
      expect(bridge('status')).toMatchObject({sensor_id: sensorId, service: 'running', running: true});
      await launchApp();
      await screenshot(info, 'OpenAIDR', 'app-after-uninstall-cancel', 'Sensor connected');
    });
    for (const reinstall of [true, false]) {
      await test.step(reinstall ? 'Uninstall with NSIS and retain user data' : 'Remove the reinstalled package with NSIS', async () => {
        const retained = retainedFiles();
        const wizard = await openUninstaller(info, reinstall ? 'uninstall' : 'final-uninstall');
        await attach(info, 'NSIS uninstall action', wizard.invoke('Uninstall'));
        let state: ReturnType<typeof removalState>;
        await expect.poll(() => {
          state = removalState();
          return state.package_removed && state.runtime_removed && state.recovery_disabled
            && !state.registered && state.tasks.length === 0 && state.processes.length === 0;
        }, {timeout: 120_000, intervals: [500, 1000], message: 'NSIS removes the app, sensor runtimes, owned tasks, and registration'}).toBe(true);
        await screenshot(info, wizard.title, reinstall ? 'uninstaller-complete' : 'final-uninstaller-complete');
        await attach(info, 'NSIS finish action', wizard.invoke('Finish'));
        await wizard.closed();
        expect(retainedFiles()).toEqual(retained);
        appRemoved = true;
        await attach(info, 'Native package removal', {...state!, retained_files: Object.keys(retained),
          enrollment_and_agent_settings_retained: true,
          scope: 'Windows NSIS retains enrollment, user data, and agent hook settings for a later reinstall.'});
      });
      if (reinstall) await test.step('Reinstall the same package and restore the enrolled sensor and hooks', async () => {
        command(installer, ['/S'], {timeout: 120_000});
        expect(JSON.parse(command(app, ['--update-build-info']))).toEqual(expectedBuild);
        expect(JSON.parse(command(sensor, ['build-info']))).toEqual(expectedBuild);
        await launchApp();
        await expect.poll(() => {
          const status = bridge('status');
          return status.sensor_id === sensorId && status.running && status.control_ready && status.service === 'running'
            && status.service_version === expectedBuild.version && status.hooks?.codex?.current && status.hooks.codex.trusted;
        }, {timeout: 90_000, intervals: [1000, 2000], message: 'Reinstall restores the same enrollment, service version, and trusted Codex hooks'}).toBe(true);
        collectCredentials();
        expect(bridge('usage.summary', {days: 30}).summary.tokens, 'Local usage survives package removal').toBeGreaterThan(0);
        await screenshot(info, 'OpenAIDR', 'app-reinstalled', 'Codex');
        await attach(info, 'Reinstalled sensor', bridge('status'));
      });
    }
    await native.coverage(info, true);
  });
});
