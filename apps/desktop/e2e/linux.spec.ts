import {test, expect, request, type APIRequestContext, type Page, type TestInfo} from '@playwright/test';
import {spawn, execFileSync, type ChildProcess} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {NativeUI} from './native-ui';
import {exerciseAppControls, exerciseAppAlerts} from './native-flows';
import {dashboardFixtures, walkDashboard} from './dashboard';

const root = path.resolve(import.meta.dirname, '../../..');
const origin = 'http://127.0.0.1:8080';
const apiKey = process.env.E2E_OPENAI_API_KEY || '';
const secrets = [apiKey].filter(Boolean);
const cleanEnv = {...process.env};
for (const key of ['E2E_CLAUDE_TOKEN', 'E2E_OPENAI_API_KEY', 'OPENAI_API_KEY', 'CODEX_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN']) delete cleanEnv[key];
let temporary = '';
let app = '';
let sensor = '';
let sensorId = '';
let api: APIRequestContext;
let postgresStarted = false;
let nativeApi: APIRequestContext;
let nativeSession = '';
let packageName = '';
let installer = '';
let packageInstalled = false;
const config = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'openaidr/sensor.yaml');
const dataDirectory = path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local/share'), 'openaidr');
const preferences = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'),
  'com.opensecura.openaidr.sensor/desktop-preferences.json');
const serviceUnit = path.join(os.homedir(), '.config/systemd/user/openaidr.service');
const unsupportedRemoval = Object.fromEntries(['#remove-app', '#resume-app', '#trash-app', '#cancel-remove', '#confirm-remove']
  .map(selector => [selector, 'Linux uses packaged CLI cleanup and DEB removal; in-app removal is not supported.']));
const processes: {name: string; process: ChildProcess}[] = [];
const browserErrors: string[] = [];
const ui = new NativeUI(redact, {evaluate: nativeScript, click: nativeClick, fill: async (selector, value) => {
  const element = await nativeElement(selector);
  await native(`element/${element}/clear`, 'POST', {});
  await native(`element/${element}/value`, 'POST', {text: value});
}}, unsupportedRemoval);

function redact(value: string): string {
  for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) value = value.split(secret).join('[REDACTED]');
  return value.replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|oa(?:et|st)_[A-Za-z0-9_-]{20,})/g, '[REDACTED]');
}

function command(file: string, args: string[], options: {input?: string; env?: NodeJS.ProcessEnv; cwd?: string; timeout?: number} = {}): string {
  try {
    return execFileSync(file, args, {encoding: 'utf8', env: cleanEnv, timeout: 30_000,
      maxBuffer: 8 * 1024 * 1024, ...options}).trim();
  } catch (error) {
    throw new Error(redact(String(error)));
  }
}

function start(name: string, file: string, args: string[], env = cleanEnv) {
  const log = fs.openSync(path.join(temporary, `${name}.log`), 'a');
  const child = spawn(file, args, {cwd: root, env, stdio: ['ignore', log, log], detached: true});
  fs.closeSync(log);
  child.on('error', error => fs.appendFileSync(path.join(temporary, `${name}.log`), redact(String(error))));
  processes.push({name, process: child});
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

async function waitHttp(url: string) {
  await expect.poll(async () => {
    try { return (await fetch(url, {signal: AbortSignal.timeout(2000)})).ok; } catch { return false; }
  }, {timeout: 60_000, intervals: [500, 1000], message: `Service ready: ${url}`}).toBe(true);
}

async function native(route: string, method = 'POST', data?: unknown): Promise<any> {
  try {
    const response = await nativeApi.fetch(`/session/${nativeSession}/${route}`, {method, data, timeout: 30_000});
    const body = await response.json();
    if (!response.ok() || body.value?.error) throw new Error(`Native app ${route}: ${JSON.stringify(body.value)}`);
    return body.value;
  } catch (error) { throw new Error(redact(String(error))); }
}

function nativeScript(script: string, args: unknown[] = []): Promise<any> {
  return native('execute/sync', 'POST', {script, args});
}

async function nativeElement(selector: string): Promise<string> {
  const element = await native('element', 'POST', {using: 'css selector', value: selector});
  return element['element-6066-11e4-a52e-4f735466cecf'];
}

async function nativeClick(selector: string) {
  await nativeScript("document.querySelector(arguments[0]).scrollIntoView({block: 'center', inline: 'nearest'})", [selector]);
  await native(`element/${await nativeElement(selector)}/click`, 'POST', {});
}

async function nativeCommand(command: string, args = {}): Promise<any> {
  const result = await native('execute/async', 'POST', {script: `const done = arguments[arguments.length - 1];
    window.__TAURI_INTERNALS__.invoke(arguments[0], arguments[1])
      .then(value => done({value}), error => done({error:String(error)}));`, args: [command, args]});
  if (result.error) throw new Error(redact(result.error));
  return result.value;
}

async function openApp() {
  const session = await nativeApi.post('/session', {data: {capabilities: {alwaysMatch: {'tauri:options': {application: app}}}}});
  expect(session.ok(), 'WebDriver launches the installed app').toBe(true);
  nativeSession = (await session.json()).value.sessionId;
  expect(nativeSession).toBeTruthy();
  await ui.connect();
  expect(await nativeCommand('sensor_request', {request: {action: 'desktop.capabilities'}}))
    .toEqual({removal_supported: false, native_uninstaller: false});
  for (const selector of Object.keys(unsupportedRemoval)) await ui.visible(selector, false);
}

async function closeApp(alreadyExited = false) {
  if (!nativeSession) return;
  const response = await nativeApi.delete(`/session/${nativeSession}`);
  expect(response.ok() || (alreadyExited && response.status() === 404), 'Native app session closes cleanly').toBe(true);
  nativeSession = '';
}

async function appScreenshot(info: TestInfo, name: string) {
  // Failure capture can happen during enrollment. Never retain a credential field.
  await nativeScript("document.querySelectorAll('input[type=password], #enrollment-link').forEach(input => { input.value = ''; })");
  const file = info.outputPath(`${name}.png`);
  fs.writeFileSync(file, Buffer.from(await native('screenshot', 'GET'), 'base64'));
  expect(fs.statSync(file).size, 'Native app screenshot must contain image data').toBeGreaterThan(1000);
  await info.attach(`${name} (${new Date().toISOString()})`, {path: file, contentType: 'image/png'});
}

async function terminalScreenshot(info: TestInfo, title: string, name: string) {
  let window = '';
  await expect.poll(() => {
    try { window = command('xdotool', ['search', '--onlyvisible', '--name', `^${title}$`]).split('\n')[0]; return Boolean(window); }
    catch { return false; }
  }, {timeout: 15_000, message: 'The real agent terminal becomes visible'}).toBe(true);
  const file = info.outputPath(`${name}.png`);
  command('import', ['-window', window, file]);
  expect(fs.statSync(file).size).toBeGreaterThan(1000);
  await info.attach(`${name} (${new Date().toISOString()})`, {path: file, contentType: 'image/png'});
}

function collectSensorSecrets() {
  if (!fs.existsSync(config)) return;
  const credentials = JSON.parse(command('python3', ['-c',
    'import json,sys,yaml; c=yaml.safe_load(open(sys.argv[1])); print(json.dumps([c.get("sensor_token",""),c.get("telemetry",{}).get("local_token","")]))', config]));
  secrets.push(...credentials.filter(Boolean));
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

test.describe('Linux installed application', () => {
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
      collectSensorSecrets();
      for (const name of ['backend', 'intelligence', 'dashboard', 'webdriver', 'postgres']) {
        const file = path.join(temporary, `${name}.log`);
        if (fs.existsSync(file)) {
          const log = fs.readFileSync(file, 'utf8');
          await attach(info, `${name}.log`, log);
          if (/^ERROR[: ]|^Traceback \(most recent call last\):|^thread .* panicked at/m.test(log))
            runtimeErrors.push(`${name} logged an error, traceback, or panic`);
        }
      }
      for (const name of ['sensor.log', 'sensor.err.log']) {
        const file = path.join(dataDirectory, name);
        if (fs.existsSync(file)) await attach(info, name, fs.readFileSync(file, 'utf8'));
      }
    }
    for (const {name, process: child} of processes) {
      if (!child.pid || child.exitCode !== null || child.signalCode !== null) runtimeErrors.push(`${name} process exited`);
    }
    if (sensor && fs.existsSync(sensor)) {
      try { await attach(info, 'Sensor status', bridge('status')); }
      catch (error) { await attach(info, 'Sensor status error', String(error)); }
    }
    if (info.status !== info.expectedStatus) {
      try { if (nativeSession) await appScreenshot(info, 'app-at-failure'); }
      catch (error) { await attach(info, 'App capture failure', String(error)); }
      try {
        await info.attach('Dashboard at failure', {body: await page.screenshot({fullPage: true}), contentType: 'image/png'});
      } catch (error) { await attach(info, 'Dashboard capture failure', String(error)); }
    }
    await attach(info, 'Browser errors', browserErrors);
    await attach(info, 'Runtime errors', runtimeErrors);
    if (info.status === 'passed') {
      if (nativeSession) await ui.healthy();
      expect(browserErrors, 'Dashboard must have no browser errors or HTTP 5xx responses').toEqual([]);
      expect(runtimeErrors, 'App, backend, and dashboard must stay healthy').toEqual([]);
    }
    await ui.coverage(info);
  });

  test.afterAll(async () => {
    if (!temporary) return;
    // Close the native app before stopping its service, so auto-setup cannot restart it.
    try {
      await closeApp();
    } finally {
      if (nativeApi) await nativeApi.dispose();
      try {
        if (sensor && fs.existsSync(sensor)) command(sensor, ['stop']);
      } finally {
        for (const {process: child} of processes.reverse()) {
          if (child.pid) { try { process.kill(-child.pid, 'SIGTERM'); } catch { /* Already exited. */ } }
        }
        if (api) await api.dispose();
        if (postgresStarted) command('pg_ctl', ['-D', path.join(temporary, 'postgres'), '-m', 'immediate', 'stop']);
        if (packageInstalled) command('sudo', ['apt-get', 'purge', '-y', packageName], {timeout: 120_000});
        fs.rmSync(temporary, {recursive: true, force: true});
      }
    }
  });

  test('Install DEB, enroll through the native app, and connect the sensor', async ({page}, info) => {
    expect(process.platform).toBe('linux');
    expect(process.getuid!(), 'Use a non-root desktop account').not.toBe(0);
    expect(process.env.GITHUB_ACTIONS, 'This suite changes the test account and must run in a disposable hosted VM').toBe('true');
    expect(process.env.RUNNER_ENVIRONMENT).toBe('github-hosted');
    expect(process.env.E2E_BUILD_OUTCOME, 'The app and dashboard build must succeed first').toBe('success');
    expect(Boolean(apiKey), 'Missing Codex credentials').toBe(true);
    for (const existing of ['/usr/bin/openaidr-desktop', path.dirname(config), dataDirectory,
      path.dirname(preferences), serviceUnit]) {
      expect(fs.existsSync(existing), `The VM must not contain previous OpenAIDR state: ${existing}`).toBe(false);
    }
    command('systemctl', ['--user', 'show-environment']);
    temporary = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP!, 'openaidr-private-'));
    fs.chmodSync(temporary, 0o700);
    const password = randomUUID();
    secrets.push(password);
    const env: NodeJS.ProcessEnv = {...cleanEnv, OPENAIDR_DATABASE_URL: 'postgresql://e2e@127.0.0.1:55432/openaidr',
      OPENAIDR_LISTEN: '127.0.0.1:8081', OPENAIDR_PUBLIC_URL: origin,
      OPENAIDR_SERVICES: 'ingest,api,detect', OPENAIDR_REQUIRE_TENANT: 'true', OPENAIDR_AUTH_MODE: 'local'};
    await test.step('Start an isolated database, real backend, and built dashboard', async () => {
      const pg = path.join(temporary, 'postgres');
      command('initdb', ['-D', pg, '-U', 'e2e', '--auth=trust', '--no-locale', '--encoding=UTF8']);
      command('pg_ctl', ['-D', pg, '-l', path.join(temporary, 'postgres.log'), '-o', '-h 127.0.0.1 -p 55432 -c timezone=UTC -c unix_socket_directories=', '-w', 'start']);
      postgresStarted = true;
      command('createdb', ['-h', '127.0.0.1', '-p', '55432', '-U', 'e2e', 'openaidr']);
      const tenant = JSON.parse(command('openaidr-server', ['tenant', 'bootstrap', '--name', 'OpenAIDR E2E',
        '--slug', 'linux-e2e', '--max-uses', '1', '--json'], {env, timeout: 120_000}));
      secrets.push(tenant.enrollment_token);
      env.OPENAIDR_TENANT_ID = tenant.tenant_id;
      const intelligenceScript = path.join(root, 'scripts/e2e_intelligence.py');
      const intelligenceDirectory = path.join(temporary, 'intelligence');
      const connection = JSON.parse(command('python3', [intelligenceScript, 'prepare', intelligenceDirectory, tenant.tenant_id]));
      secrets.push(connection.api_key);
      Object.assign(env, {OPENAIDR_INTELLIGENCE_ORIGIN: connection.origin,
        OPENAIDR_INTELLIGENCE_API_KEY: connection.api_key, OPENAIDR_INTELLIGENCE_CA_FILE: connection.ca_file});
      start('intelligence', 'python3', [intelligenceScript, 'serve', intelligenceDirectory]);
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
    await test.step('Install the unsigned DEB and open its native WebKit window', async () => {
      const directory = path.join(root, 'apps/desktop/src-tauri/target/release/bundle/deb');
      const packages = fs.readdirSync(directory).filter(name => name.endsWith('.deb'));
      expect(packages).toHaveLength(1);
      installer = path.join(directory, packages[0]);
      packageName = command('dpkg-deb', ['--field', installer, 'Package']);
      expect(packageName).toMatch(/^[a-z0-9][a-z0-9+.-]+$/);
      packageInstalled = true;
      command('sudo', ['apt-get', 'install', '-y', installer], {timeout: 120_000});
      app = '/usr/bin/openaidr-desktop';
      sensor = '/usr/bin/openaidr';
      const build = JSON.parse(fs.readFileSync(path.join(root, 'build/desktop/_build.json'), 'utf8'));
      expect(build.source_commit).toBe(process.env.GITHUB_SHA);
      expect(packages[0]).toContain(build.version);
      expect(JSON.parse(command(sensor, ['build-info']))).toEqual(build);
      expect(JSON.parse(command(app, ['--update-build-info']))).toEqual(build);
      await attach(info, 'Build and environment', {build, Linux: command('uname', ['-a']),
        codex: command('codex', ['--version']), selected: 'codex', installer: packages[0],
        dashboard_branding: 'Neutral E2E palette; private marks omitted'});
      start('window-manager', 'openbox', []);
      start('webdriver', 'tauri-driver', []);
      await waitHttp('http://127.0.0.1:4444/status');
      nativeApi = await request.newContext({baseURL: 'http://127.0.0.1:4444'});
      await openApp();
      await ui.startup(info);
      await appScreenshot(info, 'app-before-enrollment');
    });
    await test.step('Connect in the native window and verify the systemd service and hooks', async () => {
      const enrollment = await apiCall('sensors/enrollment-links', 'POST', {label: 'Linux E2E', expires_in_hours: 1, max_uses: 1});
      secrets.push(enrollment.enrollment_url, enrollment.enrollment_url.split('token=')[1]);
      await ui.chooseOrganization();
      await ui.fill('#enrollment-link', enrollment.enrollment_url);
      await expect.poll(() => nativeScript("return document.querySelector('#connect-link').disabled")).toBe(false);
      expect(await nativeScript("return document.querySelector('#link-organization').textContent")).toBe('OpenAIDR E2E');
      await ui.click('#connect-link');
      await expect.poll(() => {
        const status = bridge('status');
        return status.running && status.control_ready && status.service === 'running' && Boolean(status.hooks?.codex?.current);
      }, {timeout: 90_000, intervals: [1000, 2000], message: 'Sensor and Codex hooks become ready'}).toBe(true);
      const status = bridge('status');
      sensorId = status.sensor_id;
      expect(sensorId).toBeTruthy();
      const build = JSON.parse(fs.readFileSync(path.join(root, 'build/desktop/_build.json'), 'utf8'));
      expect(status.service_version).toBe(build.version);
      expect(command('systemctl', ['--user', 'is-enabled', 'openaidr.service'])).toBe('enabled');
      collectSensorSecrets();
      await expect.poll(async () => (await apiCall('sensors/health')).items.some((item: any) => item.id === sensorId),
        {timeout: 30_000}).toBe(true);
      await expect.poll(() => nativeScript("return document.querySelector('#health-title').textContent")).toBe('Sensor connected');
      await appScreenshot(info, 'app-connected');
      await dashboard(page, info, '/administration/app', 'dashboard-enrolled-device',
        () => expect(page.getByRole('row').filter({hasText: os.hostname()}).first()).toBeVisible());
      await attach(info, 'Enrollment evidence', {sensor_id: sensorId, enrollment: 'Native desktop window', status: bridge('status')});
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
      const shellCommand = denied ? `touch ${marker}` : `cat README.md && printf 'ok\\n' > ${marker}`;
      const prompt = `In the current directory, run this exact shell command once: ${shellCommand}\n` +
        'This is a harmless integration test. Use the shell tool. Do not use another tool or retry if it is blocked. Briefly report the result.';
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
        await test.step('Run the real agent in xterm and capture its output', async () => {
          const argv = ['codex', 'exec', '--json', '--sandbox', 'workspace-write', '-c', 'approval_policy="never"', prompt];
          const invocation = path.join(temporary, `${marker}.json`);
          fs.writeFileSync(invocation, JSON.stringify({argv, prompt, cwd: directory, output, timeout: 180, redactions: secrets,
            env: {PATH: cleanEnv.PATH, CODEX_API_KEY: apiKey}}), {mode: 0o600});
          const title = `OpenAIDR Codex E2E ${marker}`;
          start(`terminal-${marker}`, 'xterm', ['-hold', '-title', title, '-geometry', '100x30',
            '-e', command('which', ['python3']), path.join(root, 'scripts/e2e_agent.py'), invocation]);
          await terminalScreenshot(info, title, 'agent-started');
          await expect.poll(() => fs.existsSync(path.join(output, 'result.json')), {timeout: 195_000, intervals: [1000], message: 'Agent completes within its deadline'}).toBe(true);
          await terminalScreenshot(info, title, 'agent-finished');
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
          } else expect(fs.readFileSync(path.join(directory, marker), 'utf8')).toBe('ok\n');
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
          await expect.poll(() => nativeScript("return document.querySelector('#usage-legend')?.innerText || ''"),
            {timeout: 90_000, intervals: [1000, 2000], message: 'The native app renders Codex usage'}).toContain('Codex');
          await appScreenshot(info, 'app-after-agent');
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
      seedDetails: input => JSON.parse(command('python3', [path.join(root, 'scripts/e2e_dashboard_fixture.py'),
        'postgresql://e2e@127.0.0.1:55432/openaidr', path.join(temporary, 'intelligence/connection.json')], {input: JSON.stringify(input)}))});
    await page.context().addCookies((await api.storageState()).cookies);
    await walkDashboard(page, info, origin, details);
  });

  test('Native controls and tray preference preserve the Linux no-host behavior', async ({}, info) => {
    await exerciseAppControls({native: ui, screenshot: name => appScreenshot(info, name), sensorId,
      sensorStatus: () => bridge('status'), publicCertificate: command('python3', ['-c',
        'import certifi; print(open(certifi.where()).read().split("-----END CERTIFICATE-----")[0]+"-----END CERTIFICATE-----")'])});
    await test.step('The system-tray preference persists when Openbox has no tray host', async () => {
      await ui.click('#change-connection');
      await ui.text('#menu-bar-setting label span', 'Show in system tray');
      await ui.text('#menu-bar-description', 'No system tray is available');
      expect(await nativeCommand('menu_bar_settings')).toMatchObject({supported: true, available: false, enabled: false});
      await ui.click('#show-menu-bar');
      await ui.wait('const input = document.querySelector("#show-menu-bar"); return !input.disabled && input.checked;');
      expect(JSON.parse(fs.readFileSync(preferences, 'utf8')).show_in_menu_bar).toBe(true);
      await appScreenshot(info, 'app-tray-host-unavailable');
      await ui.click('#cancel-change');
      await ui.healthy();
      const windows = command('xdotool', ['search', '--onlyvisible', '--name', '^OpenAIDR$']).split('\n');
      expect(windows).toHaveLength(1);
      const pid = Number(command('xdotool', ['getwindowpid', windows[0]]));
      expect(pid).toBeGreaterThan(0);
      // Openbox sends the normal close request. Destroying an X window directly
      // would not verify the app's unavailable-tray fallback.
      command('xdotool', ['windowactivate', '--sync', windows[0]]);
      command('xdotool', ['key', '--clearmodifiers', 'alt+F4']);
      await expect.poll(() => {
        try { process.kill(pid, 0); return true; }
        catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false; throw error; }
      }, {timeout: 30_000, message: 'Closing without a tray host exits the app'}).toBe(false);
      await closeApp(true);
      expect(bridge('status')).toMatchObject({sensor_id: sensorId, running: true, control_ready: true});
      await openApp();
      await ui.click('#change-connection');
      expect(await nativeCommand('menu_bar_settings')).toMatchObject({supported: true, available: false, enabled: true});
      await ui.wait('return document.querySelector("#show-menu-bar").checked;');
      await ui.click('#show-menu-bar');
      await ui.wait('const input = document.querySelector("#show-menu-bar"); return !input.disabled && !input.checked;');
      expect(JSON.parse(fs.readFileSync(preferences, 'utf8')).show_in_menu_bar).toBe(false);
      await ui.click('#cancel-change');
      await attach(info, 'Linux tray behavior', {supported: true, available: false, host: 'Openbox without a StatusNotifier host',
        preference_survived_reopen: true, close_exited_app: true, sensor_kept_running: true,
        host_present_coverage: 'apps/desktop/src-tauri/tests/linux_tray.rs'});
    });
  });

  test('Native alert controls acknowledge a real backend alert', async ({}, info) => {
    await exerciseAppAlerts({native: ui, screenshot: name => appScreenshot(info, name), apiCall, sensorId});
  });

  test('Linux package removal and reinstall preserve enrollment, data, and agent opt-outs', async ({}, info) => {
    const retained = path.join(dataDirectory, 'e2e-retained-state.txt');
    const retainedText = 'Retain this owned test file through DEB removal and reinstall.\n';
    fs.writeFileSync(retained, retainedText);
    const savedPreferences = fs.readFileSync(preferences);
    const recordedTokens = bridge('usage.summary', {days: 30}).summary.tokens;
    expect(recordedTokens).toBeGreaterThan(0);
    await test.step('Native removal controls are unsupported on Linux', async () => {
      expect(await nativeCommand('sensor_request', {request: {action: 'desktop.capabilities'}}))
        .toEqual({removal_supported: false, native_uninstaller: false});
      for (const selector of Object.keys(unsupportedRemoval)) await ui.visible(selector, false);
      await appScreenshot(info, 'app-before-package-removal');
      await ui.healthy();
      await ui.coverage(info, true);
      await attach(info, 'Linux removal support', {removal_supported: false, controls: unsupportedRemoval,
        procedure: 'Packaged CLI disconnects agents and removes the user service, then apt purges the DEB.'});
    });
    for (const reinstall of [true, false]) {
      await test.step(reinstall ? 'Remove the DEB while retaining user state' : 'Remove the reinstalled DEB and its agent connections', async () => {
        await closeApp();
        command(sensor, ['hook', 'uninstall', '--agent', 'all']);
        command(sensor, ['telemetry', 'remove', '--agent', 'all']);
        command(sensor, ['uninstall']);
        await expect.poll(() => {
          const status = bridge('status');
          return status.service === 'not installed' && !status.running && !status.hooks?.codex?.installed &&
            !status.telemetry?.codex_installed;
        }, {timeout: 30_000, message: 'Packaged cleanup removes the user service and Codex hooks'}).toBe(true);
        expect(fs.existsSync(serviceUnit)).toBe(false);
        const disconnected = JSON.parse(command('python3', ['-c',
          'import json,sys,yaml; c=yaml.safe_load(open(sys.argv[1])); print(json.dumps({key:c.get(key,{}).get("disabled_agents",[]) for key in ("hooks","telemetry")}))', config]));
        expect(disconnected.hooks).toContain('codex');
        expect(disconnected.telemetry).toContain('codex');
        const retainedConfig = fs.readFileSync(config);
        command('sudo', ['apt-get', 'purge', '-y', packageName], {timeout: 120_000});
        packageInstalled = false;
        for (const file of [app, sensor, '/usr/bin/openaidr-sensor']) expect(fs.existsSync(file)).toBe(false);
        expect(fs.readFileSync(config).equals(retainedConfig), 'DEB purge retains enrollment and explicit opt-outs').toBe(true);
        expect(fs.readFileSync(retained, 'utf8')).toBe(retainedText);
        expect(fs.readFileSync(preferences).equals(savedPreferences)).toBe(true);
        await attach(info, reinstall ? 'First DEB removal' : 'Final DEB removal', {package_removed: true,
          service_removed: true, codex_hooks_removed: true, enrollment_config_retained: true,
          user_data_retained: true, desktop_preferences_retained: true, explicit_opt_outs: disconnected});
      });
      if (reinstall) await test.step('Reinstall preserves opt-outs until Codex is explicitly reconnected', async () => {
        packageInstalled = true;
        command('sudo', ['apt-get', 'install', '-y', installer], {timeout: 120_000});
        const build = JSON.parse(fs.readFileSync(path.join(root, 'build/desktop/_build.json'), 'utf8'));
        expect(JSON.parse(command(app, ['--update-build-info']))).toEqual(build);
        expect(JSON.parse(command(sensor, ['build-info']))).toEqual(build);
        await openApp();
        await expect.poll(() => {
          const status = bridge('status');
          return status.sensor_id === sensorId && status.running && status.control_ready && status.service === 'running';
        }, {timeout: 90_000, message: 'The reinstalled app restores the same enrolled user service'}).toBe(true);
        expect(command('systemctl', ['--user', 'is-enabled', 'openaidr.service'])).toBe('enabled');
        const status = bridge('status');
        expect(status.service_version).toBe(build.version);
        expect(status.hooks.codex.installed, 'Reinstall must preserve the explicit hook opt-out').toBe(false);
        expect(status.telemetry).toMatchObject({codex_installed: false, codex_opted_out: true});
        expect(fs.readFileSync(retained, 'utf8')).toBe(retainedText);
        expect(fs.readFileSync(preferences).equals(savedPreferences)).toBe(true);
        expect(bridge('usage.summary', {days: 30}).summary.tokens, 'Collected usage survives reinstall').toBeGreaterThanOrEqual(recordedTokens);
        command(sensor, ['hook', 'install', '--agent', 'codex']);
        command(sensor, ['telemetry', 'install', '--agent', 'codex']);
        await expect.poll(() => {
          const status = bridge('status');
          return Boolean(status.hooks?.codex?.current && status.telemetry?.codex_current);
        }, {timeout: 30_000, message: 'Explicit reconnection restores current Codex hooks and telemetry'}).toBe(true);
        await ui.text('#health-title', 'Sensor connected');
        await ui.healthy();
        await appScreenshot(info, 'app-reinstalled');
        await attach(info, 'Linux reinstall', {sensor_id: sensorId, build, service: bridge('status').service,
          user_data_retained: true, recorded_tokens_retained: recordedTokens,
          opt_out_preserved: true, codex_explicitly_reconnected: true});
      });
    }
  });
});
