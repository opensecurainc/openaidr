import {test, expect, request, type APIRequestContext, type Page, type TestInfo} from '@playwright/test';
import {spawn, execFileSync, type ChildProcess} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';

const root = path.resolve(import.meta.dirname, '../../..');
const origin = 'http://127.0.0.1:8080';
const selected = process.env.E2E_AGENTS || 'claude';
const agentSecrets = {claude: process.env.E2E_CLAUDE_TOKEN || '', codex: process.env.E2E_OPENAI_API_KEY || ''};
const secrets = Object.values(agentSecrets).filter(Boolean);
const cleanEnv = {...process.env};
for (const key of ['E2E_CLAUDE_TOKEN', 'E2E_OPENAI_API_KEY', 'OPENAI_API_KEY', 'CODEX_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN']) delete cleanEnv[key];
let temporary = '';
let app = '';
let sensor = '';
let sensorId = '';
let api: APIRequestContext;
let postgresStarted = false;
const processes: {name: string; process: ChildProcess}[] = [];
const browserErrors: string[] = [];
const chosen = (agent: string) => selected === 'both' || selected === agent;

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
  const response = await api.fetch(`/api/v1/${route}`, {method, data, maxRetries: 2});
  if (!response.ok()) throw new Error(`Backend ${method} ${route} returned HTTP ${response.status()}`);
  return response.status() === 204 ? null : response.json();
}

async function waitHttp(url: string) {
  await expect.poll(async () => {
    try { return (await fetch(url, {signal: AbortSignal.timeout(2000)})).ok; } catch { return false; }
  }, {timeout: 60_000, intervals: [500, 1000], message: `Service ready: ${url}`}).toBe(true);
}

async function screenshot(info: TestInfo, owner: string, name: string, expectedText?: string) {
  const helper = path.join(process.env.RUNNER_TEMP!, 'e2e-window');
  let windowId = '';
  await expect.poll(() => {
    try {
      // Launch Services can reject activation while a newly spawned app registers.
      if (owner === 'OpenAIDR') command('open', ['-a', app]);
      else command('open', ['-a', 'Terminal']);
      windowId = command(helper, [owner]);
      return /^\d+$/.test(windowId);
    } catch { return false; }
  }, {timeout: 15_000, message: `A visible ${owner} window must be available`}).toBe(true);
  const file = info.outputPath(`${name}.png`);
  const capture = () => command('/usr/sbin/screencapture', ['-x', '-o', '-l', windowId, file]);
  if (expectedText) {
    // The app caches usage for one minute. Wait for its actual rendered state.
    await expect.poll(() => {
      capture();
      return command(helper, ['--text', file], {timeout: 60_000});
    }, {timeout: 90_000, intervals: [1000, 2000], message: `${owner} displays ${expectedText}`}).toContain(expectedText);
  } else capture();
  expect(fs.statSync(file).size, `${owner} screenshot must contain image data`).toBeGreaterThan(1000);
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

test.describe('macOS installed application', () => {
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
      for (const name of ['backend', 'dashboard', 'app', 'postgres']) {
        const file = path.join(temporary, `${name}.log`);
        if (fs.existsSync(file)) {
          const log = fs.readFileSync(file, 'utf8');
          await attach(info, `${name}.log`, log);
          if (/^ERROR[: ]|^Traceback \(most recent call last\):|^thread .* panicked at/m.test(log))
            runtimeErrors.push(`${name} logged an error, traceback, or panic`);
        }
      }
      for (const name of ['sensor.log', 'sensor.err.log']) {
        const file = path.join(os.homedir(), 'Library/Application Support/OpenAIDR/data', name);
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
      try { if (app) await screenshot(info, 'OpenAIDR', 'app-at-failure'); }
      catch (error) { await attach(info, 'App capture failure', String(error)); }
      try {
        await info.attach('Dashboard at failure', {body: await page.screenshot({fullPage: true}), contentType: 'image/png'});
      } catch (error) { await attach(info, 'Dashboard capture failure', String(error)); }
    }
    await attach(info, 'Browser errors', browserErrors);
    await attach(info, 'Runtime errors', runtimeErrors);
    if (info.status === 'passed') {
      expect(browserErrors, 'Dashboard must have no browser errors or HTTP 5xx responses').toEqual([]);
      expect(runtimeErrors, 'App, backend, and dashboard must stay healthy').toEqual([]);
    }
  });

  test.afterAll(async () => {
    if (!temporary) return;
    if (sensor && fs.existsSync(sensor)) {
      try { command(sensor, ['stop']); } catch { /* The VM is discarded even if launchd has already stopped. */ }
    }
    for (const {process: child} of processes.reverse()) {
      if (child.pid) { try { process.kill(-child.pid, 'SIGTERM'); } catch { /* Already exited. */ } }
    }
    if (api) await api.dispose();
    if (postgresStarted) command('pg_ctl', ['-D', path.join(temporary, 'postgres'), '-m', 'immediate', 'stop']);
    fs.rmSync(temporary, {recursive: true, force: true});
  });

  test('Install DMG, enroll the packaged sensor, and connect the app', async ({page}, info) => {
    expect(process.platform).toBe('darwin');
    expect(process.env.GITHUB_ACTIONS, 'This suite changes the test account and must run in a disposable hosted VM').toBe('true');
    expect(process.env.RUNNER_ENVIRONMENT).toBe('github-hosted');
    expect(process.env.E2E_BUILD_OUTCOME, 'The app and dashboard build must succeed first').toBe('success');
    expect(['claude', 'codex', 'both']).toContain(selected);
    for (const agent of ['claude', 'codex'] as const) {
      if (chosen(agent)) expect(Boolean(agentSecrets[agent]), `Missing ${agent} credentials`).toBe(true);
    }
    expect(fs.existsSync(path.join(os.homedir(), 'Library/Application Support/OpenAIDR')), 'The VM must not contain a previous installation').toBe(false);
    temporary = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP!, 'openaidr-private-'));
    fs.chmodSync(temporary, 0o700);
    const password = randomUUID();
    secrets.push(password);
    const tenantFile = path.join(temporary, 'tenant_id');
    const env = {...cleanEnv, OPENAIDR_DATABASE_URL: 'postgresql://e2e@127.0.0.1:55432/openaidr',
      OPENAIDR_LISTEN: '127.0.0.1:8081', OPENAIDR_PUBLIC_URL: origin, OPENAIDR_TENANT_ID_FILE: tenantFile,
      OPENAIDR_REQUIRE_TENANT: 'true', OPENAIDR_SERVICES: 'ingest,api,detect'};
    await test.step('Start an isolated database, real backend, and built dashboard', async () => {
      const pg = path.join(temporary, 'postgres');
      command('initdb', ['-D', pg, '-U', 'e2e', '--auth=trust', '--no-locale', '--encoding=UTF8']);
      command('pg_ctl', ['-D', pg, '-l', path.join(temporary, 'postgres.log'), '-o', '-h 127.0.0.1 -p 55432 -c timezone=UTC', '-w', 'start']);
      postgresStarted = true;
      command('createdb', ['-h', '127.0.0.1', '-p', '55432', '-U', 'e2e', 'openaidr']);
      // The same bootstrap as compose.yaml: one workspace and its owner, bound through the tenant file.
      command('python3', [path.join(root, 'scripts/local_bootstrap.py'), '--email', 'e2e@example.test',
        '--tenant-name', 'OpenAIDR E2E', '--tenant-file', tenantFile],
        {env: {...env, OPENAIDR_TENANT_ID_FILE: '', OPENAIDR_REQUIRE_TENANT: 'false', OPENAIDR_ADMIN_PASSWORD: password}});
      start('backend', 'openaidr-server', ['serve'], env);
      await waitHttp('http://127.0.0.1:8081/readyz');
      start('dashboard', 'node', [path.join(root, 'apps/dashboard/.next/standalone/apps/dashboard/server.js')],
        {...cleanEnv, PORT: '8080', HOSTNAME: '127.0.0.1'});
      await waitHttp(origin + '/login');
      api = await request.newContext({baseURL: origin, extraHTTPHeaders: {'X-OpenAIDR-CSRF': '1', Origin: origin}});
      await apiCall('auth/login', 'POST', {email: 'e2e@example.test', password});
      for (const cookie of (await api.storageState()).cookies) secrets.push(cookie.value);
    });
    await test.step('Install the unsigned DMG and launch its native app', async () => {
      const directory = path.join(root, 'apps/desktop/src-tauri/target/release/bundle/dmg');
      const images = fs.readdirSync(directory).filter(name => name.endsWith('.dmg'));
      expect(images).toHaveLength(1);
      const mount = path.join(temporary, 'installer');
      fs.mkdirSync(mount);
      command('hdiutil', ['attach', '-nobrowse', '-readonly', '-mountpoint', mount, path.join(directory, images[0])]);
      try {
        const bundles = fs.readdirSync(mount).filter(name => name.endsWith('.app'));
        expect(bundles).toHaveLength(1);
        app = path.join(os.homedir(), 'Applications', bundles[0]);
        expect(fs.existsSync(app), 'Do not replace an existing app').toBe(false);
        command('ditto', [path.join(mount, bundles[0]), app]);
      } finally { command('hdiutil', ['detach', mount]); }
      const executable = command('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleExecutable', path.join(app, 'Contents/Info.plist')]);
      start('app', path.join(app, 'Contents/MacOS', executable), []);
      sensor = path.join(app, 'Contents/MacOS/openaidr');
      await screenshot(info, 'OpenAIDR', 'app-before-enrollment', 'Enrollment link');
      const build = JSON.parse(command(sensor, ['build-info']));
      expect(build.source_commit).toBe(process.env.GITHUB_SHA);
      await attach(info, 'Build and environment', {build, macOS: command('sw_vers', []),
        claude: command('claude', ['--version']), codex: command('codex', ['--version']), selected});
    });
    await test.step('Connect through the packaged enrollment bridge and verify live hooks', async () => {
      const enrollment = await apiCall('sensors/enrollment-links', 'POST', {label: 'macOS E2E', expires_in_hours: 1, max_uses: 1});
      secrets.push(enrollment.enrollment_url, enrollment.enrollment_url.split('token=')[1]);
      const preview = bridge('enrollment.preview', {link: enrollment.enrollment_url});
      const connected = bridge('enrollment.connect', {link: enrollment.enrollment_url, tenant_id: preview.tenant.id});
      sensorId = connected.sensor_id;
      // The native window also runs setup. Poll it instead of racing that mutation.
      await expect.poll(() => {
        const status = bridge('status');
        return status.running && status.control_ready && ['claude', 'codex'].filter(chosen).every(agent => status.hooks?.[agent]?.current);
      }, {timeout: 90_000, intervals: [1000, 2000], message: 'Sensor and selected agent hooks become ready'}).toBe(true);
      // Keep the disposable sensor's bearer and receiver tokens out of diagnostics too.
      const credentials = JSON.parse(command('python3', ['-c',
        'import json,pathlib,yaml; c=yaml.safe_load((pathlib.Path.home()/"Library/Application Support/OpenAIDR/sensor.yaml").read_text()); print(json.dumps([c.get("sensor_token",""),c.get("telemetry",{}).get("local_token","")]))']));
      secrets.push(...credentials.filter(Boolean));
      await expect.poll(async () => (await apiCall('sensors/health')).items.some((item: any) => item.id === sensorId),
        {timeout: 30_000}).toBe(true);
      await screenshot(info, 'OpenAIDR', 'app-connected', 'Connected');
      await dashboard(page, info, '/administration/app', 'dashboard-enrolled-device',
        () => expect(page.getByRole('row').filter({hasText: os.hostname()}).first()).toBeVisible());
      await attach(info, 'Enrollment evidence', {sensor_id: sensorId, enrollment: 'Packaged desktop bridge', status: bridge('status')});
    });
  });

  for (const agent of ['claude', 'codex'] as const) {
    for (const denied of [false, true]) {
      test(`${agent}: ${denied ? 'enforced command is blocked' : 'allowed command and usage reach the dashboard'}`, async ({page}, info) => {
        test.skip(!chosen(agent), `${agent} was not selected for this run`);
        const product = agent === 'claude' ? 'claude-code' : 'codex-cli';
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
          await test.step('Run the real agent in Terminal and capture its output', async () => {
            const argv = agent === 'claude'
              ? ['claude', '-p', prompt, '--output-format', 'stream-json', '--verbose', '--allowedTools', 'Bash,Read', '--max-turns', '6', '--max-budget-usd', '1']
              : ['codex', 'exec', '--json', '--sandbox', 'workspace-write', '-c', 'approval_policy="never"', prompt];
            const invocation = path.join(temporary, `${marker}.json`);
            fs.writeFileSync(invocation, JSON.stringify({argv, prompt, cwd: directory, output, timeout: 180, redactions: secrets,
              env: {PATH: cleanEnv.PATH, ...(agent === 'claude' ? {CLAUDE_CODE_OAUTH_TOKEN: agentSecrets.claude} : {CODEX_API_KEY: agentSecrets.codex})}}), {mode: 0o600});
            const quote = (text: string) => "'" + text.replaceAll("'", "'\\''") + "'";
            const shell = [command('which', ['python3']), path.join(root, 'scripts/e2e_agent.py'), invocation].map(quote).join(' ');
            const launcher = path.join(temporary, `${marker}.command`);
            fs.writeFileSync(launcher, `#!/bin/bash\nexec ${shell}\n`, {mode: 0o700});
            command('open', ['-a', 'Terminal', launcher]);
            await screenshot(info, 'Terminal', 'agent-started');
            await expect.poll(() => fs.existsSync(path.join(output, 'result.json')), {timeout: 195_000, intervals: [1000], message: 'Agent completes within its deadline'}).toBe(true);
            await screenshot(info, 'Terminal', 'agent-finished');
            const result = JSON.parse(fs.readFileSync(path.join(output, 'result.json'), 'utf8'));
            await attach(info, 'Agent process result', result);
            expect(result.timed_out).toBe(false);
            expect(result.returncode, 'The agent must complete without an authentication, CLI, or runtime failure').toBe(0);
          });
          await test.step('Correlate the real tool call, hook delivery, and filesystem effect', async () => {
            const events = fs.readFileSync(path.join(output, 'agent.jsonl'), 'utf8').split('\n').flatMap(line => {
              try { return [JSON.parse(line)]; } catch { return []; }
            });
            const sessions = new Set(events.flatMap(event => [event.session_id, event.thread_id].filter(Boolean)));
            expect(sessions.size, 'Agent must identify its actual session').toBeGreaterThan(0);
            expect(events.some(event => agent === 'claude' ? event.type === 'result' && !event.is_error : event.type === 'turn.completed'),
              'Agent must emit a successful terminal result').toBe(true);
            expect(events.some(event => event.type === 'result' ? event.is_error : event.type === 'turn.failed' || event.type === 'error'),
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
                return usage.breakdown?.some((row: any) => row.application === (agent === 'claude' ? 'claude_code' : 'codex') && row.tokens > 0);
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
            await screenshot(info, 'OpenAIDR', 'app-after-agent', agent === 'claude' ? 'Claude Code' : 'Codex');
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
  }
});
