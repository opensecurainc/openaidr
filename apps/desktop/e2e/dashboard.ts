import {expect, test, type Frame, type Page, type Request, type TestInfo} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {navigation, findNavigationPage} from '../../dashboard/src/lib/navigation';

const consoleRoot = path.resolve(import.meta.dirname, '../../dashboard/src/app/(console)');
const redirects: Record<string, string> = {
  '/activity': '/guardrail/live',
  '/administration/sensors': '/administration/app',
  '/ai-inventory/preview': '/ai-inventory',
  '/ai-supply-chain/preview': '/ai-supply-chain',
  '/costs/detections': '/costs/openaidr',
  '/devices': '/administration/app',
  '/gateways/instances': '/gateways/overview',
  '/gateways/requests': '/guardrail/history?source=gateways',
  '/telemetry': '/evidence',
};

export async function dashboardFixtures({apiCall, seedDetails, sensorId, secrets, backendOrigin}: {
  apiCall: (route: string, method?: string, data?: unknown) => Promise<any>;
  seedDetails: (input: {user: unknown; sensor_id: string; settings: unknown}) => Record<string, string>;
  sensorId: string;
  secrets: string[];
  backendOrigin: string;
}) {
  const {user} = await apiCall('auth/me');
  const settings = await apiCall('response/session-detection');
  const details = seedDetails({user, sensor_id: sensorId, settings});
  const gateway = await apiCall('gateways', 'POST', {name: 'E2E navigation fixture', environment: 'disposable test'});
  secrets.push(gateway.credential.token);
  const requestId = randomUUID();
  const response = await fetch(backendOrigin + '/ingest/v1/gateway-outcomes', {
    method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${gateway.credential.token}`},
    body: JSON.stringify({request_id: requestId, node_id: 'e2e-navigation-fixture', protocol: 'openai.chat',
      stream: false, model: 'e2e-fixture', provider: 'fixture', outcome: 'unconfirmed', status_code: 200, latency_ms: 0}),
  });
  expect(response.ok, 'Create the gateway request fixture through its real API').toBe(true);
  const requests = await apiCall(`gateways/requests?gateway_id=${gateway.gateway.id}`);
  const gatewayRequest = requests.items.find((item: any) => item.request_id === requestId);
  expect(gatewayRequest, 'The synthetic gateway outcome is stored').toBeTruthy();
  details['/gateways/instances/[id]'] = `/gateways/instances/${gateway.gateway.id}`;
  details['/gateways/requests/[id]'] = `/gateways/requests/${gatewayRequest.id}`;
  return details;
}

export function dashboardRoutes(details: Record<string, string>) {
  const menu = navigation.flatMap(group => [...group.pages]);
  const templates = fs.readdirSync(consoleRoot, {recursive: true})
    .map(String).filter(file => path.basename(file) === 'page.tsx')
    .map(file => '/' + path.dirname(file).replaceAll(path.sep, '/').replace(/^\.$/, ''));
  const routes = [...menu.map(page => page.path), ...templates.filter(route => !menu.some(page => page.path === route)).sort()];
  expect([...routes].sort(), 'Every console route has exactly one navigation case').toEqual(templates.sort());
  return routes.map(template => {
    const route = template.includes('[') ? details[template] : template;
    expect(route, `Provide a real fixture for dashboard detail route ${template}`).toBeTruthy();
    const destination = redirects[route] || route;
    const heading = findNavigationPage(new URL(destination, 'http://dashboard.test').pathname)?.page.title;
    expect(heading, `Dashboard route ${route} has page metadata`).toBeTruthy();
    return {template, route, destination, heading: heading!, sidebar: menu.some(page => page.path === route)};
  });
}

// Scope requests to one navigation. Polling may continue after the first render,
// but an in-flight data request, failed response, or visible loader cannot pass.
export function dashboardLoad(page: Page, origin: string) {
  const pending = new Set<Request>();
  let documentRequest: Request | undefined;
  const errors: string[] = [];
  const responses: {path: string; status: number}[] = [];
  const relevant = (request: Request) => {
    const url = new URL(request.url());
    return url.origin === origin && (url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/previews/') || request.isNavigationRequest());
  };
  const started = (request: Request) => {
    if (!relevant(request)) return;
    pending.add(request);
    if (request.isNavigationRequest() && request.frame() === page.mainFrame()) documentRequest = request;
  };
  const committed = (frame: Frame) => {
    if (frame !== page.mainFrame() || !documentRequest) return;
    // Chromium may never finish keepalive requests from the discarded document.
    // A same-document URL change has no new document request and clears nothing.
    for (const request of pending) if (request !== documentRequest) pending.delete(request);
    documentRequest = undefined;
  };
  const finished = (request: Request) => {
    pending.delete(request);
    if (request === documentRequest) documentRequest = undefined;
  };
  const failed = (request: Request) => {
    if (pending.has(request) && !/aborted|cancelled/i.test(request.failure()?.errorText || ''))
      errors.push(`Request failed: ${new URL(request.url()).pathname}`);
    finished(request);
  };
  const response = (reply: import('@playwright/test').Response) => {
    if (!pending.has(reply.request())) return;
    const entry = {path: new URL(reply.url()).pathname, status: reply.status()};
    responses.push(entry);
    if (entry.status >= 400) errors.push(`HTTP ${entry.status} ${entry.path}`);
  };
  const pageError = (error: Error) => errors.push(error.message);
  page.on('request', started);
  page.on('framenavigated', committed);
  page.on('requestfinished', finished);
  page.on('requestfailed', failed);
  page.on('response', response);
  page.on('pageerror', pageError);
  return {
    responses,
    async ready(heading: string, timeout = 30_000) {
      const main = page.getByRole('main');
      await expect(main).toBeVisible({timeout});
      await expect(page.getByRole('heading', {level: 1, name: heading, exact: true})).toBeVisible({timeout});
      await expect(page.getByRole('heading', {name: 'Sign in', exact: true})).toHaveCount(0);
      let settled = 0;
      await expect.poll(async () => {
        expect(errors, 'Navigation must not conceal failed requests or JavaScript errors').toEqual([]);
        const loading = await main.locator('[data-slot="skeleton"]:visible, [aria-busy="true"]:visible').count();
        const messages = await main.getByRole('status').allTextContents();
        const busy = messages.some(text => /^\s*(Loading|Checking|Generating|Refreshing)\b/i.test(text));
        const content = await main.locator('h2, iframe, [data-slot="review-summary"]').count();
        const assets = await page.evaluate(() => document.fonts.status === 'loaded' &&
          [...document.images].filter(image => image.loading !== 'lazy').every(image => image.complete && image.naturalWidth > 0));
        settled = !pending.size && !loading && !busy && content > 0 && assets ? settled + 1 : 0;
        return {ready: settled >= 2, pendingCount: pending.size,
          pending: [...new Set([...pending].map(request => new URL(request.url()).pathname))].slice(0, 20),
          loading, busy, content: content > 0, assets};
      }, {timeout, intervals: [100, 200], message: `${heading}: data, loading indicators, fonts, and images are ready`})
        .toEqual({ready: true, pendingCount: 0, pending: [], loading: 0, busy: false, content: true, assets: true});
      for (const frame of page.frames().filter(frame => frame !== page.mainFrame())) {
        await frame.waitForLoadState('load', {timeout});
        await expect(frame.locator('body')).not.toBeEmpty({timeout});
        await expect.poll(() => frame.evaluate(() => document.fonts.status === 'loaded' &&
          [...document.images].filter(image => image.loading !== 'lazy').every(image => image.complete && image.naturalWidth > 0)),
        {timeout, message: `${heading}: embedded preview assets are ready`}).toBe(true);
      }
      expect(await main.getByRole('alert').allTextContents(), 'A loaded page must not show a data error').toEqual([]);
      expect(errors).toEqual([]);
    },
    stop() {
      page.off('request', started);
      page.off('framenavigated', committed);
      page.off('requestfinished', finished);
      page.off('requestfailed', failed);
      page.off('response', response);
      page.off('pageerror', pageError);
    },
  };
}

export async function walkDashboard(page: Page, info: TestInfo, origin: string, details: Record<string, string>) {
  const routes = dashboardRoutes(details);
  const visited: {route: string; destination: string; status: string; responses: unknown[]; error?: string}[] = [];
  for (const [index, entry] of routes.entries()) {
    const load = dashboardLoad(page, origin);
    let error = '';
    try {
      await test.step(`Dashboard: ${entry.route}`, async () => {
        if (entry.sidebar && new URL(page.url()).origin === origin) {
          const link = page.getByRole('navigation', {name: 'Workspace navigation'}).locator(`a[href="${entry.route}"]`);
          await expect(link).toHaveCount(1);
          await link.click();
          await expect(link).toHaveAttribute('aria-current', 'page');
        } else {
          const response = await page.goto(origin + entry.route, {waitUntil: 'domcontentloaded'});
          expect(response?.ok(), `Dashboard document ${entry.route}`).toBe(true);
        }
        await expect(page).toHaveURL(url => url.pathname === entry.destination.split('?')[0]);
        await load.ready(entry.heading);
      });
    } catch (cause) {
      error = String(cause);
    } finally {
      visited.push({route: entry.template, destination: entry.destination, status: error ? 'failed' : 'passed',
        responses: load.responses, ...(error ? {error} : {})});
      const file = info.outputPath(`dashboard-${String(index + 1).padStart(2, '0')}-${entry.template.replace(/[^a-z0-9]+/gi, '-') || 'overview'}.png`);
      await page.screenshot({path: file, fullPage: true, animations: 'disabled'});
      await info.attach(`Dashboard ${entry.route}: ${error ? 'failed' : 'loaded'}`, {path: file, contentType: 'image/png'});
      load.stop();
    }
  }
  await info.attach('Dashboard route coverage', {body: JSON.stringify(visited, null, 2), contentType: 'application/json'});
  expect(visited.filter(result => result.status !== 'passed'), 'Every dashboard route must fully load').toEqual([]);
}
