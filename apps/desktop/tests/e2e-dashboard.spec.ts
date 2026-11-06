import {test, expect} from '@playwright/test';
import {createServer} from 'node:http';
import {dashboardLoad, dashboardRoutes} from '../e2e/dashboard';

test('new documents retire old keepalive requests while destination bodies and same-document requests remain pending', async ({page}) => {
  let finishPrevious!: () => void;
  const previousBody = new Promise<void>(resolve => { finishPrevious = resolve; });
  let previousStarted!: () => void;
  const previousRequest = new Promise<void>(resolve => { previousStarted = resolve; });
  let finishCurrent!: () => void;
  const currentBody = new Promise<void>(resolve => { finishCurrent = resolve; });
  let currentStarted!: () => void;
  const currentRequest = new Promise<void>(resolve => { currentStarted = resolve; });
  let finishDocument!: () => void;
  const documentBody = new Promise<void>(resolve => { finishDocument = resolve; });
  const server = createServer(async (request, response) => {
    if (request.url === '/api/previous') {
      previousStarted();
      await previousBody;
      response.writeHead(200, {'Content-Type': 'application/json'});
      response.end('{}');
    } else if (request.url === '/api/current') {
      response.writeHead(200, {'Content-Type': 'application/json'});
      response.write('{"loaded":');
      currentStarted();
      await currentBody;
      response.end('true}');
    } else {
      response.writeHead(200, {'Content-Type': 'text/html'});
      response.write(`<!doctype html><main><h1>Fixture</h1><h2>Data</h2><div id="result"></div></main>${request.url === '/current' ? `
        <script>addEventListener('DOMContentLoaded', () => fetch('/api/current').then(r => r.json()).then(() => {
          document.querySelector('#result').textContent = 'Current response rendered';
        }));</script>` : ''}<!--${'streamed document padding '.repeat(100)}-->`);
      if (request.url === '/current') await documentBody;
      response.end();
    }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as import('node:net').AddressInfo).port}`;
  const load = dashboardLoad(page, origin);
  try {
    await page.goto(origin + '/previous');
    await page.evaluate(() => { void fetch('/api/previous', {keepalive: true}); });
    await previousRequest;
    await page.goto(origin + '/current', {waitUntil: 'commit'});
    await expect(page.getByRole('main')).toBeVisible();
    finishPrevious();
    await expect(load.ready('Fixture', 500)).rejects.toThrow('/current');
    finishDocument();
    await currentRequest;
    await page.evaluate(() => history.replaceState({}, '', '/current?view=detail'));
    await expect(load.ready('Fixture', 500)).rejects.toThrow('/api/current');
    finishCurrent();
    await load.ready('Fixture', 2_000);
    await expect(page.locator('#result')).toHaveText('Current response rendered');
    expect(load.responses).toContainEqual({path: '/api/current', status: 200});
  } finally {
    finishPrevious();
    finishCurrent();
    finishDocument();
    load.stop();
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test('navigation waits for response bodies and rendered content while background polling continues', async ({page}) => {
  let finish!: () => void;
  const gate = new Promise<void>(resolve => { finish = resolve; });
  let started!: () => void;
  const requested = new Promise<void>(resolve => { started = resolve; });
  await page.route('http://dashboard.test/api/data', async route => {
    started();
    await gate;
    await route.fulfill({json: {loaded: true}});
  });
  await page.route('http://dashboard.test/api/poll', route => route.fulfill({json: {ok: true}}));
  await page.route('http://dashboard.test/', route => route.fulfill({contentType: 'text/html', body: `
    <main><h1>Fixture</h1><h2>Data</h2><div role="status" id="loading">Loading data…</div><div id="result"></div></main>
    <script>
      fetch('/api/data').then(r => r.json()).then(() => {
        document.querySelector('#loading').remove();
        document.querySelector('#result').textContent = 'Real response rendered';
      });
      setInterval(() => fetch('/api/poll'), 400);
    </script>`}));
  const load = dashboardLoad(page, 'http://dashboard.test');
  try {
    await page.goto('http://dashboard.test/');
    await requested;
    await expect(load.ready('Fixture', 500)).rejects.toThrow();
    finish();
    await load.ready('Fixture');
    await expect(page.locator('#result')).toHaveText('Real response rendered');
    expect(load.responses.some(item => item.path === '/api/data' && item.status === 200)).toBe(true);
  } finally {
    finish();
    load.stop();
  }
});

test('a visible page heading cannot conceal a failed data response', async ({page}) => {
  await page.route('http://dashboard.test/api/data', route => route.fulfill({status: 503, json: {error: 'Fixture failure'}}));
  await page.route('http://dashboard.test/', route => route.fulfill({contentType: 'text/html', body:
    '<main><h1>Fixture</h1><h2>Data</h2></main><script>fetch("/api/data")</script>'}));
  const load = dashboardLoad(page, 'http://dashboard.test');
  try {
    await page.goto('http://dashboard.test/');
    await expect(load.ready('Fixture', 500)).rejects.toThrow();
    expect(load.responses).toContainEqual({path: '/api/data', status: 503});
  } finally { load.stop(); }
});

test('every dynamic dashboard route requires an explicit data fixture', () => {
  expect(() => dashboardRoutes({})).toThrow(/Provide a real fixture/);
  const routes = dashboardRoutes({
    '/sessions/[id]': '/sessions/01000000-0000-7000-8000-000000000001',
    '/detections/reports/[id]': '/detections/reports/01000000-0000-7000-8000-000000000002',
    '/gateways/instances/[id]': '/gateways/instances/fixture',
    '/gateways/requests/[id]': '/gateways/requests/fixture',
  });
  expect(routes.find(route => route.route === '/devices')?.destination).toBe('/administration/app');
  expect(routes.find(route => route.route === '/gateways/instances')).toMatchObject({
    destination: '/gateways/overview', heading: 'Gateway Overview', sidebar: false,
  });
  expect(routes.find(route => route.route === '/gateways/requests')).toMatchObject({
    destination: '/guardrail/history?source=gateways', heading: 'Guardrail History', sidebar: false,
  });
  expect(routes.filter(route => route.sidebar).length).toBeGreaterThan(20);
});
