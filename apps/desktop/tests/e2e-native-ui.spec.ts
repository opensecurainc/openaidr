import {test, expect} from '@playwright/test';
import {NativeUI} from '../e2e/native-ui';

// Exercise the driver against real page navigation. Only the native WebDriver
// transport is replaced; the initial blank document and app assets are real.
for (const transport of ['WebDriver', 'adapter']) {
  test(`${transport} waits for app navigation before tracking errors`, async ({page}) => {
    const originalFetch = globalThis.fetch;
    let blankRead!: () => void;
    const readBlank = new Promise<void>(resolve => { blankRead = resolve; });
    const evaluate = async (script: string, args: unknown[]) => {
      const blank = page.url() === 'about:blank';
      const value = await page.evaluate(({script, args}) => new Function(script).apply(null, args), {script, args});
      if (blank) blankRead();
      return value;
    };
    globalThis.fetch = async (input, init) => {
      const url = new URL(String(input));
      expect(url.origin).toBe('http://127.0.0.1:4445');
      if (url.pathname === '/status') return Response.json({value:{ready:true}});
      if (url.pathname === '/session') return Response.json({value:{sessionId:'fixture'}});
      expect(url.pathname).toBe('/session/fixture/execute/sync');
      const {script, args} = JSON.parse(String(init?.body));
      const value = await evaluate(script, args);
      return Response.json({value:value ?? null});
    };
    try {
      const native = new NativeUI(text => text, transport === 'adapter' ? {
        evaluate,
        click: selector => page.locator(selector).click(),
        fill: (selector, value) => page.locator(selector).fill(value),
      } : undefined);
      const connecting = native.connect().then(() => null, error => error);
      await readBlank;
      await page.goto('/');
      expect(await connecting).toBeNull();
      await native.healthy();
      await page.evaluate(() => dispatchEvent(new ErrorEvent('error', {message:'fixture page error'})));
      await expect(native.healthy()).rejects.toThrow('fixture page error');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
}

test('native adapter reports missing controls separately from declared coverage and redacts failures', async ({page}, info) => {
  await page.setContent(`<main id="app"><input id="value"><button id="used">Use</button>
    <button id="new-control">New control</button><button id="retry" hidden>Retry</button>
    <button id="remove-app" hidden>Uninstall</button>
    <section id="usage-panel" role="tabpanel"><button data-days="1">24 hours</button></section>
    <section id="guardrails-page" role="tabpanel"><button data-days="1">24 hours</button>
      <button data-agent="codex">Codex: installed</button></section></main>`);
  const privateValue = 'private-driver-input';
  const native = new NativeUI(text => text.replaceAll(privateValue, '[REDACTED]'), {
    evaluate: (script, args) => page.evaluate(({script, args}) => new Function(script).apply(null, args), {script, args}),
    click: selector => page.locator(selector).click(),
    fill: async () => { throw new Error(privateValue); },
  }, {'#remove-app': 'This platform uses its package manager for removal.'});
  await native.connect();
  await native.visible('#remove-app', false);
  await native.click('#used');
  await expect(native.coverage(info, true)).rejects.toThrow('Every app button needs a tested flow');
  await native.click('#new-control');
  await native.click('#usage-panel [data-days="1"]');
  await native.click('[data-agent="codex"]');
  await page.locator('[data-agent="codex"]').evaluate(button => { button.textContent = 'Codex: guardrails off'; });
  await expect(native.coverage(info, true)).rejects.toThrow('Every app button needs a tested flow');
  await native.click('#guardrails-page [data-days="1"]');
  await native.coverage(info, true);
  const attachment = info.attachments.filter(item => item.name === 'App button coverage').at(-1)!;
  const rows = JSON.parse(attachment.body!.toString());
  expect(rows).toEqual(expect.arrayContaining([
    {button: '#used', coverage: 'native click'},
    {button: '#new-control', coverage: 'native click'},
    {button: '#usage-panel [data-days="1"]', coverage: 'native click'},
    {button: '#guardrails-page [data-days="1"]', coverage: 'native click'},
    {button: '[data-agent="codex"]', coverage: 'native click'},
    {button: '#retry', coverage: 'browser only', reason: expect.stringContaining('enrollment.spec.ts')},
    {button: '#remove-app', coverage: 'not supported', reason: 'This platform uses its package manager for removal.'},
  ]));
  await expect(native.fill('#value', privateValue)).rejects.toThrow('[REDACTED]');
  await native.healthy();
});
