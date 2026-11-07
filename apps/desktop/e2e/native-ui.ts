import {expect, type TestInfo} from '@playwright/test';
import fs from 'node:fs';

const startupLayout = fs.readFileSync(new URL('./startup-layout.js', import.meta.url), 'utf8');

const buttonKey = `(button) => button.id ? '#' + button.id
  : button.dataset.days ? '#' + button.closest('[role="tabpanel"]').id + ' [data-days="' + button.dataset.days + '"]'
  : button.dataset.agent ? '[data-agent="' + button.dataset.agent + '"]'
  : button.dataset.alertId ? '.alert-inbox-row'
  : (button.closest('dialog')?.id || 'app') + ': ' + (button.getAttribute('aria-label') || button.textContent.trim())`;

// Browser fixtures cover review, inventory, billing, and proxy states that the
// disposable organization does not seed. Enterprise publication runs these cases.
const browserOnly: Record<string, string> = {
  '#continue-free': 'Hosted free enrollment uses a separate identity from this organization E2E: enrollment.spec.ts and test_sensor_free_enrollment.py',
  '#retry': 'Recovery after a status/setup failure: enrollment.spec.ts',
  '#update-primary': 'Signed-update availability and retry states: enrollment.spec.ts',
  ...Object.fromEntries(['#guardrails-ask', '#guardrails-deny', '#denials-back', '#denials-close', '#denials-latest', '#denials-older',
    '#denials-retry', '#denials-report', '#denials-save-note', '#denials-cancel-note'].map(selector =>
    [selector, 'Retained evidence, review writes, pagination, and recovery: Ask inspection, Denied check, and Denial browser cases'])),
  ...Object.fromEntries(['#posture-tab', '#posture-overview-tab', '#posture-apps-tab', '#posture-components-tab', '#posture-skills-tab',
    '#posture-refresh', '#posture-next', '#posture-previous', '#posture-done', 'posture-detail: Close asset details'].map(selector =>
    [selector, 'Populated organization inventory, pagination, and asset details: Posture browser cases'])),
  '#posture-configure': 'Personal automatic checks are unavailable to organization connections; the enterprise Posture case checks this control is hidden',
  ...Object.fromEntries(['#free-plan-toggle', '#free-plan-refresh'].map(selector =>
    [selector, 'Organization billing balances and refresh: Connected enterprise-paid credits browser cases'])),
  ...Object.fromEntries(['#proxy-settings', '#settings-proxy', '#cancel-proxy', '#save-proxy', '#test-proxy'].map(selector =>
    [selector, 'Proxy credentials, test, save, and error states: network proxy browser cases'])),
};

export interface NativeDriver {
  evaluate(script: string, args: unknown[]): Promise<any>;
  click(selector: string): Promise<void>;
  fill(selector: string, value: string): Promise<void>;
}

export class NativeUI {
  private session = '';
  private buttons = new Set<string>();
  private clicked = new Set<string>();
  constructor(private redact: (text: string) => string, private driver?: NativeDriver,
    private unsupportedButtons: Record<string, string> = {}) {}

  private async request(route: string, data?: unknown, method = 'POST'): Promise<any> {
    try {
      const response = await fetch('http://127.0.0.1:4445' + route, {method,
        headers: {'Content-Type': 'application/json'},
        ...(data === undefined ? {} : {body: JSON.stringify(data)}), signal: AbortSignal.timeout(30_000)});
      const body = await response.json();
      if (!response.ok || body.value?.error) throw new Error(`Native UI ${route}: ${JSON.stringify(body.value)}`);
      return body.value;
    } catch (error) { throw new Error(this.redact(String(error))); }
  }

  async connect() {
    if (!this.driver) {
      await expect.poll(async () => {
        try { return (await fetch('http://127.0.0.1:4445/status', {signal: AbortSignal.timeout(1000)})).ok; }
        catch { return false; }
      }, {timeout: 30_000, message: 'The native app WebDriver starts'}).toBe(true);
      const session = await this.request('/session', {capabilities: {alwaysMatch: {'wdio:tauriServiceOptions': {windowLabel: 'main'}}}});
      this.session = session.sessionId;
    }
    // The driver's first document can be about:blank. Attach observers only to
    // the loaded app, otherwise navigation discards them before the first test.
    await this.wait(`return Boolean(document.querySelector('#app')) && document.readyState === 'complete' && document.fonts.status === 'loaded'
      && [...document.images].every(image => image.complete && image.naturalWidth > 0);`, [], 'Native app assets finish loading');
    await this.evaluate(`window.__e2eErrors = [];
      addEventListener('error', event => window.__e2eErrors.push(event.message));
      addEventListener('unhandledrejection', event => window.__e2eErrors.push(String(event.reason)));`);
  }

  async evaluate(script: string, args: unknown[] = []): Promise<any> {
    try {
      return await (this.driver ? this.driver.evaluate(script, args)
        : this.request(`/session/${this.session}/execute/sync`, {script, args}));
    } catch (error) { throw new Error(this.redact(String(error))); }
  }

  async wait(script: string, args: unknown[] = [], message = 'The native app finishes rendering') {
    await expect.poll(() => this.evaluate(script, args), {timeout: 90_000, intervals: [200, 500], message}).toBe(true);
  }

  async visible(selector: string, visible = true) {
    await this.wait(`const element = document.querySelector(arguments[0]);
      return Boolean(element && element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden') === arguments[1];`,
    [selector, visible], `${selector} ${visible ? 'appears' : 'closes'} in the native app`);
  }

  async text(selector: string, expected: string) {
    await this.wait('return document.querySelector(arguments[0])?.textContent.includes(arguments[1]) === true;',
      [selector, expected], `${selector} displays ${expected}`);
  }

  private async element(selector: string): Promise<string> {
    const element = await this.request(`/session/${this.session}/element`, {using: 'css selector', value: selector});
    return element['element-6066-11e4-a52e-4f735466cecf'];
  }

  async click(selector: string) {
    await this.visible(selector);
    await this.evaluate("document.querySelector(arguments[0]).scrollIntoView({block:'center',inline:'nearest'});", [selector]);
    await this.wait(`const element = document.querySelector(arguments[0]);
      if (!element || element.disabled || element.closest('[inert]')) return false;
      const rect = element.getBoundingClientRect();
      return element.contains(document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2));`,
    [selector], `${selector} is enabled and reachable in the actual app window`);
    const keys: string[] = await this.evaluate(`return [...document.querySelectorAll('button')].map(${buttonKey});`);
    keys.forEach(key => this.buttons.add(key));
    const key = await this.evaluate(`const element = document.querySelector(arguments[0]);
      return element.tagName === 'BUTTON' ? (${buttonKey})(element) : null;`, [selector]);
    if (key) this.clicked.add(key);
    try {
      if (this.driver) await this.driver.click(selector);
      else await this.request(`/session/${this.session}/element/${await this.element(selector)}/click`, {});
    } catch (error) { throw new Error(this.redact(String(error))); }
  }

  async fill(selector: string, value: string) {
    await this.visible(selector);
    try {
      if (this.driver) await this.driver.fill(selector, value);
      else {
        const element = await this.element(selector);
        await this.request(`/session/${this.session}/element/${element}/clear`, {});
        await this.request(`/session/${this.session}/element/${element}/value`, {text: value});
      }
    } catch (error) { throw new Error(this.redact(String(error))); }
  }

  async startup(info: TestInfo) {
    let layout: unknown;
    try {
      await this.text('#health-title', 'Welcome to OpenAIDR');
      // Reading bounds must precede clicks, scrollIntoView, or any app reopen.
      await expect.poll(async () => {
        layout = await this.evaluate('return ' + startupLayout);
        return (layout as {fits:boolean}).fits;
      }, {timeout: 10_000, message: 'The first native window shows enrollment controls without scrolling'}).toBe(true);
    } finally {
      if (!layout) {
        try { layout = await this.evaluate('return ' + startupLayout); }
        catch (error) { layout = {error:String(error)}; }
      }
      await info.attach('First-launch layout', {body: this.redact(JSON.stringify(layout, null, 2)), contentType: 'application/json'});
    }
  }

  async chooseOrganization() {
    if (await this.evaluate("return document.querySelector('main')?.dataset.desktopEdition === 'enterprise';")) {
      await this.visible('#enrollment-link');
      expect(await this.evaluate("return ['#continue-free', '#choose-local-runtime', '#api-key-dialog'].every(selector => !document.querySelector(selector));")).toBe(true);
      return;
    }
    await this.click('#data-use');
    await this.text('#data-use-dialog', 'Shadow mode');
    await this.click('#close-data-use');
    await this.click('#choose-organization');
    await this.visible('#enrollment-link');
    await this.click('#back-to-choices');
    await this.visible('#continue-free');
    await this.click('#choose-organization');
    await this.visible('#enrollment-link');
  }

  async healthy() {
    const errors: string[] = await this.evaluate('return window.__e2eErrors;');
    expect(errors.map(this.redact), 'Native webview JavaScript errors').toEqual([]);
  }

  async coverage(info: TestInfo, complete = false) {
    const rows = [...this.buttons].sort().map(button => {
      const reason = this.unsupportedButtons[button] || browserOnly[button];
      return {button,
        coverage: this.clicked.has(button) ? 'native click' : this.unsupportedButtons[button] ? 'not supported'
          : browserOnly[button] ? 'browser only' : 'missing',
        ...(reason && !this.clicked.has(button) ? {reason} : {})};
    });
    await info.attach('App button coverage', {body: JSON.stringify(rows, null, 2), contentType: 'application/json'});
    if (complete) expect(rows.filter(row => row.coverage === 'missing'), 'Every app button needs a tested flow').toEqual([]);
  }
}
