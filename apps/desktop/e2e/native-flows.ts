import {expect, test} from '@playwright/test';
import {randomUUID} from 'node:crypto';
import {type NativeUI} from './native-ui';

type AppFlow = {
  native: NativeUI;
  screenshot: (name: string) => Promise<void>;
  sensorId: string;
};

export async function exerciseAppControls({native, screenshot, sensorId, sensorStatus, publicCertificate}: AppFlow & {
  sensorStatus: () => any;
  publicCertificate: string;
}) {
  await test.step('Status and both usage periods', async () => {
    await native.click('#usage-tab');
    await native.click('#sensor-status');
    await native.text('#health-title', 'Sensor connected');
    await screenshot('app-status-details');
    await native.click('#close-status');
    for (const days of [1, 30]) {
      await native.click(`#usage-panel [data-days="${days}"]`);
      await native.wait(`return document.querySelector('#usage-panel [data-days="' + arguments[0] + '"]').getAttribute('aria-pressed') === 'true'
        && !document.querySelector('#usage-content').hidden
        && !document.querySelector('#usage-message').textContent.includes('Loading');`, [days]);
      await screenshot(`app-usage-${days}-days`);
    }
  });
  await test.step('Guardrail activity and agent configuration use real sensor state', async () => {
    await native.click('#guardrails-tab');
    for (const days of [30, 1]) {
      await native.click(`#guardrails-page [data-days="${days}"]`);
      await native.visible('#guardrails-data');
      await native.visible('#guardrails-message', false);
      await native.wait(`return document.querySelector('#guardrails-page [data-days="' + arguments[0] + '"]').getAttribute('aria-pressed') === 'true'
        && Number(document.querySelector('#guardrails-completed').textContent.replaceAll(',', '')) > 0
        && Number(document.querySelector('#guardrails-deny').textContent.replaceAll(',', '')) > 0;`, [days]);
      await screenshot(`app-guardrails-${days}-days`);
    }
    await native.click('#guardrails-view');
    await native.visible('#guardrails-activity');
    await native.text('#guardrails-recent', 'Codex');
    await screenshot('app-guardrails-activity');
    await native.click('#guardrails-view');
    await native.visible('#guardrails-activity', false);
    for (const agent of ['codex', 'claude', 'hermes', 'copilot', 'cursor', 'antigravity', 'opencode']) {
      await native.click(`#guardrails-page [data-agent="${agent}"]`);
      await native.wait(`return document.querySelector('#guardrails-page [data-agent="' + arguments[0] + '"]').getAttribute('aria-pressed') === 'true'
        && Boolean(document.querySelector('#agent-path').textContent);`, [agent]);
    }
    await native.click('#guardrails-page [data-agent="codex"]');
    await native.text('#agent-path', (await sensorStatus()).hooks.codex.config_path);
    await native.click('#agent-configuration');
    await native.text('#agent-feedback', 'Opened the configuration folder.');
    for (const enabled of [false, true]) {
      await native.click('#agent-enabled');
      await native.wait('const input = document.querySelector("#agent-enabled"); return !input.disabled && input.checked === arguments[0];', [enabled]);
      const state = (await sensorStatus()).hooks.codex;
      expect(state.installed).toBe(enabled);
      expect(Boolean(state.opted_out)).toBe(!enabled);
    }
    await native.click('#agent-reinstall');
    await native.text('#agent-feedback', 'Saved.');
    expect((await sensorStatus()).hooks.codex.current).toBe(true);
    await native.click('#usage-tab');
    await native.visible('#usage-content');
    await native.wait(`return document.querySelector('#usage-panel [data-days="30"]').getAttribute('aria-pressed') === 'true';`);
  });
  await test.step('Connection dialogs and certificate removal', async () => {
    await native.click('#change-connection');
    await native.visible('#connection-dialog');
    // Invalid credentials are rejected before any connection. The selected CA is public test data.
    await native.fill('#enrollment-link', 'https://127.0.0.1:9/enroll#token=invalid');
    await native.click('#certificate-options summary');
    const pem = publicCertificate;
    await native.evaluate(`const transfer = new DataTransfer();
      transfer.items.add(new File([arguments[0]], 'e2e-public-ca.pem', {type:'application/x-pem-file'}));
      const input = document.querySelector('#enrollment-ca'); input.files = transfer.files;
      input.dispatchEvent(new Event('change', {bubbles:true}));`, [pem]);
    await native.click('#remove-certificate');
    await native.visible('#remove-certificate', false);
    await native.click('#close-connection');
    await native.visible('#connection-dialog', false);
    await native.click('#change-connection');
    await native.click('#cancel-change');
    await native.visible('#connection-dialog', false);
    expect((await sensorStatus()).sensor_id).toBe(sensorId);
  });
  await test.step('About, license disclosures, and unsigned update status', async () => {
    await native.click('#show-about');
    await native.visible('#about-dialog');
    await native.click('#show-licenses');
    for (let index = 1; index <= 5; index++) {
      const selector = `#about-licenses details:nth-of-type(${index})`;
      await native.click(selector + ' summary');
      await native.visible(selector + ' pre');
      await native.click(selector + ' summary');
    }
    await screenshot('app-about-licenses');
    await native.click('#show-licenses');
    await native.visible('#about-licenses', false);
    await native.click('#close-about');
    for (const close of ['#close-update', '#update-secondary']) {
      await native.click('#check-update');
      await native.text('#update-title', 'In-app updates unavailable');
      await screenshot(`app-update-${close.slice(1)}`);
      await native.click(close);
      await native.visible('#update-panel', false);
    }
  });
}

export async function exerciseAppAlerts({native, screenshot, sensorId, apiCall,
  alertCommand = 'printf "E2E instructions only\\n"'}: AppFlow & {
  apiCall: (route: string, method?: string, data?: unknown) => Promise<any>;
  alertCommand?: string;
}) {
  const alert = await apiCall('endpoint-alerts', 'POST', {request_id: randomUUID(), sensor_ids: [sensorId],
    application_id: 'e2e-native-controls', title: 'E2E app controls', message: 'Synthetic alert for the disposable test device.',
    command: alertCommand});
  await native.visible('#endpoint-alert');
  await native.text('#endpoint-alert-title', 'E2E app controls');
  await native.click('#endpoint-alert button[aria-label="Close alert"]');
  await native.click('#open-alerts');
  await native.click('#refresh-alerts');
  await native.wait('return !document.querySelector("#refresh-alerts").disabled;');
  await native.click('.alert-inbox-row');
  await native.click('#endpoint-alert .alert-actions .alert-close');
  await native.visible('#alerts-inbox');
  await native.click('.alert-inbox-row');
  await native.click('#copy-alert-command');
  await native.wait(`return document.querySelector('#copy-alert-command').textContent.includes('Copied')
    || (!document.querySelector('#alert-copy-status').hidden && getSelection().toString() === arguments[0]);`, [alert.command]);
  await native.click('#acknowledge-alert');
  await native.text('#acknowledge-alert', 'Done');
  await expect.poll(async () => (await apiCall(`endpoint-alerts/${alert.id}`)).recipients[0].acknowledged_at,
    {timeout: 30_000}).toBeTruthy();
  await screenshot('app-alert-acknowledged');
  await native.click('#acknowledge-alert');
  await native.click('#alerts-inbox button[aria-label="Close alerts"]');
  await native.click('#open-alerts');
  await native.click('#alerts-inbox .endpoint-alert-footer .alert-close');
  await native.visible('#alerts-inbox', false);
}
