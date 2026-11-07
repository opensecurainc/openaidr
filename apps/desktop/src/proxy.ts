// Network proxy: a row in the connected sensor status, a Settings button, and one dialog.
type Request = (action:string, params?:Record<string, unknown>) => Promise<unknown>;
export type ProxyStatus = {mode:'default'|'direct'|'manual'|'invalid'; url?:string; bypass?:string[]; username?:string; password_saved?:boolean; error?:string};
type TestResult = {ok:boolean; message:string; kind?:string; latency_ms?:number};

// Same rules as openaidr.sensor.network_proxy; the sensor validates again before saving.
const HOST = /^(?:\*\.|\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6 = /^\[?[0-9a-f:.]*:[0-9a-f:.]*\]?$/;

export function validateProxyUrl(raw:string):string {
  const value = raw.trim();
  if (!value) return 'Enter a proxy URL.';
  if (/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@/i.test(value)) return 'Enter the user name and password separately, not in the URL.';
  let url:URL;
  try { url = new URL(value); } catch { return 'Enter a URL such as http://proxy.example.com:8080.'; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'Use an http:// or https:// proxy URL.';
  if (!url.hostname) return 'Enter the proxy host name.';
  if ((url.pathname && url.pathname !== '/') || url.search || url.hash) return 'Remove the path from the proxy URL.';
  return '';
}

export function parseBypass(raw:string):{hosts:string[]; error:string} {
  const hosts = [...new Set(raw.split(/[\s,;]+/).map(item => item.trim().toLowerCase()).filter(Boolean))];
  if (hosts.length > 64) return {hosts, error:'Enter up to 64 bypass entries.'};
  const invalid = hosts.find(host => !(HOST.test(host) || IPV4.test(host) || IPV6.test(host)));
  return {hosts, error:invalid ? `“${invalid}” is not a host name, domain, or IP address.` : ''};
}

export function proxySummary(status?:ProxyStatus | null):string {
  if (status?.mode === 'manual' && status.url) {
    let host = status.url;
    try { host = new URL(status.url).host; } catch { /* keep the saved text */ }
    return `Through proxy ${host}`;
  }
  if (status?.mode === 'invalid') return 'Proxy setting needs attention';
  return 'Direct connection';
}

export function initProxy(healthCard:HTMLElement, request:Request, onSaved:() => void, restoreStatus:() => void) {
  const row = document.createElement('div');
  row.id = 'proxy-row'; row.hidden = true;
  row.innerHTML = `<button id="proxy-settings" class="credit-disclosure" type="button" aria-haspopup="dialog" aria-controls="proxy-dialog" aria-describedby="proxy-summary">Network proxy<span aria-hidden="true">›</span></button><p id="proxy-summary" class="guardrail-note">Direct connection</p>`;
  healthCard.insertBefore(row, healthCard.querySelector('#retry-row'));

  const settingsButton = document.createElement('button');
  settingsButton.id = 'settings-proxy'; settingsButton.type = 'button'; settingsButton.className = 'button button-secondary';
  settingsButton.setAttribute('aria-haspopup', 'dialog'); settingsButton.setAttribute('aria-controls', 'proxy-dialog');
  settingsButton.textContent = 'Network proxy';
  document.querySelector('#settings-actions')!.prepend(settingsButton);

  const dialog = document.createElement('dialog');
  dialog.id = 'proxy-dialog'; dialog.className = 'simulation-dialog proxy-dialog'; dialog.setAttribute('aria-labelledby', 'proxy-title');
  dialog.innerHTML = `<form id="proxy-form" novalidate>
    <h2 id="proxy-title">Network proxy</h2>
    <p>Send OpenAIDR sensor and update traffic through an HTTP or HTTPS proxy. Agent hooks still reach the sensor on this computer directly.</p>
    <fieldset class="proxy-mode"><legend>Connection</legend>
      <label class="proxy-choice"><input type="radio" name="proxy-mode" id="proxy-direct" value="direct">No proxy</label>
      <label class="proxy-choice"><input type="radio" name="proxy-mode" id="proxy-manual" value="manual">Use a proxy server</label>
    </fieldset>
    <div id="proxy-fields">
      <label for="proxy-url">Proxy URL</label>
      <input id="proxy-url" type="url" inputmode="url" placeholder="http://proxy.example.com:8080" maxlength="2048" autocomplete="off" spellcheck="false" aria-describedby="proxy-url-hint">
      <p id="proxy-url-hint" class="form-hint">Starts with http:// or https://. The connection to the OpenAIDR server stays encrypted and verified end to end.</p>
      <label for="proxy-bypass">Bypass proxy for (optional)</label>
      <input id="proxy-bypass" placeholder="internal.example.com, *.corp.example.com" maxlength="4096" autocomplete="off" spellcheck="false" aria-describedby="proxy-bypass-hint">
      <p id="proxy-bypass-hint" class="form-hint">Host names, domains, or IP addresses, separated by commas.</p>
      <label class="proxy-choice"><input id="proxy-auth" type="checkbox">Proxy requires a user name and password</label>
      <div id="proxy-credentials" hidden>
        <label for="proxy-username">User name</label>
        <input id="proxy-username" maxlength="256" autocomplete="off" spellcheck="false">
        <label for="proxy-password">Password</label>
        <input id="proxy-password" type="password" maxlength="1024" autocomplete="off" aria-describedby="proxy-password-hint">
        <p id="proxy-password-hint" class="form-hint">Saved in this computer's credential store, never in the sensor configuration.</p>
      </div>
    </div>
    <p id="proxy-test-result" class="form-hint" role="status" aria-live="polite"></p>
    <p id="proxy-error" role="alert" hidden></p>
    <div class="simulation-actions"><button id="test-proxy" class="button button-secondary" type="button">Test connection</button><button id="cancel-proxy" class="button button-secondary" type="button">Cancel</button><button id="save-proxy" class="button" type="submit">Save</button></div>
  </form>`;
  document.querySelector('#app')!.append(dialog);

  const $ = <T extends HTMLElement>(id:string) => dialog.querySelector<T>('#' + id)!;
  const url = $<HTMLInputElement>('proxy-url'), bypass = $<HTMLInputElement>('proxy-bypass');
  const auth = $<HTMLInputElement>('proxy-auth'), username = $<HTMLInputElement>('proxy-username'), password = $<HTMLInputElement>('proxy-password');
  let saved:ProxyStatus = {mode:'default'}, busy = false, opener:HTMLElement = row.querySelector('#proxy-settings')!;

  const manual = () => $<HTMLInputElement>('proxy-manual').checked;
  function sync() {
    for (const node of [url, bypass, auth, username, password]) node.disabled = busy || !manual();
    $('proxy-fields').hidden = !manual();
    $('proxy-credentials').hidden = !auth.checked;
    for (const id of ['save-proxy', 'cancel-proxy']) $<HTMLButtonElement>(id).disabled = busy;
    $<HTMLButtonElement>('test-proxy').disabled = busy || !manual();
  }
  function error(message:string) { $('proxy-error').textContent = message; $('proxy-error').hidden = !message; }
  function collect():Record<string, unknown> | null {
    if (!manual()) return {mode:'direct'};
    const urlError = validateProxyUrl(url.value);
    const parsed = parseBypass(bypass.value);
    const user = auth.checked ? username.value.trim() : '';
    const keepsPassword = saved.password_saved && saved.username === user;
    const credentialError = auth.checked && !user ? 'Enter the proxy user name.'
      : auth.checked && !password.value && !keepsPassword ? 'Enter the proxy password.' : '';
    const message = urlError || parsed.error || credentialError;
    error(message);
    if (message) { (urlError ? url : parsed.error ? bypass : user ? password : username).focus(); return null; }
    return {mode:'manual', url:url.value.trim(), bypass:parsed.hosts, username:user, ...(user && password.value ? {password:password.value} : {})};
  }
  async function run(action:'proxy.test' | 'proxy.save') {
    const params = collect();
    if (!params || busy) return;
    busy = true; sync();
    $('proxy-test-result').textContent = action === 'proxy.test' ? 'Testing connection…' : 'Saving and restarting the sensor…';
    delete $('proxy-test-result').dataset.tone;
    try {
      if (action === 'proxy.test') {
        const result = await request(action, params) as TestResult;
        $('proxy-test-result').textContent = result.message;
        $('proxy-test-result').dataset.tone = result.ok ? 'success' : 'error';
      } else {
        saved = await request(action, params) as ProxyStatus;
        password.value = '';
        dialog.close(); onSaved();
      }
    } catch (failure) {
      $('proxy-test-result').textContent = '';
      error(failure instanceof Error ? failure.message : String(failure));
    } finally { busy = false; sync(); }
  }
  async function open(from:HTMLElement) {
    opener = from; error(''); $('proxy-test-result').textContent = ''; password.value = '';
    try { saved = await request('proxy.status') as ProxyStatus; } catch { saved = {mode:'default'}; }
    $<HTMLInputElement>(saved.mode === 'manual' ? 'proxy-manual' : 'proxy-direct').checked = true;
    url.value = saved.url ?? ''; bypass.value = (saved.bypass ?? []).join(', ');
    auth.checked = !!saved.username; username.value = saved.username ?? '';
    password.placeholder = saved.password_saved ? 'Saved password' : '';
    if (saved.mode === 'invalid' && saved.error) error(saved.error);
    sync(); dialog.showModal();
    (manual() ? url : $<HTMLInputElement>('proxy-direct')).focus();
  }

  row.querySelector('#proxy-settings')!.addEventListener('click', event => void open(event.currentTarget as HTMLElement));
  settingsButton.addEventListener('click', () => void open(settingsButton));
  dialog.addEventListener('change', sync);
  $('test-proxy').addEventListener('click', () => void run('proxy.test'));
  $('proxy-form').addEventListener('submit', event => { event.preventDefault(); void run('proxy.save'); });
  $('cancel-proxy').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  // Opening the modal closes the status popover; reopen it so focus returns to the opener.
  dialog.addEventListener('close', () => {
    password.value = '';
    if (healthCard.contains(opener)) restoreStatus();
    if (opener.isConnected && !opener.closest('[hidden]')) opener.focus({preventScroll:true});
  });

  return {
    // Only the compact connected status has room for the row; other states use Settings.
    update(visible:boolean, status?:ProxyStatus | null) {
      row.hidden = !visible;
      row.querySelector('#proxy-summary')!.textContent = proxySummary(status);
    },
  };
}
