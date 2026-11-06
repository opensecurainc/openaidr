type Check = {docker_ready:boolean;docker_action?:'install'|'start'|'manual';existing:boolean;managed:boolean;connected:boolean;server_url:string;message?:string};
type Request = (action:string, params?:Record<string, unknown>) => Promise<unknown>;
type Work = (operation:() => Promise<void>) => Promise<void>;

export function initLocalRuntime(request:Request, work:Work, close:(connected:boolean) => void) {
  const card = document.getElementById('connect-card')!;
  const view = document.createElement('section');
  view.id = 'local-runtime-view'; view.hidden = true; card.append(view);
  let state:Check | null = null;
  let active = false;
  let running = false;
  let complete = false;
  const node = (id:string) => document.getElementById(id)!;
  const automaticDocker = () => state?.docker_action === 'install' || state?.docker_action === 'start';
  const needsPassword = () => state?.docker_ready && state.existing && !state.managed && !state.connected;
  function availability() {
    view.querySelectorAll<HTMLButtonElement>('button').forEach(item => item.disabled = running);
    const start = view.querySelector<HTMLButtonElement>('#local-start');
    const password = view.querySelector<HTMLInputElement>('#local-password');
    if (start) {
      start.parentElement!.hidden = running || (!state?.docker_ready && !automaticDocker());
      start.disabled = running || (!state?.docker_ready && !automaticDocker()) || (!!password && !password.value.trim());
    }
    const check = view.querySelector<HTMLButtonElement>('#local-check');
    if (check) check.hidden = running || automaticDocker();
  }
  function render() {
    view.innerHTML = `<button id="local-back" class="button button-secondary">Back</button>
      <h2 tabindex="-1">${complete ? 'Your local runtime is connected' : state?.existing ? 'Local runtime found' : 'Set up local runtime'}</h2>
      <p>${complete ? 'This device is connected to OpenAIDR on this computer. Restart running coding-agent sessions to apply the new connection settings.' : 'A local dashboard and storage for this device. AI checks use OpenSecura cloud services and your free allowance.'}</p>
      <div class="local-runtime-summary"><strong>Docker with Compose</strong><span id="local-docker">${state?.docker_ready ? 'Installed and running' : state?.docker_action === 'install' ? 'Not installed' : state ? 'Not ready' : 'Checking…'}</span></div>
      <p id="local-message" role="status" aria-live="polite"></p>
      ${!complete && !state?.docker_ready ? '<p>'+(automaticDocker() ? (state?.docker_action === 'install' ? 'OpenAIDR will download and install Docker Desktop, then create your local runtime. macOS may ask for permission. Accept Docker’s terms in its setup window to continue.' : 'OpenAIDR will open Docker Desktop and continue when it is ready. Finish any prompts in Docker’s setup window.') : 'Install Docker with Compose, or start your existing local Docker engine, then check again.')+'</p><button id="local-check" class="button button-secondary">Check again</button>' : ''}
      ${needsPassword() && !complete ? '<p>Your existing data and settings are kept. Sign in as admin@localhost to connect this device.</p><label>Local administrator password<input id="local-password" type="password" autocomplete="off" maxlength="1024"></label>' : ''}
      ${!complete ? '<ol id="local-progress" hidden><li>Prepare Docker</li><li>Prepare the runtime</li><li>Start local services</li><li>Connect this device</li><li>Set up the sensor and guardrails</li></ol><div class="local-runtime-actions"><button id="local-start" class="button">'+(needsPassword() ? 'Connect this device' : 'Retry setup')+'</button></div>' : '<dl><div><dt>Dashboard</dt><dd>http://localhost:8080</dd></div><div><dt>Guardrails</dt><dd>Shadow mode by default</dd></div></dl><p>Guardrails record decisions while actions continue. Manage guardrails in the dashboard.</p>'+(state?.managed ? '<button id="local-credentials" class="button button-secondary">Show dashboard sign-in</button><p id="local-sign-in" hidden></p>' : '')+'<div class="local-runtime-actions"><button id="local-done" class="button button-secondary">Done</button><button id="local-dashboard" class="button">Open dashboard</button></div>'}
      <p class="form-hint">Keep Docker running. The runtime is accessible only on this computer. Closing OpenAIDR keeps the runtime running.</p>`;
    availability();
  }
  async function check() {
    running = true; availability();
    let message = '';
    try { await work(async () => { state = await request('local-runtime.check') as Check; }); }
    catch (error) { message = String(error); }
    finally { running = false; render(); }
    node('local-message').textContent = message || (!automaticDocker() ? state?.message : '') || '';
    if (!message) await run('local-start');
  }
  function finish() {
    active = false; view.hidden = true; view.innerHTML = ''; card.classList.remove('runtime-open'); close(complete);
  }
  document.getElementById('choose-local-runtime')!.addEventListener('click', () => {
    active = true; complete = false; state = null; view.hidden = false; card.classList.add('runtime-open');
    render(); view.querySelector<HTMLElement>('h2')!.focus(); void check();
  });
  view.addEventListener('input', availability);
  async function run(action:string) {
    if (running) return;
    if (action === 'local-start') {
      if (complete || (!state?.docker_ready && !automaticDocker())) return;
      const password = view.querySelector<HTMLInputElement>('#local-password');
      if (needsPassword() && !password?.value.trim()) { password?.focus(); return; }
    }
    running = true; availability(); node('local-message').textContent = '';
    try {
      await work(async () => {
        if (action === 'local-dashboard') { await request('desktop.dashboard', {server_url:'http://localhost:8080'}); return; }
        if (action === 'local-credentials') {
          const target = node('local-credentials');
          const signIn = node('local-sign-in');
          if (!signIn.hidden) { signIn.textContent = ''; signIn.hidden = true; target.textContent = 'Show dashboard sign-in'; return; }
          const saved = await request('local-runtime.credentials') as {email:string;password:string};
          signIn.textContent = `${saved.email}\n${saved.password}`; signIn.hidden = false; target.textContent = 'Hide dashboard sign-in'; return;
        }
        if (!state?.docker_ready) {
          node('local-message').textContent = state?.docker_action === 'install'
            ? 'Installing and starting Docker. Approve the macOS prompt and finish Docker’s setup window if asked. This may take several minutes.'
            : 'Starting Docker. Finish any prompts in Docker’s setup window. Setup will continue automatically.';
          node('local-progress').hidden = false;
          view.querySelector('#local-progress li')!.classList.add('active');
          state = await request('local-runtime.docker-setup') as Check;
          if (!state.docker_ready) throw new Error('Docker is not ready yet. Finish its setup and retry.');
          render();
          if (needsPassword()) {
            node('local-password').focus(); return;
          }
        }
        const input = view.querySelector<HTMLInputElement>('#local-password');
        const password = input?.value ?? ''; if (input) input.value = '';
        node('local-progress').hidden = false;
        const steps = [
          ['local-runtime.prepare','Preparing the runtime. First-time setup may take several minutes.'],
          ['local-runtime.start','Starting the database and dashboard.'],
          ['local-runtime.connect','Connecting this device.'],
          ['setup','Setting up the sensor and guardrails.'],
        ];
        for (const [index,[action,message]] of steps.entries()) {
          if (state?.existing && index < 2) continue;
          node('local-message').textContent = message;
          view.querySelectorAll('#local-progress li').forEach((item,i) => item.classList.toggle('active',i === index + 1));
          const result = await request(action, action === 'local-runtime.connect' ? {password} : {}) as {steps?:{ok:boolean}[]};
          if (action === 'setup' && result.steps?.some(step => !step.ok)) throw new Error('The runtime is connected, but sensor setup is incomplete. Retry setup to finish.');
        }
        state = await request('local-runtime.check') as Check;
        if (!state.connected) throw new Error('The local connection could not be verified. Retry setup; your data is kept.');
        complete = true; render(); view.querySelector<HTMLElement>('h2')!.focus();
      });
    } catch (error) { node('local-message').textContent = error instanceof Error ? error.message : String(error); }
    finally { running = false; availability(); }
  }
  view.addEventListener('click', event => {
    const target = (event.target as Element).closest('button');
    if (!target || running) return;
    if (target.id === 'local-back' || target.id === 'local-done') { finish(); return; }
    if (target.id === 'local-check') { void check(); return; }
    void run(target.id);
  });
  return {availability, isOpen:() => active, dismiss:() => { if (active && !running) finish(); }};
}
