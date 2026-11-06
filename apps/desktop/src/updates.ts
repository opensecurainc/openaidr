export type DesktopUpdate = {
  state: 'idle' | 'available' | 'checking' | 'downloading' | 'installing' | 'restarting' | 'updated' | 'error' | 'unavailable';
  latest: string; error?: string | null; downloaded_bytes?: number; total_bytes?: number;
  warning_deferred?: boolean;
  setup?: boolean;
};

export function updateWarningDeferred(update: DesktopUpdate | null | undefined): boolean {
  return update?.state === 'error' && update.warning_deferred === true;
}

const restartKey = 'openaidr-pending-update';
const refreshIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 0 1 15.36-6.36L21 8m0-5v5h-5M21 12a9 9 0 0 1-15.36 6.36L3 16m5 0H3v5"/></svg>';

export function initUpdates(request: (action:string, params?:Record<string,unknown>) => Promise<unknown>, version:string, publish:(update:DesktopUpdate) => void) {
  const button = document.getElementById('check-update') as HTMLButtonElement;
  button.innerHTML = `${refreshIcon}<span></span>`;
  const buttonLabel = button.querySelector('span')!;
  const panel = document.createElement('dialog');
  panel.id = 'update-panel'; panel.className = 'simulation-dialog update-panel';
  panel.setAttribute('aria-labelledby', 'update-title');
  panel.innerHTML = `<button id="close-update" class="button icon-button close-button" aria-label="Close update status">×</button>
    <div class="update-heading"><span id="update-icon" aria-hidden="true"></span><div><h2 id="update-title" tabindex="-1"></h2><p id="update-version"></p></div></div>
    <div role="status" aria-live="polite"><p id="update-message"></p><div id="update-progress" hidden><progress id="update-bar" max="100" aria-label="Update progress"></progress><span id="update-percent"></span><p id="update-bytes"></p></div><p id="update-detail"></p></div>
    <div class="update-actions"><button id="update-secondary" class="button button-secondary"></button><button id="update-primary" class="button"></button></div>`;
  document.getElementById('app')!.append(panel);
  const el = (id:string) => panel.querySelector<HTMLElement>(`#${id}`)!;
  const close = el('close-update') as HTMLButtonElement;
  const primary = el('update-primary') as HTMLButtonElement;
  const secondary = el('update-secondary') as HTMLButtonElement;
  let state: DesktopUpdate = {state:'idle',latest:version};
  let pending: 'check' | 'install' | null = null;
  let cancelling = false;
  let supported = true;
  let explicit = false;
  let revision = 0;

  function marker(value?:string) {
    try {
      if (value === undefined) return localStorage.getItem(restartKey);
      if (value) localStorage.setItem(restartKey,value);
      else localStorage.removeItem(restartKey);
    } catch { /* An unavailable preference store must not block updates. */ }
    return null;
  }
  const active = () => pending !== null || ['checking','downloading','installing','restarting'].includes(state.state);
  const installing = () => state.state === 'installing' || state.state === 'restarting';
  function show(open:boolean, focus = true) {
    if (open && !panel.open) panel.showModal();
    else if (!open && panel.open) panel.close();
    button.setAttribute('aria-expanded',String(open));
    renderControls();
    // Focus the title so the result is announced without drawing a focus ring on a control.
    if (open) { if (focus) el('update-title').focus({preventScroll:true}); }
    else if (focus) button.focus({preventScroll:true});
  }
  function renderControls() {
    const label = active() ? pending === 'check' || state.state === 'checking' ? 'Checking...' : 'Updating...' : 'Check updates';
    if (buttonLabel.textContent !== label) buttonLabel.textContent = label;
    button.classList.toggle('update-busy',active());
    button.disabled = !supported || (active() && panel.open);
    button.setAttribute('aria-busy',String(active()));
    close.hidden = installing();
    primary.disabled = secondary.disabled = !supported || cancelling;
  }
  function render() {
    const phase = state.state;
    const deferred = updateWarningDeferred(state);
    const title = {idle:"You're up to date",available:'Update available',checking:'Checking for updates...',downloading:'Downloading update...',installing:'Installing update...',restarting:'Restarting OpenAIDR...',updated:'OpenAIDR is up to date',error:'Could not update OpenAIDR',unavailable:'In-app updates unavailable'}[phase];
    el('update-title').textContent = state.setup ? phase === 'error' ? 'Could not finish app setup' : 'Setting up OpenAIDR...' : deferred ? 'Check delayed' : title;
    el('update-version').textContent = `Version ${phase === 'idle' || phase === 'checking' || phase === 'unavailable' ? version : state.latest || version}`;
    el('update-icon').innerHTML = phase === 'idle' || phase === 'updated'
      ? '<span class="overlay-icon success"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="m6 12 4 4 8-9"/></svg></span>'
      : deferred || phase === 'available' || phase === 'downloading'
        ? '<span class="overlay-icon info"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M12 6v10m-4-4 4 4 4-4"/></svg></span>'
        : active() ? '<span class="update-spinner"></span>' : '<span class="overlay-icon warning"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round"><path d="M12 6v7m0 5v.1"/></svg></span>';
    panel.dataset.state = phase;
    const messages:Record<DesktopUpdate['state'],string> = {
      idle:"You're using the latest available version of OpenAIDR.",available:'A newer version of OpenAIDR is ready.',checking:'Looking for the latest version of OpenAIDR.',downloading:'',installing:'OpenAIDR will restart automatically.',restarting:'Finishing the app update.',updated:'The update was installed successfully.',error:state.error || 'The update could not finish. Please try again.',unavailable:state.error || 'In-app updates are not supported by this build.',
    };
    el('update-message').textContent = state.setup && phase === 'installing'
      ? 'Verifying and installing this app with automatic updates. OpenAIDR will reopen when setup finishes.'
      : deferred ? 'The update server is temporarily unavailable. You can try again later.' : messages[phase];
    el('update-message').hidden = !messages[phase];
    el('update-detail').textContent = phase === 'available' ? 'The app will restart to finish updating.' : phase === 'downloading' ? 'OpenAIDR will restart when ready.' : phase === 'installing' || phase === 'restarting' ? 'This should only take a moment.' : phase === 'idle' ? 'Last checked just now' : phase === 'updated' ? "You're ready to continue." : '';
    const progress = el('update-bar') as HTMLProgressElement;
    progress.removeAttribute('value');
    el('update-progress').hidden = !['downloading','installing','restarting'].includes(phase);
    el('update-percent').textContent = ''; el('update-bytes').textContent = '';
    const bytes = state.downloaded_bytes, total = state.total_bytes;
    const validBytes = (value:unknown):value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 1024 * 1024 * 1024;
    if (phase === 'downloading' && validBytes(bytes)) {
      const size = (value:number) => `${(value / 1048576).toFixed(1)} MiB`;
      if (validBytes(total) && total > 0 && total >= bytes) {
        progress.value = Math.floor(bytes / total * 100);
        el('update-percent').textContent = `${progress.value}%`;
        el('update-bytes').textContent = `${size(bytes)} of ${size(total)}`;
      } else el('update-bytes').textContent = size(bytes);
    }
    primary.hidden = active() || phase === 'unavailable';
    primary.textContent = phase === 'available' ? 'Update now' : phase === 'error' ? 'Try again' : 'Done';
    secondary.hidden = installing() || (active() && !pending) || phase === 'idle' || phase === 'updated';
    secondary.textContent = cancelling ? 'Cancelling...' : pending ? pending === 'check' ? 'Cancel' : 'Cancel download' : phase === 'available' ? 'Later' : 'Close';
    renderControls();
  }
  async function run(kind:'check' | 'install') {
    if (active()) { show(true); return; }
    const generation = ++revision;
    explicit = true;
    const selected = state.latest;
    pending = kind;
    if (kind === 'install') marker(selected);
    state = {state:kind === 'check' ? 'checking' : 'downloading',latest:kind === 'check' ? version : selected};
    publish(state); render(); show(true);
    try {
      const result = await request(`desktop.update.${kind}`,kind === 'install' ? {version:selected} : {}) as DesktopUpdate;
      if (generation !== revision) return;
      state = result;
      if (result.setup && result.state === 'installing') explicit = false;
      if (result.state === 'error' || result.state === 'unavailable') marker('');
      publish(result);
    } catch (error) {
      if (generation !== revision) return;
      marker('');
      state = {state:'error',latest:selected,error:String(error instanceof Error ? error.message : error)};
      publish(state);
    } finally {
      if (generation === revision) { pending = null; cancelling = false; render(); }
    }
  }
  async function cancel() {
    if (cancelling) return;
    cancelling = true; render();
    try {
      await request('desktop.update.cancel');
      marker(''); show(false);
      // The active request completes only after the native worker has stopped.
    } catch (error) {
      el('update-detail').textContent = String(error instanceof Error ? error.message : error);
    } finally { cancelling = false; renderControls(); }
  }
  button.title = 'Check for a new version of OpenAIDR without leaving the app.';
  button.setAttribute('aria-haspopup','dialog'); button.setAttribute('aria-controls','update-panel'); button.setAttribute('aria-expanded','false');
  button.addEventListener('click', () => active() ? show(true) : void run('check'));
  close.addEventListener('click', () => show(false));
  primary.addEventListener('click', () => state.state === 'available' ? void run('install') : state.state === 'error' ? void run('check') : show(false));
  secondary.addEventListener('click', () => pending ? void cancel() : show(false));
  panel.addEventListener('cancel', event => { event.preventDefault(); if (!installing()) show(false); });
  // A click on the backdrop targets the dialog itself outside its content box.
  panel.addEventListener('click', event => {
    if (event.target !== panel || installing()) return;
    const box = panel.getBoundingClientRect();
    if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) show(false);
  });
  render();
  return {
    availability(tauri:boolean) { supported = tauri; renderControls(); },
    render(snapshot:DesktopUpdate | null | undefined) {
      if (!snapshot) {
        if (!pending && !explicit) { state = {state:'idle',latest:version}; render(); }
        return;
      }
      const progressing = ['checking','downloading','installing','restarting'].includes(snapshot.state);
      if (pending && !progressing) return;
      if (!pending && progressing) explicit = false;
      if (!pending && explicit && !progressing && snapshot.state !== 'updated') return;
      state = snapshot;
      if (snapshot.state === 'updated' && marker() === snapshot.latest && version !== snapshot.latest) state = {...snapshot,state:'restarting'};
      if (snapshot.state === 'updated' && marker() === snapshot.latest && version === snapshot.latest) { marker(''); render(); show(true); }
      else render();
    },
    reset() { revision++; pending = null; cancelling = false; explicit = false; state = {state:'idle',latest:version}; marker(''); show(false,false); },
  };
}
