type Status = {connection_mode?:string;google_account?:{email:string};enrolled?:boolean;disabled?:boolean;desktop_removal?:unknown;sensor_id?:string;server_url?:string};
type Pairing = {status:'pending'|'approved'|'expired';verification_uri?:string;expires_at?:string};
type Request = (action:string, params?:Record<string,unknown>) => Promise<unknown>;

export function initGoogleConnection(parent:HTMLElement, request:Request, connect:() => Promise<void>) {
  const card = document.createElement('section');
  card.id = 'google-connection'; card.className = 'google-connection'; card.hidden = true;
  card.innerHTML = `<button type="button" class="button button-secondary" id="google-signin">Sign in with Google to get 200 credits each week</button>
    <button type="button" class="text-button" id="google-console" hidden>Open console</button>
    <p id="google-message" class="guardrail-note" role="status" hidden></p>
    <button type="button" class="text-button" id="google-cancel" hidden>Cancel sign-in</button>`;
  parent.insertBefore(card, parent.querySelector('.health-summary'));
  const signin = card.querySelector<HTMLButtonElement>('#google-signin')!;
  const consoleButton = card.querySelector<HTMLButtonElement>('#google-console')!;
  const cancel = card.querySelector<HTMLButtonElement>('#google-cancel')!;
  const message = card.querySelector<HTMLElement>('#google-message')!;
  let identity = '', enabled = false, pending = false, revision = 0;
  let timer:ReturnType<typeof setTimeout>|undefined;
  const say = (value:string) => { message.textContent = value; message.hidden = !value; };
  function availability() { signin.disabled = !enabled || pending; consoleButton.disabled = !enabled; cancel.disabled = !enabled; }
  function stop() { clearTimeout(timer); pending = false; cancel.hidden = true; revision++; availability(); }
  async function poll(current:number) {
    if (current !== revision || !pending) return;
    if (!enabled) { timer = setTimeout(() => void poll(current), 5000); return; }
    try {
      const result = await request('google.poll') as Pairing;
      if (current !== revision) return;
      if (result.status === 'approved') {
        cancel.hidden = true; say('Connecting your Google account…'); await connect();
        if (current === revision) stop();
      } else if (result.status === 'expired') {
        stop(); say('Sign-in expired. Start again from this app.');
      } else if (result.status === 'pending') timer = setTimeout(() => void poll(current), 5000);
      else throw new Error('Could not verify Google sign-in. Try again.');
    } catch (error) {
      if (current !== revision) return;
      stop(); say(error instanceof Error ? error.message : 'Could not verify Google sign-in. Try again.');
    }
  }
  signin.addEventListener('click', async () => {
    if (!enabled || pending) return;
    pending = true; const current = ++revision; cancel.hidden = false; availability();
    say('Opening Google sign-in in your browser…');
    try {
      const result = await request('google.start') as Pairing;
      if (current !== revision) return;
      if (result.status === 'expired') { stop(); say('Sign-in expired. Start again from this app.'); return; }
      say('Finish Google sign-in and confirm this device in your browser.');
      await poll(current);
    } catch (error) {
      if (current !== revision) return;
      stop(); say(error instanceof Error ? error.message : 'Could not start Google sign-in. Try again.');
    }
  });
  cancel.addEventListener('click', () => { stop(); say('Sign-in paused. Select Sign in with Google to resume.'); });
  consoleButton.addEventListener('click', () => {
    void request('desktop.dashboard', {server_url:'https://console.opensecura.ai/'}).catch(() => say('Could not open your browser. Open https://console.opensecura.ai/ to view your account.'));
  });
  return {
    setAvailability(value:boolean) { enabled = value; availability(); },
    setStatus(status:Status) {
      const next = status.enrolled && !status.disabled && !status.desktop_removal &&
        (status.connection_mode === 'free' || status.connection_mode === 'api_key' && status.google_account)
        ? `${status.connection_mode}/${status.sensor_id}/${status.server_url}/${status.google_account?.email || ''}` : '';
      if (next !== identity) { stop(); say(''); identity = next; }
      card.hidden = !identity; signin.hidden = !!status.google_account; consoleButton.hidden = !status.google_account;
    },
  };
}
