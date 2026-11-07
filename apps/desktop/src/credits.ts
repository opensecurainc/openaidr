type Status = {connection_mode?:string; google_account?:{email:string}; enrolled?:boolean; disabled?:boolean; desktop_removal?:unknown;tenant_name?:string; sensor_id?:string; server_url?:string};
type Usage = {status:'active'|'exhausted'|'disabled';allowance?:string|null;used:string|null;reserved?:string|null;available:string|null;starts_at:string|null;resets_at?:string|null;checked_at:string};
type Snapshot = {sensor_id:string;server_url:string;plan:'free'|'paid';policy?:'anonymous_trial'|'google_weekly';usage:Usage|null};
type Request = (action:string) => Promise<unknown>;

function credits(value:unknown): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,9})(\.\d{1,6})?$/.test(value)) throw new Error('Invalid credits');
  const [whole, fraction = ''] = value.split('.');
  const result = BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, '0'));
  if (result > 9007199254740991n) throw new Error('Invalid credits');
  return result;
}

export function initCredits(parent:HTMLElement, request:Request, visible:() => boolean) {
  const card = document.createElement('section');
  card.className = 'credit-summary'; card.id = 'free-plan'; card.hidden = true; card.setAttribute('aria-label', 'Service credits');
  card.innerHTML = `<h2 id="credit-title">Credits</h2><p id="credit-owner" class="guardrail-note" hidden></p><div id="dashboard-row" hidden><span id="dashboard-address"></span></div>
    <p id="free-plan-message" role="status">Loading credit usage…</p>
    <div id="free-plan-data" hidden><p id="free-plan-total" role="group"><strong id="free-plan-used"></strong><span id="free-plan-allowance"></span></p><progress id="free-plan-progress" aria-label="Free credits used"></progress>
      <p id="free-plan-reset" class="guardrail-note"></p></div>
    <button type="button" class="credit-disclosure" id="free-plan-toggle" aria-expanded="false" aria-controls="free-plan-details">Credit details<span aria-hidden="true">›</span></button>
    <div id="free-plan-details" hidden><div id="free-plan-metadata" hidden><p id="free-plan-reset-at" class="guardrail-note"></p><p id="free-plan-period" class="guardrail-note" hidden></p><p id="free-plan-checked" class="guardrail-note"></p></div>
      <p id="free-plan-note" class="guardrail-note">Coding-agent tokens and costs are separate.</p><button type="button" class="text-button" id="free-plan-refresh">Refresh usage</button></div>`;
  parent.insertBefore(card, parent.querySelector('.health-summary'));
  const el = (id:string) => card.querySelector<HTMLElement>('#free-plan-' + id)!;
  const button = el('refresh') as HTMLButtonElement;
  let identity = '', status:Status = {}, shown = false, available = false, revision = 0, fetching = false, lastAttempt = -Infinity;
  let timer:ReturnType<typeof setTimeout>|undefined, stale:ReturnType<typeof setTimeout>|undefined;
  const active = () => !!identity && shown && available && visible();
  function clear(message:string, recover = false) {
    clearTimeout(stale); el('data').hidden = true; el('metadata').hidden = true; el('message').hidden = false; el('message').textContent = message;
    if (recover) { el('details').hidden = false; el('toggle').setAttribute('aria-expanded', 'true'); }
  }
  function schedule() {
    clearTimeout(timer);
    if (active()) timer = setTimeout(() => void refresh(), 60000);
  }
  async function refresh(force = false) {
    if (!active() || fetching || (!force && Date.now() - lastAttempt < 60000)) return;
    lastAttempt = Date.now();
    fetching = true; button.disabled = true;
    const current = revision;
    try {
      const value = await request('credits.summary') as Snapshot;
      if (current !== revision) return;
      if (!value || value.sensor_id !== status.sensor_id || value.server_url !== status.server_url?.replace(/\/$/, '')) throw new Error('Connection changed');
      if (!['free', 'paid'].includes(value.plan) || (status.connection_mode === 'free' && value.plan !== 'free')
          || (status.connection_mode === 'api_key' && value.plan !== 'paid' && !(status.google_account && value.policy === 'google_weekly'))
          || (value.policy !== undefined && (!['anonymous_trial', 'google_weekly'].includes(value.policy) || value.plan !== 'free'))) throw new Error('Invalid plan');
      title(value.plan, value.policy);
      const data = value.usage;
      if (data === null || data?.status === 'disabled') { clear('Credits are not enabled for this connection yet.'); return; }
      const checked = Date.parse(data.checked_at), age = Date.now() - checked;
      const free = value.plan === 'free';
      const trial = value.policy === 'anonymous_trial';
      if (!['active','exhausted'].includes(data.status) || !Number.isFinite(checked) || age < -30000 || age > 180000) throw new Error('Invalid credit usage');
      const used = credits(data.used), remaining = credits(data.available);
      let total = 0n;
      if (free) {
        total = credits(data.allowance);
        if (!(Date.parse(data.starts_at!) <= checked) || (trial ? data.resets_at !== null : !(checked < Date.parse(data.resets_at!))) || (!trial && total <= 0n)
            || total !== used + credits(data.reserved) + remaining || (data.status === 'exhausted') !== (remaining === 0n)) throw new Error('Invalid free usage');
      } else if (Date.parse(data.starts_at!) !== Date.UTC(new Date(checked).getUTCFullYear(), new Date(checked).getUTCMonth(), 1)) throw new Error('Invalid paid period');
      const expires = trial ? Infinity : free ? Date.parse(data.resets_at!) : Date.UTC(new Date(checked).getUTCFullYear(), new Date(checked).getUTCMonth() + 1, 1);
      if (Date.now() >= expires) throw new Error('Credit period ended');
      el('message').hidden = true; el('data').hidden = false; el('metadata').hidden = false;
      const format = (value:string|null|undefined) => new Intl.NumberFormat(undefined, {maximumFractionDigits:6}).format(Number(value));
      const compact = (value:string|null) => new Intl.NumberFormat(undefined, {maximumFractionDigits:2,notation:Number(value) >= 1000000 ? 'compact' : 'standard'}).format(Number(value));
      el('used').textContent = free ? format(data.used) : `${compact(data.used)}/${compact(data.available)}`;
      el('allowance').textContent = free ? ` of ${format(data.allowance)} credits used` : ' credits used/available';
      el('total').classList.toggle('credit-ratio', !free);
      el('total').title = free ? '' : `${format(data.used)} credits used this month (UTC); ${format(data.available)} credits available`;
      el('total').setAttribute('aria-label', el('total').title || `${format(data.used)} of ${format(data.allowance)} credits used`);
      el('note').textContent = `${trial ? 'Starter credits do not renew. ' : free ? 'Unused credits expire at the reset. ' : ''}Coding-agent tokens and costs are separate.`;
      el('period').hidden = free;
      el('period').textContent = `Used this month (UTC): ${format(data.used)} settled credits.`;
      el('reset').hidden = !free; el('reset-at').hidden = !free || trial;
      const progress = el('progress') as HTMLProgressElement;
      progress.hidden = !free; progress.max = Number(total) || 1; progress.value = Number(used);
      if (trial) el('reset').textContent = 'One-time starter credits. These do not renew.';
      else if (free) {
        const hours = Math.max(0, Math.floor((Date.parse(data.resets_at!) - Date.now()) / 3600000)), days = Math.floor(hours / 24);
        const remainingTime = [days ? `${days} day${days === 1 ? '' : 's'}` : '', hours % 24 ? `${hours % 24} hour${hours % 24 === 1 ? '' : 's'}` : ''].filter(Boolean).join(', ');
        el('reset').textContent = `Resets in ${remainingTime || 'less than 1 hour'}`;
        el('reset-at').textContent = `Resets ${new Date(data.resets_at!).toLocaleString(undefined, {month:'short',day:'numeric',hour:'numeric',minute:'2-digit',timeZone:'UTC',timeZoneName:'short'})}.`;
      }
      el('checked').textContent = `Last updated ${new Date(checked).toLocaleTimeString(undefined, {hour:'numeric',minute:'2-digit',second:'2-digit'})}.`;
      clearTimeout(stale);
      stale = setTimeout(() => clear('Usage unavailable. Refresh to check your current balance.', true), Math.max(0, Math.min(180000 - age, expires - Date.now())));
    } catch {
      if (current === revision) clear('Usage unavailable. Try refreshing shortly.', true);
    } finally {
      fetching = false; button.disabled = !available; schedule();
      if (current !== revision && active()) void refresh();
    }
  }
  function title(plan?:'free'|'paid', policy?:Snapshot['policy']) {
    const personal = status.connection_mode === 'free' || status.connection_mode === 'api_key';
    const selected = plan || (status.connection_mode === 'free' ? 'free' : status.connection_mode === 'api_key' ? 'paid' : null);
    card.querySelector('#credit-title')!.textContent = personal ? policy === 'anonymous_trial' ? 'Starter credits' : policy === 'google_weekly' ? '200 free credits each week' : status.google_account ? 'Personal account' : selected === 'free' ? 'Free plan' : 'Personal · Paid' : `Enterprise${selected ? selected === 'free' ? ' · Free' : ' · Paid' : ''}`;
    const owner = card.querySelector<HTMLElement>('#credit-owner')!;
    owner.hidden = personal && !status.google_account;
    owner.textContent = status.google_account?.email || [status.tenant_name?.trim(), 'Shared organization credits'].filter(Boolean).join(' · ');
  }
  button.addEventListener('click', () => void refresh(true));
  el('toggle').addEventListener('click', () => {
    el('details').hidden = !el('details').hidden;
    el('toggle').setAttribute('aria-expanded', String(!el('details').hidden));
  });
  return {
    refresh,
    setVisible(value:boolean) { if (shown === value) return; shown = value; schedule(); if (shown) void refresh(true); },
    setAvailability(value:boolean) { const changed = available !== value; available = value; button.disabled = !value || fetching; if (changed) { schedule(); if (active()) void refresh(); } },
    setStatus(value:Status) {
      status = value;
      const next = value.enrolled && !value.disabled && !value.desktop_removal ? `${value.connection_mode}/${value.server_url}/${value.sensor_id}/${value.google_account?.email || ''}` : '';
      if (identity !== next) { identity = next; revision++; lastAttempt = -Infinity; el('details').hidden = true; el('toggle').setAttribute('aria-expanded', 'false'); title(); clear('Loading credit usage…'); if (active()) void refresh(); }
      const owner = card.querySelector<HTMLElement>('#credit-owner')!;
      owner.textContent = status.google_account?.email || [status.tenant_name?.trim(), 'Shared organization credits'].filter(Boolean).join(' · ');
      card.hidden = !identity;
    },
  };
}
