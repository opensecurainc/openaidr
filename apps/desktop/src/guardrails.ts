import { agentIcon } from '../../../packages/ui/agent-icons/index.js';
import { initCheckReview } from './guardrail-review';

export type Agent = 'codex' | 'claude' | 'hermes' | 'copilot' | 'cursor' | 'antigravity' | 'opencode' | 'workbuddy';
export const AGENT_NAMES: Record<Agent, string> = {codex:'Codex', claude:'Claude Code', hermes:'Hermes Agent', copilot:'GitHub Copilot', cursor:'Cursor', antigravity:'Antigravity', opencode:'OpenCode', workbuddy:'WorkBuddy'};
export const AGENTS = Object.keys(AGENT_NAMES) as Agent[];
const products: Record<Agent, string> = {codex:'codex-cli', claude:'claude-code', hermes:'hermes-agent', copilot:'github-copilot', cursor:'cursor', antigravity:'antigravity', opencode:'opencode', workbuddy:'workbuddy'};
export type HookState = {available?:boolean; installed?:boolean; partial?:boolean; trusted?:boolean; current?:boolean; opted_out?:boolean; disabled?:boolean; approval_pending?:boolean; config_path?:string; config_exists?:boolean; control_events?:string[]; name?:string; profiles?:HookState[]};
type Status = {connection_mode?:'free'|'api_key'|'organization'; sensor_id?:string; server_url?:string; enrolled?:boolean; disabled?:boolean; desktop_removal?:unknown; hooks?:Partial<Record<Agent, HookState>>};
export function agentEntries(hooks:Status['hooks']) {
  return AGENTS.flatMap(agent => (agent === 'codex' && hooks?.codex?.profiles?.length
    ? hooks.codex.profiles.map(state => ({agent, state, profile:state.config_path}))
    : [{agent, state:hooks?.[agent], profile:undefined}])
    .map(entry => ({...entry, id:entry.profile || agent})));
}
type Request = (action:string, params?:Record<string, unknown>) => Promise<unknown>;
type Counts = {completed:number; allow:number; warn:number; ask:number; deny:number; unavailable:number; pending:number};
type Check = {id:string; created_at:string; product:string; hook_event:string; mode:'shadow'|'enforce'; status:'evaluated'|'unavailable'|'pending'; evaluated_decision:'allow'|'warn'|'ask'|'deny'|null; returned_decision:string|null; failure_reason?:string|null};
type Summary = {supported:true; sensor_id:string; server_url:string; days:1|30; since:string; until:string; mode:'shadow'|'enforce'; summary:Counts; by_mode:{shadow:Counts; enforce:Counts}; by_agent:{product:string; last_check_at:string}[]; recent:Check[]};
const countKeys = ['completed','allow','warn','ask','deny','unavailable','pending'] as const;
const decisions = ['allow','warn','ask','deny'];
const failureLabels = new Map([
  ['timeout', 'Check timed out.'],
  ['capture_disabled', 'Required content capture is off.'],
  ['evidence_truncated', 'Captured evidence was truncated.'],
  ['evidence_unavailable', 'Required evidence was unavailable.'],
  ['evidence_too_large', 'Evidence exceeded the service limit.'],
  ['authentication_failed', 'The service rejected the credentials.'],
  ['credits_exhausted', 'Service credits were exhausted or reserved.'],
  ['rate_limited', 'The service rate limit was reached.'],
  ['policy_unavailable', 'The local rules file could not be loaded.'],
  ['service_unavailable', 'The service was unavailable.'],
  ['service_rejected', 'The service rejected the check.'],
  ['connection_failed', 'Could not connect to the service.'],
  ['invalid_response', 'The service response was invalid.'],
  ['unscored', 'The service returned no assessment score.'],
  ['outcome_unknown', 'No completion result was recorded.'],
]);
const stamp = (value:string) => new Date(value).toLocaleString(undefined, {month:'short', day:'numeric', hour:'numeric', minute:'2-digit'});

function validSummary(value:unknown): value is Summary {
  const row = value as Summary | null;
  const validCounts = (counts:Counts) => counts && countKeys.every(key => Number.isSafeInteger(counts[key]) && counts[key] >= 0)
    && counts.completed === counts.allow + counts.warn + counts.ask + counts.deny;
  return !!row && row.supported === true && ['shadow','enforce'].includes(row.mode)
    && validCounts(row.summary) && validCounts(row.by_mode?.shadow) && validCounts(row.by_mode?.enforce)
    && countKeys.every(key => row.summary[key] === row.by_mode.shadow[key] + row.by_mode.enforce[key])
    && Number.isFinite(Date.parse(row.until)) && Number.isFinite(Date.parse(row.since))
    && Array.isArray(row.by_agent) && row.by_agent.length <= 20
    && row.by_agent.every(agent => typeof agent.product === 'string' && Number.isFinite(Date.parse(agent.last_check_at)))
    && Array.isArray(row.recent) && row.recent.length <= 20 && row.recent.every(check =>
      typeof check.id === 'string' && typeof check.product === 'string' && typeof check.hook_event === 'string'
      && Number.isFinite(Date.parse(check.created_at)) && ['shadow','enforce'].includes(check.mode)
      && ['evaluated','unavailable','pending'].includes(check.status)
      && (check.status === 'evaluated' ? decisions.includes(check.evaluated_decision!) && decisions.includes(check.returned_decision!)
        : check.evaluated_decision === null && check.returned_decision === null));
}

function setupLabel(state:HookState | undefined) {
  if (!state) return 'Status unavailable';
  if (state.opted_out) return 'Guardrails off';
  if (state.approval_pending) return 'Approval needed';
  if (state.disabled) return 'Disabled in agent';
  if (state.partial || (state.installed && state.current === false)) return 'Needs repair';
  if (state.installed) return 'Installed · On';
  return state.available ? 'Not installed' : 'Agent not detected';
}

export function initGuardrails(request:Request, configure:Request, visible:() => boolean) {
  const panel = document.createElement('section');
  panel.id = 'guardrails-page'; panel.hidden = true; panel.setAttribute('role', 'tabpanel'); panel.setAttribute('aria-labelledby', 'guardrails-tab');
  panel.innerHTML = `
    <div class="usage-heading"><div class="guardrail-title"><h1>Guardrails</h1><span>This device</span></div>
      <div class="usage-period" role="group" aria-label="Guardrail period"><button tabindex="0" type="button" data-days="1" aria-pressed="true">24 hours</button><button tabindex="0" type="button" data-days="30" aria-pressed="false">30 days</button></div></div>
    <div class="guardrail-overview"><section class="usage-card guardrail-summary" aria-label="Guardrail activity">
      <div class="guardrail-summary-heading"><h2>Guardrail actions</h2><button tabindex="0" class="text-button" id="guardrails-view" aria-expanded="false" aria-controls="guardrails-activity" disabled>View activity</button></div>
      <div class="guardrail-mode"><span id="guardrails-mode" class="mode-badge">Policy unavailable</span><span id="guardrails-policy">Organization policy</span></div>
      <p id="guardrails-message" role="status">Loading guardrail activity…</p>
      <div id="guardrails-data" hidden>
        <dl class="usage-metrics guardrail-metrics"><div><dt title="Checks completed">Checks</dt><dd id="guardrails-completed"></dd></div><div><dt title="Allow decisions">Allow</dt><dd id="guardrails-allow" class="allowed"></dd></div><div><dt id="guardrails-deny-label">Deny</dt><dd class="denied"><button type="button" id="guardrails-deny" class="guardrail-metric-button" aria-labelledby="guardrails-deny-label guardrails-deny" aria-expanded="false" aria-controls="guardrails-review" title="Review denied checks"></button></dd></div><div><dt id="guardrails-ask-label">Ask</dt><dd class="asked"><button type="button" id="guardrails-ask" class="guardrail-metric-button" aria-labelledby="guardrails-ask-label guardrails-ask" aria-expanded="false" aria-controls="guardrails-review" title="Inspect ask checks"></button></dd></div></dl>
        <p id="guardrails-exceptions" class="guardrail-note" hidden></p>
      </div>
    </section></div>
    <section id="guardrails-activity" class="usage-card" hidden aria-label="Recent guardrail activity"><p class="guardrail-note">Latest 20 checks in this period. Policy decisions do not confirm delivery or enforcement.</p><div id="guardrails-recent"></div></section>
    <div class="agent-section-heading"><h2>Agent setup</h2><span>${AGENTS.length} supported agents</span></div>
    <section class="card agent-setup" aria-label="Agent setup">
      <div class="agent-list" role="group" aria-label="Coding agents"></div>
      <div id="agent-detail" class="agent-detail" role="region" aria-labelledby="agent-name">
        <div class="agent-detail-heading"><h2 id="agent-name"></h2><span id="agent-badge" class="installation-badge"></span></div>
        <p id="agent-last-check" class="agent-subtitle"></p>
        <div class="desktop-preference"><label for="agent-enabled">Enable guardrails<input type="checkbox" id="agent-enabled"></label></div>
        <div class="agent-config-heading">Supported checks</div><div id="agent-checks" class="agent-checks"></div>
        <div class="agent-config-heading">Configuration file</div><code id="agent-path" class="agent-path"></code>
        <div class="agent-actions"><button tabindex="0" type="button" id="agent-configuration" class="button button-secondary">Show configuration</button><button tabindex="0" type="button" id="agent-reinstall" class="button button-secondary">Reinstall guardrails</button></div>
        <p id="agent-guidance" class="agent-guidance"></p><p id="agent-feedback" class="agent-guidance" role="status" hidden></p>
      </div>
    </section>`;
  document.getElementById('health-card')!.before(panel);
  const el = (id:string) => panel.querySelector<HTMLElement>('#' + id)!;
  const button = (id:string) => el(id) as HTMLButtonElement;
  const toggle = el('agent-enabled') as HTMLInputElement;
  const agentList = panel.querySelector('.agent-list')!;
  let rows:HTMLButtonElement[] = [];
  let entries = agentEntries(undefined);
  const ranges = Array.from(panel.querySelectorAll<HTMLButtonElement>('[data-days]'));
  const review = initCheckReview(panel, request, product => {
    const agent = AGENTS.find(key => products[key] === product);
    return agent ? AGENT_NAMES[agent] : product;
  });
  let status:Status = {}, selected = 'codex', days:1|30 = 1, data:Summary|undefined;
  let shown = false, available = false, fetching = false, working = false, identity = '', revision = 0;
  let timer:ReturnType<typeof setTimeout>|undefined;

  function feedback(value:string) { el('agent-feedback').textContent = value; el('agent-feedback').hidden = !value; }
  function controls() {
    const {state, agent} = entries.find(entry => entry.id === selected)!;
    const canSetUp = available && !working && !!state && (state.available || state.installed || state.partial || state.opted_out);
    toggle.disabled = !canSetUp || (!!state?.disabled && !['codex','antigravity'].includes(agent));
    button('agent-reinstall').disabled = !canSetUp;
    button('agent-configuration').disabled = !available || working || !state?.config_exists;
    ranges.forEach(range => { range.disabled = !available; });
    rows.forEach(row => { row.disabled = working; });
    button('guardrails-view').disabled = !data;
    button('guardrails-ask').disabled = !available || !data;
    button('guardrails-deny').disabled = !available || !data || (status.connection_mode === 'free' || status.connection_mode === 'api_key');
    button('guardrails-deny').title = (status.connection_mode === 'free' || status.connection_mode === 'api_key') ? 'Cloud checks are shown in View activity.' : 'Review denied checks';
  }
  function renderAgent() {
    entries = agentEntries(status.hooks);
    if (!entries.some(entry => entry.id === selected)) selected = entries[0].id;
    const previous = new Map(rows.map(row => [row.dataset.id, row]));
    rows = entries.map(entry => {
      const row = previous.get(entry.id) || document.createElement('button');
      if (!previous.has(entry.id)) {
        row.type = 'button'; row.className = 'agent-row'; row.tabIndex = 0;
        row.dataset.id = entry.id; row.dataset.agent = entry.agent;
        if (entry.profile) row.dataset.profile = entry.profile;
        row.setAttribute('aria-controls', 'agent-detail');
        row.innerHTML = `<img src="${agentIcon(products[entry.agent])}" alt=""><span><strong></strong><small></small></span><span class="chevron" aria-hidden="true">›</span>`;
        row.addEventListener('click', () => { selected = entry.id; feedback(''); renderAgent(); });
      }
      row.title = entry.profile || AGENT_NAMES[entry.agent];
      row.setAttribute('aria-pressed', String(entry.id === selected));
      row.querySelector('strong')!.textContent = AGENT_NAMES[entry.agent];
      row.querySelector('small')!.textContent = `${entry.profile ? entry.state?.name + ' · ' : ''}${setupLabel(entry.state)}`;
      return row;
    });
    const undetected = rows.filter((_, index) => setupLabel(entries[index].state) === 'Agent not detected');
    const orderedRows = [...rows.filter(row => !undetected.includes(row)), ...undetected];
    if (orderedRows.length !== agentList.children.length || orderedRows.some((row, index) => agentList.children[index] !== row)) {
      const focusedRow = rows.find(row => row === document.activeElement);
      agentList.replaceChildren(...orderedRows);
      focusedRow?.focus({preventScroll:true});
    }
    const {state, agent, profile} = entries.find(entry => entry.id === selected)!;
    el('agent-name').textContent = AGENT_NAMES[agent] + (profile ? ` · ${state?.name}` : '');
    const label = setupLabel(state);
    el('agent-badge').textContent = label === 'Installed · On' ? 'Installed' : label;
    el('agent-badge').dataset.tone = label === 'Installed · On' ? 'success' : 'neutral';
    toggle.checked = !!state?.installed && !state.opted_out && !state.disabled;
    const last = data?.by_agent.find(row => row.product === products[agent])?.last_check_at;
    el('agent-last-check').textContent = last ? `${profile ? 'Last Codex check (all profiles)' : 'Last check'} ${stamp(last)}` : data ? 'No checks in this period' : 'Last check unavailable';
    el('agent-path').textContent = state?.config_path || 'Configuration path unavailable';
    el('agent-checks').replaceChildren(...(state?.control_events ?? []).map(event => {
      const chip = document.createElement('span');
      chip.textContent = ({UserPromptSubmit:'User prompts', PreToolUse:'Tool calls', PostToolUse:agent === 'claude' ? 'Bash results' : 'Tool results'} as Record<string,string>)[event] || event;
      if (event === 'PostToolUse') chip.title = 'Requires a compatible agent version and enabled content capture.';
      return chip;
    }));
    if (!state?.control_events?.length) el('agent-checks').textContent = 'Capabilities unavailable';
    button('agent-reinstall').textContent = state?.installed || state?.partial || state?.disabled ? 'Reinstall guardrails' : 'Install guardrails';
    el('agent-guidance').textContent = state?.approval_pending
      ? 'Start Hermes chat and approve the OpenAIDR hook commands. Approval must be given in Hermes.'
      : state?.disabled ? `Hooks are disabled in ${AGENT_NAMES[agent]}. Check the agent settings before starting a new session.`
      : state?.opted_out ? 'Guardrails are off for this agent. Enable them to install hooks for new sessions.'
      : !state?.available && !state?.installed ? `Install ${AGENT_NAMES[agent]} on this device to set up guardrails.`
      : `Changes apply to new ${AGENT_NAMES[agent]} sessions. Installed settings do not confirm hooks are loaded in a running session.`;
    controls();
  }
  function renderSummary() {
    el('guardrails-data').hidden = !data;
    el('guardrails-mode').textContent = data ? data.mode === 'shadow' ? 'Monitoring (Shadow)' : 'Enforce' : 'Policy unavailable';
    const personal = status.connection_mode === 'free' || status.connection_mode === 'api_key';
    const continues = !data || data.mode === 'shadow';
    el('guardrails-policy').textContent = personal
      ? [status.connection_mode === 'api_key' ? 'API key' : '', continues ? 'Actions continue' : 'Local rules'].filter(Boolean).join(' · ')
      : continues ? 'Organization policy · Actions continue' : 'Organization policy';
    if (!data) { el('guardrails-activity').hidden = true; button('guardrails-view').setAttribute('aria-expanded', 'false'); button('guardrails-view').textContent = 'View activity'; renderAgent(); return; }
    for (const key of ['completed','allow','deny','ask'] as const) el('guardrails-' + key).textContent = data.summary[key].toLocaleString();
    const shadowOnly = data.by_mode.enforce.completed === 0 && data.by_mode.shadow.completed > 0;
    el('guardrails-deny-label').textContent = shadowOnly ? 'Would deny' : 'Deny';
    el('guardrails-ask-label').textContent = shadowOnly ? 'Would ask' : 'Ask';
    const {warn, unavailable, pending} = data.summary;
    el('guardrails-exceptions').textContent = [warn ? `${warn.toLocaleString()} warn decisions` : '', unavailable ? `${unavailable.toLocaleString()} checks unavailable` : '', pending ? `${pending.toLocaleString()} pending` : ''].filter(Boolean).join(' · ');
    el('guardrails-exceptions').hidden = !warn && !unavailable && !pending;
    el('guardrails-recent').replaceChildren(...data.recent.map(check => {
      const row = document.createElement('div'); row.className = 'guardrail-activity-row';
      const title = document.createElement('strong'), detail = document.createElement('span');
      const agent = AGENTS.find(key => products[key] === check.product);
      const decision = check.status === 'evaluated' ? check.evaluated_decision : check.status;
      title.textContent = `${agent ? AGENT_NAMES[agent] : check.product} · ${decision}`;
      detail.textContent = `${stamp(check.created_at)} · ${check.mode === 'shadow' ? 'Shadow' : 'Enforce'} · ${check.hook_event}${check.returned_decision ? ` · Response: ${check.returned_decision}` : ''}`;
      row.append(title, detail);
      if (check.status === 'unavailable' && (status.connection_mode === 'free' || status.connection_mode === 'api_key')) {
        const reason = document.createElement('span');
        reason.textContent = failureLabels.get(check.failure_reason ?? '') ?? 'Reason not recorded.';
        row.append(reason);
      }
      return row;
    }));
    if (!data.recent.length) el('guardrails-recent').textContent = 'No checks reported in this period.';
    renderAgent();
  }
  function schedule() {
    clearTimeout(timer);
    if (!panel.hidden && available && visible()) timer = setTimeout(() => void refresh(), 15000);
  }
  async function refresh() {
    if (fetching || panel.hidden || !available || !visible() || !identity) return;
    fetching = true;
    const readRevision = revision;
    try {
      const response = await request('guardrails.summary', {days});
      if (revision !== readRevision) return;
      if ((response as {supported?:boolean})?.supported === false) throw new Error('Activity requires an updated organization server. Agent setup is available below.');
      if (!validSummary(response) || response.days !== days || response.sensor_id !== status.sensor_id || response.server_url.replace(/\/$/, '') !== status.server_url?.replace(/\/$/, '')) throw new Error('Guardrail activity is unavailable. Try again shortly.');
      data = response;
      el('guardrails-message').hidden = true;
    } catch (error) {
      if (revision !== readRevision) return;
      data = undefined; el('guardrails-message').hidden = false;
      el('guardrails-message').textContent = error instanceof Error ? error.message : String(error);
    } finally {
      fetching = false;
      if (revision === readRevision) { renderSummary(); schedule(); }
      else void refresh();
    }
  }
  async function change(enabled:boolean) {
    if (working) return;
    working = true; feedback('Saving agent setup…'); renderAgent();
    const {agent, profile} = entries.find(entry => entry.id === selected)!;
    try { await configure('guardrails.configure', {agent, enabled, ...(profile ? {profile} : {})}); feedback('Saved. Start a new agent session to use this setup.'); }
    catch (error) { feedback(error instanceof Error ? error.message : String(error)); }
    finally { working = false; renderAgent(); }
  }
  toggle.addEventListener('change', () => void change(toggle.checked));
  button('agent-reinstall').addEventListener('click', () => void change(true));
  button('agent-configuration').addEventListener('click', async () => {
    const {agent, profile} = entries.find(entry => entry.id === selected)!;
    try { await request('guardrails.configuration', {agent, ...(profile ? {profile} : {})}); feedback('Opened the configuration folder.'); }
    catch (error) { feedback(error instanceof Error ? error.message : String(error)); }
  });
  button('guardrails-view').addEventListener('click', () => {
    const open = el('guardrails-activity').hidden;
    el('guardrails-activity').hidden = !open;
    button('guardrails-view').setAttribute('aria-expanded', String(open));
    button('guardrails-view').textContent = open ? 'Hide activity' : 'View activity';
  });
  button('guardrails-deny').addEventListener('click', () => { if (data) review.open(data, 'deny'); });
  button('guardrails-ask').addEventListener('click', () => { if (data) review.open(data, 'ask'); });
  ranges.forEach(range => range.addEventListener('click', () => {
    const next = Number(range.dataset.days) as 1|30;
    if (next === days) return;
    days = next; revision++; data = undefined; review.reset();
    ranges.forEach(button => button.setAttribute('aria-pressed', String(Number(button.dataset.days) === days)));
    el('guardrails-message').hidden = false; el('guardrails-message').textContent = 'Loading guardrail activity…';
    renderSummary(); void refresh();
  }));
  return {
    refresh() { return refresh(); },
    setVisible(value:boolean) { shown = value; panel.hidden = !shown || !identity; schedule(); if (shown) void refresh(); },
    setAvailability(value:boolean) { available = value; review.setAvailability(value); controls(); schedule(); },
    setStatus(value:Status) {
      status = value;
      const next = status.enrolled && !status.disabled && !status.desktop_removal ? `${status.server_url}/${status.sensor_id}` : '';
      if (identity !== next) { identity = next; revision++; data = undefined; review.reset(); feedback(''); el('guardrails-message').hidden = false; el('guardrails-message').textContent = 'Loading guardrail activity…'; }
      panel.hidden = !shown || !identity; renderSummary(); schedule();
    },
  };
}
