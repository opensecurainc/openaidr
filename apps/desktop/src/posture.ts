import { agentIcon } from '../../../packages/ui/agent-icons/index.js';
import './posture.css';

type Status = {enrolled?:boolean; disabled?:boolean; desktop_removal?:unknown; sensor_id?:string; server_url?:string; connection_mode?:string};
type Group = 'apps'|'components'|'skills';
type Asset = {id:string; name:string; kind:string; source:string|null; path:string|null; version:string|null; publisher:string|null;
  scope:string|null; last_seen_at:string|null; root_status:string|null; product:string|null; attention:boolean;
  approval_status:'approved'|'unapproved'|'monitoring'|'unavailable';
  assessment_status:'complete'|'partial'|'pending'|'failed'|'stale'|'unsupported'|'disabled';
  findings:{title:string;detail:string}[]; findings_truncated:boolean; metadata:Record<string,unknown>};
type Inventory = {items:Asset[]; total:number; truncated:boolean};
type Checks = {enabled:boolean; state:string;
  billing:{status:string; available:string; reserved:string; used:string; resets_at:string|null; checked_at:string}|null;
  usage:{credits_charged:string; credits_reserved:string; unknown_attempts:number}|null};
type Snapshot = {supported:true; schema_version:1; source?:'local'; sensor_id:string; server_url:string; scope:string; collected_at:string|null;
  assessments?:unknown;
  groups:Record<Group,Inventory>; coverage:{status:'complete'|'partial'|'unavailable'; sources:{source:string;status:'ok'|'partial'|'error'|'unavailable';collected_at:string|null;message:string}[]}};
const groups:Record<Group,{label:string;noun:string}> = {
  apps:{label:'AI Apps',noun:'apps'},
  components:{label:'Supply Chain',noun:'components'},
  skills:{label:'AI Skills',noun:'skills'},
};
const approvals = {approved:'Approved',unapproved:'Unapproved',monitoring:'Monitoring',unavailable:'Review unavailable'};
const assessments = {complete:'Complete',partial:'Partial',pending:'Pending',failed:'Failed',stale:'Stale',unsupported:'Not assessed',disabled:'Disabled'};
const record = (value:unknown):value is Record<string,unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const stamp = (value:string|null) => value ? new Date(value).toLocaleString(undefined,{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}) : 'Not reported';
const date = (value:unknown) => value === null || typeof value === 'string' && Number.isFinite(Date.parse(value));
const groupKeys = Object.keys(groups) as Group[];
function checks(value:unknown):Checks|undefined {
  const amount = (value:unknown) => typeof value === 'string' && value.length <= 40 && /^(0|[1-9]\d*)(\.\d{1,6})?$/.test(value);
  if (!record(value) || typeof value.enabled !== 'boolean' || typeof value.state !== 'string') return;
  const billing = value.billing, usage = value.usage;
  return {enabled:value.enabled,state:value.state,
    billing:record(billing) && typeof billing.status === 'string' && ['available','reserved','used'].every(key => amount(billing[key]))
      && date(billing.resets_at) && typeof billing.checked_at === 'string' && date(billing.checked_at) ? billing as Checks['billing'] : null,
    usage:record(usage) && amount(usage.credits_charged) && amount(usage.credits_reserved)
      && Number.isSafeInteger(usage.unknown_attempts) && (usage.unknown_attempts as number) >= 0 ? usage as Checks['usage'] : null};
}
function valid(value:unknown):value is Snapshot {
  if (!record(value) || value.supported !== true || value.schema_version !== 1 || !date(value.collected_at)
      || value.source !== undefined && value.source !== 'local'
      || !record(value.groups) || !record(value.coverage) || !['complete','partial','unavailable'].includes(String(value.coverage.status))
      || !Array.isArray(value.coverage.sources) || value.coverage.sources.length > 100) return false;
  const inventories = value.groups;
  return value.coverage.sources.every(s => record(s) && typeof s.source === 'string' && typeof s.message === 'string'
    && ['ok','partial','error','unavailable'].includes(String(s.status)) && date(s.collected_at))
    && groupKeys.every(key => {
      const group = inventories[key];
      return record(group) && Array.isArray(group.items) && group.items.length <= 200 && Number.isSafeInteger(group.total)
        && (group.total as number) >= group.items.length && typeof group.truncated === 'boolean'
        && (group.truncated || group.total === group.items.length) && new Set(group.items.map(item => item?.id)).size === group.items.length
        && group.items.every(item => record(item) && ['id','name','kind'].every(field => typeof item[field] === 'string')
          && ['source','path','version','publisher','scope','root_status','product'].every(field => item[field] === null || typeof item[field] === 'string')
          && date(item.last_seen_at) && typeof item.attention === 'boolean' && Object.hasOwn(approvals,String(item.approval_status))
          && Object.hasOwn(assessments,String(item.assessment_status)) && record(item.metadata)
          && Array.isArray(item.findings) && item.findings.length <= 10 && typeof item.findings_truncated === 'boolean'
          && item.findings.every(finding => record(finding) && typeof finding.title === 'string' && typeof finding.detail === 'string'));
    });
}
function node<K extends keyof HTMLElementTagNameMap>(tag:K, text = '', className = '') {
  const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
}
function groupIcon(group:Group) {
  const paths = {apps:'M7 7h10v10H7zM5 3h14v18H5zM1 7h4m-4 5h4m-4 5h4m14-10h4m-4 5h4m-4 5h4',components:'m12 3 9 5v9l-9 5-9-5V8zM3 8l9 5 9-5m-9 5v9M7 5l10 6',skills:'M12 5C8 2 5 3 2 4v16c4-2 7-1 10 1 3-2 6-3 10-1V4c-3-1-6-2-10 1zm0 0v16'};
  const mark = node('span','','posture-symbol'); mark.setAttribute('aria-hidden','true');
  mark.innerHTML = `<svg viewBox="0 0 24 24"><path d="${paths[group]}"/></svg>`; return mark;
}
function assetIcon(asset:Asset, group:Group) {
  const src = asset.product ? agentIcon(asset.product) : undefined;
  if (src) { const image = node('img','','posture-icon'); image.src = src; image.alt = ''; return image; }
  const mark = groupIcon(group); mark.classList.add('posture-icon'); return mark;
}
function badge(asset:Asset, group:Group, local = false) {
  const findings = `${asset.findings.length}${asset.findings_truncated ? '+' : ''} finding${asset.findings.length === 1 && !asset.findings_truncated ? '' : 's'}`;
  const label = local || group === 'components' ? asset.findings.length ? findings : assessments[asset.assessment_status] : approvals[asset.approval_status];
  return node('span',label,`posture-badge${asset.attention ? ' posture-warning' : ''}`);
}

export function initPosture(request:(action:string, params?:Record<string,unknown>) => Promise<unknown>, visible:() => boolean) {
  const panel = node('section'); panel.id = 'posture-page'; panel.hidden = true; panel.setAttribute('role','tabpanel'); panel.setAttribute('aria-labelledby','posture-tab');
  panel.innerHTML = `<div class="posture-heading"><h1>AI posture</h1><button type="button" class="button button-secondary" id="posture-refresh">Refresh</button></div>
    <div class="posture-nav" role="tablist" aria-label="Posture pages"></div>
    <p id="posture-message" role="status"></p>
    <div id="posture-content" hidden>
      <section id="posture-overview" role="tabpanel" aria-labelledby="posture-overview-tab"><div class="posture-stats"></div>
        <section id="posture-checks" class="card posture-card" aria-label="Automatic checks" hidden>
          <div class="posture-section-heading"><div><h2>Automatic checks</h2><span id="posture-check-state" role="status"></span></div><button type="button" class="button button-secondary" id="posture-configure">Enable automatic checks</button></div>
          <p class="posture-check-copy">Sends package identifiers and skill content to OpenSecura and uses credits. One billed request per skill; AI review is partial.</p>
          <div class="posture-credit-summary"><span>Account available <strong id="posture-credit-available"></strong></span><span>Posture charged on this device <strong id="posture-credit-charged"></strong></span></div>
          <details id="posture-credit-details"><summary>Credit details</summary><p id="posture-credit-info"></p><p>Posture totals cover retained checks for this connection on this device. Unconfirmed charges are excluded. Pausing stops new checks; admitted checks may finish.</p></details>
          <p id="posture-check-message" role="status"></p>
        </section>
        <section class="card posture-card"><div class="posture-section-heading"><h2>Needs attention <span id="posture-attention-count" class="posture-count"></span></h2></div><div id="posture-attention"></div></section>
      </section>
      <section id="posture-inventory" role="tabpanel" hidden><div class="posture-filters"><input id="posture-search" type="search" aria-label="Search loaded assets" placeholder="Search loaded assets"><label><input type="checkbox" id="posture-only-attention">Needs attention</label></div>
        <section class="card posture-card"><div class="posture-list-heading"><span id="posture-column">Asset</span><span id="posture-review-column">Organization review</span></div><div id="posture-rows"></div><div class="posture-list-footer"><span id="posture-result" role="status"></span><div><button type="button" class="button button-secondary" id="posture-previous" aria-label="Previous asset page">‹</button><span id="posture-page-number"></span><button type="button" class="button button-secondary" id="posture-next" aria-label="Next asset page">›</button></div></div></section>
      </section>
      <details id="posture-coverage-details" class="card posture-card posture-coverage"><summary aria-label="Collection details" aria-describedby="posture-coverage-title posture-loaded"><span class="posture-coverage-copy"><strong id="posture-coverage-title"></strong><span id="posture-loaded" hidden></span></span><span class="posture-coverage-toggle" aria-hidden="true">Details <span>›</span></span></summary><div class="posture-coverage-body"><p id="posture-collected"></p><p class="posture-note" id="posture-note"></p><div id="posture-sources"></div></div></details>
    </div>`;
  document.getElementById('health-card')!.before(panel);
  const dialog = node('dialog','','simulation-dialog posture-dialog'); dialog.id = 'posture-detail'; dialog.setAttribute('aria-labelledby','posture-detail-title');
  dialog.innerHTML = `<div class="posture-detail-heading"><h2 id="posture-detail-title"></h2><button type="button" class="button icon-button close-button" aria-label="Close asset details">×</button></div><div id="posture-detail-content"></div><div class="posture-detail-footer"><span>Reported data · This device</span><button type="button" id="posture-done">Done</button></div>`;
  document.body.append(dialog);
  const el = (id:string) => document.getElementById(`posture-${id}`)!;
  const button = (id:string) => el(id) as HTMLButtonElement;
  const search = el('search') as HTMLInputElement, attention = el('only-attention') as HTMLInputElement;
  const nav = panel.querySelector('.posture-nav')!;
  const pages = ['overview',...groupKeys] as const;
  let selected:typeof pages[number] = 'overview', page = 0, identity = '', revision = 0, readAt = 0;
  let status:Status = {}, snapshot:Snapshot|undefined, shown = false, available = false, fetching = false, opener:HTMLElement|undefined;
  let configuring = false;
  let timer:ReturnType<typeof setTimeout>|undefined;
  const active = () => shown && available && !!identity && visible();
  const tabs = pages.map(key => {
    const tab = node('button',key === 'overview' ? 'Overview' : groups[key].label); tab.type = 'button'; tab.id = `posture-${key}-tab`;
    tab.setAttribute('role','tab'); tab.setAttribute('aria-controls',key === 'overview' ? 'posture-overview' : 'posture-inventory');
    tab.addEventListener('click',() => select(key)); nav.append(tab); return tab;
  });
  function message(value:string) { el('message').textContent = value; el('message').hidden = !value; }
  function controls() {
    button('refresh').disabled = !available || fetching || configuring;
    button('configure').disabled = !available || fetching || configuring || !checks(snapshot?.assessments);
    tabs.forEach(tab => { tab.disabled = !available; });
    search.disabled = attention.disabled = !available;
    panel.querySelectorAll<HTMLButtonElement>('[data-asset], .posture-stat').forEach(control => { control.disabled = !available; });
    if (selected !== 'overview' && snapshot) {
      const count = filtered().length;
      button('previous').disabled = !available || page === 0;
      button('next').disabled = !available || (page+1)*6 >= count;
    }
  }
  function select(key:typeof selected) {
    selected = key; page = 0; search.value = ''; attention.checked = false;
    tabs.forEach((tab,i) => { tab.setAttribute('aria-selected',String(pages[i] === key)); tab.tabIndex = pages[i] === key ? 0 : -1; });
    el('overview').hidden = key !== 'overview'; el('inventory').hidden = key === 'overview';
    panel.querySelector('h1')!.textContent = key === 'overview' ? 'AI posture' : groups[key].label;
    if (key !== 'overview') {
      el('inventory').setAttribute('aria-labelledby',`posture-${key}-tab`);
      search.placeholder = `Search ${groups[key].noun}`;
    }
    render();
  }
  function filtered() {
    if (!snapshot || selected === 'overview') return [];
    const query = search.value.trim().toLocaleLowerCase();
    return snapshot.groups[selected].items.filter(item => (!attention.checked || item.attention) && [item.name,item.kind,item.source,item.publisher,item.path].some(value => value?.toLocaleLowerCase().includes(query)));
  }
  function row(asset:Asset, group:Group, overview = false) {
    const control = node('button','','posture-row'); control.type = 'button'; control.dataset.asset = asset.id;
    const copy = node('span','','posture-row-copy'); copy.append(node('strong',asset.name));
    const local = snapshot?.source === 'local';
    const detail = overview ? asset.findings[0]?.title || (!local && asset.approval_status === 'unapproved' ? 'Awaiting review' : '') : [group === 'components' ? asset.kind : null,asset.version,asset.publisher || asset.source].filter(Boolean).join(' · ');
    if (detail) copy.append(node('small',detail));
    const chevron = node('span','›','posture-chevron'); chevron.setAttribute('aria-hidden','true');
    control.append(assetIcon(asset,group),copy,badge(asset,group,local),chevron);
    control.addEventListener('click',() => detailView(asset,group,control)); return control;
  }
  function render() {
    if (!snapshot) { controls(); return; }
    const local = snapshot.source === 'local';
    el('content').hidden = false;
    el('checks').hidden = !local;
    if (local) {
      const value = checks(snapshot.assessments), billing = value?.billing, usage = value?.usage;
      const states:Record<string,string> = {running:'Checking',idle:'Watching for changes',waiting:'Waiting for the worker',exhausted:'Out of credits',unavailable:'Checks unavailable',suspended:'Account restricted',disabled:'Paused'};
      el('check-state').textContent = !value ? 'Settings unavailable' : !value.enabled ? 'Paused' : states[value.state] || 'Checks unavailable';
      button('configure').textContent = configuring ? 'Saving…' : value?.enabled ? 'Pause checks' : 'Enable automatic checks';
      el('credit-available').textContent = billing ? `${billing.available} credits` : 'Unavailable';
      el('credit-charged').textContent = usage ? `${usage.credits_charged} credits` : 'Unavailable';
      el('credit-info').textContent = [billing ? `Account: ${billing.status}. Reserved: ${billing.reserved} credits. Used: ${billing.used} credits. Updated ${stamp(billing.checked_at)}.${billing.resets_at ? ' Resets '+stamp(billing.resets_at)+'.' : ''}` : 'Account credit details unavailable.',
        usage ? `Posture reserved: ${usage.credits_reserved} credits. Unconfirmed checks: ${usage.unknown_attempts}. Their results or charges are uncertain; held checks do not retry automatically.` : 'Posture receipt totals unavailable.'].join(' ');
    }
    if (selected === 'overview') {
      const stats = panel.querySelector('.posture-stats')!;
      stats.replaceChildren(...groupKeys.map(group => {
        const inventory = snapshot!.groups[group], count = inventory.items.filter(item => item.attention).length;
        const stat = node('button','','card posture-card posture-stat'); stat.type = 'button'; stat.setAttribute('aria-label',`View ${groups[group].label}`);
        const title = node('span','','posture-stat-title'); title.append(groupIcon(group),node('span',groups[group].label));
        stat.append(title,node('strong',inventory.total.toLocaleString()),node('small',`${count}${inventory.truncated ? ' loaded' : ''} ${count === 1 ? 'needs' : 'need'} attention`));
        stat.addEventListener('click',() => { select(group); tabs[pages.indexOf(group)].focus(); }); return stat;
      }));
      const issues = groupKeys.flatMap(group => snapshot!.groups[group].items.filter(asset => asset.attention).map(asset => ({asset,group})));
      el('attention-count').textContent = `${issues.length}${groupKeys.some(group => snapshot!.groups[group].truncated) ? ' loaded' : ''}`;
      el('attention').replaceChildren(...issues.slice(0,3).map(({asset,group}) => row(asset,group,true)));
      if (!issues.length) el('attention').append(node('p','No attention items in loaded records.','posture-empty'));
      if (issues.length > 3) el('attention').append(node('p','Open a category for more.','posture-note'));
    } else {
      const inventory = snapshot.groups[selected], rows = filtered(), pages = Math.max(1,Math.ceil(rows.length/6));
      page = Math.min(page,pages-1);
      el('column').textContent = selected === 'apps' ? 'Application' : selected === 'skills' ? 'Skill' : 'Component';
      el('review-column').textContent = local || selected === 'components' ? 'Assessment' : 'Organization review';
      el('rows').replaceChildren(...rows.slice(page*6,page*6+6).map(asset => row(asset,selected as Group)));
      if (!rows.length) el('rows').append(node('p',inventory.items.length ? 'No matching assets. Clear the search or attention filter.' : 'No assets have been reported in this category.','posture-empty'));
      el('result').textContent = `${rows.length ? `${page*6+1}–${Math.min(page*6+6,rows.length)} of ${rows.length}` : '0'}${inventory.truncated ? ' loaded' : ''} ${groups[selected].noun}`;
      el('page-number').textContent = `${page+1} / ${pages}`;
    }
    const incomplete = groupKeys.filter(group => snapshot!.groups[group].truncated).map(group => `${groups[group].label}: ${snapshot!.groups[group].items.length} of ${snapshot!.groups[group].total} loaded`);
    const coverage = snapshot.coverage;
    el('coverage-title').textContent = coverage.status === 'complete' ? 'Collection complete' : coverage.status === 'partial' ? 'Collection incomplete' : 'Collection unavailable';
    el('loaded').textContent = incomplete.join(' · ');
    el('loaded').hidden = !incomplete.length;
    el('collected').textContent = `Oldest source update: ${stamp(snapshot.collected_at)}`;
    el('note').textContent = [incomplete.length ? `${incomplete.join('; ')}. Search and attention counts cover loaded records only.` : '',local ? 'Inventory is collected on this device. When enabled, automatic checks send selected data for assessment. Collection alone does not assess security.' : selected === 'components' ? 'Assessment status is separate from organization approval.' : 'Organization approval is separate from security assessment.'].filter(Boolean).join(' ');
    el('sources').replaceChildren(...snapshot.coverage.sources.map(source => {
      const line = node('p'); line.append(node('strong',`${source.source}: ${source.status}`),node('span',` · ${stamp(source.collected_at)}${source.message ? ' · '+source.message : ''}`)); return line;
    }));
    if (!snapshot.coverage.sources.length) el('sources').append(node('p','No collection source details were reported.'));
    controls();
  }
  function detailView(asset:Asset, group:Group, control:HTMLElement) {
    opener = control; el('detail-title').textContent = asset.name;
    const content = el('detail-content'); content.replaceChildren();
    const local = snapshot?.source === 'local';
    const states = node('p','','posture-detail-states'); states.append(badge(asset,group,local),node('span',`Assessment: ${assessments[asset.assessment_status]}${!local && group === 'components' ? ' · Organization review: '+approvals[asset.approval_status] : ''}`)); content.append(states);
    content.append(node('h3','Reported findings'));
    if (asset.findings.length) for (const finding of asset.findings) { content.append(node('strong',finding.title),node('p',finding.detail)); }
    else content.append(node('p',asset.assessment_status === 'complete' ? 'No findings were included in the completed assessment.' : 'No completed finding details are available.'));
    if (asset.findings_truncated) content.append(node('p',local ? 'Additional findings are not shown in this view.' : 'Additional findings are available in the dashboard.'));
    if (asset.attention) { content.append(node('h3','Suggested next step'),node('p',local ? 'Review the reported findings and source details before using this asset.' : 'Review the reported findings and source with your administrator in the dashboard. This view does not change approval or agent configuration.')); }
    const facts = node('dl','','posture-facts');
    const values:[string,unknown][] = [['Kind',asset.kind],['Source',asset.source],['Publisher',asset.publisher],['Version',asset.version],['Scope',asset.scope],['Location',asset.path],['Root status',asset.root_status],['Last detected',stamp(asset.last_seen_at)]];
    for (const [key,label] of Object.entries({description:'Description',license:'License',repository_url:'Repository',source_url:'Source URL',revision:'Revision',content_sha256:'Content hash',tools:'Tools',assessment_scope:'Review scope',assessment_coverage:'Review coverage'})) {
      const value = asset.metadata[key];
      if (typeof value === 'string' || Array.isArray(value) && value.every(entry => typeof entry === 'string')) values.push([label,Array.isArray(value) ? value.join(', ') : value]);
    }
    const prepared = asset.metadata.assessment_prepared_at;
    if (typeof prepared === 'number' && Number.isFinite(prepared) && date(new Date(prepared*1000).toString())) values.push(['Prepared',stamp(new Date(prepared*1000).toISOString())]);
    for (const [label,value] of values) if (value) { const line = node('div'); line.append(node('dt',label),node('dd',String(value))); facts.append(line); }
    content.append(facts); dialog.showModal(); dialog.scrollTop = 0; dialog.querySelector<HTMLButtonElement>('.close-button')!.focus();
  }
  function schedule() { clearTimeout(timer); if (active()) timer = setTimeout(() => void refresh(),30000); }
  async function refresh(force = false) {
    if (!active() || fetching || configuring || !force && Date.now()-readAt < 30000) return;
    fetching = true; controls(); const current = revision;
    try {
      const response = await request('posture.summary');
      if (revision !== current) return;
      if (!record(response) || response.sensor_id !== status.sensor_id || response.server_url !== status.server_url?.replace(/\/$/,'') || typeof response.scope !== 'string' || !response.scope) throw new Error('Posture response does not match this device.');
      if (response.supported === false) {
        snapshot = undefined; el('content').hidden = true; dialog.close();
        message(response.reason === 'connection_mode' ? 'Update OpenAIDR to view local posture for this connection.' : 'Posture inventory is unavailable on this server. Ask your administrator to update it.');
      } else {
        if (!valid(response)) throw new Error('Posture data is unavailable. Try refreshing shortly.');
        if (snapshot?.scope !== response.scope) { el('check-message').textContent = ''; el('credit-details').removeAttribute('open'); }
        snapshot = response; message(''); render();
      }
    } catch (error) {
      if (revision !== current) return;
      message(`${snapshot ? 'Showing previously loaded posture. ' : ''}${error instanceof Error ? error.message : 'Posture is unavailable. Try refreshing shortly.'}`);
    } finally {
      fetching = false;
      if (revision === current) { readAt = Date.now(); controls(); schedule(); }
      else void refresh();
    }
  }
  button('configure').addEventListener('click',async () => {
    const value = checks(snapshot?.assessments);
    if (!active() || !snapshot || snapshot.source !== 'local' || !value || fetching || configuring) return;
    const current = revision, scope = snapshot.scope, automatic = !value.enabled;
    configuring = true; el('check-message').textContent = ''; render();
    try {
      const response = await request('posture.configure',{automatic,scope});
      if (current !== revision || snapshot?.scope !== scope) return;
      if (!record(response) || response.scope !== scope || response.enabled !== automatic) throw new Error('Could not confirm the saved setting. Refresh before trying again.');
      snapshot.assessments = {...value,enabled:automatic,state:automatic ? 'waiting' : 'disabled'};
      el('check-message').textContent = automatic ? 'Automatic checks enabled.' : 'Paused. Admitted checks may finish.';
    } catch (error) {
      if (current === revision && snapshot?.scope === scope) el('check-message').textContent = error instanceof Error ? error.message : 'Could not save the setting. Refresh and try again.';
    } finally {
      configuring = false; render(); await refresh(true);
    }
  });
  search.addEventListener('input',() => { page = 0; render(); }); attention.addEventListener('change',() => { page = 0; render(); });
  button('previous').addEventListener('click',() => { page--; render(); }); button('next').addEventListener('click',() => { page++; render(); });
  button('refresh').addEventListener('click',() => void refresh(true));
  nav.addEventListener('keydown',event => {
    const key = (event as KeyboardEvent).key; if (!['ArrowLeft','ArrowRight','Home','End'].includes(key)) return;
    event.preventDefault(); const index = tabs.indexOf(document.activeElement as HTMLButtonElement);
    const next = key === 'Home' ? 0 : key === 'End' ? tabs.length-1 : (index+(key === 'ArrowRight' ? 1 : -1)+tabs.length)%tabs.length;
    select(pages[next]); tabs[next].focus();
  });
  dialog.querySelector('.close-button')!.addEventListener('click',() => dialog.close()); button('done').addEventListener('click',() => dialog.close());
  dialog.addEventListener('close',() => {
    if (opener?.isConnected && shown && (document.activeElement === document.body || dialog.contains(document.activeElement))) opener.focus();
  });
  select('overview');
  return {
    refresh,
    setVisible(value:boolean) { shown = value; panel.hidden = !shown || !identity; if (!shown) dialog.close(); schedule(); if (shown) void refresh(); },
    setAvailability(value:boolean) { available = value; controls(); schedule(); },
    setStatus(value:Status) {
      status = value; const next = value.enrolled && !value.disabled && !value.desktop_removal ? `${value.connection_mode}/${value.server_url}/${value.sensor_id}` : '';
      if (identity !== next) { identity = next; revision++; readAt = 0; snapshot = undefined; opener = undefined; dialog.close(); el('content').hidden = true; el('check-message').textContent = ''; el('credit-details').removeAttribute('open'); el('coverage-details').removeAttribute('open'); select('overview'); message('Loading posture…'); }
      panel.hidden = !shown || !identity; schedule();
    },
  };
}
