import { agentIcon } from '../../../packages/ui/agent-icons/index.js';

type Counts = {tokens:number; calls:number; priced_calls:number; cost_usd:number|null;
  cached_input_tokens?:number; uncached_input_tokens?:number; output_tokens?:number};
type Row = Counts & {name:string};
type Breakdown = Counts & {application:string; model:string; reasoning_effort:string};
type Day = Counts & {date:string; breakdown?:Breakdown[]};
type HookEstimate = {application:string; model:string; model_source:string; observations:number;
  priced_observations:number; estimated_input_tokens:number; estimated_output_tokens:number;
  estimated_cost_usd:string|null};
type Usage = {
  days:1|30; granularity?:'hour'|'day'; timezone:string; since?:string; until:string; summary:Counts;
  series:Day[]; by_model:Row[]; by_reasoning_effort:Row[]; breakdown?:Breakdown[];
  pending_exports:number; history_incomplete?:boolean; source?:'local';
  history_recovery?:{recovered_calls:number; last_scan_at:string|null; blocked_files:number;
    inaccessible_sources:number; inaccessible_files:number; invalid_records:number;
    unsupported_records:number; pending_files:number; unreconciled_records?:number};
  hook_estimates?:{items:HookEstimate[]};
};
type Status = {enrolled?:boolean; disabled?:boolean; sensor_id?:string; server_url?:string; desktop_removal?:unknown;
  hooks?:{hermes?:{available?:boolean}};
  telemetry?:{codex_available?:boolean; claude_available?:boolean; workbuddy_available?:boolean}; desktop_update?:{status_cached?:boolean}};
const compact = new Intl.NumberFormat('en-US', {notation:'compact', maximumFractionDigits:2});
const tokenCompact = new Intl.NumberFormat('en-US', {notation:'compact', maximumSignificantDigits:3});
const percent = new Intl.NumberFormat('en-US', {style:'percent', maximumFractionDigits:1});
const dollars = new Intl.NumberFormat('en-US', {style:'currency', currency:'USD'});
const costTransition = 250;
const effortLabels:Record<string,string> = {none:'None',minimal:'Minimal',low:'Low',medium:'Medium',high:'High',xhigh:'Extra high',max:'Max',ultra:'Ultra',auto:'Auto',unknown:'Unknown'};
const appLabels:Record<string,string> = {codex:'Codex',claude_code:'Claude Code',gemini:'Gemini CLI',cowork:'Claude Cowork',copilot:'GitHub Copilot',cursor:'Cursor',hermes:'Hermes Agent',opencode:'OpenCode',workbuddy:'WorkBuddy',unknown:'Unattributed'};
const effortName = (name:string) => effortLabels[name] ?? 'Unknown';
const modelName = (name:string) => name.replace(/jev/gi, 'Guardrail');
const money = (value:number|null) => value === null ? 'N/A' : dollars.format(value);
const dailyCost = (counts:Counts) => counts.calls === 0 ? 0 : counts.cost_usd;
const dateLabel = (value:string) => value.includes('T')
  ? new Date(value).toLocaleString('en-US', {month:'short',day:'numeric',hour:'numeric',minute:'2-digit',timeZoneName:'short'})
  : new Date(`${value}T12:00:00`).toLocaleDateString('en-US', {month:'short',day:'numeric'});
const hourLabel = (value:string) => new Date(value).toLocaleTimeString('en-US', {hour:'numeric'});
function costCoverage(counts:Counts) {
  const unpriced = counts.calls - counts.priced_calls;
  return unpriced > 0 ? `${unpriced.toLocaleString('en-US')} unpriced ${unpriced === 1 ? 'call' : 'calls'} excluded.` : '';
}
function byCost<T extends Row>(values:T[]) {
  return [...values].sort((a, b) => Number(a.cost_usd === null) - Number(b.cost_usd === null)
    || (b.cost_usd ?? 0) - (a.cost_usd ?? 0) || a.name.localeCompare(b.name, 'en'));
}
function applications(values:Breakdown[]) {
  const groups = new Map<string, Row & {rows:Breakdown[]}>();
  for (const row of values) {
    const name = row.application;
    const group = groups.get(name) ?? {name,tokens:0,calls:0,priced_calls:0,cost_usd:null,rows:[]};
    group.tokens += row.tokens; group.calls += row.calls; group.priced_calls += row.priced_calls;
    if (row.cost_usd !== null) group.cost_usd = (group.cost_usd ?? 0) + row.cost_usd;
    group.rows.push(row); groups.set(name, group);
  }
  return byCost([...groups.values()]);
}

export function initUsage(request:(action:string, params?:Record<string,unknown>) => Promise<unknown>, visible:() => boolean = () => !document.hidden) {
  const panel = document.createElement('section');
  panel.id = 'usage-panel'; panel.hidden = true; panel.setAttribute('aria-label', 'Your usage');
  panel.innerHTML = `
    <div class="usage-heading"><div class="usage-title"><h1>Your usage</h1>
      <div id="usage-tools" class="detected-tools" role="group" aria-label="Coding tools detected on this device" hidden>
        <span class="detected-tool" data-agent="codex" tabindex="0" role="img" aria-label="Codex" aria-describedby="codex-detected" hidden><img class="codex-mark" src="${agentIcon('codex-cli')}" alt=""><span id="codex-detected" class="detected-tooltip" role="tooltip"><strong>Codex</strong><span>Detected on this device</span></span></span>
        <span class="detected-tool" data-agent="claude" tabindex="0" role="img" aria-label="Claude Code" aria-describedby="claude-detected" hidden><img src="${agentIcon('claude-code')}" alt=""><span id="claude-detected" class="detected-tooltip" role="tooltip"><strong>Claude Code</strong><span>Detected on this device</span></span></span>
        <span class="detected-tool" data-agent="hermes" tabindex="0" role="img" aria-label="Hermes Agent" aria-describedby="hermes-detected" hidden><img src="${agentIcon('hermes-agent')}" alt=""><span id="hermes-detected" class="detected-tooltip" role="tooltip"><strong>Hermes Agent</strong><span>Detected on this device</span></span></span>
        <span class="detected-tool" data-agent="workbuddy" tabindex="0" role="img" aria-label="WorkBuddy" aria-describedby="workbuddy-detected" hidden><img src="${agentIcon('workbuddy')}" alt=""><span id="workbuddy-detected" class="detected-tooltip" role="tooltip"><strong>WorkBuddy</strong><span>Detected on this device</span></span></span>
      </div></div>
      <div class="usage-period" role="group" aria-label="Usage period"><button type="button" tabindex="0" data-days="1" aria-pressed="false">24 hours</button><button type="button" tabindex="0" data-days="30" aria-pressed="true">30 days</button></div></div>
    <p id="usage-message" role="status">Loading usage…</p>
    <div id="usage-content" hidden>
      <section class="usage-card" aria-label="Usage trend">
        <div class="usage-totals"><div><span>Total tokens</span><strong id="usage-tokens"></strong></div>
          <div><span id="usage-cost-label">Estimated cost (API equivalent)</span>
            <button type="button" tabindex="0" class="usage-cost-info" aria-label="Cost estimate information" aria-describedby="usage-history-note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.01"/></svg><span id="usage-history-note" class="detected-tooltip" role="tooltip">Historical cost may be incomplete.</span></button>
            <strong id="usage-cost"></strong></div></div>
        <div class="usage-chart-heading"><h2 id="usage-chart-title">Daily estimated cost</h2><span id="usage-range"></span></div>
        <div id="usage-legend" class="usage-legend" aria-label="Applications" hidden></div>
        <div id="usage-plot"><div id="usage-chart" class="usage-chart" role="group" aria-label="Daily estimated cost in USD"></div>
          <div id="usage-average-line" class="usage-average-line" aria-hidden="true" hidden><span>Average</span></div>
          <div id="usage-tooltip" class="usage-tooltip" role="tooltip" tabindex="0" hidden></div></div>
        <div id="usage-axis" class="usage-axis"></div>
        <dl class="usage-metrics"><div><dt id="usage-average-label">Daily average</dt><dd id="usage-average"></dd></div><div><dt id="usage-peak-label">Peak day</dt><dd id="usage-peak"></dd></div><div><dt id="usage-current-label">Today</dt><dd id="usage-current"></dd></div></dl>
        <p id="usage-coverage" hidden></p>
      </section>
      <div class="usage-breakdowns"><section class="usage-card"><div class="usage-chart-heading"><h2>Models</h2><span>Est. cost</span></div><div id="usage-models" class="usage-rows"></div></section>
        <section class="usage-card"><div class="usage-chart-heading"><h2>Reasoning effort</h2><span>Est. cost</span></div><div id="usage-efforts" class="usage-rows"></div></section></div>
      <section id="usage-hook-estimates" class="usage-card usage-hook-estimates" aria-label="Hook estimates" hidden>
        <div class="usage-chart-heading"><h2>Hook estimates</h2><span>Partial captured text</span></div>
        <p>Approximate tokens and list-price cost for observed text. Excludes hidden and repeated context. Separate from usage above; not billed spend.</p>
        <div id="usage-hook-rows" class="usage-hook-rows" tabindex="0" aria-label="Estimates by agent and model"></div>
      </section>
    </div>`;
  document.querySelector('#health-card')!.before(panel);
  const node = (id:string) => panel.querySelector<HTMLElement>(`#usage-${id}`)!;
  const text = (id:string, value:string) => { node(id).textContent = value; };
  let days:1|30 = 30;
  let shown = true;
  let identity = '';
  let revision = 0;
  const cache = new Map<1|30, {data?:Usage; readAt:number}>();
  let pending:Promise<void>|undefined;
  let timer:ReturnType<typeof setTimeout>|undefined;
  let availability:'enabled'|'cached'|'disabled' = 'enabled';
  let activeBar:HTMLElement|undefined;
  let focused = document.hasFocus();
  const refreshInterval = () => focused ? 1000 : 10000;
  let rendered = '';
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  let currentCost:{key:string; value:number|null; target:number|null}|undefined;
  let costFrame:number|undefined;

  function finishCurrentCost() {
    if (costFrame !== undefined) cancelAnimationFrame(costFrame);
    costFrame = undefined;
    if (currentCost) {
      currentCost.value = currentCost.target;
      text('current', money(currentCost.target));
    }
  }

  function renderCurrentCost(data:Usage) {
    const day = data.series.at(-1)!;
    const key = `${data.days}/${data.timezone}/${day.date}`;
    const target = dailyCost(day);
    if (currentCost?.key === key && currentCost.target === target) return;
    const previous = currentCost;
    if (costFrame !== undefined) cancelAnimationFrame(costFrame);
    costFrame = undefined;
    const state = currentCost = {key,value:target,target};
    if (previous?.key !== key || previous.value === null || previous.target === null || target === null
      || target <= previous.target || reducedMotion.matches || !focused || !visible() || panel.hidden
      || node('content').hidden || availability !== 'enabled') {
      text('current', money(target));
      return;
    }
    const from = previous.value;
    const start = performance.now();
    state.value = from;
    const tick = (now:number) => {
      const progress = Math.min((now - start) / costTransition, 1);
      state.value = progress === 1 ? target : from + (target - from) * progress;
      const value = money(state.value);
      if (node('current').textContent !== value) text('current', value);
      costFrame = progress < 1 ? requestAnimationFrame(tick) : undefined;
    };
    costFrame = requestAnimationFrame(tick);
  }
  reducedMotion.addEventListener('change', () => { if (reducedMotion.matches) finishCurrentCost(); });

  function schedule() {
    if (!visible() || panel.hidden || availability !== 'enabled') {
      clearTimeout(timer); timer = undefined;
      finishCurrentCost();
    } else if (timer === undefined && !pending) {
      timer = setTimeout(() => { timer = undefined; void refresh(); }, refreshInterval());
    }
  }
  for (const event of ['focus','blur']) window.addEventListener(event, () => {
    focused = event === 'focus';
    clearTimeout(timer); timer = undefined;
    if (focused) void refresh();
    else finishCurrentCost();
    schedule();
  });
  document.addEventListener('visibilitychange', schedule);
  window.addEventListener('openaidr-window-visibility', () => queueMicrotask(schedule));

  function updateAvailability() {
    panel.querySelectorAll<HTMLButtonElement>('[data-days]').forEach(button => {
      const period = Number(button.dataset.days) as 1|30;
      button.disabled = availability !== 'enabled' && (availability !== 'cached' || !cache.get(period)?.data);
    });
  }

  function hideTooltip() {
    node('tooltip').hidden = true;
    activeBar?.removeAttribute('aria-describedby'); activeBar = undefined;
  }
  document.addEventListener('pointermove', event => {
    if (!(event.target as Element).closest('.usage-day,#usage-tooltip')
      && !node('chart').contains(document.activeElement) && !node('tooltip').contains(document.activeElement)) hideTooltip();
  });
  const tools = Array.from(node('tools').querySelectorAll<HTMLElement>('.detected-tool'));
  const tooltipTriggers = [...tools, panel.querySelector<HTMLElement>('.usage-cost-info')!];
  for (const trigger of tooltipTriggers) {
    const reveal = () => trigger.classList.remove('tooltip-dismissed');
    trigger.addEventListener('pointerenter', reveal);
    trigger.addEventListener('focus', reveal);
  }
  panel.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      hideTooltip();
      tooltipTriggers.forEach(trigger => trigger.classList.add('tooltip-dismissed'));
    }
  });
  node('tooltip').addEventListener('focusout', event => {
    if (!node('chart').contains(event.relatedTarget as Node) && !node('tooltip').contains(event.relatedTarget as Node)) hideTooltip();
  });
  document.querySelector('#app')!.addEventListener('scroll', positionTooltip);
  window.addEventListener('resize', positionTooltip);

  function positionTooltip() {
    const tooltip = node('tooltip');
    if (tooltip.hidden || !activeBar) return;
    const rect = activeBar.getBoundingClientRect();
    const {width, height} = tooltip.getBoundingClientRect();
    const left = rect.left > innerWidth / 2 ? rect.left - width : rect.right;
    tooltip.style.left = `${Math.max(8, Math.min(left, innerWidth - width - 8))}px`;
    tooltip.style.top = `${Math.max(8, Math.min(rect.top, innerHeight - height - 8))}px`;
  }

  function costLine(label:string, counts:Counts, className:string) {
    const item = document.createElement('div'); item.className = className;
    const name = document.createElement('span'); name.textContent = label; name.title = label;
    const value = document.createElement('b'); value.textContent = money(counts.cost_usd);
    item.append(name, value);
    item.title = `${label}: ${counts.calls.toLocaleString()} calls, ${compact.format(counts.tokens)} tokens${costCoverage(counts) ? `. ${costCoverage(counts)}` : ''}`;
    return item;
  }

  function appDetails(values:Breakdown[]) {
    return applications(values).map(app => {
      const group = document.createElement('div'); group.className = 'usage-application'; group.dataset.application = app.name;
      const heading = costLine(appLabels[app.name] ?? 'Unknown', app, 'usage-app-heading');
      const swatch = document.createElement('i'); swatch.className = 'usage-swatch'; swatch.setAttribute('aria-hidden', 'true');
      heading.firstElementChild!.prepend(swatch);
      group.append(heading);
      const models = new Map<string, Row>();
      for (const row of app.rows) {
        const model = models.get(row.model) ?? {name:row.model,tokens:0,calls:0,priced_calls:0,cost_usd:null};
        model.tokens += row.tokens; model.calls += row.calls; model.priced_calls += row.priced_calls;
        if (row.cost_usd !== null) model.cost_usd = (model.cost_usd ?? 0) + row.cost_usd;
        models.set(row.model, model);
      }
      group.append(...byCost([...models.values()]).map(model => costLine(modelName(model.name), model, 'usage-app-detail')));
      return group;
    });
  }

  function showTooltip(day:Day, bar:HTMLElement) {
    hideTooltip(); activeBar = bar;
    const tooltip = node('tooltip');
    const heading = document.createElement('strong'); heading.textContent = dateLabel(day.date);
    const item = document.createElement('div');
    const label = document.createElement('span'); label.textContent = 'Estimated cost';
    const value = document.createElement('b'); value.textContent = money(dailyCost(day));
    item.append(label, value);
    tooltip.replaceChildren(heading, item);
    if (day.breakdown) tooltip.append(...appDetails(day.breakdown));
    if (costCoverage(day)) {
      const coverage = document.createElement('p'); coverage.textContent = costCoverage(day);
      tooltip.append(coverage);
    }
    tooltip.hidden = false;
    bar.setAttribute('aria-describedby', tooltip.id);
    positionTooltip();
  }

  function rows(id:string, values:Row[], label:(name:string) => string) {
    const max = Math.max(...values.map(row => row.cost_usd ?? 0), 0);
    node(id).replaceChildren(...byCost(values).map(row => {
      const element = document.createElement('div'); element.className = 'usage-row';
      const heading = document.createElement('div');
      const name = document.createElement('span'); name.textContent = label(row.name); name.title = name.textContent;
      const cost = document.createElement('span'); cost.textContent = money(row.cost_usd);
      heading.append(name, cost);
      const track = document.createElement('div'); track.className = 'usage-track'; track.setAttribute('aria-hidden', 'true');
      const bar = document.createElement('div'); bar.style.width = `${max ? (row.cost_usd ?? 0) / max * 100 : 0}%`; track.append(bar);
      element.append(heading, track); element.title = `${label(row.name)}: ${row.calls.toLocaleString()} calls, ${compact.format(row.tokens)} tokens${row.priced_calls < row.calls ? "; costs exclude unpriced calls" : ""}`;
      return element;
    }));
  }

  function tokenSummary(counts:Counts) {
    const {cached_input_tokens:cached, uncached_input_tokens:uncached, output_tokens:output} = counts;
    const values = [cached, uncached, output];
    const complete = values.every(value => Number.isSafeInteger(value) && value! >= 0)
      && cached! + uncached! + output! === counts.tokens;
    const tokens = node('tokens');
    const format = (value:number) => tokenCompact.formatToParts(value).map(part => part.type === 'compact' ? ` ${part.value === 'K' ? 'k' : part.value}` : part.value).join('');
    if (!complete) {
      tokens.textContent = format(counts.tokens);
      tokens.title = `${counts.tokens.toLocaleString('en-US')} total tokens. Input/output breakdown is incomplete for this period.`;
      return;
    }
    const input = cached! + uncached!;
    const incoming = document.createElement('span'); incoming.textContent = `${format(input)} in`;
    const rate = document.createElement('small'); rate.textContent = `(${input ? percent.format(cached! / input) : 'N/A'} cached)`;
    const outgoing = document.createElement('span'); outgoing.textContent = `/ ${format(output!)} out`;
    tokens.replaceChildren(incoming, ' ', rate, ' ', outgoing);
    tokens.title = `${input.toLocaleString('en-US')} input tokens (${cached!.toLocaleString('en-US')} cached), ${output!.toLocaleString('en-US')} output tokens. Cache rate is cached input divided by total input.`;
  }

  function render(data:Usage) {
    const hourly = data.days === 1;
    // Response timestamps advance even when all displayed values stay the same.
    const content = JSON.stringify([data.days,data.timezone,data.summary,data.series,data.by_model,
      data.by_reasoning_effort,data.breakdown,data.pending_exports,data.history_incomplete,data.source,data.hook_estimates?.items,data.history_recovery]);
    if (content === rendered) return;
    rendered = content;
    const tooltipFocused = document.activeElement === node('tooltip');
    const tooltipScroll = node('tooltip').scrollTop;
    const focusedDate = (tooltipFocused ? activeBar : node('chart').querySelector<HTMLElement>('.usage-day:focus'))?.dataset.date;
    const tooltipHidden = node('tooltip').hidden;
    node('content').hidden = false;
    node('message').hidden = data.summary.calls > 0 && data.pending_exports === 0;
    text('message', data.pending_exports ? 'Recent usage is still processing.' : data.hook_estimates?.items.length ? 'No reported usage for this period. Partial hook estimates are shown below.' : data.source === 'local' ? 'No usage stored for this period. Use a connected coding agent to get started. Earlier uploads are not stored here.' : data.history_incomplete ? 'No usage available. Older activity may be missing for this device.' : 'No usage yet for this period. Use a connected coding agent to get started.');
    const estimates = data.hook_estimates?.items ?? [];
    node('hook-estimates').hidden = estimates.length === 0;
    node('hook-rows').replaceChildren(...estimates.map(item => {
      const row = document.createElement('div'); row.className = 'usage-hook-row';
      const heading = document.createElement('strong');
      heading.textContent = item.application === 'github-copilot' ? 'GitHub Copilot' : 'Cursor';
      const detail = document.createElement('span');
      detail.textContent = item.model === 'unknown' ? 'Model unknown' : `${item.model_source === 'configured' ? 'Assumed model: ' : ''}${modelName(item.model)}`;
      const counts = document.createElement('span');
      counts.textContent = `~${tokenCompact.format(item.estimated_input_tokens)} in / ~${tokenCompact.format(item.estimated_output_tokens)} out`;
      const cost = document.createElement('b');
      cost.textContent = item.estimated_cost_usd === null ? 'Cost unknown' : `~${Number(item.estimated_cost_usd).toLocaleString('en-US', {style:'currency',currency:'USD',maximumFractionDigits:6})}`;
      if (item.estimated_cost_usd !== null && item.priced_observations < item.observations)
        cost.textContent += ` (${item.priced_observations}/${item.observations} priced)`;
      row.append(heading, cost, detail, counts); return row;
    }));
    tokenSummary(data.summary);
    const totalCost = dailyCost(data.summary);
    text('cost', money(totalCost));
    node('cost').title = data.summary.priced_calls < data.summary.calls ? 'Excludes calls without a known cost.' : '';
    const recovery = data.history_recovery;
    const recoveryNotes:string[] = [];
    if (recovery) {
      recoveryNotes.push(`History recovery: ${recovery.recovered_calls.toLocaleString('en-US')} additional calls in the last 30 days.`);
      if (recovery.last_scan_at) recoveryNotes.push(`Last checked ${dateLabel(recovery.last_scan_at)}.`);
      if (recovery.inaccessible_sources || recovery.inaccessible_files) recoveryNotes.push('Some history sources could not be read.');
      if (recovery.blocked_files) recoveryNotes.push('Some history could not be matched safely to existing usage.');
      if (recovery.invalid_records || recovery.unsupported_records) recoveryNotes.push('Some history records could not be recovered.');
      if (recovery.unreconciled_records) recoveryNotes.push('Some older history could not be updated.');
      if (recovery.pending_files) recoveryNotes.push('Waiting for history files to finish writing.');
    }
    const coverage = [costCoverage(data.summary), data.breakdown?.some(row => row.application === 'unknown')
      ? 'Unattributed usage has no recorded app identity. Older sensor versions did not retain it.' : '',
      ...recoveryNotes].filter(Boolean).join(' ');
    text('coverage', coverage);
    node('coverage').hidden = !coverage;
    text('range', hourly ? 'Last 24 hours' : 'Last 30 days');
    text('chart-title', hourly ? 'Hourly estimated cost' : 'Daily estimated cost');
    node('chart').setAttribute('aria-label', `${hourly ? 'Hourly' : 'Daily'} estimated cost in USD`);
    text('average-label', hourly ? 'Hourly average' : 'Daily average');
    text('current-label', hourly ? 'This hour' : 'Today');
    hideTooltip();
    const apps = data.breakdown ? applications(data.breakdown) : [];
    node('legend').hidden = apps.length === 0;
    node('legend').replaceChildren(...apps.map(app => {
      const label = document.createElement('span'); label.dataset.application = app.name;
      const swatch = document.createElement('i'); swatch.className = 'usage-swatch'; swatch.setAttribute('aria-hidden', 'true');
      label.append(swatch, appLabels[app.name] ?? 'Unknown'); return label;
    }));
    const firstRecordedDay = Math.max(0, data.series.findIndex(day => day.calls > 0));
    const average = totalCost === null ? null : totalCost / (hourly ? 24 : data.days - firstRecordedDay);
    const max = totalCost === null ? null : Math.max(...data.series.map(day => dailyCost(day) ?? 0), 0);
    const scale = Math.max(max ?? 0, average ?? 0);
    const averageLine = node('average-line');
    averageLine.hidden = average === null || scale === 0;
    if (!averageLine.hidden) averageLine.style.top = `calc((100% - 1px) * ${1 - average! / scale})`;
    node('chart').replaceChildren(...data.series.map(day => {
      const bar = document.createElement('div'); bar.className = 'usage-day'; bar.tabIndex = 0; bar.setAttribute('role', 'img');
      bar.dataset.date = day.date;
      bar.setAttribute('aria-label', `${dateLabel(day.date)}: ${money(dailyCost(day))} estimated cost.${costCoverage(day) ? ` ${costCoverage(day)}` : ''}`);
      const fill = document.createElement('div'); fill.className = 'usage-bar'; fill.setAttribute('aria-hidden', 'true');
      fill.style.height = `${scale ? (dailyCost(day) ?? 0) / scale * 100 : 0}%`;
      if (day.breakdown) {
        fill.classList.add('usage-stack');
        const groups = applications(day.breakdown);
        for (const app of apps) {
          const group = groups.find(group => group.name === app.name);
          if (!group) continue;
          const segment = document.createElement('span'); segment.dataset.application = app.name;
          segment.style.height = `${day.cost_usd ? (group.cost_usd ?? 0) / day.cost_usd * 100 : 0}%`;
          fill.append(segment);
        }
      }
      bar.append(fill);
      bar.addEventListener('pointerenter', () => showTooltip(day, bar));
      bar.addEventListener('focus', () => showTooltip(day, bar));
      bar.addEventListener('blur', event => { if (!node('tooltip').contains(event.relatedTarget as Node)) hideTooltip(); });
      return bar;
    }));
    const peak = data.series.find(day => day.cost_usd === max);
    node('axis').replaceChildren(...(hourly ? data.series.filter((_, index) => index % 6 === 0) : [data.series[0], data.series.at(-1)!]).map(day => {
      const label = document.createElement('span'); label.textContent = hourly ? hourLabel(day.date) : dateLabel(day.date); return label;
    }));
    text('average', money(average));
    text('peak-label', max !== null && max > 0 && peak ? `Peak · ${hourly ? hourLabel(peak.date) : dateLabel(peak.date)}` : hourly ? 'Peak hour' : 'Peak day');
    text('peak', money(max));
    renderCurrentCost(data);
    rows('models', data.by_model, modelName);
    rows('efforts', data.by_reasoning_effort, effortName);
    if (focusedDate && !panel.hidden && !node('content').hidden) {
      const bar = Array.from(node('chart').querySelectorAll<HTMLElement>('.usage-day')).find(bar => bar.dataset.date === focusedDate);
      bar?.focus({preventScroll:true});
      if (bar && tooltipFocused) {
        node('tooltip').focus({preventScroll:true}); node('tooltip').scrollTop = tooltipScroll;
      }
      if (tooltipHidden) hideTooltip();
    }
  }

  function validUsage(data:Usage|undefined, period:1|30): data is Usage {
    return !!data && data.days === period && (period !== 1 || data.granularity === 'hour')
      && Array.isArray(data.series) && data.series.length === (period === 1 ? 25 : period)
      && !!data.summary && Array.isArray(data.by_model) && Array.isArray(data.by_reasoning_effort);
  }
  async function refresh(force = false, period:1|30 = days):Promise<void> {
    if (panel.hidden || availability !== 'enabled' || !visible()) return;
    const version = revision;
    const cached = cache.get(period);
    if (!force && cached && Date.now() - cached.readAt < refreshInterval()) { schedule(); return; }
    if (pending) {
      await pending;
      if (version === revision) return refresh(false, period);
      return;
    }
    const entry = cached ?? {readAt:0};
    clearTimeout(timer); timer = undefined;
    cache.set(period, entry);
    const read = (async () => {
      try {
        const data = await request('usage.summary', {days:period}) as Usage & {periods?:Partial<Record<1|30,Usage>>};
        if (version !== revision) return;
        if (!validUsage(data, period)) throw new Error('Usage data stored on this device is unavailable. Try again later.');
        const readAt = Date.now();
        entry.data = data; entry.readAt = readAt;
        const alternate = period === 1 ? 30 : 1;
        const other = data.periods?.[alternate];
        if (validUsage(other, alternate) && other.until === data.until) {
          cache.set(alternate, {data:other, readAt});
          if (alternate === days) render(other);
        }
        if (period === days) render(data);
      } catch (error) {
        if (version !== revision) return;
        entry.readAt = Date.now();
        if (period !== days) return;
        finishCurrentCost();
        rendered = '';
        node('content').hidden = !entry.data; node('message').hidden = false;
        const message = error instanceof Error ? error.message : typeof error === 'string' ? error : 'Usage is unavailable. Try again later.';
        text('message', entry.data ? `Showing previously loaded usage. ${message}` : message);
      }
    })();
    pending = read;
    await read;
    if (pending === read) pending = undefined;
    updateAvailability();
    schedule();
    if (version === revision && period === days && entry.data) void refresh(false, period === 1 ? 30 : 1);
  }
  panel.querySelectorAll<HTMLButtonElement>('[data-days]').forEach(button => button.addEventListener('click', () => {
    const next = Number(button.dataset.days) as 1|30;
    if (button.disabled || next === days) return;
    finishCurrentCost(); currentCost = undefined; rendered = '';
    days = next;
    panel.querySelectorAll('[data-days]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    const data = cache.get(days)?.data;
    if (data) render(data);
    else {
      node('content').hidden = true; node('message').hidden = false; text('message', 'Loading usage…');
    }
    void refresh(!data);
  }));
  return {
    refresh,
    setVisible(value:boolean) {
      shown = value; panel.hidden = !shown || !identity;
      if (!shown) hideTooltip();
      schedule();
      if (shown) void refresh();
    },
    setAvailability(mode:typeof availability) {
      availability = mode;
      updateAvailability();
      schedule();
    },
    setStatus(status:Status) {
      for (const tool of tools) {
        const key = `${tool.dataset.agent}_available` as keyof NonNullable<Status['telemetry']>;
        const available = tool.dataset.agent === 'hermes' ? status.hooks?.hermes?.available : status.telemetry?.[key];
        tool.hidden = !!status.desktop_update?.status_cached || available !== true;
      }
      node('tools').hidden = tools.every(tool => tool.hidden);
      const enabled = status.enrolled && !status.disabled && !status.desktop_removal;
      const next = enabled ? `${status.server_url ?? ''}/${status.sensor_id ?? ''}` : '';
      if (identity !== next) {
        hideTooltip();
        finishCurrentCost(); currentCost = undefined; rendered = '';
        identity = next; revision++; cache.clear(); pending = undefined;
        node('content').hidden = true; node('message').hidden = false; text('message', 'Loading usage…');
      }
      panel.hidden = !enabled || !shown;
      updateAvailability();
      schedule();
    },
  };
}
