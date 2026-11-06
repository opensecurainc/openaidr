import { agentIcon } from '../../../packages/ui/agent-icons/index.js';

type Request = (action:string, params?:Record<string, unknown>) => Promise<unknown>;
type Context = {days:1|30; until:string; sensor_id:string; server_url:string};
type Review = {id:string; label:'correct_denial'|'false_positive'|'insufficient_context'|null; note:string|null; reviewed_at:string|null; review_revision?:number};
type Check = Review & {created_at:string; product:string; hook_event:string; mode:'shadow'|'enforce'; returned_decision:string};
type Evidence = {assessment_input:{state:{latest_prompt:unknown;prior_events:unknown[]}}|null;decision_basis:Record<string,unknown>;assessment:unknown;decision:Record<string,unknown>;gaps:string[]};
type Detail = Check & {actions:unknown[];reason:string;evidence?:Evidence;evidence_sha256?:string};
type Envelope = {supported:boolean; sensor_id:string; server_url:string; scope:string;review_version?:number};
const labels = {correct_denial:'Correct denial', false_positive:'Reported', insufficient_context:'Insufficient context'};
const gapText:Record<string,string> = {
  bounded_context:'Only a bounded portion of earlier activity was included.',
  no_prior_context:'Only this action was assessed; earlier conversation context was not included.',
  assessment_not_retained:'The assessment details were not retained.',
  assessment_input_not_retained:'The original assessment input was not retained.',
  policy_snapshot_not_retained:'The original policy was not retained.',
  content_redacted:'Some captured content was redacted.',
  redaction_status_unknown:'Redaction details were not retained.',
  context_truncated:'Some earlier activity was omitted to fit the assessment.',
  content_truncated:'Some captured content was shortened.',
  capture_disabled:'Content capture was disabled.',
  unsupported_boundary:'This agent action did not support enforcement.',
  retained_evidence_not_in_snapshot:'Some retained evidence cannot be shown in this review.',
  service_request_mapping_unavailable:'The assessment service reference was not retained.',
  unknown:'Capture details were not retained.',
};
const reviewValid = (row:Review) => row && typeof row.id === 'string'
  && (row.label === null || Object.hasOwn(labels, row.label)) && (row.note === null || typeof row.note === 'string')
  && (row.reviewed_at === null || Number.isFinite(Date.parse(row.reviewed_at)));
const record = (value:unknown):Record<string,unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string,unknown> : {};
const riskValue = (value:unknown):value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100;

export function initCheckReview(panel:HTMLElement, request:Request, agentName:(product:string) => string) {
  const section = document.createElement('section');
  section.id = 'guardrails-review'; section.className = 'usage-card'; section.hidden = true; section.setAttribute('aria-label', 'Denied checks');
  section.innerHTML = `
    <div class="guardrail-statusline"><h2 id="denials-heading" tabindex="-1">Denied checks</h2><button type="button" class="text-button" id="denials-back" hidden>‹ Back to checks</button><button type="button" class="text-button" id="denials-close">Close</button></div>
    <p id="denials-status" role="status"></p>
    <div id="denials-list"></div>
    <div class="agent-actions"><button type="button" class="button button-secondary" id="denials-latest" hidden>Latest checks</button><button type="button" class="button button-secondary" id="denials-older" hidden>Older checks</button><button type="button" class="button button-secondary" id="denials-retry" hidden>Retry</button></div>
    <form id="denials-detail" hidden>
      <div class="denial-detail-heading"><div class="denial-agent-heading"><span id="denials-icon" hidden></span><h3 id="denials-title" tabindex="-1"></h3></div><button type="submit" id="denials-report" value="report" class="button button-secondary" aria-describedby="denials-sharing" title="Send feedback to your organization. Policy is unchanged.">This is incorrect</button></div>
      <div class="denial-explanation" role="group" aria-label="Decision reason">
        <strong id="denials-explanation-heading">Why Guardrail recommends denial</strong><p id="denials-rule" hidden></p><p id="denials-reason"></p>
        <h4>Guardrail assessment</h4><p id="denials-assessment-reason"></p>
        <dl id="denials-thresholds" hidden><div id="denials-score-row" hidden><dt>Risk score</dt><dd id="denials-score"></dd></div><div id="denials-threshold-row" hidden><dt id="denials-threshold-label">Configured deny threshold</dt><dd id="denials-threshold"></dd></div></dl>
      </div>
      <div class="denial-preview"><pre id="denials-preview" aria-label="Request preview"></pre></div>
      <p id="denials-feedback" role="status"></p>
      <details id="denials-note-details" hidden><summary>Add a note</summary>
        <textarea id="denials-note" aria-label="Note (optional)" rows="2" maxlength="2000" placeholder="What looks incorrect?"></textarea>
        <div class="agent-actions">
          <button type="submit" id="denials-save-note" value="note" class="button button-secondary">Save note</button>
          <button type="button" id="denials-cancel-note" class="text-button">Cancel</button>
        </div>
      </details>
      <details id="denials-technical"><summary>Details</summary>
        <p id="denials-meta" class="guardrail-note"></p>
        <p id="denials-boundary" class="guardrail-note"></p>
        <p id="denials-sharing" class="guardrail-note">Feedback is shared with your organization and attributed to this device. Policy is unchanged.</p>
        <p id="denials-saved-review" class="guardrail-note" hidden></p>
        <details id="denials-request"><summary>Full request</summary>
          <dl id="denials-prompt" class="denial-request" hidden><div><dt>User request</dt><dd><pre id="denials-prompt-text" tabindex="0"></pre></dd></div></dl>
          <div id="denials-evidence"></div>
          <details><summary>Raw request</summary><pre id="denials-raw" tabindex="0"></pre></details>
        </details>
        <div id="denials-context" hidden>
          <details><summary>Prior request context</summary><pre id="denials-prior" tabindex="0"></pre></details>
          <details><summary>Policy and decision</summary><pre id="denials-policy" tabindex="0"></pre></details>
          <details><summary>Assessment</summary><pre id="denials-assessment" tabindex="0"></pre></details>
          <details><summary>Evidence gaps</summary><ul id="denials-gaps"></ul></details>
        </div>
        <p id="denials-legacy" class="guardrail-note" hidden>Update your organization server to review policy and earlier context.</p>
      </details>
    </form>`;
  panel.querySelector('#guardrails-activity')!.after(section);
  const el = (id:string) => section.querySelector<HTMLElement>('#denials-' + id)!;
  const button = (id:string) => el(id) as HTMLButtonElement;
  const note = el('note') as HTMLTextAreaElement, noteDetails = el('note-details') as HTMLDetailsElement;
  let context:Context|undefined, revision = 0, scope = '', next = '', cursor = '', selected:Detail|undefined;
  let decision:'ask'|'deny' = 'deny';
  const checkName = () => decision === 'ask' ? 'Ask checks' : 'Denied checks';
  const decisionLabel = (mode:string) => mode === 'shadow' ? decision === 'ask' ? 'Would ask' : 'Would deny' : decision === 'ask' ? 'Ask decision' : 'Deny decision';
  let reviewVersion = 0, pendingSave:{key:string;payload:Record<string,unknown>}|undefined;
  let items:Check[] = [], busy = false, available = true;
  const message = (value:string) => {
    el('status').textContent = selected ? '' : value;
    el('feedback').textContent = selected ? value : '';
  };
  function renderExplanation(detail:Detail) {
    const evidence = reviewVersion ? detail.evidence : undefined;
    const assessment = record(evidence?.assessment), settings = record(record(evidence?.decision_basis).risk_settings);
    const scored = assessment.status === 'scored';
    el('reason').textContent = detail.reason || 'No decision reason was recorded.';
    el('assessment-reason').textContent = scored && typeof assessment.reason === 'string' && assessment.reason.trim()
      ? assessment.reason : 'No scored assessment explanation was retained.';
    const score = scored && riskValue(assessment.score) ? assessment.score : null;
    const configured = settings[decision === 'ask' ? 'ask_threshold' : 'block_threshold'];
    const threshold = settings.enabled === true && riskValue(configured) ? configured : null;
    el('score-row').hidden = score === null; el('score').textContent = score === null ? '' : `${score} / 100`;
    el('threshold-row').hidden = threshold === null; el('threshold').textContent = threshold === null ? '' : String(threshold);
    el('thresholds').hidden = score === null && threshold === null;
    const prompt = record(record(record(evidence?.assessment_input).state).latest_prompt).text;
    el('prompt').hidden = typeof prompt !== 'string' || !prompt;
    el('prompt-text').textContent = typeof prompt === 'string' ? prompt : '';
  }
  function renderEvidence(actions:unknown[]) {
    const first = record(actions[0]), command = record(first.command), tool = record(first.tool), file = record(first.file), network = record(first.network);
    const preview = command.text ?? first.text ?? tool.input ?? tool.output ?? file.path ?? network.url ?? network.host ?? actions[0];
    const missing = decision === 'ask' ? 'Request content was not retained.' : 'Request content was not captured.';
    el('preview').textContent = (typeof preview === 'string' ? preview : JSON.stringify(preview, null, 2)) ?? missing;
    el('request').querySelector('summary')!.textContent = actions.length > 1 ? `Full request (${actions.length} actions)` : 'Full request';
    el('raw').textContent = JSON.stringify(actions, null, 2);
    el('evidence').replaceChildren(...actions.map(action => {
      const item = record(action), command = record(item.command), tool = record(item.tool), file = record(item.file), network = record(item.network);
      const card = document.createElement('dl'); card.className = 'denial-request';
      const field = (name:string, value:unknown, prose = false) => {
        if (value === undefined || value === null) return;
        const group = document.createElement('div'), title = document.createElement('dt'), body = document.createElement('dd'), content = document.createElement('pre');
        title.textContent = name; content.tabIndex = 0;
        content.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
        if (prose) content.className = 'denial-prose';
        body.append(content); group.append(title, body); card.append(group);
      };
      field('Command', command.text);
      field('Working directory', command.cwd);
      field('Exit code', command.exit_code);
      field(item.kind === 'prompt' ? 'Prompt' : item.kind === 'response' ? 'Response' : 'Text', item.text, true);
      field('Tool', tool.name);
      if (tool.is_error === true) field('Result', 'Error', true);
      field('Input', tool.input);
      field('Output', tool.output);
      field('File', file.path);
      field('Operation', file.op);
      field('URL', network.url);
      field('Host', network.host);
      if (!card.childElementCount) field('Request', action ?? 'No request content was retained.');
      if (item.truncated === true) field('Capture note', 'The captured content was shortened.', true);
      return card;
    }));
    if (!actions.length) el('evidence').textContent = missing;
  }
  function controls() {
    section.querySelectorAll<HTMLButtonElement|HTMLTextAreaElement>('button,textarea').forEach(control => {
      control.disabled = busy || !available;
    });
    button('close').disabled = false;
    const reported = selected?.label === 'false_positive';
    button('report').hidden = decision === 'ask';
    el('sharing').hidden = decision === 'ask';
    button('report').disabled ||= decision === 'ask' || !selected || reported;
    button('report').textContent = reported ? 'Reported' : 'This is incorrect';
    button('report').classList.toggle('reported', reported);
    noteDetails.hidden = decision === 'ask' || !reported;
    noteDetails.querySelector('summary')!.textContent = selected?.note ? 'Edit note' : 'Add a note';
    button('save-note').disabled ||= decision === 'ask' || !reported;
    el('saved-review').hidden = decision === 'ask' || !selected?.label || reported;
    el('saved-review').textContent = selected?.label && !reported ? `Saved review: ${labels[selected.label]}${selected.note ? '\n' + selected.note : ''}` : '';
  }
  function reset() {
    revision++; context = undefined; selected = undefined; scope = ''; busy = false; reviewVersion = 0; pendingSave = undefined;
    items = []; el('list').replaceChildren(); el('evidence').textContent = ''; note.value = '';
    for (const id of ['preview','raw','prior','policy','assessment','gaps','reason','assessment-reason','prompt-text']) el(id).replaceChildren();
    section.hidden = true; panel.querySelector('#guardrails-' + decision)!.setAttribute('aria-expanded', 'false');
  }
  async function call<T>(action:string, params:Record<string, unknown>):Promise<T & Envelope> {
    const response = await request('guardrails.' + action, params) as T & Envelope;
    if (response?.supported === false) throw new Error('Inspecting checks requires an updated service.');
    if (!context || !response?.supported || response.sensor_id !== context.sensor_id
      || response.server_url?.replace(/\/$/, '') !== context.server_url.replace(/\/$/, '') || typeof response.scope !== 'string') {
      throw new Error('Could not load this device’s checks. Reopen checks.');
    }
    return response;
  }
  function renderList() {
    selected = undefined; pendingSave = undefined; el('detail').hidden = true; el('list').hidden = false;
    el('heading').hidden = false; button('back').hidden = true;
    button('older').hidden = !next; button('latest').hidden = !cursor;
    el('list').replaceChildren(...items.map(check => {
      const row = document.createElement('button'); row.type = 'button'; row.className = 'button-secondary guardrail-denial-row';
      const title = document.createElement('strong'), detail = document.createElement('span');
      title.textContent = `${agentName(check.product)} · ${decisionLabel(check.mode)}`;
      detail.textContent = `${new Date(check.created_at).toLocaleString()} · ${check.hook_event}${decision === 'deny' ? ` · ${check.label ? labels[check.label] : 'Not reviewed'}` : ''}`;
      row.append(title, detail); row.addEventListener('click', () => void detailView(check)); return row;
    }));
    controls();
  }
  async function load(pageCursor = '') {
    if (!context || busy) return;
    const read = ++revision;
    busy = true; controls(); message(`Loading ${checkName().toLowerCase()}…`); button('retry').hidden = true;
    try {
      const params = {days:context.days,until:context.until,cursor:pageCursor,...(decision === 'ask' ? {decision} : {})};
      let response = await call<{items:Check[]; next_cursor:string}>('denials', {...params,...(reviewVersion ? {review_version:1} : {})});
      if (read !== revision) return;
      if (!reviewVersion && response.review_version === 1) {
        reviewVersion = 1;
        response = await call<{items:Check[]; next_cursor:string}>('denials', {...params,review_version:1});
      }
      if (read !== revision) return;
      if (!Array.isArray(response.items) || response.items.length > 20 || typeof response.next_cursor !== 'string'
        || !response.items.every(check => reviewValid(check) && Number.isFinite(Date.parse(check.created_at))
          && typeof check.product === 'string' && typeof check.hook_event === 'string' && ['shadow','enforce'].includes(check.mode))) throw new Error('Invalid checks response.');
      scope = response.scope; items = response.items; next = response.next_cursor; cursor = pageCursor;
      renderList(); message(items.length ? '' : `No ${checkName().toLowerCase()} in this period.`);
    } catch (error) {
      if (read !== revision) return;
      message(error instanceof Error ? error.message : String(error));
      button('retry').hidden = false; button('retry').onclick = () => void load(pageCursor);
    } finally { if (read === revision) { busy = false; controls(); } }
  }
  async function detailView(check:Check) {
    const read = ++revision;
    busy = true; controls(); message('Loading request…'); button('retry').hidden = true;
    try {
      const response = await call<Detail>('check', {id:check.id,scope,...(decision === 'ask' ? {decision} : {}),...(reviewVersion ? {review_version:1} : {})});
      if (read !== revision) return;
      if (!reviewValid(response) || response.id !== check.id || response.scope !== scope || !Array.isArray(response.actions)
        || typeof response.reason !== 'string') throw new Error('Invalid check details.');
      if (reviewVersion && (response.review_version !== 1 || !Number.isSafeInteger(response.review_revision)
        || response.review_revision! < 0 || !/^[0-9a-f]{64}$/.test(response.evidence_sha256 ?? '')
        || !response.evidence || !Array.isArray(response.evidence.gaps)
        || !response.evidence.gaps.every(gap => typeof gap === 'string'))) throw new Error('Invalid review context. Reopen the check.');
      selected = response; pendingSave = undefined;
      el('list').hidden = true; el('detail').hidden = false; button('older').hidden = true; button('latest').hidden = true;
      el('heading').hidden = true; button('back').hidden = false;
      el('title').textContent = `${agentName(check.product)} · ${decisionLabel(check.mode)}`;
      const icon = agentIcon(check.product);
      el('icon').hidden = !icon;
      el('icon').replaceChildren();
      if (icon) {
        const image = document.createElement('img'); image.src = icon; image.alt = '';
        image.classList.toggle('codex-mark', icon === agentIcon('codex-cli'));
        el('icon').append(image);
      }
      el('meta').textContent = `${new Date(check.created_at).toLocaleString()} · Returned: ${response.returned_decision} · Enforcement unconfirmed`;
      el('boundary').textContent = `Mode: ${check.mode === 'shadow' ? 'Monitoring (Shadow)' : 'Enforce'}. Hook: ${check.hook_event}. Returned decisions do not confirm enforcement.`;
      const rule = record(response.evidence?.decision_basis?.matched_rule);
      el('rule').textContent = reviewVersion && rule.action === decision && typeof rule.name === 'string' ? rule.name : '';
      el('rule').hidden = !el('rule').textContent;
      renderExplanation(response);
      renderEvidence(response.actions);
      el('context').hidden = !reviewVersion; el('legacy').hidden = !!reviewVersion;
      if (response.evidence && reviewVersion) {
        const evidence = response.evidence, state = evidence.assessment_input?.state;
        el('prior').textContent = state ? JSON.stringify({latest_prompt:state.latest_prompt,prior_events:state.prior_events}, null, 2) : 'The original request context was not retained.';
        el('policy').textContent = JSON.stringify({policy:evidence.decision_basis,decision:evidence.decision}, null, 2);
        el('assessment').textContent = evidence.assessment ? JSON.stringify(evidence.assessment, null, 2) : 'No assessment was retained.';
        el('gaps').replaceChildren(...evidence.gaps.map(gap => {
          const item = document.createElement('li'); item.textContent = gapText[gap] ?? 'Additional evidence is unavailable.'; return item;
        }));
      }
      section.querySelectorAll('details').forEach(details => { details.open = false; });
      note.value = response.note || '';
      message(''); el('title').focus();
    } catch (error) {
      if (read !== revision) return;
      message(error instanceof Error ? error.message : String(error));
      button('retry').hidden = false; button('retry').onclick = () => void detailView(check);
    } finally { if (read === revision) { busy = false; controls(); } }
  }
  el('detail').addEventListener('submit', async event => {
    event.preventDefault();
    const action = (event as SubmitEvent).submitter?.getAttribute('value');
    if (decision === 'ask' || busy || !available || !selected || !['report','note'].includes(action ?? '')
      || (action === 'report' ? selected.label === 'false_positive' : selected.label !== 'false_positive')) return;
    const read = revision, id = selected.id;
    busy = true; controls(); message(action === 'report' ? 'Reporting…' : 'Saving note…');
    try {
      const payload = {id,scope,label:'false_positive',note:action === 'report' ? selected.note || '' : note.value,...(reviewVersion ? {
        review_version:1,evidence_sha256:selected.evidence_sha256,expected_revision:selected.review_revision,
      } : {})};
      const key = JSON.stringify(payload);
      if (!pendingSave || pendingSave.key !== key) pendingSave = {key,payload:{...payload,...(reviewVersion ? {request_id:crypto.randomUUID()} : {})}};
      const result = await call<Review>('review', pendingSave.payload);
      if (read !== revision) return;
      if (!reviewValid(result) || result.id !== id || result.scope !== scope || result.label !== 'false_positive') throw new Error('Could not confirm the report. Reopen the check.');
      if (reviewVersion && (result.review_version !== 1 || !Number.isSafeInteger(result.review_revision)
        || result.review_revision! < 1)) throw new Error('Could not confirm the saved revision. Reopen the check.');
      selected = {...selected,...result}; pendingSave = undefined;
      items = items.map(item => item.id === id ? {...item,...result} : item);
      note.value = result.note || ''; noteDetails.open = false;
      message(action === 'report' ? 'Report sent.' : 'Note saved.');
      controls();
      noteDetails.querySelector('summary')!.focus();
    } catch (error) { if (read === revision) message(error instanceof Error ? error.message : String(error)); }
    finally { if (read === revision) { busy = false; controls(); } }
  });
  button('cancel-note').onclick = () => {
    note.value = selected?.note || ''; noteDetails.open = false; message('');
    noteDetails.querySelector('summary')!.focus();
  };
  button('back').onclick = () => { renderList(); message(''); el('list').querySelector('button')?.focus(); };
  button('close').onclick = () => { reset(); panel.querySelector<HTMLButtonElement>('#guardrails-' + decision)!.focus(); };
  button('older').onclick = () => void load(next);
  button('latest').onclick = () => void load();
  return {
    reset,
    setAvailability(value:boolean) { available = value; controls(); },
    open(value:Context, selectedDecision:'ask'|'deny') {
      reset(); decision = selectedDecision;
      section.dataset.decision = decision; section.setAttribute('aria-label', checkName());
      el('heading').textContent = checkName();
      el('explanation-heading').textContent = decision === 'ask' ? 'Why Guardrail recommends asking' : 'Why Guardrail recommends denial';
      el('threshold-label').textContent = decision === 'ask' ? 'Configured ask threshold' : 'Configured deny threshold';
      context = value; section.hidden = false; el('detail').hidden = true; el('list').hidden = false;
      el('heading').hidden = false; button('back').hidden = true;
      button('older').hidden = true; button('latest').hidden = true;
      panel.querySelector('#guardrails-' + decision)!.setAttribute('aria-expanded', 'true');
      section.querySelector<HTMLElement>('h2')!.focus(); void load();
    },
  };
}
