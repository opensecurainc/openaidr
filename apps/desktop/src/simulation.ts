type Simulation = {
  enabled?: boolean; configured?: boolean; state?: string; destination?: string;
  enrolled?: number; records_sent?: number; inventories_sent?: number; errors?: number; error?: string;
};

export async function initSimulation(request: (action: string) => Promise<unknown>) {
  let status: Simulation;
  try { status = await request('simulation.status') as Simulation; }
  catch { return; }
  if (!status.enabled) return;

  const trigger = document.createElement('button');
  trigger.className = 'button button-secondary';
  trigger.id = 'show-simulation';
  trigger.setAttribute('aria-haspopup', 'dialog');
  trigger.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><rect x="2" y="3" width="16" height="12" rx="1"/><path d="M7 20h6m-3-5v5"/><rect x="16" y="10" width="6" height="11" rx="1"/></svg>Simulation';
  document.getElementById('change-connection')!.after(trigger);
  const dialog = document.createElement('dialog');
  dialog.className = 'simulation-dialog';
  dialog.setAttribute('aria-labelledby', 'simulation-title');
  dialog.innerHTML = `
    <div class="simulation-heading"><strong>Simulation</strong><span class="simulation-badge">Development only</span><button class="button icon-button close-button" id="simulation-dismiss" tabindex="0" aria-label="Close simulation">×</button></div>
    <h1 id="simulation-title">Simulate 100 devices</h1>
    <p class="simulation-description">Send varied activity and inventory to your test workspace.</p>
    <dl class="simulation-details"><dt>Destination</dt><dd id="simulation-destination"></dd><dt>Devices</dt><dd>100</dd><dt>Inventory</dt><dd>Stable subsets of this device</dd></dl>
    <div class="simulation-status" role="status" aria-live="polite"><span id="simulation-state"></span><span id="simulation-counts"></span></div>
    <p id="simulation-error" class="error-text" role="alert" hidden></p>
    <div class="simulation-actions"><button class="button button-secondary" id="simulation-close">Close</button><button class="button" id="simulation-action">Start simulation</button></div>`;
  document.body.append(dialog);
  const node = (id: string) => dialog.querySelector<HTMLElement>(`#simulation-${id}`)!;
  const action = node('action') as HTMLButtonElement;
  let pending = false;
  let polling = false;
  let revision = 0;
  const active = () => ['starting', 'running', 'stopping'].includes(status.state || '');
  const render = () => {
    node('destination').textContent = status.destination || 'Not configured';
    const labels: Record<string, string> = {stopped:'Stopped', starting:'Starting…', running:'Running', stopping:'Stopping…', error:'Needs attention'};
    node('state').textContent = labels[status.state || 'stopped'] || 'Status unavailable';
    node('state').className = status.state === 'running' ? 'simulation-running' : '';
    node('counts').textContent = `${status.enrolled || 0}/100 enrolled · ${(status.records_sent || 0).toLocaleString()} records sent · ${status.errors || 0} errors`;
    node('error').textContent = status.error || '';
    node('error').title = status.error || '';
    node('error').hidden = !status.error;
    action.textContent = active() ? 'Stop simulation' : 'Start simulation';
    action.disabled = pending || (!active() && !status.configured);
    trigger.classList.toggle('simulation-running', active());
    trigger.title = active() ? 'Device simulation is running' : 'Simulate 100 devices';
  };
  async function refresh() {
    if (pending || polling) return;
    polling = true;
    const currentRevision = revision;
    try {
      const latest = await request('simulation.status') as Simulation;
      if (currentRevision === revision) status = latest;
    }
    catch { if (currentRevision === revision) status.error = 'Cannot read simulation status. Try Stop or reopen the panel.'; }
    finally { polling = false; render(); }
  }
  trigger.addEventListener('click', () => { render(); dialog.showModal(); void refresh(); });
  for (const id of ['close', 'dismiss']) node(id).addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => trigger.focus());
  action.addEventListener('click', async () => {
    if (pending) return;
    const operation = active() ? 'stop' : 'start';
    revision += 1;
    pending = true;
    status.state = operation === 'start' ? 'starting' : 'stopping';
    status.error = '';
    render();
    try { status = await request(`simulation.${operation}`) as Simulation; }
    catch (error) { status.error = String(error); status.state = operation === 'start' ? 'error' : 'running'; }
    finally { pending = false; render(); }
  });
  render();
  setInterval(() => { if (dialog.open || active()) void refresh(); }, 2000);
}
