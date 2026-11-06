import { isTauri } from '@tauri-apps/api/core';
import geistLicense from '../../../packages/ui/fonts/Geist-OFL.txt?raw';
import osqueryLicense from '../licenses/osquery-LICENSE?raw';
import apacheLicense from '../licenses/osquery-Apache-2.0.txt?raw';
import pythonLicense from '../licenses/osquery-python-LICENSE?raw';
import pythonPatents from '../licenses/osquery-python-PATENTS?raw';

export function initAbout(request: (action:string) => Promise<unknown>) {
  const button = document.getElementById('show-about') as HTMLButtonElement;
  const panel = document.createElement('dialog');
  panel.id = 'about-dialog'; panel.className = 'simulation-dialog about-dialog';
  panel.setAttribute('aria-label', 'About OpenAIDR');
  panel.innerHTML = `<button id="close-about" tabindex="0" class="button icon-button close-button" aria-label="Close About OpenAIDR">×</button>
    <div class="about-content">
      <img class="about-icon" src="/icon.svg" alt="" width="80" height="80">
      <h2 id="about-title" tabindex="-1">OpenAIDR</h2>
      <div class="about-links"><button id="show-licenses" tabindex="0" class="about-link" aria-expanded="false" aria-controls="about-licenses">Licenses and acknowledgements</button><a id="contact-support" tabindex="0" class="about-link" href="mailto:contact@opensecura.ai">Contact support</a></div>
      <p id="about-support-error" role="alert" hidden></p>
      <p class="about-copyright">© 2026 OpenSecura.<br>All rights reserved.</p>
    </div>
    <section id="about-licenses" aria-labelledby="licenses-title" hidden><h3 id="licenses-title" tabindex="-1">Licenses and acknowledgements</h3><p>OpenAIDR uses open source software. The notices below are included with this app.</p></section>`;
  document.getElementById('app')!.append(panel);
  const licenses = panel.querySelector<HTMLElement>('#about-licenses')!;
  for (const [name, content] of [
    ['Geist fonts', geistLicense],
    ['osquery (macOS)', osqueryLicense],
    ['Apache License 2.0', apacheLicense],
    ['osquery Python bindings (macOS)', pythonLicense],
    ['osquery Python patent grant (macOS)', pythonPatents],
  ]) {
    const item = document.createElement('details');
    const title = document.createElement('summary');
    title.tabIndex = 0;
    title.textContent = name;
    const text = document.createElement('pre');
    text.textContent = content;
    item.append(title, text);
    licenses.append(item);
  }
  const title = panel.querySelector<HTMLElement>('#about-title')!;
  const licenseButton = panel.querySelector<HTMLButtonElement>('#show-licenses')!;
  button.addEventListener('click', () => {
    panel.querySelector<HTMLElement>('#about-support-error')!.hidden = true;
    if (!panel.open) panel.showModal();
    button.setAttribute('aria-expanded', 'true');
    title.focus({preventScroll:true});
  });
  panel.querySelector('#close-about')!.addEventListener('click', () => panel.close());
  panel.addEventListener('click', event => {
    const bounds = panel.getBoundingClientRect();
    if (event.target === panel && (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom)) panel.close();
  });
  panel.addEventListener('close', () => {
    button.setAttribute('aria-expanded', 'false');
    licenses.hidden = true;
    licenseButton.setAttribute('aria-expanded', 'false');
    button.focus({preventScroll:true});
  });
  licenseButton.addEventListener('click', () => {
    licenses.hidden = !licenses.hidden;
    licenseButton.setAttribute('aria-expanded', String(!licenses.hidden));
    if (!licenses.hidden) panel.querySelector<HTMLElement>('#licenses-title')!.focus();
  });
  panel.querySelector('#contact-support')!.addEventListener('click', async event => {
    if (!isTauri()) return;
    event.preventDefault();
    const error = panel.querySelector<HTMLElement>('#about-support-error')!;
    error.hidden = true;
    try { await request('desktop.support'); }
    catch {
      error.textContent = 'Could not open your email app. Email contact@opensecura.ai for support.';
      error.hidden = false;
    }
  });
}
