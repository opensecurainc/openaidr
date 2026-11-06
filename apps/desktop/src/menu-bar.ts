import { invoke, isTauri } from '@tauri-apps/api/core';

export function initMenuBar(refresh: () => void, fit: () => void) {
  const setting = document.createElement('div');
  setting.id = 'menu-bar-setting'; setting.className = 'desktop-preference'; setting.hidden = true;
  setting.innerHTML = `<label><input id="show-menu-bar" type="checkbox" aria-describedby="menu-bar-description"><span>Show in menu bar</span></label>
    <p id="menu-bar-description">Keep status available when the window is closed. Quitting the app leaves the sensor running.</p>
    <p id="menu-bar-error" role="alert" hidden></p>`;
  document.getElementById('settings-actions')!.before(setting);
  const checkbox = setting.querySelector('input')!;
  const description = setting.querySelector<HTMLElement>('#menu-bar-description')!;
  const availableDescription = description.textContent;
  const availability = (available: boolean) => {
    description.textContent = available ? availableDescription : 'No system tray is available. Closing the window exits the app and leaves the sensor running.';
    if (supported) fit();
  };
  const error = setting.querySelector<HTMLElement>('[role=alert]')!;
  let supported = false, enabled = false, visible = true;
  let health = {label:'Checking sensor…',attention:false};
  const hidden = () => !visible || document.hidden;
  const publish = () => {
    if (supported) void invoke('menu_bar_health', health).catch(() => {});
  };
  checkbox.addEventListener('change', async () => {
    checkbox.disabled = true; error.hidden = true;
    try {
      const result = await invoke<{enabled:boolean}>('menu_bar_settings', {enabled:checkbox.checked});
      enabled = result.enabled;
    } catch (failure) {
      error.textContent = failure instanceof Error ? failure.message : String(failure); error.hidden = false;
    } finally {
      checkbox.checked = enabled; checkbox.disabled = false; fit();
    }
  });
  if (isTauri()) void invoke<{supported:boolean;enabled:boolean;label?:string;available?:boolean}>('menu_bar_settings').then(result => {
    supported = result.supported; enabled = result.enabled;
    setting.querySelector('label span')!.textContent = result.label ?? 'Show in menu bar';
    setting.hidden = !supported; checkbox.checked = enabled;
    availability(result.available !== false);
    if (supported) publish();
  }).catch(() => {});
  window.addEventListener('openaidr-tray-availability', event => availability((event as CustomEvent<boolean>).detail));
  window.addEventListener('openaidr-window-visibility', event => {
    visible = (event as CustomEvent<boolean>).detail;
    if (visible) { refresh(); fit(); }
  });
  window.addEventListener('openaidr-background-status', () => {
    if (enabled && hidden()) refresh();
  });
  return {
    hidden,
    update(label: string, attention: boolean) { health = {label,attention}; publish(); },
  };
}
