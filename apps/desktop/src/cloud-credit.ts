import { isTauri } from '@tauri-apps/api/core';
import { isPermissionGranted, sendNotification } from '@tauri-apps/plugin-notification';

export type CloudProtection = {
  schema_version: 1;
  state: 'connecting' | 'active' | 'exhausted' | 'unavailable'; checked_at: number | null;
  guardrail_configured: boolean; guardrail_available: boolean;
  credit_status: 'disabled' | 'unconfigured' | 'active' | 'exhausted' | 'unavailable' | null;
  credits_per_usd: '100'; reset_at: string | null;
};

export function verifiedCredit(value: CloudProtection): CloudProtection {
  const unavailable: CloudProtection = {schema_version:1,state:'unavailable',checked_at:null,
    guardrail_configured:false,guardrail_available:false,credit_status:'unavailable',credits_per_usd:'100',reset_at:null};
  const fields = ['schema_version','state','checked_at','guardrail_configured','guardrail_available','credit_status','credits_per_usd','reset_at'];
  if (typeof value !== 'object' || value === null || Object.keys(value).length !== fields.length
      || Object.keys(value).some(key => !fields.includes(key)) || value.schema_version !== 1
      || !['connecting','active','exhausted','unavailable'].includes(value.state)
      || typeof value.guardrail_configured !== 'boolean' || typeof value.guardrail_available !== 'boolean'
      || !['disabled','unconfigured','active','exhausted','unavailable',null].includes(value.credit_status)
      || value.credits_per_usd !== '100' || (value.reset_at !== null && (typeof value.reset_at !== 'string' || !Number.isFinite(Date.parse(value.reset_at))))
      || (value.checked_at !== null && (typeof value.checked_at !== 'number' || !Number.isFinite(value.checked_at) || value.checked_at < 0))) return unavailable;
  const stale = value.checked_at === null || value.checked_at > Date.now()/1000 + 30 || Date.now()/1000 - value.checked_at > 180;
  if ((value.checked_at !== null && stale) || (value.state === 'active' && (stale || !value.guardrail_available
      || !value.guardrail_configured || ![null,'disabled','active'].includes(value.credit_status)))) return unavailable;
  return value;
}
type Status = {connection_mode?: 'free' | 'api_key' | 'organization'; enrolled?: boolean; disabled?: boolean; desktop_removal?: unknown; sensor_id?: string; server_url?: string; cloud_protection?: CloudProtection | null};

export function initCloudCredit() {
  const notice = document.createElement('details');
  notice.id = 'cloud-credit'; notice.className = 'cloud-credit'; notice.hidden = true;
  notice.setAttribute('aria-label', 'Cloud protection');
  const title = document.createElement('summary');
  const detail = document.createElement('p'); detail.setAttribute('role', 'status');
  notice.append(title, detail);
  document.getElementById('update-guidance')!.after(notice);
  let previous = '', revision = 0;

  return {
    setStatus(status: Status, deferUnavailable = false) {
      const credit = status.cloud_protection ? verifiedCredit(status.cloud_protection) : null;
      const deferred = deferUnavailable && credit?.state === 'unavailable' && credit.checked_at !== null
        && credit.credit_status !== 'exhausted' && credit.credit_status !== 'unconfigured';
      const show = !!credit && credit.state !== 'active' && !deferred && !!status.enrolled && !status.disabled && !status.desktop_removal;
      notice.hidden = !show;
      if (!show || !credit) { previous = ''; revision++; return; }
      const state = credit.state;
      let message: string;
      if (state === 'exhausted') {
        title.textContent = 'Cloud guardrails inactive';
        message = credit.credit_status === 'exhausted'
          ? 'Service credits are exhausted or reserved for pending usage.'
          : 'The free cloud protection allowance is exhausted or reserved for pending usage.';
        const reset = credit.credit_status !== 'exhausted' && credit.reset_at ? new Date(credit.reset_at) : null;
        if (reset && Number.isFinite(reset.getTime())) message += ` Free protection resets ${reset.toLocaleDateString()}.`;
        message += ' Local rules and collection remain available.';
      } else if (state === 'connecting') {
        title.textContent = 'Connecting cloud protection';
        message = 'Connecting to the cloud protection service. Local rules and collection remain available.';
      } else {
        title.textContent = 'Cloud guardrails inactive';
        message = 'Cloud protection is unavailable. OpenAIDR will reconnect automatically. Local rules and collection remain available.';
      }
      if ((status.connection_mode === 'free' || status.connection_mode === 'api_key')) {
        message = message.replace('Local rules and collection remain available.', 'Usage stays on this device. Actions continue.');
      }
      detail.textContent = message;
      notice.classList.toggle('warning', state === 'exhausted' || state === 'unavailable');
      const identity = `${status.server_url}:${status.sensor_id}:${state}`;
      if (identity === previous) return;
      notice.open = true;
      previous = identity;
      const current = ++revision;
      if (isTauri() && (state === 'exhausted' || state === 'unavailable')) {
        void isPermissionGranted().then(allowed => {
          if (allowed && current === revision) sendNotification({title: 'OpenAIDR cloud guardrails inactive', body: message});
        }).catch(() => { /* The persistent in-app notice remains visible. */ });
      }
    },
  };
}
