import { type Page } from "@playwright/test";

export const alertExample = {
  id: "01000000-0000-7000-8000-000000000042", title: "Upgrade your LiteLLM version",
  message: "Activate the Python environment that uses LiteLLM, run the command, then restart the application.",
  command: 'python -m pip install --upgrade "litellm==1.106.2"', installed_version: "1.105.0", required_version: "1.106.2",
  sender_name: "Test operator", created_at: "2026-10-18T09:15:00Z", expires_at: "2026-11-17T09:15:00Z",
  device_count: 1, received_count: 0, acknowledged_count: 0, expired: false,
};

export async function alertApi(page: Page) {
  const state = { failSend: false, unavailable: false, sent: false, received: false, acknowledged: false,
    writes: [] as { body: Record<string, unknown>; csrf: string | undefined }[], queries: [] as URL[] };
  await page.route("**/api/v1/endpoint-alerts**", async route => {
    const request = route.request(), url = new URL(request.url());
    state.queries.push(url);
    if (state.unavailable) return route.fulfill({status:404, json:{error:"Not found"}});
    if (request.method() === "POST") {
      state.writes.push({body:request.postDataJSON(), csrf:request.headers()["x-openaidr-csrf"]});
      if (state.failSend) { state.failSend = false; return route.abort("failed"); }
      state.sent = true;
      return route.fulfill({status:201, json:alertExample});
    }
    const record = {...alertExample, received_count: state.received ? 1 : 0, acknowledged_count: state.acknowledged ? 1 : 0};
    if (url.pathname.endsWith(alertExample.id)) return route.fulfill({json:{...record, recipients:[{
      sensor_id:"device-0", hostname:"macbook-pro-07", received_at:state.received ? alertExample.created_at : null,
      acknowledged_at:state.acknowledged ? alertExample.created_at : null, disabled:false, deleted_at:null,
    }]}});
    return route.fulfill({json:{items:state.sent ? [record] : [], has_more:false}});
  });
  return state;
}
