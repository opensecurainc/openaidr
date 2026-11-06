"use client";

import { useState } from "react";
import { type DeviceHealth, number } from "@/lib/api";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";

export function healthStatus(device: DeviceHealth) {
  if (device.status === "disabled") return "disabled";
  if (device.status === "offline") return "unknown";
  return device.health?.status ?? "unknown";
}

const labels = { healthy: "Healthy", needs_attention: "Needs attention", unknown: "Health not reported", disabled: "Disabled" };

export function SensorHealthCell({ device }: { device: DeviceHealth }) {
  const [open, setOpen] = useState(false);
  const { dateTime } = useTimeZone();
  const state = healthStatus(device);
  const health = device.health;
  const offline = device.status === "offline";
  const label = offline ? "Health unknown" : labels[state];
  const reasons = offline ? [] : health?.reasons ?? [];
  const name = device.label || device.hostname || "Unnamed device";
  const count = (value: number | null | undefined) => value == null ? "Not reported" : number(value);
  return <>
    <Button variant="ghost" className="h-auto justify-start px-0 py-1 text-left" aria-label={`View health for ${name}`} onClick={() => setOpen(true)}>
      <Status tone={state === "needs_attention" ? "warning" : state === "healthy" ? "ok" : "neutral"}>{label}</Status>
    </Button>
    {reasons[0] && <p className="max-w-64 whitespace-normal text-xs text-muted-foreground">{reasons[0].message}{reasons.length > 1 ? ` (+${reasons.length - 1})` : ""}</p>}
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-h-[85dvh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Sensor health</DialogTitle>
          <DialogDescription>{name} · {label}</DialogDescription>
        </DialogHeader>
        {reasons.length > 0 && <ul className="list-disc space-y-1 pl-5 text-sm">{reasons.map(reason => <li key={reason.code}>{reason.message}</li>)}</ul>}
        {state === "unknown" && <p className="text-sm text-muted-foreground">{offline ? "Current sensor health is unknown while this device is offline." : "This sensor has not supplied current health diagnostics. Update the sensor to report upload and collection failures."}</p>}
        {state === "healthy" && <p className="text-sm text-muted-foreground">The latest heartbeat reports no upload, queue, receiver, or collection faults.</p>}
        {(offline || health?.stale) && <p className="text-sm text-muted-foreground">Measurements below are from the last heartbeat. Current device health is unavailable.</p>}
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
          <dt>Last heartbeat</dt><dd>{dateTime(device.last_heartbeat_at)}</dd>
          <dt>Health reported</dt><dd>{health?.reported_at ? dateTime(health.reported_at) : "Not reported"}</dd>
          <dt>Pending activity</dt><dd>{count(device.queue_depth)}</dd>
          <dt>Pending exports</dt><dd>{count(device.telemetry_queue_depth)}</dd>
          <dt>Last activity upload</dt><dd>{health?.report?.activity.last_success_at ? dateTime(health.report.activity.last_success_at) : "Not reported"}</dd>
          <dt>Last telemetry upload</dt><dd>{health?.report?.telemetry.last_success_at ? dateTime(health.report.telemetry.last_success_at) : "Not reported"}</dd>
          <dt>Activity dropped this session</dt><dd>{count(health?.report?.activity.dropped)}</dd>
          <dt>Failed collectors</dt><dd>{count(health?.report?.collectors_failed)}</dd>
        </dl>
        <p className="text-xs text-muted-foreground">Upload errors need attention immediately. A queued upload is stalled after five minutes without progress. Offline and disabled devices are excluded from attention counts.</p>
      </DialogContent>
    </Dialog>
  </>;
}
