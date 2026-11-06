"use client";

import { useState } from "react";
import { ChartReadout } from "@/components/chart-readout";
import { Popover, PopoverAnchor, PopoverContent } from "@/components/ui/popover";
import { type DeviceHealth, number } from "@/lib/api";
import { appVersionAge } from "@/lib/app-version-age";

const series = [
  { key: "online", label: "Online", color: "var(--chart-1)" },
  { key: "offline", label: "Offline", color: "var(--input)" },
] as const;

export function AppVersionAge({ devices, loading, error }: {
  devices?: DeviceHealth[];
  loading: boolean;
  error: boolean;
}) {
  const [active, setActive] = useState<number | null>(null);
  const age = appVersionAge(devices ?? []);
  const totals = {
    online: age.buckets.reduce((sum, bucket) => sum + bucket.online, 0),
    offline: age.buckets.reduce((sum, bucket) => sum + bucket.offline, 0),
  };
  const count = totals.online + totals.offline;
  const max = Math.max(1, ...age.buckets.map((bucket) => bucket.online + bucket.offline));
  const message = !devices
    ? loading ? "Loading app versions…" : "App versions unavailable"
    : devices.length === 0 ? "No enrolled devices"
    : count === 0 ? "No online or offline devices with version dates" : null;

  return (
    <section aria-label="Relative App version age" className="min-w-0 bg-card px-4 py-3 sm:col-span-2 xl:col-span-4 2xl:col-span-1">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <h2 className="font-medium">Relative App version age</h2>
        {devices && <span>{number(count)} plotted</span>}
      </div>
      {message ? <p className="flex min-h-24 items-center text-xs text-muted-foreground" role="status">{message}</p> : <>
        <ul aria-label="Version age series" className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
          {series.map(({ key, label, color }) => <li key={key} className="flex items-center gap-1.5">
            <span aria-hidden="true" className="size-2.5 rounded-xs" style={{ background: color }} />
            {label} {number(totals[key])}
          </li>)}
        </ul>
        <div className="mt-2 grid grid-cols-11 gap-0.5" role="group" aria-label="Devices by days behind newest reported version">
          {age.buckets.map((bucket, index) => {
            const total = bucket.online + bucket.offline;
            const label = `${bucket.label}: ${number(bucket.online)} online, ${number(bucket.offline)} offline`;
            return <Popover key={bucket.label} open={active === index} onOpenChange={(open) => setActive(open ? index : null)}>
              <PopoverAnchor asChild>
                <button
                  type="button"
                  aria-label={label}
                  onPointerEnter={(event) => { if (event.pointerType === "mouse") setActive(index); }}
                  onPointerLeave={(event) => { if (event.pointerType === "mouse") setActive(null); }}
                  onFocus={() => setActive(index)}
                  onBlur={() => setActive(null)}
                  onClick={() => setActive(index)}
                  className="number min-w-0 rounded-xs text-xs focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                >
                  <span aria-hidden="true" className="flex h-16 flex-col justify-end">
                    <span className="mb-1 block text-foreground">{number(total)}</span>
                    <span className="mx-auto flex w-full flex-col gap-0.5 overflow-hidden rounded-t-xs" style={{ height: `${total / max * 40}px` }}>
                      {bucket.offline > 0 && <span className="min-h-0 bg-input" style={{ flex: bucket.offline }} />}
                      {bucket.online > 0 && <span className="min-h-0 bg-chart-1" style={{ flex: bucket.online }} />}
                    </span>
                  </span>
                  <span aria-hidden="true" className="mt-1 block text-muted-foreground">{bucket.label}</span>
                </button>
              </PopoverAnchor>
              <PopoverContent
                variant="readout" side="top" align="center"
                onOpenAutoFocus={(event) => event.preventDefault()}
                onCloseAutoFocus={(event) => event.preventDefault()}
              >
                <ChartReadout
                  timestamp={`${bucket.label} behind newest reported version`}
                  rows={series.map(({ key, label, color }) => ({ label, value: `${number(bucket[key])} ${bucket[key] === 1 ? "device" : "devices"}`, color }))}
                >
                  <p>Reference build date: {age.referenceDate}</p>
                  {error && <p>Stale app version data</p>}
                </ChartReadout>
              </PopoverContent>
            </Popover>;
          })}
        </div>
        <div className="sr-only"><table>
          <caption>Relative App version age in days. Newest enrolled build date: {age.referenceDate}.</caption>
          <thead><tr><th scope="col">Days behind</th><th scope="col">Online devices</th><th scope="col">Offline devices</th></tr></thead>
          <tbody>{age.buckets.map((bucket) => <tr key={bucket.label}>
            <th scope="row">{bucket.label}</th><td>{bucket.online}</td><td>{bucket.offline}</td>
          </tr>)}</tbody>
        </table></div>
      </>}
      {age.referenceVersions.length > 0 && <p className="mt-1 wrap-anywhere text-xs text-muted-foreground">
        Days behind newest reported version ({age.referenceVersions.join(", ")})
      </p>}
      {(age.unknown > 0 || age.disabled > 0) && <p className="mt-1 text-xs text-muted-foreground">
        Excluded: {[
          age.unknown > 0 && `${number(age.unknown)} unknown version`,
          age.disabled > 0 && `${number(age.disabled)} disabled`,
        ].filter(Boolean).join(" · ")}
      </p>}
      {devices && error && <p className="mt-1 text-xs text-muted-foreground">Stale app version data</p>}
    </section>
  );
}
