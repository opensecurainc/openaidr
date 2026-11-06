import type { DeviceHealth } from "./api";

function versionDay(version: string): number | null {
  const match = /^v?(\d{4})\.(\d{1,2})\.(\d{1,2})\+[0-9a-f]{7,40}$/.exec(version);
  if (!match) return null;
  const [year, month, day] = match.slice(1).map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
  return date.getTime() / 86400000;
}

export function appVersionAge(devices: readonly Pick<DeviceHealth, "sensor_version" | "status">[]) {
  const versions = devices.map((device) => ({ version: device.sensor_version, status: device.status, day: versionDay(device.sensor_version) }));
  const newest = versions.reduce<number | null>((latest, { day }) =>
    day === null ? latest : Math.max(latest ?? day, day), null);
  const buckets = Array.from({ length: 11 }, (_, days) => ({
    label: days === 10 ? ">9d" : `${days}d`,
    online: 0,
    offline: 0,
  }));
  let unknown = 0;
  let disabled = 0;
  for (const device of versions) {
    if (device.status === "disabled") {
      disabled++;
    } else if (device.day === null || newest === null) {
      unknown++;
    } else {
      buckets[Math.min(newest - device.day, 10)][device.status]++;
    }
  }
  const date = newest === null ? null : new Date(newest * 86400000);
  return {
    buckets,
    referenceDate: date && `${date.getUTCFullYear()}.${date.getUTCMonth() + 1}.${date.getUTCDate()}`,
    referenceVersions: newest === null ? [] : [...new Set(versions.filter(({ day }) => day === newest).map(({ version }) => version))].sort(),
    unknown,
    disabled,
  };
}
