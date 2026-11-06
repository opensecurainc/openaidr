export function sensorCpu(value: number | null | undefined) {
  if (value == null) return "Not reported";
  return value > 0 && value < 0.1 ? "<0.1%" : `${value.toFixed(1)}%`;
}

export function sensorMemory(value: number | null | undefined) {
  if (value == null) return "Not reported";
  const mib = value / 1024 ** 2;
  return mib > 0 && mib < 0.1 ? "<0.1 MiB" : `${mib.toFixed(1)} MiB`;
}
