export function isUtcDailySeries(bucketSeconds: number, starts: readonly string[]) {
  return (
    bucketSeconds === 86400 && starts.length > 0 &&
    starts.every((start) => Date.parse(start) % 86400000 === 0)
  );
}

/** Daily aggregates keep the UTC calendar day used by the server. */
export function chartTimestamp(value: string | number, daily = false, timeZone?: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not reported";
  return date.toLocaleString("en-US", {
    timeZone: daily ? "UTC" : timeZone,
    month: "short",
    day: "numeric",
    year: "numeric",
    ...(daily ? {} : {
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
      timeZoneName: "short",
    }),
  }) + (daily ? " UTC" : "");
}

export function chartTimeTick(value: number, daily = false, timeZone?: string) {
  return new Date(value).toLocaleString("en-US", {
    timeZone: daily ? "UTC" : timeZone,
    month: "short",
    day: "numeric",
    ...(daily ? {} : { hour: "2-digit", minute: "2-digit", hourCycle: "h23" }),
  });
}

export function chartTicks(max: number, integer = false, minimumStep = 0) {
  if (!(max > 0)) return [0, minimumStep || 1];
  const rough = max / 4;
  const magnitude = 10 ** Math.floor(Math.log10(rough));
  const step = Math.max(
    integer ? 1 : minimumStep,
    [1, 2, 2.5, 5, 10]
      .map((factor) => factor * magnitude)
      .find(
        (value) => value >= rough && (!integer || Number.isInteger(value)),
      ) ?? 1,
  );
  const ticks: number[] = [];
  for (let i = 0; i <= Math.floor(max / step) + 1; i++)
    ticks.push(Number((i * step).toPrecision(12)));
  return ticks;
}

export function showSample(
  timestamps: number[],
  index: number,
  width: number,
  start: number,
  end: number,
) {
  const spacing = Math.min(
    index > 0 ? timestamps[index] - timestamps[index - 1] : Infinity,
    index + 1 < timestamps.length
      ? timestamps[index + 1] - timestamps[index]
      : Infinity,
  );
  return (
    timestamps.length === 1 ||
    (Math.max(width, 0) * spacing) / Math.max(end - start, 1) >= 12
  );
}
