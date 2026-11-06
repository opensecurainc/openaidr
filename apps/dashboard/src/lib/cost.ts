const usd = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});

export function money(value: number | null) {
  if (value === null) return "Unavailable";
  return value > 0 && value < 0.01 ? "<$0.01" : usd.format(value);
}

const compactUsd = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  notation: "compact",
  maximumSignificantDigits: 3,
});

export const costTick = (value: number) =>
  value >= 1000 ? compactUsd.format(value) : money(value);
