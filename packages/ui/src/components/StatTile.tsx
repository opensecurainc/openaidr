import type { ReactNode } from "react";
import { compact } from "../utils/format";

export function StatTile({ label, value, sub, delta, hero, format = compact }: {
  label: string; value: number | string; sub?: ReactNode; delta?: { value: number; label: string; upIsGood?: boolean }; hero?: boolean; format?: (n: number) => string;
}) {
  const v = typeof value === "number" ? format(value) : value;
  let deltaCls = "tile__delta";
  if (delta && delta.value !== 0) {
    const good = (delta.value > 0) === (delta.upIsGood ?? true);
    deltaCls += good ? " tile__delta--up" : " tile__delta--down";
  }
  return (
    <div className={`tile${hero ? " tile--hero" : ""}`}>
      <p className="tile__label">{label}</p>
      <div className="tile__value">{v}</div>
      {delta && <div className={deltaCls}>{delta.value > 0 ? "+" : ""}{delta.value}{" "}{delta.label}</div>}
      {sub && <div className="tile__sub">{sub}</div>}
    </div>
  );
}
