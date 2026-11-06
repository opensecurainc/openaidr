// Deterministic PRNG so fixtures are stable between reloads.
export function mulberry32(seed: number) {
  let a = seed >>> 0;
  return function next(): number {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export class Rand {
  private next: () => number;
  constructor(seed: number) { this.next = mulberry32(seed); }
  float(): number { return this.next(); }
  int(min: number, max: number): number { return min + Math.floor(this.next() * (max - min + 1)); }
  chance(p: number): boolean { return this.next() < p; }
  pick<T>(arr: readonly T[]): T { return arr[Math.floor(this.next() * arr.length)]!; }
  weighted<T>(entries: readonly [T, number][]): T {
    const total = entries.reduce((s, [, w]) => s + w, 0);
    let r = this.next() * total;
    for (const [v, w] of entries) { r -= w; if (r <= 0) return v; }
    return entries[entries.length - 1]![0];
  }
  uuid(): string {
    const h = () => Math.floor(this.next() * 16).toString(16);
    const s = (n: number) => Array.from({ length: n }, h).join("");
    return `${s(8)}-${s(4)}-4${s(3)}-${this.pick(["8", "9", "a", "b"])}${s(3)}-${s(12)}`;
  }
  token(prefix: string, n = 32): string {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    return prefix + Array.from({ length: n }, () => chars[Math.floor(this.next() * chars.length)]).join("");
  }
  shuffle<T>(arr: T[]): T[] {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(this.next() * (i + 1)); [a[i], a[j]] = [a[j]!, a[i]!]; }
    return a;
  }
}
