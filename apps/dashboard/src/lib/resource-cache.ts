"use client";

import { createContext } from "react";

type Entry = { data: unknown; updated: Date; revision: number };
type Listener = { path: string; receive: (entry: Entry | null) => void };

/** Recent validated reads, owned by one authenticated dashboard provider. */
export class ResourceCache {
  generation = 0;
  private revision = 0;
  private entries = new Map<string, Entry>();
  private listeners = new Set<Listener>();

  peek(path: string) {
    return this.entries.get(path) ?? null;
  }

  read(path: string) {
    const entry = this.peek(path);
    if (!entry || Date.now() - entry.updated.getTime() >= 60_000) return null;
    return entry;
  }

  write(path: string, data: unknown, updated: Date) {
    const entry = { data, updated, revision: ++this.revision };
    this.entries.delete(path);
    this.entries.set(path, entry);
    if (this.entries.size > 16) this.entries.delete(this.entries.keys().next().value!);
    for (const listener of this.listeners) {
      if (listener.path === path) listener.receive(entry);
    }
  }

  subscribe(path: string, receive: Listener["receive"]) {
    const listener = { path, receive };
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  clear() {
    this.generation++;
    this.entries.clear();
    for (const listener of this.listeners) listener.receive(null);
  }
}

export const ResourceCacheContext = createContext<ResourceCache | null>(null);
