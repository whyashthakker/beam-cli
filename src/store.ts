import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Event, Scan } from "./core.js";
import { detectSequenceFindings } from "./sequences.js";

export class Store {
  events: Event[] = [];
  scans: Scan[] = [];
  reviews: Record<string, boolean> = {};
  private queue: Promise<unknown> = Promise.resolve();
  readonly maxEvents = 10_000;
  constructor(readonly directory: string) {}
  async init() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await chmod(this.directory, 0o700);
    for (const name of ["events", "scans", "reviews"] as const) {
      const file = join(this.directory, `${name}.ndjson`);
      let contents = "";
      try { if ((await stat(file)).size > 64_000_000) throw new Error(`${name} store exceeds 64 MB; archive it before starting.`); contents = await readFile(file, "utf8"); await chmod(file, 0o600); }
      catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
      const lines = contents.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (!lines[i].trim()) continue;
        try {
          const row = JSON.parse(lines[i]);
          if (name === "events") this.events.push(row);
          else if (name === "scans") this.scans.push(row);
          else this.reviews[row.id] = row.reviewed;
        } catch { throw new Error(`Invalid ${name} store at line ${i + 1}; preserve and repair this file before restarting.`); }
      }
    }
    this.events = this.events.slice(-this.maxEvents);
    this.scans = this.scans.slice(-500);
  }
  private serialized<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.queue.then(fn);
    this.queue = result.catch(() => {});
    return result;
  }
  private async replace(name: string, rows: unknown[]) {
    const target = join(this.directory, `${name}.ndjson`);
    const temp = `${target}.tmp`;
    await writeFile(temp, rows.map(r => JSON.stringify(r)).join("\n") + "\n", { mode: 0o600 });
    await rename(temp, target);
  }
  addEvents(rows: Event[]) {
    return this.serialized(async () => {
      const ids = new Set(this.events.map(e => e.id));
      const fresh = rows.filter(r => { if (ids.has(r.id)) return false; ids.add(r.id); return true; });
      let next = [...this.events, ...fresh].slice(-this.maxEvents);
      if (fresh.length) {
        // Re-evaluate cross-event sequence rules, but only for sessions this batch actually
        // touched -- bounds the cost regardless of total store size.
        const touchedSessions = new Set(fresh.map(e => e.session));
        const bySession = new Map<string, Event[]>();
        for (const e of next) {
          if (!touchedSessions.has(e.session)) continue;
          const list = bySession.get(e.session);
          if (list) list.push(e); else bySession.set(e.session, [e]);
        }
        for (const sessionEvents of bySession.values()) {
          const attach = detectSequenceFindings(sessionEvents);
          if (attach.size) next = next.map(e => attach.has(e.id) ? { ...e, findings: [...e.findings, ...attach.get(e.id)!] } : e);
        }
        // Atomic replacement bounds disk use and makes retry after uncertain delivery idempotent.
        await this.replace("events", next);
        this.events = next;
      }
      return { accepted: fresh.length, duplicates: rows.length - fresh.length };
    });
  }
  addScan(scan: Scan) {
    return this.serialized(async () => {
      const next = [...this.scans, scan].slice(-500);
      await this.replace("scans", next); this.scans = next; return scan;
    });
  }
  review(id: string, reviewed: boolean) {
    return this.serialized(async () => {
      if (!this.events.some(e => e.id === id)) throw new Error("Event not found.");
      const next = { ...this.reviews, [id]: reviewed };
      const ids = new Set(this.events.map(e => e.id));
      const rows = Object.entries(next).filter(([key]) => ids.has(key)).map(([key, value]) => ({ id: key, reviewed: value }));
      await this.replace("reviews", rows); this.reviews = Object.fromEntries(rows.map(r => [r.id, r.reviewed]));
    });
  }
}
