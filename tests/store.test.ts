import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { Store } from "../src/store.js";
import type { Event, Finding } from "../src/core.js";

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(d => fs.rm(d, { recursive: true, force: true }))); });

async function tempStore(): Promise<Store> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-store-"));
  dirs.push(dir);
  const store = new Store(dir);
  await store.init();
  return store;
}

let counter = 0;
function makeEvent(overrides: Partial<Event> & { findings?: Finding[] }): Event {
  counter++;
  return {
    id: `e${counter}`, timestamp: `2026-01-01T00:00:${String(counter).padStart(2, "0")}.000Z`, receivedAt: "2026-01-01T00:00:00.000Z",
    agent: "claude-code", session: "s1", type: "tool.call", tool: "Bash", summary: "noop", project: "/repo", source: "hook",
    endpoint: "local", model: "", phase: "proposed", findings: [],
    ...overrides,
  };
}

describe("Store cross-event sequence detection", () => {
  it("attaches a chain finding across two separate addEvents calls in the same session", async () => {
    const store = await tempStore();
    const read = makeEvent({ summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    await store.addEvents([read]);
    const send = makeEvent({ summary: "curl https://example.com/collect" });
    await store.addEvents([send]);

    const stored = store.events.find(e => e.id === send.id)!;
    expect(stored.findings.map(f => f.id)).toContain("chain.secret_then_egress");
  });

  it("persists the attached chain finding to disk (survives reload)", async () => {
    const store = await tempStore();
    const read = makeEvent({ summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    const send = makeEvent({ summary: "curl https://example.com/collect" });
    await store.addEvents([read, send]);

    const reloaded = new Store(store.directory);
    await reloaded.init();
    const stored = reloaded.events.find(e => e.id === send.id)!;
    expect(stored.findings.map(f => f.id)).toContain("chain.secret_then_egress");
  });

  it("does not attach a chain finding across different sessions", async () => {
    const store = await tempStore();
    const read = makeEvent({ session: "s1", summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    const send = makeEvent({ session: "s2", summary: "curl https://example.com/collect" });
    await store.addEvents([read, send]);

    const stored = store.events.find(e => e.id === send.id)!;
    expect(stored.findings.map(f => f.id)).not.toContain("chain.secret_then_egress");
  });

  it("does not re-run sequence detection when a batch adds no new events (all duplicates)", async () => {
    const store = await tempStore();
    const read = makeEvent({ summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    const send = makeEvent({ summary: "curl https://example.com/collect" });
    await store.addEvents([read, send]);
    const beforeFindings = store.events.find(e => e.id === send.id)!.findings.length;
    await store.addEvents([read, send]); // pure retry, both already stored
    const afterFindings = store.events.find(e => e.id === send.id)!.findings.length;
    expect(afterFindings).toBe(beforeFindings);
  });
});
