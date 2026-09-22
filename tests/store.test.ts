import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { Store } from "../src/store.js";
import type { Event, Finding } from "../src/core.js";
import { applyApproval, createApprovalRequest } from "../src/approvals.js";

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

describe("Store cross-agent duplicate suppression", () => {
  it("keeps only the first event when two agents log the same command/cwd within the dedup window", async () => {
    const store = await tempStore();
    const cursor = makeEvent({ id: "cursor-1", agent: "cursor", timestamp: "2026-01-01T00:00:00.000Z", summary: 'echo "hello world"' });
    const claude = makeEvent({ id: "claude-1", agent: "claude-code", timestamp: "2026-01-01T00:00:00.900Z", summary: 'echo "hello world"' });
    const result = await store.addEvents([cursor, claude]);

    expect(result.accepted).toBe(1);
    expect(store.events).toHaveLength(1);
    expect(store.events[0].agent).toBe("cursor");
  });

  it("relabels a same-id duplicate (already collapsed upstream by tool_use_id) to the specific agent", async () => {
    const store = await tempStore();
    const claude = makeEvent({ id: "shared-id", agent: "claude-code", timestamp: "2026-01-01T00:00:00.000Z", summary: 'echo "hello world"' });
    const cursor = makeEvent({ id: "shared-id", agent: "cursor", timestamp: "2026-01-01T00:00:00.900Z", summary: 'echo "hello world"' });
    const result = await store.addEvents([claude, cursor]);

    expect(result.accepted).toBe(1);
    expect(store.events).toHaveLength(1);
    expect(store.events[0].agent).toBe("cursor");
  });

  it("relabels a same-id duplicate that was already persisted in an earlier addEvents call", async () => {
    const store = await tempStore();
    const claude = makeEvent({ id: "shared-id-2", agent: "claude-code", timestamp: "2026-01-01T00:00:00.000Z", summary: 'echo "hello world"' });
    await store.addEvents([claude]);
    const cursor = makeEvent({ id: "shared-id-2", agent: "cursor", timestamp: "2026-01-01T00:00:00.900Z", summary: 'echo "hello world"' });
    const result = await store.addEvents([cursor]);

    expect(result.accepted).toBe(0);
    expect(result.relabeled).toHaveLength(1);
    expect(result.relabeled[0].agent).toBe("cursor");
    expect(store.events).toHaveLength(1);
    expect(store.events[0].agent).toBe("cursor");
  });

  it("keeps both events when the same agent logs the same command twice", async () => {
    const store = await tempStore();
    const first = makeEvent({ id: "e-a", agent: "cursor", timestamp: "2026-01-01T00:00:00.000Z", summary: 'echo "hello world"' });
    const second = makeEvent({ id: "e-b", agent: "cursor", timestamp: "2026-01-01T00:00:00.900Z", summary: 'echo "hello world"' });
    const result = await store.addEvents([first, second]);

    expect(result.accepted).toBe(2);
    expect(store.events).toHaveLength(2);
  });

  it("relabels the surviving event to the specific agent when the generic claude-code echo arrives first", async () => {
    const store = await tempStore();
    const claude = makeEvent({ id: "claude-3", agent: "claude-code", timestamp: "2026-01-01T00:00:00.000Z", summary: 'echo "hello world"' });
    const cursor = makeEvent({ id: "cursor-3", agent: "cursor", timestamp: "2026-01-01T00:00:00.900Z", summary: 'echo "hello world"' });
    const result = await store.addEvents([claude, cursor]);

    expect(result.accepted).toBe(1);
    expect(store.events).toHaveLength(1);
    expect(store.events[0].agent).toBe("cursor");
    expect(store.events[0].id).toBe("claude-3");
  });

  it("relabels a duplicate that was already persisted in an earlier addEvents call", async () => {
    const store = await tempStore();
    const claude = makeEvent({ id: "claude-4", agent: "claude-code", timestamp: "2026-01-01T00:00:00.000Z", summary: 'echo "hello world"' });
    await store.addEvents([claude]);
    const cursor = makeEvent({ id: "cursor-4", agent: "cursor", timestamp: "2026-01-01T00:00:00.900Z", summary: 'echo "hello world"' });
    const result = await store.addEvents([cursor]);

    expect(result.accepted).toBe(0);
    expect(result.relabeled).toHaveLength(1);
    expect(result.relabeled[0].id).toBe("claude-4");
    expect(result.relabeled[0].agent).toBe("cursor");
    expect(store.events).toHaveLength(1);
    expect(store.events[0].agent).toBe("cursor");
  });

  it("keeps both events when two agents log the same command far apart in time", async () => {
    const store = await tempStore();
    const cursor = makeEvent({ id: "cursor-2", agent: "cursor", timestamp: "2026-01-01T00:00:00.000Z", summary: 'echo "hello world"' });
    const claude = makeEvent({ id: "claude-2", agent: "claude-code", timestamp: "2026-01-01T00:00:10.000Z", summary: 'echo "hello world"' });
    const result = await store.addEvents([cursor, claude]);

    expect(result.accepted).toBe(2);
    expect(store.events).toHaveLength(2);
  });
});

describe("Store approval persistence", () => {
  it("persists approval requests, lifecycle changes, and audit records", async () => {
    const store = await tempStore();
    const request = createApprovalRequest({ user: "Rahul", role: "Developer", approver: ["Lead"], level: "MANAGER", mode: "SINGLE", agent: "claude-code", tool: "Bash", command: "git push", policy_version: 1, risk_score: 50, risk_level: "MEDIUM", risk_factors: [] });
    await store.addApproval(request);
    const approved = await store.resolveApproval(request.request_id, "APPROVE_ONCE", "Lead", applyApproval);
    expect(approved.status).toBe("APPROVED");
    const reloaded = new Store(store.directory); await reloaded.init();
    expect(reloaded.approvals[0].status).toBe("APPROVED");
    expect(reloaded.approvalAudit.map(a => a.event)).toContain("approval_approved");
  });
});
