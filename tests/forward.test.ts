import { afterEach, beforeEach, expect, it, jest } from "@jest/globals";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ForwardQueue } from "../src/forward.js";
import { normalize } from "../src/core.js";
import { writeIdentity, type Identity } from "../src/enroll.js";
import { createCollector } from "../src/server.js";
import { HOOK_CATALOG, hookKind } from "../src/hook-catalog.js";
import { adaptHookPayload } from "../src/hook-adapters.js";

const originalEnv = { ...process.env };
const originalFetch = global.fetch;
const queues: ForwardQueue[] = [];
let directory: string;
const identity: Identity = {
  deviceId: "device", orgId: "org", deviceSecret: "test-secret",
  apiBase: "https://workspace.invalid", publicKey: "", privateKey: "",
  hostname: "test", os: "test", enrolledAt: "2026-11-03T00:00:00Z",
};
const event = () => normalize({ source_agent: "muse", source_type: "hook", hook_event_name: "PreToolUse",
  session_id: "session", tool_use_id: "call", tool_name: "Edit",
  tool_input: { file_path: "/repo/a.ts", old_string: "before", new_string: "after" } });

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), "beam-forward-"));
  process.env.BEAM_DATA_DIR = directory;
  await writeIdentity(identity);
  jest.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(async () => {
  global.fetch = async () => new Response("offline", { status: 503 });
  for (const queue of queues.splice(0)) await queue.close();
  global.fetch = originalFetch;
  process.env = { ...originalEnv };
  jest.restoreAllMocks();
  await rm(directory, { recursive: true, force: true });
});

it("retains rejected events on disk and retries the identical payload after restart", async () => {
  const sent: unknown[] = [];
  global.fetch = async (_url, init) => { sent.push(JSON.parse(String(init?.body))); return new Response("rejected", { status: 400 }); };
  const first = new ForwardQueue(directory); queues.push(first);
  const expected = event();
  await first.push([expected]);
  await first.close();
  const files = await readdir(join(directory, "event-outbox"));
  expect(files).toHaveLength(1);
  expect(JSON.parse(await readFile(join(directory, "event-outbox", files[0]), "utf8")).events).toEqual([expected]);
  global.fetch = async (_url, init) => { sent.push(JSON.parse(String(init?.body))); return Response.json({ accepted: 1, duplicates: 0 }); };
  const restarted = new ForwardQueue(directory); queues.push(restarted);
  await restarted.flush();
  expect(sent).toEqual([[expected], [expected]]);
  expect(await readdir(join(directory, "event-outbox"))).toEqual([]);
});

it("does not send a queued event into a newly enrolled workspace", async () => {
  const fetcher = jest.fn<typeof fetch>().mockResolvedValue(Response.json({ accepted: 1 }));
  global.fetch = fetcher;
  const queue = new ForwardQueue(directory); queues.push(queue);
  await queue.push([event()]);
  await writeIdentity({ ...identity, orgId: "other", deviceId: "other", apiBase: "https://other.invalid" });
  await queue.flush();
  expect(fetcher).not.toHaveBeenCalled();
  expect(await readdir(join(directory, "event-outbox"))).toHaveLength(1);
  await writeIdentity(identity);
  await queue.flush();
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it("batches separate hook captures while retaining every unsent envelope on network failure", async () => {
  const queue = new ForwardQueue(directory); queues.push(queue);
  const expected = [0, 1, 2].map(n => ({ ...event(), id: `event-${n}` }));
  for (const row of expected) await queue.push([row]);
  global.fetch = async () => { throw new Error("offline"); };
  await queue.flush();
  expect(await readdir(join(directory, "event-outbox"))).toHaveLength(3);
  const sent: unknown[][] = [];
  global.fetch = async (_url, init) => { sent.push(JSON.parse(String(init?.body))); return Response.json({ accepted: 3 }); };
  await queue.flush();
  expect(sent).toHaveLength(1);
  expect(sent[0]).toEqual(expect.arrayContaining(expected));
  expect(sent[0]).toHaveLength(3);
  expect(await readdir(join(directory, "event-outbox"))).toEqual([]);
});

it("normalizes every agent's tool hooks before sending the complete activity envelope", async () => {
  const app = await createCollector({ directory, token: "test-token", rulesHome: directory });
  queues.push(app.forwardQueue);
  const sent: Record<string, any>[] = [];
  global.fetch = async (_url, init) => { sent.push(...JSON.parse(String(init?.body))); return Response.json({ accepted: 6 }); };
  const payload = HOOK_CATALOG.map(spec => adaptHookPayload(spec.id, {
    session_id: `session-${spec.id}`, tool_use_id: `call-${spec.id}`,
    tool_name: "Edit", tool_input: { file_path: `/repo/${spec.id}.ts`, old_string: "before", new_string: "after" },
  }, spec.events.find(name => hookKind(name) === "pre")));
  const response = await app.fetch(new Request("http://127.0.0.1:4319/ingest", {
    method: "POST", headers: { Authorization: "Bearer test-token" }, body: JSON.stringify(payload),
  }));
  expect(response.status).toBe(200);
  await app.forwardQueue.flush();
  expect(sent).toHaveLength(HOOK_CATALOG.length);
  expect(new Set(sent.map(row => row.agent))).toEqual(new Set(HOOK_CATALOG.map(spec => spec.id)));
  for (const row of sent) {
    expect(row.id).toMatch(/^[a-f0-9]{64}$/);
    expect(row.timestamp).toBeTruthy();
    expect(row.type).toBe("file.write");
    expect(row.activity.paths).toEqual([`/repo/${row.agent}.ts`]);
    expect(row.activity.edits).toEqual({ old: "before", new: "after" });
  }
});

it("bounds normalized identifiers to the workspace ingest contract", () => {
  const row = normalize({ source_agent: "a".repeat(500), session_id: "s".repeat(500),
    event_type: "t".repeat(500), tool_name: "x".repeat(500) });
  expect([row.agent.length, row.session.length, row.type.length, row.tool.length]).toEqual([100, 200, 100, 100]);
});

it("delivers generated regexes for every catalogued agent through local ingest and the outbox", async () => {
  const app = await createCollector({ directory, token: "test-token", rulesHome: directory });
  queues.push(app.forwardQueue);
  const sent: Record<string, any>[] = [];
  global.fetch = async (_url, init) => { sent.push(...JSON.parse(String(init?.body))); return Response.json({ accepted: HOOK_CATALOG.length }); };
  const payload = HOOK_CATALOG.map(spec => adaptHookPayload(spec.id, {
    session_id: `regex-${spec.id}`, tool_use_id: `regex-${spec.id}`, tool_name: "exec_command",
    tool_input: { cmd: "python3 -c \"from pathlib import Path; Path('page.html').write_text('new content')\"" },
  }, spec.events.find(name => hookKind(name) === "pre")));
  const response = await app.fetch(new Request("http://127.0.0.1:4319/ingest", {
    method: "POST", headers: { Authorization: "Bearer test-token" }, body: JSON.stringify(payload),
  }));
  expect(response.status).toBe(200);
  await app.forwardQueue.flush();
  expect(new Set(sent.map(row => row.agent))).toEqual(new Set(HOOK_CATALOG.map(spec => spec.id)));
  for (const row of sent) {
    expect(row.type).toBe("command.exec");
    expect(row.mitigationCandidate).toMatchObject({ kind: "command", version: 1 });
    const regex = new RegExp(row.mitigationCandidate.pattern, "i");
    expect(regex.test("python3 -c \"from pathlib import Path; Path('page.html').write_text('changed again')\"")).toBe(true);
    expect(regex.test("python3 -c \"from pathlib import Path; Path('other.html').write_text('new content')\"")).toBe(false);
  }
});
