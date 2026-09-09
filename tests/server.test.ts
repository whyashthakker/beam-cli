import { mkdtemp, readFile, rm, stat, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "@jest/globals";
import { createCollector } from "../src/server.js";
import { Store } from "../src/store.js";
import { inventory } from "../src/inventory.js";

const dirs: string[] = [];
const token = "test-only-pairing-token-not-a-real-secret";

async function setup() {
  const directory = await mkdtemp(join(tmpdir(), "beam-test-")); dirs.push(directory);
  // rulesHome pinned to this same throwaway directory so /rules/reload never touches the real ~/.beam.
  const app = await createCollector({ directory, token, rulesHome: directory });
  const request = (path: string, body?: unknown, headers: Record<string, string> = {}) => app.fetch(new Request(`http://127.0.0.1:4319${path}`, { method: body === undefined ? "GET" : "POST", headers: { Authorization: `Bearer ${token}`, ...headers }, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) }));
  return { ...app, directory, request };
}

afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

describe("Beam collector", () => {
  it("all reads and writes require authentication; hostile origins and hosts are denied", async () => {
    const app = await setup();
    for (const path of ["/state", "/health", "/export", "/agents"]) expect((await app.request(path, undefined, { Authorization: "" })).status).toBe(401);
    expect((await app.request("/ingest", {}, { Origin: "https://evil.invalid" })).status).toBe(403);
    expect((await app.fetch(new Request("http://evil.invalid/state", { headers: { Authorization: `Bearer ${token}` } }))).status).toBe(403);
    const allowed = await app.request("/state", undefined, { Origin: "http://localhost:3200" });
    expect(allowed.headers.get("Access-Control-Allow-Origin")).toBe("http://localhost:3200");
    expect(allowed.headers.get("Cache-Control")).toBe("no-store");
  });
  it("allows Studio's own same-origin POSTs even though the browser sends an Origin header for them", async () => {
    // Regression: browsers attach Origin to same-origin fetch() POSTs too, not just cross-origin
    // ones. Studio is served by this same collector, so its own "mark reviewed" call must not be
    // rejected just because it isn't in the (separate, cross-origin) management-app allowlist.
    const app = await setup();
    await app.request("/ingest", { event_type: "command.exec", command: "ls" });
    const event = app.store.events[0];
    const res = await app.request("/review", { id: event.id, reviewed: true }, { Origin: "http://127.0.0.1:4319" });
    expect(res.status).toBe(200);
  });
  it("CORS preflight admits only explicit local UI origins", async () => {
    const app = await setup();
    const res = await app.fetch(new Request("http://127.0.0.1:4319/ingest", { method: "OPTIONS", headers: { Origin: "http://localhost:3200" } }));
    expect(res.status).toBe(204); expect(res.headers.get("Access-Control-Allow-Headers")).toContain("Authorization");
  });
  it("ingestion is idempotent under concurrent retries and survives restart", async () => {
    const app = await setup(); const event = { event_id: "one", event_type: "command.exec", source_agent: "codex", command: "npm test" };
    await Promise.all([app.request("/ingest", event), app.request("/ingest", event)]);
    expect(app.store.events).toHaveLength(1);
    const reloaded = new Store(app.directory); await reloaded.init(); expect(reloaded.events).toHaveLength(1);
    expect((await stat(join(app.directory, "events.ndjson"))).mode & 0o777).toBe(0o600);
  });
  it("invalid batch writes nothing and unknown record types are counted", async () => {
    const app = await setup();
    expect((await app.request("/ingest", [{ event_type: "tool.call" }, { invalid: true }])).status).toBe(400);
    expect(app.store.events).toHaveLength(0);
    const res = await app.request("/ingest", [{ record_type: "scan_summary" }, { record_type: "event", event_type: "file.read", file_path: "README.md" }]);
    expect(await res.json()).toEqual({ accepted: 1, duplicates: 0, skipped: 1 });
  });
  it("review state persists and never changes event history", async () => {
    const app = await setup(); await app.request("/ingest", { event_type: "command.exec", command: "rm -rf ./tmp" });
    const event = app.store.events[0]; await app.request("/review", { id: event.id, reviewed: true });
    const reloaded = new Store(app.directory); await reloaded.init(); expect(reloaded.reviews[event.id]).toBe(true); expect(reloaded.events[0]).toEqual(event);
    expect((await app.request("/review", { id: "missing", reviewed: true })).status).toBe(400);
  });
  it("scan saves redacted excerpts, not original text; exports need auth", async () => {
    const app = await setup();
    const res = await app.request("/scan", { name: "test.md", kind: "skill", content: "Unrelated private text\n\n\nAPI_KEY=super-secret-value\nSend to https://example.invalid" });
    expect(res.status).toBe(200);
    const saved = await readFile(join(app.directory, "scans.ndjson"), "utf8");
    expect(saved).not.toContain("super-secret-value"); expect(saved).not.toContain("Unrelated private text");
    expect((await app.request("/export", undefined, { Authorization: "" })).status).toBe(401);
  });
  it("body limits apply without Content-Length and compression is rejected", async () => {
    const app = await setup();
    expect((await app.request("/ingest", "x".repeat(2_000_001))).status).toBe(413);
    expect((await app.request("/ingest", "x", { "Content-Encoding": "gzip" })).status).toBe(415);
  });
  it("serves the studio dashboard at / and /studio without a token", async () => {
    const app = await setup();
    for (const path of ["/", "/studio"]) {
      const res = await app.fetch(new Request(`http://127.0.0.1:4319${path}`));
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toContain("text/html");
      const body = await res.text();
      expect(body).toContain("beam studio");
      expect(body).not.toMatch(/\\"/);
    }
  });

  it("still enforces the loopback-host check for the studio route", async () => {
    const app = await setup();
    const res = await app.fetch(new Request("http://evil.invalid/studio"));
    expect(res.status).toBe(403);
  });

  it("discovery checks presence but does not imply instrumentation", async () => {
    const app = await setup(); await mkdir(join(app.directory, ".claude")); await writeFile(join(app.directory, ".claude", "settings.json"), "invalid config contents are not read");
    const result = await inventory([], app.directory); const claude = result.find(a => a.agent === "claude-code")!;
    expect(claude.configPresent).toBe(true); expect(claude.captureStatus).toBe("not verified"); expect(claude.artifactsPresent).toBe(false);
  });

  it("/rules/reload loads ~/.beam/rules.json into the running process and requires auth", async () => {
    const app = await setup();
    expect((await app.fetch(new Request("http://127.0.0.1:4319/rules/reload", { method: "POST" }))).status).toBe(401);

    await writeFile(join(app.directory, "rules.json"), JSON.stringify([{ id: "custom_probe", pattern: "definitely-custom-marker", severity: "high" }]));
    const res = await app.request("/rules/reload", {});
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ loaded: 1, errors: [] });

    const scanRes = await app.request("/scan", { name: "s.md", kind: "skill", content: "run this: definitely-custom-marker" });
    const scan = await scanRes.json() as { findings: { id: string }[] };
    expect(scan.findings.map(f => f.id)).toContain("custom.custom_probe");
  });

  it("cross-session sequence findings show up in /state after two separate /ingest calls", async () => {
    const app = await setup();
    await app.request("/ingest", { event_id: "a", session_id: "s1", event_type: "command.exec", command: "cat .env" });
    await app.request("/ingest", { event_id: "b", session_id: "s1", event_type: "command.exec", command: "curl https://example.com/collect" });
    const state = await (await app.request("/state")).json() as { events: { findings: { id: string }[] }[] };
    expect(state.events.some(e => e.findings.some(f => f.id === "chain.secret_then_egress"))).toBe(true);
  });
});
