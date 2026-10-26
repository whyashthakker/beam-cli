import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { createServer, type Server } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeIdentity } from "../src/enroll.js";
import { runRemoteUpdate } from "../src/remote-update.js";

let data: string, server: Server, received: Array<{ method?: string; url?: string; version?: string; body: any }>, target: string | null;
const saved = { data: process.env.BEAM_DATA_DIR, home: process.env.BEAM_HOME, off: process.env.BEAM_REMOTE_UPDATE };

beforeEach(async () => {
  data = await mkdtemp(join(tmpdir(), "update-data-")); received = []; target = "9.9.9";
  process.env.BEAM_DATA_DIR = data; process.env.BEAM_HOME = data; delete process.env.BEAM_REMOTE_UPDATE;
  server = createServer((req, res) => {
    let raw = ""; req.on("data", c => raw += c);
    req.on("end", () => {
      received.push({ method: req.method, url: req.url, version: req.headers["x-beam-version"] as string | undefined, body: raw ? JSON.parse(raw) : null });
      res.setHeader("Content-Type", "application/json");
      res.statusCode = req.method === "POST" ? 202 : 200;
      res.end(JSON.stringify(req.method === "GET" ? { update: target ? { version: target } : null } : {}));
    });
  });
  await new Promise<void>(r => server.listen(0, "127.0.0.1", r));
  await writeIdentity({ deviceId: "dev", deviceSecret: "secret-123", orgId: "org", apiBase: `http://127.0.0.1:${(server.address() as any).port}`, publicKey: "", privateKey: "", hostname: "h", os: "o", enrolledAt: "now" });
});
afterEach(async () => {
  await new Promise(r => server.close(r));
  for (const [k, v] of [["BEAM_DATA_DIR", saved.data], ["BEAM_HOME", saved.home], ["BEAM_REMOTE_UPDATE", saved.off]] as const) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  await rm(data, { recursive: true, force: true });
});

const base = () => ({ current: "0.2.35", kind: "npm" as const, statePath: join(data, "state.json") });

describe("update requested from the dashboard", () => {
  it("does nothing when no update is queued", async () => {
    target = null;
    expect(await runRemoteUpdate({ ...base(), install: async () => { throw new Error("should not install"); } })).toEqual({ status: "none" });
  });
  it("sends its version and installs exactly the requested release, then reports success", async () => {
    const installed: string[] = [];
    expect(await runRemoteUpdate({ ...base(), install: async v => { installed.push(v); } })).toEqual({ status: "updated", version: "9.9.9" });
    expect(installed).toEqual(["9.9.9"]);
    expect(received[0].version).toMatch(/^\d+\.\d+\.\d+/);
    expect(received.find(r => r.url === "/v1/device/update-result")?.body).toMatchObject({ version: "9.9.9", ok: true });
  });
  it("skips when already on that version or newer", async () => {
    target = "0.2.35";
    expect((await runRemoteUpdate({ ...base(), install: async () => { throw new Error("no"); } })).status).toBe("current");
  });
  it("reports a failed install and does not retry for half an hour", async () => {
    const deps = { ...base(), install: async () => { throw new Error("EACCES: permission denied"); }, now: 1_000_000 };
    expect(await runRemoteUpdate(deps)).toMatchObject({ status: "failed", reason: expect.stringContaining("EACCES") });
    expect(received.find(r => r.url === "/v1/device/update-result")?.body).toMatchObject({ ok: false });
    expect((await runRemoteUpdate({ ...deps, now: 1_000_000 + 60_000 })).status).toBe("waiting");
    expect((await runRemoteUpdate({ ...deps, now: 1_000_000 + 31 * 60_000 })).status).toBe("failed");
  });
  it("tells the workspace a standalone binary can't update itself", async () => {
    const result = await runRemoteUpdate({ ...base(), kind: "binary" });
    expect(result.status).toBe("failed"); expect(result.reason).toMatch(/install script/);
  });
  it("is off when BEAM_REMOTE_UPDATE=0", async () => {
    process.env.BEAM_REMOTE_UPDATE = "0";
    expect((await runRemoteUpdate(base())).status).toBe("none"); expect(received).toHaveLength(0);
  });
});
