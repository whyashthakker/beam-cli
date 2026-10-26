import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { createServer, type Server } from "node:http";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeIdentity } from "../src/enroll.js";
import { indexSkills, readInventory } from "../src/skill-inventory.js";
import { runSkillActions } from "../src/skill-remote.js";

let home: string, data: string, server: Server, received: Array<{ method?: string; url?: string; body: any }>, actions: { remove: Array<{ id: string }>; read: Array<{ id: string }> };
const saved = { data: process.env.BEAM_DATA_DIR, off: process.env.BEAM_SKILL_REMOTE_ACTIONS, api: process.env.BEAM_API_URL };
const exists = (path: string) => access(path).then(() => true, () => false);
async function skill(dir: string, body: string) { await mkdir(dir, { recursive: true }); await writeFile(join(dir, "SKILL.md"), `---\nname: x\n---\n${body}\n`); }

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "remote-home-")); data = await mkdtemp(join(tmpdir(), "remote-data-")); received = []; actions = { remove: [], read: [] };
  process.env.BEAM_DATA_DIR = data; delete process.env.BEAM_SKILL_REMOTE_ACTIONS;
  server = createServer((req, res) => {
    let raw = ""; req.on("data", c => raw += c);
    req.on("end", () => {
      received.push({ method: req.method, url: req.url, body: raw ? JSON.parse(raw) : null });
      res.setHeader("Content-Type", "application/json");
      if (req.method === "GET" && req.url === "/v1/skills/actions") { res.end(JSON.stringify(actions)); return; }
      res.statusCode = 202; res.end("{}");
    });
  });
  await new Promise<void>(r => server.listen(0, "127.0.0.1", r));
  process.env.BEAM_API_URL = `http://127.0.0.1:${(server.address() as any).port}`; // the inventory report goes to the configured collector
  await writeIdentity({ deviceId: "dev", deviceSecret: "secret-123", orgId: "org", apiBase: `http://127.0.0.1:${(server.address() as any).port}`, publicKey: "", privateKey: "", hostname: "h", os: "o", enrolledAt: "now" });
  await skill(join(home, ".claude/skills/keep"), "Summarize the diff.");
  await skill(join(home, ".claude/skills/drop"), "Format the changelog. token=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789");
  await indexSkills({ roots: [join(home, ".claude")] }, home);
});
afterEach(async () => {
  await new Promise(r => server.close(r));
  for (const [k, v] of [["BEAM_DATA_DIR", saved.data], ["BEAM_SKILL_REMOTE_ACTIONS", saved.off], ["BEAM_API_URL", saved.api]] as const) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  await rm(home, { recursive: true, force: true }); await rm(data, { recursive: true, force: true });
});

const idOf = async (dir: string) => (await readInventory())!.skills.find(s => s.dir === dir)!.id!;

describe("skill actions queued in the dashboard", () => {
  it("does nothing when no request is open", async () => {
    expect(await runSkillActions({ home })).toBeNull();
    expect(received.map(r => `${r.method} ${r.url}`)).toEqual(["GET /v1/skills/actions"]);
  });
  it("deletes the requested skill folder, keeps the rest, and reports the new inventory", async () => {
    const drop = join(home, ".claude/skills/drop"), keep = join(home, ".claude/skills/keep");
    actions.remove = [{ id: await idOf(drop) }];
    const result = await runSkillActions({ home });
    expect(result?.skipped).toEqual([]); expect(result?.removed).toEqual([drop]);
    expect(await exists(drop)).toBe(false); expect(await exists(keep)).toBe(true);
    const report = received.find(r => r.url === "/v1/skills/inventory");
    expect(report?.body.skills.map((s: any) => s.name)).toEqual(["keep"]);
  });
  it("ignores an id that is not in this device's inventory", async () => {
    actions.remove = [{ id: "not-a-real-id" }];
    const result = await runSkillActions({ home });
    expect(result?.removed).toEqual([]); expect(result?.skipped[0]?.id).toBe("not-a-real-id");
    expect(received.some(r => r.url === "/v1/skills/inventory")).toBe(false);
  });
  it("refuses to delete a folder that has no SKILL.md", async () => {
    const drop = join(home, ".claude/skills/drop");
    const id = await idOf(drop);
    await rm(join(drop, "SKILL.md"));
    actions.remove = [{ id }];
    const result = await runSkillActions({ home });
    expect(result?.skipped[0]?.reason).toMatch(/no SKILL\.md/); expect(await exists(drop)).toBe(true);
  });
  it("sends SKILL.md with secrets redacted when the dashboard asks to view it", async () => {
    const drop = join(home, ".claude/skills/drop");
    actions.read = [{ id: await idOf(drop) }];
    const result = await runSkillActions({ home });
    expect(result?.sent).toHaveLength(1);
    const post = received.find(r => r.url === "/v1/skills/content")!;
    expect(post.body.content).toContain("Format the changelog.");
    expect(post.body.content).not.toContain("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789");
    expect(post.body.truncated).toBe(false); expect(await exists(drop)).toBe(true);
  });
  it("does nothing when remote actions are turned off", async () => {
    process.env.BEAM_SKILL_REMOTE_ACTIONS = "0";
    actions.remove = [{ id: await idOf(join(home, ".claude/skills/drop")) }];
    expect(await runSkillActions({ home })).toBeNull(); expect(received).toHaveLength(0);
  });
});
