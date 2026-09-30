import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { createServer, type Server } from "node:http";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeIdentity } from "../src/enroll.js";
import { indexSkills, inventoryFile, readInventory } from "../src/skill-inventory.js";
import { CHECK_EVERY_MS, checkSkills, checkSkillsIfDue, skillCheckDue } from "../src/skill-watch.js";

let home: string, data: string, server: Server, received: any[];
const saved = { data: process.env.BEAM_DATA_DIR, api: process.env.BEAM_API_URL };
const names = (report: any) => report.skills.map((s: any) => s.name).sort();

async function skill(dir: string, body = "Summarize the diff.") { await mkdir(dir, { recursive: true }); await writeFile(join(dir, "SKILL.md"), `---\nname: x\n---\n${body}\n`); }

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "watch-home-")); data = await mkdtemp(join(tmpdir(), "watch-data-")); received = [];
  process.env.BEAM_DATA_DIR = data;
  server = createServer((req, res) => { let raw = ""; req.on("data", c => raw += c); req.on("end", () => { received.push(JSON.parse(raw)); res.statusCode = 202; res.end("{}"); }); });
  await new Promise<void>(r => server.listen(0, "127.0.0.1", r));
  process.env.BEAM_API_URL = `http://127.0.0.1:${(server.address() as any).port}`;
  await writeIdentity({ deviceId: "d", deviceSecret: "s", orgId: "o", apiBase: "http://x", publicKey: "", privateKey: "", hostname: "h", os: "o", enrolledAt: "now" });
  await skill(join(home, ".claude/skills/a"));
});
afterEach(async () => {
  await new Promise(r => server.close(r));
  for (const [k, v] of [["BEAM_DATA_DIR", saved.data], ["BEAM_API_URL", saved.api]] as const) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  await rm(home, { recursive: true, force: true }); await rm(data, { recursive: true, force: true });
});

describe("background skill watch", () => {
  it("finds a newly added skill and reports it on its own, with no manual sync", async () => {
    expect((await checkSkills({ home })).sync?.status).toBe("sent");
    expect(names(received[0])).toEqual(["a"]);
    expect((await checkSkills({ home })).sync?.status).toBe("unchanged"); // nothing new: nothing sent

    await skill(join(home, ".claude/skills/brand-new"));
    const result = await checkSkills({ home });
    expect(result.changes.added).toEqual([join(home, ".claude/skills/brand-new")]);
    expect(result.sync?.status).toBe("sent");
    expect(names(received[1])).toEqual(["a", "brand-new"]);
    expect(received).toHaveLength(2);
  });

  it("never starts a whole-home search on its own: project folders stay untouched until you have run one", async () => {
    await skill(join(home, "Desktop/proj/skills/in-project"));
    const result = await checkSkills({ home });
    expect(result.scanned).toBe("agents");
    expect(names(received[0])).toEqual(["a"]); // the Desktop skill was never looked for
    expect((await readInventory())?.lastFullScanAt ?? null).toBeNull();
  });

  it("after you have searched your home folder once, the daily scan repeats that search so project skills are picked up", async () => {
    await indexSkills({}, home); // what `beam skills index` does
    await checkSkills({ home }); // first report
    received.length = 0;
    await skill(join(home, "Desktop/proj/skills/added-later"));
    const result = await checkSkills({ home });
    expect(result.scanned).toBe("full");
    expect(result.changes.added).toEqual([join(home, "Desktop/proj/skills/added-later")]);
    expect(result.sync?.status).toBe("sent");
    expect(names(received[0])).toEqual(["a", "added-later"]);
  });

  it("runs at most once a day: nothing happens until 24 hours after the last scan", async () => {
    // No inventory yet: due, and the check runs.
    expect(await skillCheckDue()).toBe(true);
    expect((await checkSkillsIfDue({ home }))?.sync?.status).toBe("sent");
    received.length = 0;

    // Just scanned: not due, so not even a scan happens (a skill added now waits for the daily run).
    await skill(join(home, ".claude/skills/added-after"));
    expect(await skillCheckDue()).toBe(false);
    expect(await checkSkillsIfDue({ home })).toBeNull();
    expect(received).toHaveLength(0);
    expect(names((await readInventory())!)).not.toContain("added-after");

    // A day later it is due, finds the new skill and reports it.
    const later = Date.now() + CHECK_EVERY_MS + 60_000;
    expect(await skillCheckDue(later)).toBe(true);
    const result = await checkSkillsIfDue({ home, now: later });
    expect(result?.changes.added).toEqual([join(home, ".claude/skills/added-after")]);
    expect(names(received[0])).toEqual(["a", "added-after"]);
  });

  it("a device that isn't enrolled still keeps its local inventory fresh but sends nothing", async () => {
    await rm(join(data, "identity.json"));
    const result = await checkSkills({ home });
    expect(result.sync?.status).toBe("not-enrolled"); expect(received).toHaveLength(0);
    expect(JSON.parse(await readFile(inventoryFile(), "utf8")).skills).toHaveLength(1);
  });
});
