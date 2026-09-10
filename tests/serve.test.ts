import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "@jest/globals";
import { startServer } from "../src/serve.js";

const dirs: string[] = [];
const servers: { close: () => void }[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) server.close();
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe("startServer", () => {
  it("boots a real HTTP server, generates a token, and serves /health", async () => {
    const directory = await mkdtemp(join(tmpdir(), "beam-serve-")); dirs.push(directory);
    const result = await startServer({ directory, port: 0, rulesHome: directory, agentHome: directory });
    servers.push(result);
    expect(result.token).toHaveLength(64);
    const res = await fetch(`${result.url}/health`, { headers: { Authorization: `Bearer ${result.token}` } });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ name: "Beam", mode: "observe" });
  });

  it("reuses a persisted token across restarts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "beam-serve-token-")); dirs.push(directory);
    const first = await startServer({ directory, port: 0, rulesHome: directory, agentHome: directory });
    servers.push(first);
    first.close();
    const second = await startServer({ directory, port: 0, rulesHome: directory, agentHome: directory });
    servers.push(second);
    expect(second.token).toBe(first.token);
  });

  it("auto-detects and wires beam's hook into agents present on the machine at start", async () => {
    const directory = await mkdtemp(join(tmpdir(), "beam-serve-agents-")); dirs.push(directory);
    const agentHome = await mkdtemp(join(tmpdir(), "beam-serve-agenthome-")); dirs.push(agentHome);
    // Simulate Codex already being on this machine (its config-presence signal), but never
    // having had beam's hook wired in yet.
    await mkdir(join(agentHome, ".codex"), { recursive: true });
    await writeFile(join(agentHome, ".codex", "config.toml"), "model = \"test\"\n");

    const result = await startServer({ directory, port: 0, rulesHome: directory, agentHome });
    servers.push(result);

    const codex = result.agentInstalls.find(r => r.agent === "codex");
    expect(codex?.status).toBe("installed");
    const hooks = JSON.parse(await readFile(join(agentHome, ".codex", "hooks.json"), "utf8"));
    expect(hooks.hooks.PreToolUse[0].hooks[0].command).toBe("beam hook codex");
  });
});
