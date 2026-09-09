import { mkdtemp, rm } from "node:fs/promises";
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
    const result = await startServer({ directory, port: 0, rulesHome: directory });
    servers.push(result);
    expect(result.token).toHaveLength(64);
    const res = await fetch(`${result.url}/health`, { headers: { Authorization: `Bearer ${result.token}` } });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ name: "Beam", mode: "observe" });
  });

  it("reuses a persisted token across restarts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "beam-serve-token-")); dirs.push(directory);
    const first = await startServer({ directory, port: 0, rulesHome: directory });
    servers.push(first);
    first.close();
    const second = await startServer({ directory, port: 0, rulesHome: directory });
    servers.push(second);
    expect(second.token).toBe(first.token);
  });
});
