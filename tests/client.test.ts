import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { captureHook, importEvents, readToken, scanFile } from "../src/client.js";

const temporaryDirectories: string[] = [];
const originalEnv = { ...process.env };
const originalFetch = global.fetch;

beforeEach(() => {
  process.env = { ...originalEnv };
  delete process.env.BEAM_TOKEN;
  delete process.env.BEAM_DATA_DIR;
  delete process.env.BEAM_HOME;
  delete process.env.BEAM_COLLECTOR_URL;
});

afterEach(async () => {
  global.fetch = originalFetch;
  process.env = { ...originalEnv };
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

async function tempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(dir);
  return dir;
}

describe("readToken", () => {
  it("prefers BEAM_TOKEN when set", async () => {
    process.env.BEAM_TOKEN = "env-token";
    await expect(readToken()).resolves.toBe("env-token");
  });

  it("reads the token file under BEAM_DATA_DIR", async () => {
    const dir = await tempDir("beam-token-");
    await fs.writeFile(path.join(dir, "token"), "file-token\n");
    process.env.BEAM_DATA_DIR = dir;
    await expect(readToken()).resolves.toBe("file-token");
  });

  it("throws a clear message when no token file exists", async () => {
    const dir = await tempDir("beam-missing-");
    process.env.BEAM_DATA_DIR = dir;
    await expect(readToken()).rejects.toThrow("beam start");
  });
});

describe("importEvents", () => {
  it("posts the file contents to /ingest", async () => {
    process.env.BEAM_TOKEN = "t";
    const dir = await tempDir("beam-import-");
    const file = path.join(dir, "events.ndjson");
    await fs.writeFile(file, '{"event_type":"file.read"}\n');
    const fetchMock = jest.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe("http://127.0.0.1:4319/ingest");
      expect((init.headers as Record<string, string>).Authorization).toBe("Bearer t");
      expect(String(init.body)).toContain("file.read");
      return new Response(JSON.stringify({ imported: 1 }), { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await expect(importEvents(file)).resolves.toEqual({ imported: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects files over 2 MB", async () => {
    process.env.BEAM_TOKEN = "t";
    const dir = await tempDir("beam-big-");
    const file = path.join(dir, "events.ndjson");
    await fs.writeFile(file, "x".repeat(2_000_001));
    await expect(importEvents(file)).rejects.toThrow("exceeds 2 MB");
  });

  it("surfaces the collector's rejection message", async () => {
    process.env.BEAM_TOKEN = "t";
    const dir = await tempDir("beam-reject-");
    const file = path.join(dir, "events.ndjson");
    await fs.writeFile(file, "{}");
    global.fetch = (async () => new Response("bad token", { status: 401 })) as unknown as typeof fetch;
    await expect(importEvents(file)).rejects.toThrow("bad token");
  });
});

describe("scanFile", () => {
  it("scans locally by default without contacting the collector", async () => {
    const dir = await tempDir("beam-scan-");
    const file = path.join(dir, "SKILL.md");
    await fs.writeFile(file, "rm -rf /data");
    global.fetch = jest.fn() as unknown as typeof fetch;
    const report = await scanFile(file) as { findings: { id: string }[] };
    expect(report.findings.map(f => f.id)).toContain("destructive.delete");
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("saves the report to the collector when --save is set", async () => {
    process.env.BEAM_TOKEN = "t";
    const dir = await tempDir("beam-scan-save-");
    const file = path.join(dir, "SKILL.md");
    await fs.writeFile(file, "# Safe skill");
    global.fetch = (async () => new Response(JSON.stringify({ saved: true }), { status: 200 })) as unknown as typeof fetch;
    await expect(scanFile(file, { save: true })).resolves.toEqual({ saved: true });
  });
});

describe("captureHook", () => {
  function withStdin(payload: string): void {
    const stream = Readable.from([payload]);
    Object.defineProperty(process, "stdin", { value: stream, configurable: true });
  }

  it("forwards a hook payload and never throws", async () => {
    process.env.BEAM_TOKEN = "t";
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }));
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      expect(body.source_agent).toBe("claude-code");
      expect(body.source_type).toBe("hook");
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await expect(captureHook()).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("maps UserPromptSubmit prompt onto command/event_type/tool_name", async () => {
    process.env.BEAM_TOKEN = "t";
    withStdin(JSON.stringify({ hook_event_name: "UserPromptSubmit", prompt: "help me deploy" }));
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      expect(body.event_type).toBe("prompt.submit");
      expect(body.tool_name).toBe("UserPromptSubmit");
      expect(body.command).toBe("help me deploy");
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("codex");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("logs and resolves instead of throwing when the collector is unreachable", async () => {
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse" }));
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(captureHook()).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});
