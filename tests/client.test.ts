import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { captureHook, extractPreview, extractSave, importEvents, readToken, scanFile } from "../src/client.js";

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

describe("scanFile custom rules", () => {
  it("loads a custom rule from the given beamHome and applies it during an offline scan", async () => {
    const beamHome = await tempDir("beam-scan-rules-");
    await fs.writeFile(path.join(beamHome, "rules.json"), JSON.stringify([{ id: "probe", pattern: "definitely-custom", severity: "high" }]));
    const dir = await tempDir("beam-scan-file-");
    const file = path.join(dir, "SKILL.md");
    await fs.writeFile(file, "run definitely-custom now");
    const report = await scanFile(file, {}, beamHome) as { findings: { id: string }[] };
    expect(report.findings.map(f => f.id)).toContain("custom.probe");
  });

  it("regression: a beamHome pointing at a directory with no rules.json loads zero custom rules, not the real machine's", async () => {
    const beamHome = await tempDir("beam-scan-empty-rules-");
    const dir = await tempDir("beam-scan-file2-");
    const file = path.join(dir, "SKILL.md");
    await fs.writeFile(file, "definitely-custom marker with no rule defined for it");
    const report = await scanFile(file, {}, beamHome) as { findings: { id: string }[] };
    expect(report.findings.map(f => f.id)).not.toContain("custom.probe");
  });
});

describe("scanFile", () => {
  it("scans locally by default without contacting the collector", async () => {
    const dir = await tempDir("beam-scan-");
    const file = path.join(dir, "SKILL.md");
    await fs.writeFile(file, "rm -rf /data");
    global.fetch = jest.fn() as unknown as typeof fetch;
    const report = await scanFile(file, {}, dir) as { findings: { id: string }[] };
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
  // Isolate the data dir so no real ~/.beam/identity.json or policy.json leaks in
  // and triggers workspace forwarding / enforcement during these unit tests.
  beforeEach(async () => {
    process.env.BEAM_DATA_DIR = await tempDir("beam-hook-");
  });

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

async function writeJsonl(filePath: string, rows: unknown[]): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, rows.map(r => JSON.stringify(r)).join("\n") + "\n");
}

describe("extractPreview", () => {
  it("normalizes locally and never contacts the collector", async () => {
    const home = await tempDir("beam-extract-preview-");
    await writeJsonl(path.join(home, ".claude", "projects", "p", "s.jsonl"), [
      { type: "assistant", session_id: "s1", cwd: "/repo", timestamp: "2026-01-01T00:00:00.000Z", message: { content: [{ type: "tool_use", id: "t1", name: "Bash", input: { command: "echo API_KEY=super-secret-value" } }] } },
    ]);
    global.fetch = jest.fn() as unknown as typeof fetch;
    const result = await extractPreview("claude-code", 200, home, home);
    expect(result.found).toBe(1);
    expect(global.fetch).not.toHaveBeenCalled();
    // normalize() redacts before this ever reaches the caller, even in preview mode.
    expect(JSON.stringify(result.events)).not.toContain("super-secret-value");
  });

  it("applies a custom rule loaded from the separate beamHome argument, not the extraction home", async () => {
    const home = await tempDir("beam-extract-home-");
    const beamHome = await tempDir("beam-extract-beamhome-");
    await fs.writeFile(path.join(beamHome, "rules.json"), JSON.stringify([{ id: "probe", pattern: "definitely-custom", severity: "high" }]));
    await writeJsonl(path.join(home, ".claude", "projects", "p", "s.jsonl"), [
      { type: "assistant", session_id: "s1", cwd: "/repo", timestamp: "2026-01-01T00:00:00.000Z", message: { content: [{ type: "tool_use", id: "t1", name: "Bash", input: { command: "run definitely-custom now" } }] } },
    ]);
    const result = await extractPreview("claude-code", 200, home, beamHome);
    expect(result.events[0].findings.map(f => f.id)).toContain("custom.probe");
  });

  it("caps the preview at the given limit while still reporting the true total found", async () => {
    const home = await tempDir("beam-extract-limit-");
    const rows = Array.from({ length: 5 }, (_, i) => ({ type: "assistant", session_id: "s", cwd: "/repo", timestamp: "2026-01-01T00:00:00.000Z", message: { content: [{ type: "tool_use", id: `t${i}`, name: "Bash", input: { command: "ls" } }] } }));
    await writeJsonl(path.join(home, ".claude", "projects", "p", "s.jsonl"), rows);
    const result = await extractPreview("claude-code", 2, home, home);
    expect(result.found).toBe(5);
    expect(result.previewed).toBe(2);
    expect(result.events).toHaveLength(2);
  });
});

describe("extractSave", () => {
  it("batches sends of more than 2000 records so the collector's per-request cap is never hit", async () => {
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-extract-batch-");
    const rows = Array.from({ length: 4500 }, (_, i) => ({ type: "assistant", session_id: "s", cwd: "/repo", timestamp: "2026-01-01T00:00:00.000Z", message: { content: [{ type: "tool_use", id: `t${i}`, name: "Bash", input: { command: "ls" } }] } }));
    await writeJsonl(path.join(home, ".claude", "projects", "p", "s.jsonl"), rows);
    const batchSizes: number[] = [];
    global.fetch = (async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      batchSizes.push(body.length);
      return new Response(JSON.stringify({ accepted: body.length, duplicates: 0, skipped: 0 }), { status: 200 });
    }) as unknown as typeof fetch;
    const result = await extractSave("claude-code", home);
    expect(batchSizes).toEqual([2000, 2000, 500]);
    expect(result).toEqual({ found: 4500, accepted: 4500, duplicates: 0, skipped: 0 });
  });

  it("reports zero found without making any request when there is nothing to extract", async () => {
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-extract-empty-");
    global.fetch = jest.fn() as unknown as typeof fetch;
    const result = await extractSave("claude-code", home);
    expect(result).toEqual({ found: 0, accepted: 0, duplicates: 0, skipped: 0 });
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
