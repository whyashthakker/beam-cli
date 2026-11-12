import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { askApproval, captureHook, extractPreview, extractSave, importEvents, listPendingApprovals, readToken, resolveApproval, scanFile } from "../src/client.js";
import type { ApprovalRequest } from "../src/approvals.js";
import { writeIdentity } from "../src/enroll.js";
import { approvedActionsFile, recordApprovedAction } from "../src/approved-actions.js";

const temporaryDirectories: string[] = [];
const originalEnv = { ...process.env };
const originalFetch = global.fetch;

beforeEach(() => {
  process.env = { ...originalEnv };
  delete process.env.BEAM_TOKEN;
  delete process.env.BEAM_DATA_DIR;
  delete process.env.BEAM_HOME;
  delete process.env.BEAM_COLLECTOR_URL;
  delete process.env.BEAM_API_URL;
});

afterEach(async () => {
  global.fetch = originalFetch;
  process.env = { ...originalEnv };
  // captureHook sets process.exitCode = 2 on a real deny (the documented fail-closed signal for
  // a real short-lived `beam hook` process) -- reset it so a deny exercised in one test doesn't
  // leak into this shared Jest process's own exit code and fail an otherwise-green run.
  process.exitCode = 0;
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

describe("approval requests", () => {
  it("askApproval files a request, polls, and returns once an admin approves it", async () => {
    // No identity.json in this fresh dir, so askApproval takes the local-loopback path tested
    // here rather than the remote-collector path (askRemoteApproval, covered separately below).
    process.env.BEAM_DATA_DIR = await tempDir("beam-approvals-local-1-");
    process.env.BEAM_TOKEN ="fixture-token";
    let listCalls = 0;
    let filed: ApprovalRequest | undefined;
    const fetchMock = jest.fn(async (url: string, init: RequestInit) => {
      if (url === "http://127.0.0.1:4319/approvals" && init.method === "POST") {
        filed = JSON.parse(String(init.body)) as ApprovalRequest;
        expect(filed.status).toBe("PENDING");
        expect(filed.reason).toBe("need to clean a scratch dir");
        return new Response(JSON.stringify(filed), { status: 200 });
      }
      if (url === "http://127.0.0.1:4319/approvals" && !init.method) {
        listCalls += 1;
        const status = listCalls < 2 ? "PENDING" : "APPROVED";
        return new Response(JSON.stringify([{ ...filed, status, decision_reason: status === "APPROVED" ? "fine, it's scoped to tmp" : undefined }]), { status: 200 });
      }
      throw new Error(`unexpected request: ${url}`);
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    const result = await askApproval({ agent: "codex", tool: "Bash", command: "rm -rf /tmp/scratch", reason: "need to clean a scratch dir", pollMs: 1 });
    expect(result.status).toBe("APPROVED");
    expect(result.decision_reason).toBe("fine, it's scoped to tmp");
    expect(listCalls).toBeGreaterThanOrEqual(2);
  });

  it("askApproval reports EXPIRED once the request's own expiry passes, without polling forever", async () => {
    process.env.BEAM_DATA_DIR = await tempDir("beam-approvals-local-2-");
    process.env.BEAM_TOKEN ="fixture-token";
    let filed: ApprovalRequest | undefined;
    const fetchMock = jest.fn(async (url: string, init: RequestInit) => {
      if (init.method === "POST") { filed = JSON.parse(String(init.body)) as ApprovalRequest; return new Response(JSON.stringify(filed), { status: 200 }); }
      return new Response(JSON.stringify([{ ...filed, status: "PENDING", expires_at: new Date(Date.now() - 1).toISOString() }]), { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    const result = await askApproval({ agent: "codex", tool: "Bash", command: "x", reason: "r", pollMs: 1 });
    expect(result.status).toBe("EXPIRED");
  });

  it("listPendingApprovals only returns requests still awaiting a decision", async () => {
    process.env.BEAM_TOKEN = "fixture-token";
    global.fetch = (async () => new Response(JSON.stringify([
      { request_id: "a", status: "PENDING" }, { request_id: "b", status: "APPROVED" },
    ]), { status: 200 })) as unknown as typeof fetch;
    const pending = await listPendingApprovals();
    expect(pending.map(r => r.request_id)).toEqual(["a"]);
  });

  it("resolveApproval posts the decision and reason to /approvals/resolve", async () => {
    process.env.BEAM_TOKEN = "fixture-token";
    const fetchMock = jest.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe("http://127.0.0.1:4319/approvals/resolve");
      expect(JSON.parse(String(init.body))).toEqual({ request_id: "r1", decision: "DENY", approver: "admin", decision_reason: "not authorized for prod" });
      return new Response(JSON.stringify({ request_id: "r1", status: "DENIED", decision_reason: "not authorized for prod" }), { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    const result = await resolveApproval("r1", "DENY", "admin", "not authorized for prod");
    expect(result.status).toBe("DENIED");
  });

  it("askApproval files against the workspace collector, not the local loopback, once the device is enrolled", async () => {
    const dataDir = await tempDir("beam-approvals-remote-");
    process.env.BEAM_DATA_DIR = dataDir;
    process.env.BEAM_API_URL = "https://collector.test";
    await writeIdentity({
      deviceId: "dev_1", deviceSecret: "device-secret-xyz", orgId: "org_1", apiBase: "https://app.test",
      publicKey: "pub", privateKey: "priv", hostname: "host", os: "darwin", enrolledAt: new Date().toISOString(),
    });
    let listCalls = 0;
    const fetchMock = jest.fn(async (url: string, init: RequestInit) => {
      expect((init.headers as Record<string, string>).Authorization).toBe("Bearer device-secret-xyz");
      if (url === "https://collector.test/v1/approvals" && init.method === "POST") {
        const posted = JSON.parse(String(init.body));
        expect(posted.reason).toBe("need to clean a scratch dir");
        return new Response(JSON.stringify({ id: "remote_1", agent: "codex", tool: "Bash", command: "rm -rf /tmp/scratch", path: null, url: null, level: "ADMIN", approver: ["user_1"], riskScore: 50, riskLevel: "MEDIUM", riskFactors: [], reason: "need to clean a scratch dir", status: "PENDING", decision: null, decisionReason: null, expiresAt: new Date(Date.now() + 60_000).toISOString(), createdAt: new Date().toISOString() }), { status: 202 });
      }
      if (url === "https://collector.test/v1/approvals" && !init.method) {
        listCalls += 1;
        const status = listCalls < 2 ? "PENDING" : "APPROVED";
        return new Response(JSON.stringify([{ id: "remote_1", agent: "codex", tool: "Bash", command: "rm -rf /tmp/scratch", path: null, url: null, level: "ADMIN", approver: ["user_1"], riskScore: 50, riskLevel: "MEDIUM", riskFactors: [], reason: "need to clean a scratch dir", status, decision: status === "APPROVED" ? "APPROVE_ONCE" : null, decisionReason: status === "APPROVED" ? "known scratch dir, fine" : null, expiresAt: new Date(Date.now() + 60_000).toISOString(), createdAt: new Date().toISOString() }]), { status: 200 });
      }
      throw new Error(`unexpected request: ${url}`);
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    const result = await askApproval({ agent: "codex", tool: "Bash", command: "rm -rf /tmp/scratch", reason: "need to clean a scratch dir", pollMs: 1 });
    expect(result.request_id).toBe("remote_1");
    expect(result.status).toBe("APPROVED");
    expect(result.decision_reason).toBe("known scratch dir, fine");
    expect(fetchMock).not.toHaveBeenCalledWith("http://127.0.0.1:4319/approvals", expect.anything());
  });

  it("askApproval honors the approver's chosen grant duration for the local retry window", async () => {
    const dataDir = await tempDir("beam-approvals-grant-");
    process.env.BEAM_DATA_DIR = dataDir;
    process.env.BEAM_API_URL = "https://collector.test";
    await writeIdentity({
      deviceId: "dev_1", deviceSecret: "device-secret-xyz", orgId: "org_1", apiBase: "https://app.test",
      publicKey: "pub", privateKey: "priv", hostname: "host", os: "darwin", enrolledAt: new Date().toISOString(),
    });
    const remoteRow = (grantMinutes: number | null) => ({ id: "remote_2", agent: "codex", tool: "Bash", command: "aws --version", path: null, url: null, level: "ADMIN", approver: ["user_1"], riskScore: 10, riskLevel: "LOW", riskFactors: [], reason: "need aws cli", status: "APPROVED", decision: "APPROVE_ONCE", decisionReason: null, grantMinutes, expiresAt: new Date(Date.now() + 60_000).toISOString(), createdAt: new Date().toISOString() });
    global.fetch = (async (url: string, init: RequestInit) => {
      if (init.method === "POST") return new Response(JSON.stringify(remoteRow(40)), { status: 202 });
      return new Response(JSON.stringify([remoteRow(40)]), { status: 200 });
    }) as unknown as typeof fetch;
    const before = Date.now();
    await askApproval({ agent: "codex", tool: "Bash", command: "aws --version", reason: "need aws cli", pollMs: 1 });
    const stored = JSON.parse(await fs.readFile(approvedActionsFile(), "utf8")) as { expiresAt: string }[];
    expect(stored).toHaveLength(1);
    const minutesGranted = (Date.parse(stored[0]!.expiresAt) - before) / 60_000;
    expect(minutesGranted).toBeGreaterThan(39);
    expect(minutesGranted).toBeLessThan(41);
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
    process.env.BEAM_HOME = process.env.BEAM_DATA_DIR;
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

  it("captures redacted prompt text on UserPromptSubmit", async () => {
    process.env.BEAM_TOKEN = "t";
    // Forced deny (via a matching policy) purely so /ingest actually fires here -- an allowed
    // prompt.submit event skips ingest entirely, which would make the assertions below vacuous.
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["UserPromptSubmit"], blockedCommandPatterns: [], disabledAgents: [] } }));
    withStdin(JSON.stringify({ hook_event_name: "UserPromptSubmit", prompt: "help me deploy" }));
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      expect(body.event_type).toBe("prompt.submit");
      expect(body.tool_name).toBe("UserPromptSubmit");
      expect(body.prompt).toBe("help me deploy");
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("codex");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retains prompt session identity for the activity timeline", async () => {
    process.env.BEAM_TOKEN = "t";
    // Forced deny (via a matching policy) purely so /ingest actually fires here -- an allowed
    // prompt.submit event skips ingest entirely, which would make the assertions below vacuous.
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["UserPromptSubmit"], blockedCommandPatterns: [], disabledAgents: [] } }));
    withStdin(JSON.stringify({ hook_event_name: "UserPromptSubmit", prompt: "help me deploy", session_id: "s1" }));
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      expect(body.session_id).toBe("s1");
      expect(body.sessionId).toBeUndefined();
      expect(body.session).toBeUndefined();
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps the session id for non-prompt hook events", async () => {
    process.env.BEAM_TOKEN = "t";
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s1" }));
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      expect(body.session_id).toBe("s1");
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("backfills model from the session transcript for claude-code", async () => {
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-home-");
    await writeJsonl(path.join(home, ".claude", "projects", "p", "s1.jsonl"), [
      { type: "assistant", session_id: "s1", message: { model: "claude-sonnet-5", content: [] } },
    ]);
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s1" }));
    let captured: Record<string, unknown> | undefined;
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captured = JSON.parse(String(init.body));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("claude-code", home);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(captured?.model).toBe("claude-sonnet-5");
  });

  it("leaves model empty when no matching session transcript is found", async () => {
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-nohome-");
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "unknown" }));
    let captured: Record<string, unknown> | undefined;
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captured = JSON.parse(String(init.body));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("claude-code", home);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(captured?.model).toBe("");
  });

  it("backfills model from the rollout file for codex", async () => {
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-codex-home-");
    await writeJsonl(path.join(home, ".codex", "sessions", "rollout-1.jsonl"), [
      { type: "session_meta", payload: { session_id: "thr_1", cwd: "/workspace" } },
      { type: "turn_context", payload: { model: "gpt-5-codex" } },
    ]);
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "thr_1" }));
    let captured: Record<string, unknown> | undefined;
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captured = JSON.parse(String(init.body));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("codex", home);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(captured?.model).toBe("gpt-5-codex");
  });

  it("backfills token usage for codex from the transcript_path the hook payload points at, even when it doesn't match ~/.codex/sessions by mtime", async () => {
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-codex-usage-home-");
    // Deliberately outside the usual sessions/archived_sessions scan roots findCodexUsage()
    // also supports, so this only passes if transcript_path itself is being used.
    const transcriptPath = path.join(home, ".codex", "sessions", "elsewhere", "rollout-x.jsonl");
    await writeJsonl(transcriptPath, [
      { type: "session_meta", payload: { session_id: "thr_2", cwd: "/workspace" } },
      { type: "event_msg", payload: { type: "token_count", info: { total_token_usage: { input_tokens: 111, output_tokens: 22 } } } },
    ]);
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "thr_2", transcript_path: transcriptPath }));
    let captured: Record<string, unknown> | undefined;
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captured = JSON.parse(String(init.body));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("codex", home);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(captured?.input_tokens).toBe(111);
    expect(captured?.output_tokens).toBe(22);
  });

  it("still backfills token usage for codex when the hook payload already includes model", async () => {
    // Codex 0.155.1+ sends `model` as a common field on every hook event (not just when it was
    // previously unset) -- token backfill must not be silently skipped just because model backfill
    // was already unnecessary.
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-codex-model-and-usage-home-");
    const transcriptPath = path.join(home, ".codex", "sessions", "rollout-y.jsonl");
    await writeJsonl(transcriptPath, [
      { type: "session_meta", payload: { session_id: "thr_4", cwd: "/workspace" } },
      { type: "event_msg", payload: { type: "token_count", info: { total_token_usage: { input_tokens: 777, output_tokens: 88 } } } },
    ]);
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "thr_4", model: "gpt-5-codex", transcript_path: transcriptPath }));
    let captured: Record<string, unknown> | undefined;
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captured = JSON.parse(String(init.body));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("codex", home);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(captured?.model).toBe("gpt-5-codex");
    expect(captured?.input_tokens).toBe(777);
    expect(captured?.output_tokens).toBe(88);
  });

  it("ignores a transcript_path outside ~/.codex and falls back to the mtime scan", async () => {
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-codex-usage-fallback-home-");
    await writeJsonl(path.join(home, ".codex", "sessions", "rollout-1.jsonl"), [
      { type: "session_meta", payload: { session_id: "thr_3", cwd: "/workspace" } },
      { type: "event_msg", payload: { type: "token_count", info: { total_token_usage: { input_tokens: 5, output_tokens: 6 } } } },
    ]);
    const outsideHome = await tempDir("beam-outside-codex-home-");
    const maliciousPath = path.join(outsideHome, "not-a-real-transcript.jsonl");
    await writeJsonl(maliciousPath, [
      { type: "session_meta", payload: { session_id: "thr_3" } },
      { type: "event_msg", payload: { type: "token_count", info: { total_token_usage: { input_tokens: 999, output_tokens: 999 } } } },
    ]);
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "thr_3", transcript_path: maliciousPath }));
    let captured: Record<string, unknown> | undefined;
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captured = JSON.parse(String(init.body));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("codex", home);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(captured?.input_tokens).toBe(5);
    expect(captured?.output_tokens).toBe(6);
  });

  it("does not double-count codex tokens when two tool calls fire before the next token_count event is written", async () => {
    // A single Codex turn that makes several tool calls fires PreToolUse once per call; if none
    // of them wait for a fresh token_count event, they'd all read the same total and each
    // separately report it as new usage without the cursor.
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-codex-usage-dedup-home-");
    const transcriptPath = path.join(home, ".codex", "sessions", "rollout-dedup.jsonl");
    await writeJsonl(transcriptPath, [
      { type: "session_meta", payload: { session_id: "thr_5", cwd: "/workspace" } },
      { type: "event_msg", payload: { type: "token_count", info: { total_token_usage: { input_tokens: 100, output_tokens: 40 } } } },
    ]);
    const captures: (Record<string, unknown> | undefined)[] = [];
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captures.push(JSON.parse(String(init.body)));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "thr_5", transcript_path: transcriptPath }));
    await captureHook("codex", home);
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "pwd" }, session_id: "thr_5", transcript_path: transcriptPath }));
    await captureHook("codex", home);

    expect(captures[0]?.input_tokens).toBe(100);
    expect(captures[0]?.output_tokens).toBe(40);
    expect(captures[1]?.input_tokens).toBeUndefined();
    expect(captures[1]?.output_tokens).toBeUndefined();

    // A third tool call after Codex writes the *next* token_count event should report only the
    // new increment, not the full cumulative total again.
    await writeJsonl(transcriptPath, [
      { type: "session_meta", payload: { session_id: "thr_5", cwd: "/workspace" } },
      { type: "event_msg", payload: { type: "token_count", info: { total_token_usage: { input_tokens: 100, output_tokens: 40 } } } },
      { type: "event_msg", payload: { type: "token_count", info: { total_token_usage: { input_tokens: 150, output_tokens: 60 } } } },
    ]);
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "whoami" }, session_id: "thr_5", transcript_path: transcriptPath }));
    await captureHook("codex", home);
    expect(captures[2]?.input_tokens).toBe(50);
    expect(captures[2]?.output_tokens).toBe(20);
  });

  it("does not double-count claude-code tokens when one turn requests two tool calls", async () => {
    // Claude Code logs one JSONL row per streamed content block, so a single assistant turn that
    // requests two tool calls appears as two "assistant" rows sharing one message.id, both
    // carrying that same turn's full usage -- only the hook for the first tool_use block should
    // report it.
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-claude-usage-dedup-home-");
    const usage = { input_tokens: 200, output_tokens: 50 };
    await writeJsonl(path.join(home, ".claude", "projects", "p", "s.jsonl"), [
      { type: "assistant", session_id: "s", cwd: "/repo", timestamp: "2026-01-01T00:00:00.000Z", message: { id: "msg_1", model: "claude-sonnet-5", usage, content: [{ type: "tool_use", id: "call-1", name: "Bash", input: { command: "ls" } }] } },
      { type: "assistant", session_id: "s", cwd: "/repo", timestamp: "2026-01-01T00:00:00.100Z", message: { id: "msg_1", model: "claude-sonnet-5", usage, content: [{ type: "tool_use", id: "call-2", name: "Bash", input: { command: "pwd" } }] } },
    ]);
    const captures: (Record<string, unknown> | undefined)[] = [];
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captures.push(JSON.parse(String(init.body)));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s", tool_use_id: "call-1" }));
    await captureHook("claude-code", home);
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "pwd" }, session_id: "s", tool_use_id: "call-2" }));
    await captureHook("claude-code", home);

    expect(captures[0]?.input_tokens).toBe(200);
    expect(captures[0]?.output_tokens).toBe(50);
    expect(captures[1]?.input_tokens).toBeUndefined();
    expect(captures[1]?.output_tokens).toBeUndefined();
  });

  it("does not overwrite a model the agent's own hook payload already provided", async () => {
    process.env.BEAM_TOKEN = "t";
    const home = await tempDir("beam-hook-cursor-home-");
    withStdin(JSON.stringify({ hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: "ls" }, model: "claude-opus" }));
    let captured: Record<string, unknown> | undefined;
    const fetchMock = jest.fn(async (_url: string, init: RequestInit) => {
      captured = JSON.parse(String(init.body));
      return new Response("{}", { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await captureHook("cursor", home);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(captured?.model).toBe("claude-opus");
  });

  it("queues an event instead of throwing when the collector is unreachable", async () => {
    withStdin(JSON.stringify({ hook_event_name: "PreToolUse" }));
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(captureHook()).resolves.toBeUndefined();
    expect((await fs.readdir(path.join(process.env.BEAM_DATA_DIR!, "hook-spool"))).some(f => f.endsWith(".json"))).toBe(true);
    errorSpy.mockRestore();
  });

  it.each([
    ["cursor", '"permission":"deny"'],
    ["copilot-cli", '"permissionDecision":"deny"'],
    ["gemini", '"decision":"deny"'],
  ])("emits a blocking decision for %s", async (agent, expected) => {
    process.env.BEAM_TOKEN = "t";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash"], blockedCommandPatterns: [], disabledAgents: [] } }));
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "echo blocked" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation((chunk) => { if (typeof chunk === "string") expect(chunk).toContain(expected); return true; });
    await captureHook(agent);
    expect(output).toHaveBeenCalled();
    output.mockRestore();
  });

  it("a workspace-wide Bash block still lets 'beam policy ask' through, but not an ordinary command", async () => {
    process.env.BEAM_TOKEN = "[SECRET_002]";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash"], blockedCommandPatterns: [], disabledAgents: [] } }));
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: 'beam policy ask "rm -rf /tmp/x" "cleanup the task needs"' }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      expect(output.mock.calls.map(([chunk]) => String(chunk)).join("")).not.toContain('"permissionDecision":"deny"');
      expect(process.exitCode).not.toBe(2);
    } finally { output.mockRestore(); }
  });

  it("does not exempt 'beam policy approve'/'reject' -- only an ordinary blocked command would otherwise let an agent self-approve its own request", async () => {
    process.env.BEAM_TOKEN = "[SECRET_002]";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash"], blockedCommandPatterns: [], disabledAgents: [] } }));
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "beam policy approve req_123" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      expect(output.mock.calls.map(([chunk]) => String(chunk)).join("")).toContain('"permissionDecision":"deny"');
    } finally { output.mockRestore(); }
  });

  it("does not exempt a chained command riding along with 'beam policy ask'", async () => {
    process.env.BEAM_TOKEN = "[SECRET_002]";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash"], blockedCommandPatterns: [], disabledAgents: [] } }));
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: 'beam policy ask "x" "y" && rm -rf /tmp' }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      expect(output.mock.calls.map(([chunk]) => String(chunk)).join("")).toContain('"permissionDecision":"deny"');
    } finally { output.mockRestore(); }
  });

  it("a deny for an ordinary blocked command tells the agent how to ask for an exception", async () => {
    process.env.BEAM_TOKEN = "[SECRET_002]";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash"], blockedCommandPatterns: [], disabledAgents: [] } }));
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf /some/dir" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      const written = output.mock.calls.map(([chunk]) => String(chunk)).join("");
      expect(written).toContain('"permissionDecision":"deny"');
      expect(written).toContain("beam policy ask");
      expect(written).toContain("rm -rf /some/dir");
      // Regression: the hint must name the real blocked agent/tool, not generic placeholders --
      // beam policy ask's own --agent/--tool default to "cli"/"Bash" when omitted, which silently
      // mismatches the fingerprint an approval needs to actually grant this agent's retry (see
      // approved-actions.ts). Verified live: the hint used to read without --agent/--tool at all,
      // and an approval filed by following it never unblocked the retry.
      expect(written).toContain('--agent \\"claude-code\\"');
      expect(written).toContain('--tool \\"Bash\\"');
    } finally { output.mockRestore(); }
  });

  it("the hint names the real agent/tool for a different agent and tool too, not just the Bash default", async () => {
    process.env.BEAM_TOKEN = "[SECRET_002]";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [], rules: [{ id: "protected-folder", agent: "codex", eventType: "file.read", path: "/protected/**", action: "BLOCK" }] } }));
    withStdin(JSON.stringify({ tool_name: "exec_command", tool_input: { cmd: "cat /protected/secret.txt" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("codex");
      const written = output.mock.calls.map(([chunk]) => String(chunk)).join("");
      expect(written).toContain('--agent \\"codex\\"');
      expect(written).toContain('--tool \\"exec_command\\"');
    } finally { output.mockRestore(); }
  });

  it("end to end: approving the exact command the hint suggests actually unblocks the retry", async () => {
    process.env.BEAM_TOKEN = "[SECRET_002]";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [], rules: [{ id: "block-aws", tool: "Bash", command: "aws", action: "BLOCK" }] } }));

    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "aws --version" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const denyOutput = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    let hint = "";
    try {
      await captureHook("claude-code");
      hint = denyOutput.mock.calls.map(([chunk]) => String(chunk)).join("");
      expect(hint).toContain('"permissionDecision":"deny"');
    } finally { denyOutput.mockRestore(); }

    // Parse the exact fields the hint told the agent to use, same as a real agent would read
    // them off the deny message, and approve under those exact fields -- not by calling
    // recordApprovedAction() with values a test already knows are correct.
    const agent = /--agent \\"([^"\\]+)\\"/.exec(hint)?.[1];
    const tool = /--tool \\"([^"\\]+)\\"/.exec(hint)?.[1];
    expect(agent).toBe("claude-code");
    expect(tool).toBe("Bash");
    await recordApprovedAction({ agent: agent!, tool: tool!, command: "aws --version" });
    process.exitCode = 0; // reset the deny phase's exit code before checking the retry's own

    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "aws --version" }, session_id: "s1" }));
    const retryOutput = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      expect(retryOutput.mock.calls.map(([chunk]) => String(chunk)).join("")).not.toContain('"permissionDecision":"deny"');
      expect(process.exitCode).not.toBe(2);
    } finally { retryOutput.mockRestore(); }
  });

  it("never adds the 'beam policy ask' hint to Beam's own self-protection deny", async () => {
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf ~/.beam" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      const written = output.mock.calls.map(([chunk]) => String(chunk)).join("");
      expect(written).toContain('"permissionDecision":"deny"');
      expect(written).not.toContain("beam policy ask");
    } finally { output.mockRestore(); }
  });

  it("an action an admin already approved goes through on retry, and only once", async () => {
    process.env.BEAM_TOKEN = "[SECRET_002]";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash"], blockedCommandPatterns: [], disabledAgents: [] } }));
    await recordApprovedAction({ agent: "claude-code", tool: "Bash", command: "rm -rf /tmp/approved-scratch" });
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf /tmp/approved-scratch" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const firstOutput = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      // A plain "allow" for claude-code writes nothing to stdout at all (silence/exit 0 is the
      // host's own implicit allow) -- so the only thing to assert is the absence of a deny.
      const written = firstOutput.mock.calls.map(([chunk]) => String(chunk)).join("");
      expect(written).not.toContain('"permissionDecision":"deny"');
      expect(process.exitCode).not.toBe(2);
    } finally { firstOutput.mockRestore(); }

    // Single-use: the identical command, asked again, is denied like normal -- the earlier
    // approval was already consumed.
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf /tmp/approved-scratch" }, session_id: "s1" }));
    const secondOutput = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      expect(secondOutput.mock.calls.map(([chunk]) => String(chunk)).join("")).toContain('"permissionDecision":"deny"');
    } finally { secondOutput.mockRestore(); }
  });

  it("an approved action does not grant a different, unapproved command", async () => {
    process.env.BEAM_TOKEN = "[SECRET_002]";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash"], blockedCommandPatterns: [], disabledAgents: [] } }));
    await recordApprovedAction({ agent: "claude-code", tool: "Bash", command: "rm -rf /tmp/approved-scratch" });
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf /tmp/some-other-dir" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      expect(output.mock.calls.map(([chunk]) => String(chunk)).join("")).toContain('"permissionDecision":"deny"');
    } finally { output.mockRestore(); }
  });

  it("never grants an approved action over Beam's own self-protection", async () => {
    await recordApprovedAction({ agent: "claude-code", tool: "Bash", command: "rm -rf ~/.beam" });
    withStdin(JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf ~/.beam" }, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook("claude-code");
      expect(output.mock.calls.map(([chunk]) => String(chunk)).join("")).toContain('"permissionDecision":"deny"');
    } finally { output.mockRestore(); }
  });

  it.each([
    ["claude-code", "Bash", { command: "cat ../protected/note.txt" }, '"permissionDecision":"deny"'],
    ["codex", "exec_command", { cmd: "cat ../protected/note.txt" }, '"permissionDecision":"deny"'],
    ["cursor", "read_file", { target_file: "../protected/note.txt" }, '"permission":"deny"'],
    ["gemini", "read_file", { file_path: "../protected/note.txt" }, '"decision":"deny"'],
  ])("enforces an agent-scoped folder policy through the %s hook", async (agent, tool, input, expected) => {
    process.env.BEAM_TOKEN = "t";
    const directory = await tempDir("beam-folder-hook-");
    const protectedPath = path.join(directory, "protected");
    await fs.mkdir(protectedPath);
    const cwd = path.join(directory, "outside");
    await fs.mkdir(cwd);
    await fs.writeFile(path.join(process.env.BEAM_DATA_DIR!, "policy.json"), JSON.stringify({ version: 1, rules: {
      mode: "enforce", blockedTools: [], disabledAgents: [], blockedCommandPatterns: [],
      rules: [{ id: "protected-folder", agent, eventType: "file.read", path: `${protectedPath}/**`, action: "BLOCK", reason: "Protected folder" }],
    } }));
    withStdin(JSON.stringify({ tool_name: tool, tool_input: input, cwd, session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await captureHook(agent);
      expect(output.mock.calls.map(([chunk]) => String(chunk)).join("")).toContain(expected);
      expect(process.exitCode).toBe(2);
    } finally { output.mockRestore(); }
  });

  it.each([
    ["claude-code", "UserPromptSubmit", '"hookEventName":"UserPromptSubmit"'],
    ["codex", "UserPromptSubmit", '"hookEventName":"UserPromptSubmit"'],
  ])("blocks a disabled %s agent at its prompt-submit hook, not just at tool-call time", async (agent, hookEventName, expected) => {
    process.env.BEAM_TOKEN = "t";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [agent] } }));
    withStdin(JSON.stringify({ hook_event_name: hookEventName, prompt: "do something", session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      if (typeof chunk === "string") { expect(chunk).toContain('"permissionDecision":"deny"'); expect(chunk).toContain(expected); }
      return true;
    });
    await captureHook(agent);
    expect(output).toHaveBeenCalled();
    output.mockRestore();
  });

  it("blocks a disabled cursor agent at beforeSubmitPrompt using the continue/user_message contract", async () => {
    process.env.BEAM_TOKEN = "t";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: ["cursor"] } }));
    withStdin(JSON.stringify({ hook_event_name: "beforeSubmitPrompt", prompt: "do something", session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      if (typeof chunk === "string") {
        expect(chunk).toContain('"continue":false');
        expect(chunk).not.toContain('"permission"');
      }
      return true;
    });
    await captureHook("cursor");
    expect(output).toHaveBeenCalled();
    output.mockRestore();
  });

  it("blocks a disabled gemini agent at BeforeAgent with {decision:deny} and exit code 2", async () => {
    process.env.BEAM_TOKEN = "t";
    const policyDir = process.env.BEAM_DATA_DIR!;
    await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: ["gemini"] } }));
    withStdin(JSON.stringify({ hook_event_name: "BeforeAgent", prompt: "do something", session_id: "s1" }));
    global.fetch = jest.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const output = jest.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      if (typeof chunk === "string") expect(chunk).toContain('"decision":"deny"');
      return true;
    });
    await captureHook("gemini");
    expect(output).toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    output.mockRestore();
  });

  describe("PostToolUse output redaction", () => {
    it("redacts a real secret a command's output exposed, and rewrites it via updatedToolOutput for claude-code", async () => {
      withStdin(JSON.stringify({
        hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "cat .env" },
        tool_response: { stdout: "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstu\nPORT=3000\n", stderr: "", interrupted: false },
      }));
      const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
      await captureHook("claude-code");
      expect(output).toHaveBeenCalledTimes(1);
      const written = JSON.parse(String(output.mock.calls[0]![0]));
      expect(written.hookSpecificOutput.hookEventName).toBe("PostToolUse");
      expect(written.hookSpecificOutput.updatedToolOutput.stdout).not.toContain("ghp_abcdefghijklmnopqrstu");
      expect(written.hookSpecificOutput.updatedToolOutput.stdout).toContain("PORT=3000"); // ordinary vars pass through untouched
      output.mockRestore();
    });

    describe("user-facing notices (systemMessage)", () => {
      const run = async (agent: string, payload: Record<string, unknown>) => {
        withStdin(JSON.stringify(payload));
        const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
        await captureHook(agent);
        const writes = output.mock.calls.map(c => String(c[0]));
        output.mockRestore();
        return writes;
      };

      it("tells the user what was redacted in a tool's output, in the same JSON as the rewrite, with kinds and counts but no real values", async () => {
        const writes = await run("claude-code", {
          hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "cat customers.txt" },
          tool_response: { stdout: "ssn 123-45-6789 card 4111 1111 1111 1111\n", stderr: "", interrupted: false },
        });
        expect(writes).toHaveLength(1); // a hook must emit exactly one JSON object
        const out = JSON.parse(writes[0]!);
        expect(out.systemMessage).toMatch(/^Beam: redacted 2 values \(1× CREDIT_CARD, 1× SSN\) in this tool's output/);
        expect(out.systemMessage).not.toContain("123-45-6789");
        expect(out.systemMessage).not.toContain("4111");
        expect(out.hookSpecificOutput.updatedToolOutput.stdout).not.toContain("123-45-6789");
      });

      it("warns that a typed prompt containing PII was sent unredacted, without blocking it (piiPrompt=warn)", async () => {
        process.env.BEAM_PII_PROMPT = "warn";
        const writes = await run("claude-code", { hook_event_name: "UserPromptSubmit", prompt: "my ssn is 123-45-6789, summarise", session_id: "s1" });
        expect(writes).toHaveLength(1);
        const out = JSON.parse(writes[0]!);
        expect(out.systemMessage).toMatch(/your prompt contains 1 value \(1× SSN\)/);
        expect(out.systemMessage).toContain("sent to the model as typed");
        expect(out.hookSpecificOutput?.permissionDecision).not.toBe("deny");
        expect(out.decision).toBeUndefined();
        delete process.env.BEAM_PII_PROMPT;
      });

      it("says nothing for a clean prompt and a clean action", async () => {
        expect(await run("claude-code", { hook_event_name: "UserPromptSubmit", prompt: "refactor the parser", session_id: "s1" })).toEqual([]);
        expect(await run("claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s1" })).toEqual([]);
      });

      it("notes that sensitive values in an allowed action are redacted from Beam's activity log", async () => {
        const writes = await run("claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "echo 123-45-6789" }, session_id: "s1" });
        expect(writes).toHaveLength(1);
        expect(JSON.parse(writes[0]!).systemMessage).toMatch(/1 value \(1× SSN\) in this action will be redacted from Beam's activity log/);
      });

      it("falls back to stderr for agents without a verified systemMessage field", async () => {
        process.env.BEAM_PII_PROMPT = "warn";
        withStdin(JSON.stringify({ hook_event_name: "beforeSubmitPrompt", prompt: "my ssn is 123-45-6789", session_id: "s1" }));
        const stdout = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
        const stderr = jest.spyOn(process.stderr, "write").mockImplementation(() => true);
        await captureHook("cursor");
        const err = stderr.mock.calls.map(c => String(c[0])).join("");
        stdout.mockRestore(); stderr.mockRestore();
        delete process.env.BEAM_PII_PROMPT;
        expect(err).toContain("your prompt contains 1 value (1× SSN)");
      });
    });

    it("does not touch output that already uses the credential-reference convention", async () => {
      withStdin(JSON.stringify({
        hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "cat .env" },
        tool_response: { stdout: "STRIPE_SECRET_KEY=op://vault/stripe/credential\n", stderr: "", interrupted: false },
      }));
      const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
      await captureHook("claude-code");
      expect(output).not.toHaveBeenCalled(); // nothing changed -- no JSON written at all
      output.mockRestore();
    });

    it("writes nothing for a PostToolUse call with no secret in its output (no-op, not a block)", async () => {
      withStdin(JSON.stringify({
        hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "ls" },
        tool_response: { stdout: "README.md\npackage.json\n", stderr: "", interrupted: false },
      }));
      const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
      await captureHook("claude-code");
      expect(output).not.toHaveBeenCalled();
      output.mockRestore();
    });

    it("never rewrites output for agents other than claude-code (unverified updatedToolOutput support)", async () => {
      withStdin(JSON.stringify({
        hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "cat .env" },
        tool_response: { stdout: "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstu\n", stderr: "", interrupted: false },
      }));
      const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
      await captureHook("codex");
      expect(output).not.toHaveBeenCalled();
      output.mockRestore();
    });

    it("captures a completed PostToolUse action without applying pre-action policy", async () => {
      process.env.BEAM_TOKEN = "t";
      const policyDir = process.env.BEAM_DATA_DIR!;
      // A policy that would BLOCK this exact command at PreToolUse must have no effect here --
      // the command already ran; PostToolUse can only redact what's shown, never block.
      await fs.writeFile(path.join(policyDir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash"], blockedCommandPatterns: [], disabledAgents: [] } }));
      withStdin(JSON.stringify({
        hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "cat .env" },
        tool_response: { stdout: "ready\n", stderr: "", interrupted: false },
      }));
      const fetchMock = jest.fn(async () => new Response("{}", { status: 200 }));
      global.fetch = fetchMock as unknown as typeof fetch;
      const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
      await captureHook("claude-code");
      expect(output).not.toHaveBeenCalled(); // nothing to redact, and no block JSON either
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(process.exitCode).not.toBe(2);
      output.mockRestore();
    });
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
