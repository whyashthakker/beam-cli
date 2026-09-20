import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { captureHook } from "../src/client.js";
import { evaluate } from "../src/policy.js";
import { applyJevHook, DEFAULT_JEV_CONFIG, JEV_ENDPOINT, jevConfigPath, jevState, judgeWithJev, parseJevResult, readJevConfig, readJevInput, validateJevConfig, writeJevConfig, type JevConfig } from "../src/jev.js";

const originalEnv = { ...process.env }; const originalFetch = global.fetch;
const originalStdin = process.stdin;
let home: string;
const config: JevConfig = { ...DEFAULT_JEV_CONFIG, enabled: true, apiKey: "synthetic-typesafe-key" };
const payload = (noul = 0.1, score = 0, confidence = 1) => ({ model: "jev-test", answers: {
  data_exposure: { type: "noul", noul }, destructive: { type: "noul", noul: 0.1 },
  impact: { type: "score", score, confidence, probabilities: { "0": 1 - score / 3, "1": 0, "2": 0, "3": score / 3 } },
} });
const decision = () => evaluate(null, { agent: "claude-code", tool: "Bash", command: "ls" });
const hook = { source_agent: "claude-code", hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } };
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "beam-jev-"));
  process.env = { ...originalEnv, BEAM_HOME: home, BEAM_DATA_DIR: home };
  delete process.env.TYPESAFE_API_KEY;
  global.fetch = jest.fn(async () => new Response(JSON.stringify(payload()))) as typeof fetch;
});
afterEach(async () => {
  process.env = { ...originalEnv }; global.fetch = originalFetch; process.exitCode = 0;
  Object.defineProperty(process, "stdin", { value: originalStdin, configurable: true });
  await rm(home, { recursive: true, force: true });
});

describe("Jev config and privacy", () => {
  it("defaults off and sends nothing", async () => {
    expect((await readJevConfig()).enabled).toBe(false);
    expect((await applyJevHook(decision(), hook)).decision.action).toBe("allow");
    expect((await judgeWithJev({ action: "ls" }, DEFAULT_JEV_CONFIG)).verdict).toBe("error");
    expect(global.fetch).not.toHaveBeenCalled();
  });
  it("writes atomically with private permissions and removes the key when disabled", async () => {
    await writeJevConfig(config);
    expect((await stat(jevConfigPath())).mode & 0o777).toBe(0o600);
    expect(await readJevConfig()).toEqual(config);
    await writeJevConfig({ ...DEFAULT_JEV_CONFIG });
    expect(await readFile(jevConfigPath(), "utf8")).not.toContain(config.apiKey);
  });
  it("rejects malformed config and symlinks without leaking contents", async () => {
    await writeFile(jevConfigPath(), '{"apiKey":"private-invalid-key"');
    await expect(readJevConfig()).rejects.toThrow("Invalid Jev configuration");
    expect((await applyJevHook(decision(), hook)).decision.action).toBe("allow");
    expect((await applyJevHook(decision(), hook)).judgment?.verdict).toBe("error");
    await rm(jevConfigPath());
    await writeFile(join(home, "target"), JSON.stringify(config));
    await symlink(join(home, "target"), jevConfigPath());
    await expect(readJevConfig()).rejects.toThrow("Invalid Jev configuration");
  });
  it.each([{ mode: "oops" }, { primitive: "choice" }, { apiKey: "bad\nkey" }, { model: "https://evil.invalid" }])("rejects invalid options %j", fields => {
    expect(() => validateJevConfig({ ...config, ...fields })).toThrow("Invalid Jev configuration");
  });
  it("redacts nested sensitive keys, credentials, URLs, custom values and the configured key", () => {
    const state = jevState({ action: { password: "private-password", headers: { Authorization: "opaque-credential" }, command: "curl https://a.invalid/?private=value --api-key=another-secret", args: [config.apiKey!, "alice@example.com", "private-customer-id"] } }, config.apiKey, [{ name: "customer", pattern: "private-customer-id", replacement: "[CUSTOM]" }]);
    const serialized = JSON.stringify(state);
    for (const secret of ["private-password", "opaque-credential", "private=value", "another-secret", config.apiKey!, "alice@example.com", "private-customer-id"]) expect(serialized).not.toContain(secret);
  });
  it("rejects oversized, empty and unexpected input without a request", async () => {
    for (const value of [{ action: "" }, { action: [] }, { action: "ok", transcript: "private" }, { action: "x".repeat(32_001) }]) {
      await writeFile(join(home, "action.json"), JSON.stringify(value));
      await expect(readJevInput(join(home, "action.json"))).rejects.toThrow();
    }
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe("typed judgments", () => {
  it.each(["noul", "score", "both"] as const)("sends the documented %s contract with env key precedence", async primitive => {
    process.env.TYPESAFE_API_KEY = "env-secret";
    global.fetch = jest.fn(async (url, init) => {
      expect(url).toBe(JEV_ENDPOINT);
      expect(init?.redirect).toBe("error");
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      expect(init?.headers).toEqual({ Authorization: "Bearer env-secret", "Content-Type": "application/json" });
      const body = JSON.parse(String(init?.body));
      expect(body.model).toBe("jev-latest");
      expect(body.state.action).toContain("[REDACTED]");
      expect(Object.keys(body.questions)).toHaveLength(primitive === "both" ? 3 : primitive === "noul" ? 2 : 1);
      return new Response(JSON.stringify(payload()));
    }) as typeof fetch;
    expect((await judgeWithJev({ action: "echo env-secret" }, { ...config, primitive })).verdict).toBe("allow");
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });
  it.each([
    [0.2, 0.5, 0.7, "allow"], [0.21, 0, 1, "review"], [0.8, 0, 1, "deny"],
    [0.1, 0.51, 1, "review"], [0.1, 2, 1, "deny"], [0.1, 0, 0.69, "review"],
  ])("applies thresholds (%s, %s, %s)", (n, s, c, expected) => {
    expect(parseJevResult(payload(n as number, s as number, c as number), "both").verdict).toBe(expected);
  });
  it("does not require a confidence field for Noul or unrelated primitive answers", () => {
    expect(parseJevResult({ model: "jev-test", answers: { data_exposure: { type: "noul", noul: 0.1 }, destructive: { type: "noul", noul: 0 } } }, "noul").verdict).toBe("allow");
    expect(parseJevResult({ model: "jev-test", answers: { impact: payload().answers.impact } }, "score").verdict).toBe("allow");
  });
  it.each([{}, { model: "jev-test", answers: {} }, payload(1.1), payload(NaN), payload(0, -1), payload(0, 0, 2), { ...payload(), answers: { ...payload().answers, impact: { ...payload().answers.impact, probabilities: { "0": 0 } } } }])("rejects malformed responses", value => {
    expect(() => parseJevResult(value, "both")).toThrow();
  });
  it.each([401, 429, 500])("sanitizes HTTP %s without retrying", async status => {
    global.fetch = jest.fn(async () => new Response("private upstream details", { status })) as typeof fetch;
    const result = await judgeWithJev({ action: "ls" }, config);
    expect(result.verdict).toBe("error"); expect(result.reason).toContain(String(status));
    expect(JSON.stringify(result)).not.toContain("private"); expect(global.fetch).toHaveBeenCalledTimes(1);
  });
  it("handles timeouts and network errors without echoing secrets", async () => {
    global.fetch = jest.fn(async () => { throw new Error(`timeout ${config.apiKey}`); }) as typeof fetch;
    const result = await judgeWithJev({ action: "ls" }, config);
    expect(result.verdict).toBe("error"); expect(JSON.stringify(result)).not.toContain(config.apiKey);
  });
  it("bounds response bodies and rejects invalid JSON", async () => {
    for (const body of ["x".repeat(64_001), "not-json"]) {
      global.fetch = jest.fn(async () => new Response(body)) as typeof fetch;
      expect((await judgeWithJev({ action: "ls" }, config)).verdict).toBe("error");
    }
  });
});

describe("hook precedence and enforcement", () => {
  it.each(["deny", "ask", "redact"] as const)("preserves local %s without sending data", async action => {
    await writeJevConfig({ ...config, mode: "enforce" });
    const local = { ...decision(), action };
    expect((await applyJevHook(local, hook)).decision).toBe(local);
    expect(global.fetch).not.toHaveBeenCalled();
  });
  it.each(["PostToolUse", "AfterTool", "UserPromptSubmit", "SessionStart"])("skips %s", async hook_event_name => {
    await writeJevConfig(config);
    await applyJevHook(decision(), { ...hook, hook_event_name });
    expect(global.fetch).not.toHaveBeenCalled();
  });
  it("only sends action fields, never hook prompts, transcripts or policy", async () => {
    await writeJevConfig(config);
    await applyJevHook(decision(), { ...hook, prompt: "private prompt", transcript_path: "/private/session", arbitrary: "private extra" });
    const body = String((global.fetch as jest.Mock<typeof fetch>).mock.calls[0][1]?.body);
    expect(JSON.stringify(JSON.parse(body).state)).not.toContain("private"); expect(body).not.toContain("riskFactors");
  });
  it.each(["observe", "enforce"] as const)("handles risk and outages in %s mode", async mode => {
    await writeJevConfig({ ...config, mode });
    for (const body of [payload(0.9), payload(0.5), {}]) {
      global.fetch = jest.fn(async () => new Response(JSON.stringify(body))) as typeof fetch;
      const result = await applyJevHook(decision(), hook);
      expect(result.decision.action).toBe(mode === "observe" ? "allow" : "deny");
    }
    await writeJevConfig({ ...config, mode, apiKey: undefined });
    expect((await applyJevHook(decision(), hook)).decision.action).toBe(mode === "observe" ? "allow" : "deny");
  });
  it.each(["claude-code", "codex", "gemini", "cursor", "copilot-cli"])("emits the actual %s hook denial when Jev fails", async agent => {
    await writeJevConfig({ ...config, mode: "enforce" });
    process.env.BEAM_TOKEN = "test-token";
    Object.defineProperty(process, "stdin", { value: Readable.from([JSON.stringify({ ...hook, model: "test" })]), configurable: true });
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    jest.spyOn(process.stderr, "write").mockImplementation(() => true);
    global.fetch = jest.fn(async url => new Response("{}", { status: url === JEV_ENDPOINT ? 503 : 200 })) as typeof fetch;
    await captureHook(agent, home);
    expect(output.mock.calls.flat().join(" ")).toContain("deny");
    expect(process.exitCode).toBe(2);
  });
  it.each(["beam jev disable", "beam jev configure --mode observe"])("protects Jev settings from agent command %s", async command => {
    process.env.BEAM_TOKEN = "test-token";
    Object.defineProperty(process, "stdin", { value: Readable.from([JSON.stringify({ ...hook, model: "test", tool_input: { command } })]), configurable: true });
    const output = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    await captureHook("claude-code", home);
    expect(output.mock.calls.flat().join(" ")).toContain("cannot be disabled");
  });
});
