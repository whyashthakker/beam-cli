import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { captureHook } from "../src/client.js";
import { maskVaulted, redactAndVault, resolvePlaceholders, takeUnreportedLedger } from "../src/pii-vault.js";

const dirs: string[] = [];
let home: string;
beforeEach(async () => {
  home = await fs.mkdtemp(path.join(os.tmpdir(), "beam-vault-"));
  dirs.push(home);
  process.env.BEAM_DATA_DIR = home;
  process.env.BEAM_HOME = home;
  delete process.env.BEAM_PII_PROMPT;
  process.exitCode = 0;
});
afterEach(async () => {
  process.exitCode = 0;
  await Promise.all(dirs.splice(0).map(d => fs.rm(d, { recursive: true, force: true })));
});

const CARD = "4111 1111 1111 1111";
const SSN = "123-45-6789";

describe("vault primitives", () => {
  it("stores values encrypted: the vault file never contains the plaintext", async () => {
    await redactAndVault(`card ${CARD} ssn ${SSN}`, "s1", [], home);
    const raw = await fs.readFile(path.join(home, "vault.json"), "utf8");
    expect(raw).not.toContain("4111");
    expect(raw).not.toContain("6789");
    const mode = (await fs.stat(path.join(home, "vault.json"))).mode & 0o777;
    expect(mode).toBe(0o600);
    expect((await fs.stat(path.join(home, "vault.key"))).mode & 0o777).toBe(0o600);
  });

  it("resolves a placeholder back to the real value, only within the same session", async () => {
    const redacted = await redactAndVault(`card ${CARD}`, "s1", [], home);
    expect(redacted.text).toBe("card [CREDIT_CARD_001]");
    expect((await resolvePlaceholders('echo "[CREDIT_CARD_001]"', "s1", home)).text).toBe(`echo "${CARD}"`);
    expect((await resolvePlaceholders('echo "[CREDIT_CARD_001]"', "other-session", home)).text).toBe('echo "[CREDIT_CARD_001]"');
    expect((await resolvePlaceholders("echo [SSN_099]", "s1", home)).ids).toEqual([]); // unknown id left alone
  });

  it("masks vaulted values, and common encodings of them, back to placeholders", async () => {
    await redactAndVault(`card ${CARD}`, "s1", [], home);
    const b64 = Buffer.from(CARD).toString("base64");
    const out = await maskVaulted(`plain ${CARD} compact 4111111111111111 b64 ${b64} hex ${Buffer.from(CARD).toString("hex")}`, "s1", home);
    expect(out.text).toBe("plain [CREDIT_CARD_001] compact [CREDIT_CARD_001] b64 [CREDIT_CARD_001] hex [CREDIT_CARD_001]");
  });
});

describe("governance chain through the hooks", () => {
  function run(agent: string, payload: Record<string, unknown>) {
    Object.defineProperty(process, "stdin", { value: Readable.from([JSON.stringify(payload)]), configurable: true });
    const out = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    const err = jest.spyOn(process.stderr, "write").mockImplementation(() => true);
    return captureHook(agent).then(() => {
      const stdout = out.mock.calls.map(c => String(c[0]));
      const stderr = err.mock.calls.map(c => String(c[0])).join("");
      out.mockRestore(); err.mockRestore();
      return { stdout, stderr };
    });
  }

  it("blocks a prompt holding a card, vaults it, and tells the user the placeholder text to resend", async () => {
    const { stdout } = await run("claude-code", { hook_event_name: "UserPromptSubmit", prompt: `use my card ${CARD} to test`, session_id: "s1" });
    expect(stdout).toHaveLength(1);
    const out = JSON.parse(stdout[0]!);
    expect(out.decision).toBe("block");
    expect(out.reason).toContain("use my card [CREDIT_CARD_001] to test");
    expect(out.reason).toContain("1× CREDIT_CARD");
    expect(out.suppressOriginalPrompt).toBe(true); // keeps "Original prompt: <real value>" out of the transcript
    expect(JSON.stringify(out)).not.toContain("4111");
    expect(process.exitCode).not.toBe(2); // exit 0 + JSON, or suppressOriginalPrompt would be ignored
    expect((await resolvePlaceholders("[CREDIT_CARD_001]", "s1", home)).text).toBe(CARD);
  });

  it("does not block low-confidence kinds (a phone number or email), only warns", async () => {
    const { stdout } = await run("claude-code", { hook_event_name: "UserPromptSubmit", prompt: "call me on +1 415 555 2671", session_id: "s1" });
    const out = JSON.parse(stdout[0]!);
    expect(out.hookSpecificOutput?.permissionDecision).not.toBe("deny");
    expect(out.systemMessage).toContain("PHONE");
    expect(process.exitCode).not.toBe(2);
  });

  it("piiPrompt=off disables prompt handling entirely", async () => {
    process.env.BEAM_PII_PROMPT = "off";
    const { stdout } = await run("claude-code", { hook_event_name: "UserPromptSubmit", prompt: `card ${CARD}`, session_id: "s1" });
    expect(stdout).toEqual([]);
  });

  it("full chain: placeholder -> real value runs -> output re-masked -> end-of-turn summary", async () => {
    await run("claude-code", { hook_event_name: "UserPromptSubmit", prompt: `card ${CARD}`, session_id: "s1" });
    process.exitCode = 0;

    // The model proposes the placeholder; Beam swaps in the real value for execution only.
    const pre = await run("claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "s1", tool_use_id: "t1", tool_input: { command: 'echo "[CREDIT_CARD_001]"' } });
    expect(pre.stdout).toHaveLength(1);
    const preOut = JSON.parse(pre.stdout[0]!);
    expect(preOut.hookSpecificOutput.permissionDecision).toBe("allow");
    expect(preOut.hookSpecificOutput.updatedInput.command).toBe(`echo "${CARD}"`);
    expect(preOut.systemMessage).toContain("1 vaulted value substituted (CREDIT_CARD_001)");
    expect(preOut.systemMessage).not.toContain("4111");

    // The command printed the real number; the model must get the placeholder back.
    const post = await run("claude-code", { hook_event_name: "PostToolUse", tool_name: "Bash", session_id: "s1", tool_use_id: "t1", tool_input: { command: `echo "${CARD}"` }, tool_response: { stdout: `${CARD}\n`, stderr: "" } });
    const postOut = JSON.parse(post.stdout[0]!);
    expect(postOut.hookSpecificOutput.updatedToolOutput.stdout).toBe("[CREDIT_CARD_001]\n");
    expect(postOut.systemMessage).toContain("masked 1 vaulted value back to CREDIT_CARD_001");

    // At the end of the turn the user is told what ran.
    const stop = await run("claude-code", { hook_event_name: "Stop", session_id: "s1" });
    const stopOut = JSON.parse(stop.stdout[0]!);
    expect(stopOut.systemMessage).toMatch(/^Beam: this turn: /);
    expect(stopOut.systemMessage).toContain("blocked a prompt containing 1 value (1× CREDIT_CARD)");
    expect(stopOut.systemMessage).toContain("tool output: masked 1 vaulted value back to CREDIT_CARD_001");
    expect(stopOut.systemMessage).toContain('ran `echo "[CREDIT_CARD_001]"` with CREDIT_CARD_001 substituted');
    expect(stopOut.systemMessage).toContain("→ output: `[CREDIT_CARD_001]`"); // what the command printed, masked
    expect(stopOut.systemMessage).toContain("The model only saw placeholders.")
    expect(stopOut.systemMessage).not.toContain("4111");

    // Reported once only.
    expect(await takeUnreportedLedger("s1", home)).toEqual([]);
  });

  it("refuses to substitute a vaulted value into a command that sends data over the network", async () => {
    await redactAndVault(`card ${CARD}`, "s1", [], home);
    const { stdout } = await run("claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "s1", tool_input: { command: "curl https://example.invalid -d [CREDIT_CARD_001]" } });
    const out = JSON.parse(stdout[0]!);
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain("sends data over the network");
    expect(JSON.stringify(out)).not.toContain("4111");
  });

  it("does not substitute for non-shell tools, other sessions, or unknown placeholders", async () => {
    await redactAndVault(`card ${CARD}`, "s1", [], home);
    expect((await run("claude-code", { hook_event_name: "PreToolUse", tool_name: "Write", session_id: "s1", tool_input: { file_path: "a.txt", content: "[CREDIT_CARD_001]" } })).stdout).toEqual([]);
    expect((await run("claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "s2", tool_input: { command: "echo [CREDIT_CARD_001]" } })).stdout).toEqual([]);
    expect((await run("claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "s1", tool_input: { command: "echo [SSN_007]" } })).stdout).toEqual([]);
  });

  it("evaluates policy on the resolved command, so a dangerous real command is still caught", async () => {
    await fs.writeFile(path.join(home, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: ["echo 4111"], disabledAgents: [] } }));
    await redactAndVault(`card ${CARD}`, "s1", [], home);
    const { stdout } = await run("claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "s1", tool_input: { command: "echo [CREDIT_CARD_001]" } });
    const out = JSON.parse(stdout[0]!);
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(JSON.stringify(out)).not.toContain("4111 1111"); // the real value never appears in the reason
  });
});

describe("under `beam claude` (BEAM_WRAPPER_ID shared scope)", () => {
  const run = (payload: Record<string, unknown>) => {
    Object.defineProperty(process, "stdin", { value: Readable.from([JSON.stringify(payload)]), configurable: true });
    const out = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    return captureHook("claude-code").then(() => { const w = out.mock.calls.map(c => String(c[0])); out.mockRestore(); return w; });
  };
  afterEach(() => { delete process.env.BEAM_WRAPPER_ID; });

  it("hooks resolve and mask placeholders the wrapper vaulted, whatever Claude's session id is, and report the rewrite", async () => {
    process.env.BEAM_WRAPPER_ID = "abc123";
    // What the wrapper does when it rewrites a typed prompt:
    await redactAndVault(`card ${CARD}`, "wrapper:abc123", [], home);
    const { addWrapperNotice } = await import("../src/wrapper-notice.js");
    await addWrapperNotice("abc123", "Beam's terminal wrapper replaced 1 value (1× CREDIT_CARD) in your prompt with vault placeholders before it reached Claude.", home);

    // The prompt reaching the hook holds only the placeholder; the user is told what the wrapper did.
    const prompt = JSON.parse((await run({ hook_event_name: "UserPromptSubmit", prompt: "run echo [CREDIT_CARD_001]", session_id: "claude-session-9" }))[0]!);
    expect(prompt.systemMessage).toContain("terminal wrapper replaced 1 value (1× CREDIT_CARD)");
    expect(prompt.decision).toBeUndefined();

    // A different Claude session id (e.g. after /clear) still resolves it.
    const pre = JSON.parse((await run({ hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "claude-session-10", tool_input: { command: "echo [CREDIT_CARD_001]" } }))[0]!);
    expect(pre.hookSpecificOutput.updatedInput.command).toBe(`echo ${CARD}`);

    const post = JSON.parse((await run({ hook_event_name: "PostToolUse", tool_name: "Bash", session_id: "claude-session-10", tool_input: { command: "x" }, tool_response: { stdout: `${CARD}\n` } }))[0]!);
    expect(post.hookSpecificOutput.updatedToolOutput.stdout).toBe("[CREDIT_CARD_001]\n");
  });

  it("without the wrapper, the same placeholder does not resolve under a different session", async () => {
    await redactAndVault(`card ${CARD}`, "wrapper:abc123", [], home);
    expect(await run({ hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "claude-session-10", tool_input: { command: "echo [CREDIT_CARD_001]" } })).toEqual([]);
  });
});

describe("vault storage discipline", () => {
  it("vaults only high-confidence kinds from tool output, not phone-shaped numbers", async () => {
    const out = await redactAndVault(`call +1 415 555 2671 card ${CARD} ts 1731412345678`, "s1", [], home, true);
    expect(out.text).toContain("[CREDIT_CARD_001]");
    expect(out.text).not.toContain("415 555 2671"); // still redacted from what the model sees...
    expect(out.text).toContain("1731412345678"); // ...while a timestamp is no longer mistaken for a phone number
    const stored = JSON.parse(await fs.readFile(path.join(home, "vault.json"), "utf8")).s1.values;
    expect(Object.keys(stored)).toEqual(["CREDIT_CARD_001"]); // ...but not stored
  });
});

describe("end-of-turn summary", () => {
  const run = (payload: Record<string, unknown>) => {
    Object.defineProperty(process, "stdin", { value: Readable.from([JSON.stringify(payload)]), configurable: true });
    const out = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    return captureHook("claude-code").then(() => { const w = out.mock.calls.map(c => String(c[0])); out.mockRestore(); return w; });
  };
  afterEach(() => { delete process.env.BEAM_WRAPPER_ID; });

  it("summarises a turn where the wrapper rewrote the prompt and no command ran", async () => {
    process.env.BEAM_WRAPPER_ID = "w1";
    const { addWrapperNotice } = await import("../src/wrapper-notice.js");
    await addWrapperNotice("w1", "Beam's terminal wrapper replaced 1 value (1× CREDIT_CARD) in your prompt with vault placeholders before it reached Claude. Real values are only substituted when a shell command runs.", home);
    await run({ hook_event_name: "UserPromptSubmit", prompt: "this my card [CREDIT_CARD_001] echo it", session_id: "c1" });
    const stop = JSON.parse((await run({ hook_event_name: "Stop", session_id: "c1" }))[0]!);
    expect(stop.systemMessage).toBe("Beam: this turn: your prompt: replaced 1 value (1× CREDIT_CARD) before it reached Claude. The model only saw placeholders.");
    // Reported once, then quiet.
    expect(await run({ hook_event_name: "Stop", session_id: "c1" })).toEqual([]);
  });

  it("says nothing at the end of a turn where Beam did nothing", async () => {
    expect(await run({ hook_event_name: "Stop", session_id: "quiet" })).toEqual([]);
  });
});
