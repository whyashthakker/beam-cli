import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { captureHook } from "../src/client.js";
import { applyGitGate, gitGateMode, parseGitCommands, scanGitIntent } from "../src/git-gate.js";
import { resetNotices, pendingNotices } from "../src/hook-notice.js";
import type { Decision } from "../src/policy.js";

const dirs: string[] = [];
let repo: string;
const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
const git = (cwd: string, ...args: string[]) => { const r = spawnSync("git", args, { cwd, env, encoding: "utf8" }); if (r.status !== 0) throw new Error(r.stderr); return r.stdout; };
const write = (name: string, text: string) => fs.writeFile(path.join(repo, name), text);
const AWS = "AKIAIOSFODNN7EXAMPLE";
const base = (extra: Partial<Decision> = {}): Decision => ({ action: "allow", mode: "enforce", policyVersion: 1, riskScore: 0, riskLevel: "LOW", riskFactors: [], ...extra });

beforeEach(async () => {
  repo = await fs.mkdtemp(path.join(os.tmpdir(), "beam-git-")); dirs.push(repo);
  git(repo, "init", "-q"); git(repo, "config", "commit.gpgsign", "false");
  await write("README.md", "hello\n"); git(repo, "add", "."); git(repo, "commit", "-qm", "init");
  process.env.BEAM_DATA_DIR = await fs.mkdtemp(path.join(os.tmpdir(), "beam-data-")); dirs.push(process.env.BEAM_DATA_DIR);
  resetNotices();
});
afterEach(async () => { delete process.env.BEAM_GIT_GATE; await Promise.all(dirs.splice(0).map(d => fs.rm(d, { recursive: true, force: true }))); });

describe("parseGitCommands", () => {
  it("finds commit, push and add, through chains, -C and global options", () => {
    expect(parseGitCommands('git add -A && git commit -m "x; y" && git push origin main').map(i => i.kind)).toEqual(["add", "commit", "push"]);
    expect(parseGitCommands("cd /tmp && git -C /repo -c user.name=a commit -am wip")[0]).toMatchObject({ kind: "commit", dir: "/repo", all: true });
    expect(parseGitCommands("git commit --no-verify -m x")[0]!.noVerify).toBe(true);
    expect(parseGitCommands("git push --force-with-lease")[0]!.force).toBe(true);
  });
  it("ignores other git subcommands and non-git commands", () => {
    expect(parseGitCommands("git status && git log && ls && echo git commit")).toEqual([]);
  });
});

describe("scanGitIntent", () => {
  it("flags a secret in a staged commit with file:line and kind, and never the value", async () => {
    await write("config.ts", `const a = 1;\nconst key = "${AWS}";\n`);
    git(repo, "add", "config.ts");
    const scan = scanGitIntent(parseGitCommands("git commit -m x")[0]!, repo);
    expect(scan.findings).toEqual([{ file: "config.ts", line: 2, kind: "API_KEY" }]);
    expect(JSON.stringify(scan)).not.toContain(AWS);
  });

  it("finds nothing in a clean commit, and ignores lockfiles", async () => {
    await write("a.ts", "export const x = 1;\n"); await write("package-lock.json", `{"integrity":"${AWS}"}\n`);
    git(repo, "add", ".");
    expect(scanGitIntent(parseGitCommands("git commit -m x")[0]!, repo)).toMatchObject({ findings: [], privateFiles: [] });
  });

  it("flags a private file such as .env even when its content looks harmless", async () => {
    await write(".env", "PORT=3000\n"); git(repo, "add", "-f", ".env");
    expect(scanGitIntent(parseGitCommands("git commit -m x")[0]!, repo).privateFiles).toEqual([".env"]);
  });

  it("does not flag a committed template like .env.example", async () => {
    await write(".env.example", "PORT=3000\n"); git(repo, "add", ".env.example");
    expect(scanGitIntent(parseGitCommands("git commit -m x")[0]!, repo).privateFiles).toEqual([]);
  });

  it("`git commit -a` includes unstaged changes to tracked files; plain commit does not", async () => {
    await write("README.md", `token ${AWS}\n`);
    expect(scanGitIntent(parseGitCommands("git commit -m x")[0]!, repo).findings).toEqual([]);
    expect(scanGitIntent(parseGitCommands("git commit -am x")[0]!, repo).findings.map(f => f.kind)).toEqual(["API_KEY"]);
  });

  it("push scans only commits not yet on a remote", async () => {
    const remote = await fs.mkdtemp(path.join(os.tmpdir(), "beam-remote-")); dirs.push(remote);
    git(remote, "init", "-q", "--bare");
    await write("old.ts", `const k = "${AWS}";\n`); git(repo, "add", "."); git(repo, "commit", "-qm", "old");
    git(repo, "remote", "add", "origin", remote); git(repo, "push", "-q", "origin", "HEAD:main");
    git(repo, "fetch", "-q", "origin");
    await write("new.ts", "export const y = 2;\n"); git(repo, "add", "."); git(repo, "commit", "-qm", "clean");
    expect(scanGitIntent(parseGitCommands("git push")[0]!, repo).findings).toEqual([]); // the secret is already published
    await write("leak.ts", `const k = "${AWS}";\n`); git(repo, "add", "."); git(repo, "commit", "-qm", "leak");
    expect(scanGitIntent(parseGitCommands("git push")[0]!, repo).findings).toEqual([{ file: "leak.ts", line: 1, kind: "API_KEY" }]);
  });

  it("`git add` scans the files it would stage, via dry-run", async () => {
    await write("notes.txt", `card 4111 1111 1111 1111\n`); await write("fine.txt", "ok\n");
    const scan = scanGitIntent(parseGitCommands("git add .")[0]!, repo);
    expect(scan.findings).toEqual([{ file: "notes.txt", line: 1, kind: "CREDIT_CARD" }]);
  });

  it("honours extra ignore patterns and reports non-repos instead of throwing", async () => {
    await write("fixtures.ts", `const k = "${AWS}";\n`); git(repo, "add", ".");
    expect(scanGitIntent(parseGitCommands("git commit -m x")[0]!, repo, { ignore: [/fixtures\.ts$/] }).findings).toEqual([]);
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), "beam-nogit-")); dirs.push(outside);
    expect(scanGitIntent(parseGitCommands("git commit -m x")[0]!, outside).skipped).toBe("not a git repository");
  });
});

describe("applyGitGate", () => {
  beforeEach(async () => { await write("c.ts", `const k = "${AWS}";\n`); git(repo, "add", "c.ts"); });

  it("asks by default in enforce mode, with a reason that names file, kind and line but not the value", () => {
    const next = applyGitGate(base(), { command: "git commit -m x", cwd: repo, mode: gitGateMode(undefined, undefined, "enforce") });
    expect(next.action).toBe("ask");
    expect(next.rule).toBe("beam.git-gate");
    expect(next.reason).toContain("c.ts:1");
    expect(next.reason).toContain("1× API_KEY");
    expect(next.reason).not.toContain(AWS);
  });
  it("only warns in observe mode, and denies in block mode", () => {
    expect(gitGateMode(undefined, undefined, "observe")).toBe("warn");
    const warned = applyGitGate(base({ mode: "observe" }), { command: "git commit -m x", cwd: repo, mode: "warn" });
    expect(warned.action).toBe("allow");
    expect(pendingNotices().join(" ")).toContain("git commit would include");
    expect(applyGitGate(base(), { command: "git commit -m x", cwd: repo, mode: "block" }).action).toBe("deny");
  });
  it("does nothing when off, for other commands, and never downgrades an existing deny", () => {
    expect(applyGitGate(base(), { command: "git commit -m x", cwd: repo, mode: "off" }).action).toBe("allow");
    expect(applyGitGate(base(), { command: "git status", cwd: repo, mode: "ask" }).action).toBe("allow");
    expect(applyGitGate(base({ action: "deny", rule: "other" }), { command: "git commit -m x", cwd: repo, mode: "ask" })).toMatchObject({ action: "deny", rule: "other" });
  });
  it("notes --no-verify", () => {
    applyGitGate(base(), { command: "git commit --no-verify -m x", cwd: repo, mode: "warn" });
    expect(pendingNotices().join(" ")).toContain("--no-verify");
  });
});

describe("through the hook", () => {
  const run = (payload: Record<string, unknown>) => {
    Object.defineProperty(process, "stdin", { value: Readable.from([JSON.stringify(payload)]), configurable: true });
    const out = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    return captureHook("claude-code").then(() => { const w = out.mock.calls.map(c => String(c[0])); out.mockRestore(); return w; });
  };
  it("asks before an agent commits a secret, once policy enforces", async () => {
    await fs.writeFile(path.join(process.env.BEAM_DATA_DIR!, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [] } }));
    await write("c.ts", `const k = "${AWS}";\n`); git(repo, "add", "c.ts");
    const out = JSON.parse((await run({ hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "g1", cwd: repo, tool_input: { command: 'git commit -m "add config"' } }))[0]!);
    expect(out.hookSpecificOutput.permissionDecision).toBe("ask");
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain("c.ts:1");
    expect(JSON.stringify(out)).not.toContain(AWS);
  });
  it("lets a clean commit through silently", async () => {
    await write("ok.ts", "export const x = 1;\n"); git(repo, "add", "ok.ts");
    expect(await run({ hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "g2", cwd: repo, tool_input: { command: 'git commit -m "ok"' } })).toEqual([]);
  });
});
