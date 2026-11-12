import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { doctorExitCode, formatDoctor, runDoctor, type Check, type DoctorContext } from "../src/doctor.js";

const dirs: string[] = [];
let home: string, repo: string, data: string;
const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
const git = (...args: string[]) => { const r = spawnSync("git", args, { cwd: repo, env, encoding: "utf8" }); if (r.status !== 0) throw new Error(r.stderr); return r.stdout; };
const ctx = (extraEnv: NodeJS.ProcessEnv = {}): DoctorContext => ({ cwd: repo, home, dataDir: data, env: { PATH: process.env.PATH, ...extraEnv }, spawn: spawnSync });
const by = (checks: Check[], id: string) => checks.find(c => c.id === id)!;
const beamHooks = Object.fromEntries(["PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop"].map(e => [e, [{ hooks: [{ type: "command", command: `node /x/cli.js hook claude-code --event "${e}"` }] }]]));

beforeEach(async () => {
  home = await fs.mkdtemp(path.join(os.tmpdir(), "beam-dh-")); repo = await fs.mkdtemp(path.join(os.tmpdir(), "beam-dr-")); data = await fs.mkdtemp(path.join(os.tmpdir(), "beam-dd-"));
  dirs.push(home, repo, data); process.env.BEAM_DATA_DIR = data;
  await fs.mkdir(path.join(home, ".claude"), { recursive: true });
  git("init", "-q"); await fs.writeFile(path.join(repo, "a.ts"), "export const a = 1;\n"); git("add", "."); git("commit", "-qm", "init");
});
afterEach(async () => { await Promise.all(dirs.splice(0).map(d => fs.rm(d, { recursive: true, force: true }))); });

describe("beam doctor", () => {
  it("fails when Beam hooks are not installed, passes when all four are", async () => {
    expect(by(await runDoctor(ctx()), "hooks").status).toBe("fail");
    await fs.writeFile(path.join(home, ".claude", "settings.json"), JSON.stringify({ hooks: beamHooks }));
    expect(by(await runDoctor(ctx()), "hooks").status).toBe("pass");
  });

  it("flags Claude Code auto memory (on by default) and accepts each documented way to turn it off", async () => {
    expect(by(await runDoctor(ctx()), "memory").status).toBe("fail");
    expect(by(await runDoctor(ctx({ CLAUDE_CODE_DISABLE_AUTO_MEMORY: "1" })), "memory").status).toBe("pass");
    await fs.writeFile(path.join(home, ".claude", "settings.json"), JSON.stringify({ autoMemoryEnabled: false }));
    expect(by(await runDoctor(ctx()), "memory").status).toBe("pass");
    await fs.mkdir(path.join(repo, ".claude")); await fs.writeFile(path.join(repo, ".claude", "settings.local.json"), JSON.stringify({ autoMemoryEnabled: true }));
    expect(by(await runDoctor(ctx()), "memory").status).toBe("fail"); // project-local setting wins over user settings
  });

  it("reports observe mode as a warning and an explicit piiPrompt=off as a failure", async () => {
    expect(by(await runDoctor(ctx()), "policy-mode").status).toBe("warn");
    await fs.writeFile(path.join(data, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [], piiPrompt: "off", gitGate: "off" } }));
    const checks = await runDoctor(ctx());
    expect(by(checks, "policy-mode").status).toBe("pass");
    expect(by(checks, "pii-prompt").status).toBe("fail");
    expect(by(checks, "git-gate").status).toBe("fail");
  });

  it("checks network environment: disabled TLS verification and a non-Anthropic endpoint fail", async () => {
    const ok = await runDoctor(ctx());
    expect(by(ok, "tls").status).toBe("pass"); expect(by(ok, "endpoint").status).toBe("pass");
    const bad = await runDoctor(ctx({ NODE_TLS_REJECT_UNAUTHORIZED: "0", ANTHROPIC_BASE_URL: "https://proxy.example.com" }));
    expect(by(bad, "tls").status).toBe("fail"); expect(by(bad, "endpoint").status).toBe("fail");
    expect(by(await runDoctor(ctx({ ANTHROPIC_BASE_URL: "https://api.anthropic.com" })), "endpoint").status).toBe("pass");
  });

  it("flags world-readable vault files", async () => {
    await fs.writeFile(path.join(data, "vault.json"), "{}", { mode: 0o644 }); await fs.chmod(path.join(data, "vault.json"), 0o644); await fs.chmod(data, 0o700);
    expect(by(await runDoctor(ctx()), "vault-perms").status).toBe("fail");
    await fs.chmod(path.join(data, "vault.json"), 0o600);
    expect(by(await runDoctor(ctx()), "vault-perms").status).toBe("pass");
  });

  describe("repository controls", () => {
    it("fails when .env is not ignored, passes when it is", async () => {
      expect(by(await runDoctor(ctx()), "gitignore").status).toBe("fail");
      await fs.writeFile(path.join(repo, ".gitignore"), ".env\n.env.*\n");
      expect(by(await runDoctor(ctx()), "gitignore").status).toBe("pass");
    });

    it("fails when a secret file is tracked", async () => {
      await fs.writeFile(path.join(repo, ".env"), "PORT=1\n"); git("add", "-f", ".env"); git("commit", "-qm", "oops");
      const check = by(await runDoctor(ctx()), "tracked-secrets");
      expect(check.status).toBe("fail"); expect(check.detail).toContain(".env");
    });

    it("warns without a pre-commit secret scanner and passes with one", async () => {
      expect(by(await runDoctor(ctx()), "precommit").status).toBe("warn");
      await fs.writeFile(path.join(repo, ".git", "hooks", "pre-commit"), "#!/bin/sh\ngitleaks protect --staged\n", { mode: 0o755 });
      expect(by(await runDoctor(ctx()), "precommit").status).toBe("pass");
    });

    it("fails on a hard-coded key in source, warns when only in tests, and never prints the key", async () => {
      const KEY = "AKIAIOSFODNN7EXAMPLE";
      await fs.mkdir(path.join(repo, "tests")); await fs.writeFile(path.join(repo, "tests", "fixture.ts"), `const k = "${KEY}";\n`); git("add", "."); git("commit", "-qm", "t");
      const testOnly = by(await runDoctor(ctx()), "hardcoded-keys");
      expect(testOnly.status).toBe("warn");
      await fs.writeFile(path.join(repo, "config.ts"), `export const k = "${KEY}";\n`); git("add", "."); git("commit", "-qm", "c");
      const real = by(await runDoctor(ctx()), "hardcoded-keys");
      expect(real.status).toBe("fail"); expect(real.detail).toContain("config.ts");
      expect(JSON.stringify(real)).not.toContain(KEY);
    });

    it("skips repository checks outside a git repository", async () => {
      const outside = await fs.mkdtemp(path.join(os.tmpdir(), "beam-nr-")); dirs.push(outside);
      expect(by(await runDoctor({ ...ctx(), cwd: outside }), "repo").status).toBe("skip");
    });
  });

  it("marks what cannot be verified locally as skip, not pass", async () => {
    const checks = await runDoctor(ctx());
    expect(by(checks, "api-tier").status).toBe("skip"); expect(by(checks, "workstation").status).toBe("skip");
  });

  it("formats a readable report and exits non-zero only on failures", async () => {
    const checks = await runDoctor(ctx());
    const text = formatDoctor(checks);
    expect(text).toContain("beam doctor");
    expect(text).toMatch(/\d+ passed, \d+ warnings, \d+ failed, \d+ not checkable\./);
    expect(doctorExitCode(checks)).toBe(1); // hooks missing + memory on
    expect(doctorExitCode([{ id: "x", policy: "1", title: "t", status: "warn", detail: "d" }])).toBe(0);
  });
});
