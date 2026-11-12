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

describe("beam doctor: completed partial checks", () => {
  it("fails when an API key is stored in a file, passes with env var or apiKeyHelper", async () => {
    expect(by(await runDoctor(ctx({ ANTHROPIC_API_KEY: "x" })), "api-key-storage").status).toBe("pass");
    await fs.writeFile(path.join(home, ".claude", "settings.json"), JSON.stringify({ env: { ANTHROPIC_API_KEY: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz" } }));
    expect(by(await runDoctor(ctx()), "api-key-storage").status).toBe("fail");
    await fs.writeFile(path.join(home, ".claude", "settings.json"), JSON.stringify({ apiKeyHelper: "op read x" }));
    expect(by(await runDoctor(ctx()), "api-key-storage").status).toBe("pass");
  });

  it("flags customer-data files in the workspace and ignores fixtures", async () => {
    expect(by(await runDoctor(ctx()), "workspace-isolation").status).toBe("pass");
    await fs.mkdir(path.join(repo, "tests")); await fs.writeFile(path.join(repo, "tests", "customers.csv"), "a");
    expect(by(await runDoctor(ctx()), "workspace-isolation").status).toBe("pass");
    await fs.writeFile(path.join(repo, "customers.csv"), "name\nx\n");
    expect(by(await runDoctor(ctx()), "workspace-isolation").status).toBe("warn");
  });

  it("installs a pre-commit hook that blocks a staged secret and is idempotent", async () => {
    const { installPrecommit, scanStaged } = await import("../src/precommit.js");
    expect(installPrecommit(repo).changed).toBe(true);
    expect(installPrecommit(repo).changed).toBe(false);
    expect(by(await runDoctor(ctx()), "precommit").status).toBe("pass");
    expect(scanStaged(repo, { env: { CLAUDECODE: "1" } }).code).toBe(0);
    await fs.writeFile(path.join(repo, "k.ts"), 'const k = "-----BEGIN RSA PRIVATE KEY-----\\nabc\\n-----END RSA PRIVATE KEY-----";\n');
    git("add", "k.ts");
    expect(scanStaged(repo, { env: {} })).toEqual({ code: 0, report: "" }); // a human commit is never blocked
    const r = scanStaged(repo, { env: { CLAUDECODE: "1" } }); expect(r.code).toBe(1); expect(r.report).not.toContain("abc");
    expect(scanStaged(repo, { env: {}, everyone: true }).code).toBe(1); // opt-in for humans
  });
});

describe("auto pre-commit on first touch of a git workspace", () => {
  it("installs once, respects removal, opt-out, and existing scanners", async () => {
    const { ensurePrecommit } = await import("../src/precommit.js");
    const hook = path.join(repo, ".git", "hooks", "pre-commit");
    expect(ensurePrecommit(repo, { env: {}, policyValue: "off" })).toBeNull();
    expect(ensurePrecommit(repo, { env: { BEAM_AUTO_PRECOMMIT: "0" } })).toBeNull();
    expect(ensurePrecommit(repo, { env: {} })?.changed).toBe(true);
    expect(await fs.readFile(hook, "utf8")).toContain("beam git-scan");
    await fs.rm(hook);
    expect(ensurePrecommit(repo, { env: {} })).toBeNull(); // already handled: not put back
    expect(await fs.stat(hook).catch(() => null)).toBeNull();
    expect(ensurePrecommit(os.tmpdir(), { env: {} })).toBeNull(); // not a repo
  });
});

describe("beam doctor: history, visibility and rotation guidance", () => {
  const AKIA = "AKIA" + "ABCDEFGHIJKLMNOP";
  it("finds a key that was committed and later deleted, names the provider and commit, never the value", async () => {
    expect(by(await runDoctor(ctx()), "history-secrets").status).toBe("pass");
    await fs.writeFile(path.join(repo, "config.ts"), `export const k = "${AKIA}";\n`); git("add", "."); git("commit", "-qm", "oops");
    await fs.writeFile(path.join(repo, "config.ts"), "export const k = process.env.K;\n"); git("add", "."); git("commit", "-qm", "fix");
    const c = by(await runDoctor(ctx()), "history-secrets");
    expect(c.status).toBe("fail");
    expect(c.detail).toContain("config.ts @ "); expect(c.detail).toContain("AWS key");
    expect(c.fix).toContain("IAM"); // rotation guidance for the right provider
    expect(JSON.stringify(c)).not.toContain(AKIA);
  });

  it("only warns when the key is in a test fixture, and flags a committed .env file", async () => {
    await fs.mkdir(path.join(repo, "tests")); await fs.writeFile(path.join(repo, "tests", "a.ts"), `const k = "${AKIA}";\n`); git("add", "."); git("commit", "-qm", "fixture");
    expect(by(await runDoctor(ctx()), "history-secrets").status).toBe("warn");
    await fs.writeFile(path.join(repo, ".env"), "X=1\n"); git("add", "-f", ".env"); git("commit", "-qm", "env"); git("rm", "-q", "--cached", ".env"); git("commit", "-qm", "untrack");
    const c = by(await runDoctor(ctx()), "history-secrets");
    expect(c.status).toBe("fail"); expect(c.detail).toContain("credential file");
  });

  it("fails on a public GitHub remote, passes on private, skips when gh can't answer or host is unknown", async () => {
    git("remote", "add", "origin", "git@github.com:acme/app.git");
    const withGh = (out: string, status = 0): DoctorContext => ({ ...ctx(), spawn: ((cmd: string, args: string[], o: any) => cmd === "gh" ? { status, stdout: out, stderr: "" } : spawnSync(cmd, args, o)) as any });
    expect(by(await runDoctor(withGh("PUBLIC\n")), "repo-visibility").status).toBe("fail");
    expect(by(await runDoctor(withGh("PRIVATE\n")), "repo-visibility").status).toBe("pass");
    expect(by(await runDoctor(withGh("", 1)), "repo-visibility").status).toBe("skip");
    git("remote", "set-url", "origin", "git@gitlab.com:acme/app.git");
    expect(by(await runDoctor(ctx()), "repo-visibility").status).toBe("skip");
  });
});

describe("beam doctor: incidents (8.2)", () => {
  it("passes with none, warns while open, fails past the deadline, passes again once reported", async () => {
    const { createIncident, markReported } = await import("../src/incidents.js");
    expect(by(await runDoctor(ctx()), "incidents").status).toBe("pass");
    const fresh = createIncident({ type: "other", summary: "s", dir: data }).incident;
    expect(by(await runDoctor(ctx()), "incidents").status).toBe("warn");
    createIncident({ type: "other", summary: "old", at: new Date(Date.now() - 5 * 3600_000), dir: data });
    expect(by(await runDoctor(ctx()), "incidents").status).toBe("fail");
    for (const i of (await import("../src/incidents.js")).listIncidents(data)) markReported(i.id, "lead", data);
    expect(by(await runDoctor(ctx()), "incidents").status).toBe("pass"); void fresh;
  });
});
