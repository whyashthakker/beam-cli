import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ensureMonitorConfig, monitorConfigPath, readMonitorConfig } from "../src/monitor-config.js";
import { ownLlmConfig } from "../src/monitor-llm.js";
import { monitorConfigure, runMonitor } from "../src/monitor.js";

const originalEnv = process.env;
let home: string;
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "beam-monitor-config-"));
  process.env = { ...originalEnv, BEAM_HOME: home, BEAM_DATA_DIR: join(home, "data") };
  for (const name of Object.keys(process.env)) if (/^BEAM_LLM_|_API_KEY$|^ANTHROPIC_AUTH_TOKEN$|^BEAM_APP_TOKEN$/.test(name)) delete process.env[name];
});
afterEach(async () => {
  process.env = originalEnv;
  await rm(home, { recursive: true, force: true });
});

describe("monitor.json", () => {
  it("is created on the first monitor command after an upgrade, private to the user", async () => {
    expect(await readMonitorConfig()).toBeNull();
    const first = await ensureMonitorConfig();
    expect(first).toMatchObject({ created: true, config: { version: 1, files: [], app: null, llm: { provider: "beam" } } });
    expect((await stat(monitorConfigPath())).mode & 0o777).toBe(0o600);
    expect((await ensureMonitorConfig()).created).toBe(false);
  });
  it("carries over older BEAM_LLM_* settings, naming the key's variable but never copying the key", async () => {
    process.env.BEAM_LLM_BASE_URL = "http://localhost:4000/v1";
    process.env.BEAM_LLM_MODEL = "llama3.2";
    process.env.BEAM_LLM_API_KEY = "sk-secret-value";
    const { config } = await ensureMonitorConfig();
    expect(config.llm).toEqual({ provider: "custom", model: "llama3.2", baseUrl: "http://localhost:4000/v1", apiKeyEnv: "BEAM_LLM_API_KEY" });
    expect(await readFile(monitorConfigPath(), "utf8")).not.toContain("sk-secret-value");
  });
  it("explains an invalid file instead of guessing", async () => {
    await writeFile(monitorConfigPath(), "{ not json");
    await expect(ensureMonitorConfig()).rejects.toThrow("monitor.json is invalid (not valid JSON)");
    await writeFile(monitorConfigPath(), JSON.stringify({ version: 1, llm: { apiKeyEnv: "not a var" } }));
    await expect(readMonitorConfig()).rejects.toThrow("llm.apiKeyEnv must be a variable name");
  });
  it("is read after --llm and the environment", async () => {
    process.env.OPENAI_API_KEY = "sk-openai";
    process.env.ANTHROPIC_API_KEY = "sk-ant";
    const file = { provider: "openai", model: null, baseUrl: null, apiKeyEnv: null };
    expect(ownLlmConfig(process.env, undefined, file)).toMatchObject({ provider: "openai", keySource: "OPENAI_API_KEY" });
    expect(ownLlmConfig({ ...process.env, BEAM_LLM_PROVIDER: "anthropic" }, undefined, file)).toMatchObject({ provider: "anthropic" });
    expect(ownLlmConfig(process.env, "beam", file)).toBeNull();
    // A file left at the default doesn't hide BEAM_LLM_* settings made later.
    expect(ownLlmConfig({ BEAM_LLM_BASE_URL: "http://localhost:11434/v1", BEAM_LLM_MODEL: "m" }, undefined, { ...file, provider: "beam" })).toMatchObject({ model: "m" });
    expect(ownLlmConfig({ TEAM_OPENAI: "sk-team" }, undefined, { ...file, apiKeyEnv: "TEAM_OPENAI" })).toMatchObject({ apiKey: "sk-team", keySource: "TEAM_OPENAI" });
  });
});

describe("beam monitor configure", () => {
  it("saves a provider, a key variable and what to watch, and never prints a stored key", async () => {
    const out: string[] = [];
    process.env.OPENAI_API_KEY = "sk-openai";
    await monitorConfigure({ llm: "openai", files: ["/var/log/nginx/access.log"], app: "/srv/app" }, l => out.push(l));
    expect(await readMonitorConfig()).toMatchObject({ files: ["/var/log/nginx/access.log"], app: "/srv/app", llm: { provider: "openai" } });
    expect(out.join("\n")).toContain("your own OpenAI with your key from OPENAI_API_KEY");

    out.length = 0;
    await monitorConfigure({ llm: "anthropic", key: "sk-ant-stored" }, l => out.push(l));
    const saved = (await readMonitorConfig())!;
    expect(saved.llm).toMatchObject({ provider: "anthropic", model: null, apiKey: "sk-ant-stored" });
    expect(ownLlmConfig({}, undefined, saved.llm)).toMatchObject({ apiKey: "sk-ant-stored", keySource: "monitor.json" });
    out.length = 0;
    await monitorConfigure({}, l => out.push(l));
    expect(out.join("\n")).toContain('"apiKey": "(stored)"');
    expect(out.join("\n")).not.toContain("sk-ant-stored");

    await monitorConfigure({ forgetKey: true, noFiles: true, noApp: true }, () => {});
    expect((await readMonitorConfig())!).toMatchObject({ files: [], app: null, llm: { provider: "anthropic" } });
    expect((await readMonitorConfig())!.llm.apiKey).toBeUndefined();
  });
  it("saves a provider whose key lives only where beam monitor runs, with a warning", async () => {
    const out: string[] = [];
    await monitorConfigure({ llm: "groq" }, l => out.push(l));
    expect(out.join("\n")).toContain("set GROQ_API_KEY");
    expect((await readMonitorConfig())!.llm.provider).toBe("groq");
    await expect(monitorConfigure({ llm: "chatgpt" }, () => {})).rejects.toThrow('Unknown LLM provider "chatgpt"');
  });
  it("lets a plain 'beam monitor' fall back to the saved sources, and says how to save them", async () => {
    await expect(runMonitor({}, () => {})).rejects.toThrow("beam monitor configure --file");
  });
});

describe("config layers: managed, user, project", () => {
  const managedFile = () => join(home, "managed", "monitor.json");
  beforeEach(async () => {
    const { mkdir } = await import("node:fs/promises");
    await mkdir(join(home, "managed"), { recursive: true });
    await mkdir(join(home, "app"), { recursive: true });
    process.env.BEAM_MANAGED_CONFIG = managedFile();
  });
  it("applies managed, then user, then project, and says where each value came from", async () => {
    const { resolveMonitorSettings } = await import("../src/monitor-config.js");
    await writeFile(managedFile(), JSON.stringify({ version: 1, maxCpuPercent: 10 }));
    await monitorConfigure({ files: ["/var/log/user.log"] }, () => {});
    await writeFile(join(home, "app", "beam.monitor.json"), JSON.stringify({ version: 1, files: ["/var/log/app.log"], llm: { provider: "openai" } }));
    const resolved = await resolveMonitorSettings({ cwd: join(home, "app") });
    expect(resolved.settings).toMatchObject({ maxCpuPercent: 10, files: ["/var/log/app.log"], llm: { provider: "openai" } });
    expect(resolved.origins).toEqual({ files: "project", app: "default", maxCpuPercent: "managed", llm: "project", pause: "default" });
  });
  it("lets IT lock settings that nothing below, flags included, can change", async () => {
    const { resolveMonitorSettings } = await import("../src/monitor-config.js");
    await writeFile(managedFile(), JSON.stringify({ version: 1, llm: { provider: "beam" }, maxCpuPercent: 5, locked: ["llm", "maxCpuPercent"] }));
    await writeFile(join(home, "app", "beam.monitor.json"), JSON.stringify({ version: 1, llm: { provider: "openai" }, maxCpuPercent: 80 }));
    process.env.OPENAI_API_KEY = "sk-personal";
    process.env.BEAM_LLM_API_KEY = "sk-legacy";
    const resolved = await resolveMonitorSettings({ cwd: join(home, "app") });
    expect(resolved.settings).toMatchObject({ maxCpuPercent: 5, llm: { provider: "beam" } });
    expect([...resolved.locked].sort()).toEqual(["llm", "maxCpuPercent"]);
    const out: string[] = [];
    await monitorConfigure({ llm: "openai" }, l => out.push(l));
    expect(out.join("\n")).toContain("managed config locks the LLM check");
    const logs: string[] = [];
    await expect(runMonitor({ llm: "openai", files: ["/tmp/x.log"] }, m => logs.push(m))).rejects.toThrow(); // stops at auth, after settings
    expect(logs.join("\n")).toContain("--llm openai doesn't apply");
  });
  it("refuses keys in shared files and reports a broken layer clearly", async () => {
    const { resolveMonitorSettings } = await import("../src/monitor-config.js");
    await writeFile(join(home, "app", "beam.monitor.json"), JSON.stringify({ version: 1, llm: { provider: "openai", apiKey: "sk-in-the-repo" } }));
    await expect(resolveMonitorSettings({ cwd: join(home, "app") })).rejects.toThrow("keys don't belong in a shared file");
    await writeFile(join(home, "app", "beam.monitor.json"), JSON.stringify({ version: 1, locked: ["llm"] }));
    await expect(resolveMonitorSettings({ cwd: join(home, "app") })).rejects.toThrow("only the managed config can lock");
    const out: string[] = [];
    const cwd = process.cwd();
    process.chdir(join(home, "app"));
    try { expect(await monitorConfigure({ check: true }, l => out.push(l))).toBe(1); } finally { process.chdir(cwd); }
    expect(out.join("\n")).toContain("only the managed config can lock");
  });
});
