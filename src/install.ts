import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { AGENTS, findAgent, hookConfigFullPath, type AgentDefinition, type Obj } from "./agents.js";

export interface InstallResult { agent: string; path: string; alreadyInstalled: boolean }

export async function installHook(agentId: string, home = homedir()): Promise<InstallResult> {
  const agent = findAgent(agentId);
  if (!agent) throw new Error(`Unknown agent '${agentId}'. Run 'beam agent list' to see supported agents.`);
  if (!agent.hookConfigPath || !agent.mergeHookConfig) throw new Error(`${agent.name} has no supported hook install path yet; see 'beam agent list' for its status.`);

  const path = hookConfigFullPath(agent, home);
  const command = `beam hook ${agent.id}`;

  let existing: Obj = {};
  let raw = "";
  try { raw = await readFile(path, "utf8"); existing = raw.trim() ? JSON.parse(raw) as Obj : {}; }
  catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
      if (e instanceof SyntaxError) throw new Error(`${path} contains invalid JSON; fix or remove it before installing.`);
      throw e;
    }
  }

  const merged = agent.mergeHookConfig(existing, command);
  const alreadyInstalled = JSON.stringify(merged) === JSON.stringify(existing) && raw.trim() !== "";

  if (!alreadyInstalled) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(merged, null, 2)}\n`);
  }

  return { agent: agent.id, path, alreadyInstalled };
}

async function isDetected(agent: AgentDefinition, home: string): Promise<boolean> {
  for (const relativePath of agent.configs) {
    try { await access(join(home, relativePath)); return true; } catch { /* check the next path */ }
  }
  return false;
}

export type InstallAllStatus = "installed" | "already-installed" | "not-detected" | "not-supported" | "error";
export interface InstallAllResult { agent: string; name: string; status: InstallAllStatus; path?: string; error?: string }

// Detects which agents are actually present on this machine (via agents.ts's real, non-circular
// config-presence signals — never the hook file beam itself would write) and installs beam's
// hook into every one that's both detected and supported, skipping the rest without erroring.
export async function installAllDetectedHooks(home = homedir()): Promise<InstallAllResult[]> {
  const results: InstallAllResult[] = [];
  for (const agent of AGENTS) {
    if (!(await isDetected(agent, home))) { results.push({ agent: agent.id, name: agent.name, status: "not-detected" }); continue; }
    if (!agent.hookConfigPath || !agent.mergeHookConfig) { results.push({ agent: agent.id, name: agent.name, status: "not-supported" }); continue; }
    try {
      const result = await installHook(agent.id, home);
      results.push({ agent: agent.id, name: agent.name, status: result.alreadyInstalled ? "already-installed" : "installed", path: result.path });
    } catch (e) {
      results.push({ agent: agent.id, name: agent.name, status: "error", error: e instanceof Error ? e.message : String(e) });
    }
  }
  return results;
}
