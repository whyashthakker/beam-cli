import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { findAgent, hookConfigFullPath, type Obj } from "./agents.js";

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
