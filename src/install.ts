import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AGENTS, findAgent, hookConfigFullPath, type AgentDefinition, type Obj } from "./agents.js";

export interface InstallResult { agent: string; path: string; alreadyInstalled: boolean }
const OPEN_CODE_PLUGIN = `import { spawnSync } from "node:child_process";

export const BeamPlugin = async () => ({
  "tool.execute.before": async (input: any, output: any) => {
    const payload = { tool_name: input?.tool, tool_input: output?.args ?? {}, session_id: input?.sessionID, cwd: input?.directory ?? input?.worktree, source_agent: "opencode", source_type: "hook" };
    const result = spawnSync("beam", ["hook", "opencode"], { input: JSON.stringify(payload), encoding: "utf8", timeout: 5000 });
    let response: any = {};
    try { response = JSON.parse(result.stdout || "{}"); } catch { /* fail closed below */ }
    if (result.error || result.status !== 0 || response.decision === "deny") throw new Error(response.reason || "Beam denied this tool execution.");
  },
});
`;

// A bare "beam" command relies on beam's global bin symlink being resolvable on PATH -- but the
// shell that runs an agent's hooks (e.g. Claude Code's own PreToolUse child process) doesn't
// always source the same profile a user's interactive shell does, so "beam" can 404 silently
// there even though it works fine when the user types it themselves. Embedding the absolute path
// to this running install (both the node binary and dist/cli.js, resolved via import.meta.url
// rather than argv[1] so it's correct however beam itself was invoked) sidesteps PATH entirely.
function resolveHookCommand(agentId: string): string {
  const cliPath = fileURLToPath(new URL("./cli.js", import.meta.url));
  return `${quoteForShell(process.execPath)} ${quoteForShell(cliPath)} hook ${agentId}`;
}

function quoteForShell(value: string): string {
  return `"${value.replace(/(["\\$`])/g, "\\$1")}"`;
}

// Pre-fix installs wrote a bare "beam hook <agent>" command that depends on PATH; recognizing it
// here lets installHook migrate an existing entry to the absolute-path form instead of leaving a
// dead duplicate behind, and lets uninstallHook still find and remove it.
function legacyHookCommand(agentId: string): string {
  return `beam hook ${agentId}`;
}

export async function installHook(agentId: string, home = homedir()): Promise<InstallResult> {
  const agent = findAgent(agentId);
  if (!agent) throw new Error(`Unknown agent '${agentId}'. Run 'beam agent list' to see supported agents.`);
  if (agent.id === "opencode" && agent.pluginPath) {
    const path = join(home, agent.pluginPath); const existing = await readFile(path, "utf8").catch(() => "");
    if (!existing) { await mkdir(dirname(path), { recursive: true }); await writeFile(path, OPEN_CODE_PLUGIN, { mode: 0o600 }); }
    return { agent: agent.id, path, alreadyInstalled: Boolean(existing) };
  }
  if (!agent.hookConfigPath || !agent.mergeHookConfig || !agent.unmergeHookConfig) throw new Error(`${agent.name} has no supported hook install path yet; see 'beam agent list' for its status.`);

  const path = hookConfigFullPath(agent, home);
  const command = resolveHookCommand(agent.id);

  let existing: Obj = {};
  let raw = "";
  try { raw = await readFile(path, "utf8"); existing = raw.trim() ? JSON.parse(raw) as Obj : {}; }
  catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
      if (e instanceof SyntaxError) throw new Error(`${path} contains invalid JSON; fix or remove it before installing.`);
      throw e;
    }
  }

  // Strip any pre-fix legacy entry first so re-installing migrates it rather than duplicating.
  const base = agent.unmergeHookConfig(existing, legacyHookCommand(agent.id));
  const merged = agent.mergeHookConfig(base, command);
  const alreadyInstalled = JSON.stringify(merged) === JSON.stringify(existing) && raw.trim() !== "";

  if (!alreadyInstalled) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(merged, null, 2)}\n`);
  }

  return { agent: agent.id, path, alreadyInstalled };
}

export interface UninstallResult { agent: string; path: string; removed: boolean }

// Reverse of installHook: strips beam's hook entry back out of the agent's config file, leaving
// any other hooks untouched. A missing config file or one that never had beam installed is a
// no-op (removed: false), not an error -- 'beam uninstall' should never fail on an agent that
// was never wired up.
export async function uninstallHook(agentId: string, home = homedir()): Promise<UninstallResult> {
  const agent = findAgent(agentId);
  if (!agent) throw new Error(`Unknown agent '${agentId}'. Run 'beam agent list' to see supported agents.`);
  if (agent.id === "opencode" && agent.pluginPath) {
    const path = join(home, agent.pluginPath); const existing = await readFile(path, "utf8").catch(() => "");
    if (existing === OPEN_CODE_PLUGIN) { const { rm } = await import("node:fs/promises"); await rm(path, { force: true }); return { agent: agent.id, path, removed: true }; }
    return { agent: agent.id, path, removed: false };
  }
  if (!agent.hookConfigPath || !agent.unmergeHookConfig) throw new Error(`${agent.name} has no supported hook path yet; see 'beam agent list' for its status.`);

  const path = hookConfigFullPath(agent, home);

  let existing: Obj = {};
  let raw = "";
  try { raw = await readFile(path, "utf8"); existing = raw.trim() ? JSON.parse(raw) as Obj : {}; }
  catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { agent: agent.id, path, removed: false };
    if (e instanceof SyntaxError) throw new Error(`${path} contains invalid JSON; fix or remove it manually.`);
    throw e;
  }

  // Remove both the current absolute-path command and any pre-fix legacy "beam hook <agent>"
  // entry, so uninstall cleans up a machine regardless of which form was installed.
  const withoutCurrent = agent.unmergeHookConfig(existing, resolveHookCommand(agent.id));
  const updated = agent.unmergeHookConfig(withoutCurrent, legacyHookCommand(agent.id));
  const removed = JSON.stringify(updated) !== JSON.stringify(existing);
  if (removed) await writeFile(path, `${JSON.stringify(updated, null, 2)}\n`);

  return { agent: agent.id, path, removed };
}

// Attempts removal from every agent beam knows how to uninstall from, regardless of whether its
// presence-signal files still exist -- unlike installAllDetectedHooks, this errs on the side of
// trying rather than skipping, since a stale hook entry left behind after 'beam uninstall' is
// worse than one harmless extra file read.
export async function uninstallAllHooks(home = homedir()): Promise<UninstallResult[]> {
  const results: UninstallResult[] = [];
  for (const agent of AGENTS) {
    if (agent.id !== "opencode" && (!agent.hookConfigPath || !agent.unmergeHookConfig)) continue;
    results.push(await uninstallHook(agent.id, home));
  }
  return results;
}

async function isDetected(agent: AgentDefinition, home: string): Promise<boolean> {
  for (const relativePath of agent.configs) {
    try { await access(join(home, relativePath)); return true; } catch { /* check the next path */ }
  }
  return false;
}

// Detection only, no writes — lets a caller (e.g. `beam setup`) show what's on the machine
// and let the user choose before `installHook` touches anything.
export async function detectAgents(home = homedir()): Promise<AgentDefinition[]> {
  const found: AgentDefinition[] = [];
  for (const agent of AGENTS) {
    if (await isDetected(agent, home)) found.push(agent);
  }
  return found;
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
    if (agent.id !== "opencode" && (!agent.hookConfigPath || !agent.mergeHookConfig)) { results.push({ agent: agent.id, name: agent.name, status: "not-supported" }); continue; }
    try {
      const result = await installHook(agent.id, home);
      results.push({ agent: agent.id, name: agent.name, status: result.alreadyInstalled ? "already-installed" : "installed", path: result.path });
    } catch (e) {
      results.push({ agent: agent.id, name: agent.name, status: "error", error: e instanceof Error ? e.message : String(e) });
    }
  }
  return results;
}
