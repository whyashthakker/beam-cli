import { access } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CUSTOM_INSTALLERS } from './agent-installers.js';
import { catalogInstaller, agentDetectionPaths } from './agent-hook-install.js';
import { hookSpec } from './hook-catalog.js';
import { AGENTS, findAgent, type AgentDefinition } from './agents.js';

export interface InstallResult { agent: string; path: string; alreadyInstalled: boolean; note?: string }
export interface UninstallResult { agent: string; path: string; removed: boolean; note?: string }
function installer(agentId: string, settings?: string) {
  const agent = findAgent(agentId);
  if (!agent) throw new Error(`Unknown agent '${agentId}'. Run 'beam agent list' to see supported agents.`);
  if (!agent.customInstall) throw new Error(`${agent.name} has no supported hook install path yet.`);
  if (settings && agentId === 'openclaw') throw new Error('OpenClaw uses plugin registration; --settings is not supported.');
  return settings ? catalogInstaller(hookSpec(agentId)!, settings) : CUSTOM_INSTALLERS[agentId];
}
export async function installHook(agentId: string, home = homedir(), settings?: string): Promise<InstallResult> {
  const result = await installer(agentId, settings).install(home, { nodePath: process.execPath, cliPath: fileURLToPath(new URL('./cli.js', import.meta.url)), agentId: agentId === "vscode" ? "copilot-cli" : agentId });
  return { agent: agentId, ...result };
}
export async function uninstallHook(agentId: string, home = homedir(), settings?: string): Promise<UninstallResult> {
  return { agent: agentId, ...await installer(agentId, settings).uninstall(home) };
}
export async function isHookInstalled(agentId: string, home = homedir(), settings?: string): Promise<boolean> {
  if (!findAgent(agentId)?.customInstall) return false;
  try { return await installer(agentId, settings).isInstalled(home); } catch { return false; }
}
export async function uninstallAllHooks(home = homedir()): Promise<UninstallResult[]> {
  const results: UninstallResult[] = [];
  for (const agent of AGENTS) if (agent.customInstall && agent.id !== 'openhands') results.push(await uninstallHook(agent.id, home));
  return results;
}
export async function installedHookAgentIds(home = homedir()): Promise<string[]> {
  const ids: string[] = [];
  for (const agent of AGENTS) if (agent.id !== 'openhands' && await isHookInstalled(agent.id, home)) ids.push(agent.id);
  return ids;
}
async function isDetected(agent: AgentDefinition, home: string): Promise<boolean> {
  if (agent.id === 'openhands') return false; // only install with an explicit project path
  const spec = hookSpec(agent.id);
  for (const path of spec ? agentDetectionPaths(spec, home) : agent.configs.map(p => join(home, p))) {
    try { await access(path); return true; } catch { /* next presence signal */ }
  }
  return false;
}
export async function detectAgents(home = homedir()): Promise<AgentDefinition[]> {
  const found: AgentDefinition[] = [];
  for (const agent of AGENTS) if (await isDetected(agent, home)) found.push(agent);
  return found;
}
export type InstallAllStatus = 'installed' | 'already-installed' | 'not-detected' | 'not-supported' | 'error';
export interface InstallAllResult { agent: string; name: string; status: InstallAllStatus; path?: string; error?: string; note?: string }
export async function installAllDetectedHooks(home = homedir()): Promise<InstallAllResult[]> {
  const results: InstallAllResult[] = [];
  for (const agent of AGENTS) {
    if (!(await isDetected(agent, home))) { results.push({ agent: agent.id, name: agent.name, status: 'not-detected' }); continue; }
    if (!agent.customInstall) { results.push({ agent: agent.id, name: agent.name, status: 'not-supported' }); continue; }
    // Copilot and VS Code load the same file. The runtime resolves the actual host.
    if (agent.id === 'vscode' && results.some(r => r.agent === 'copilot-cli' && ['installed','already-installed'].includes(r.status))) {
      results.push({ agent: agent.id, name: agent.name, status: 'already-installed', note: 'Uses the shared Copilot hook file.' }); continue;
    }
    try {
      const result = await installHook(agent.id, home);
      results.push({ agent: agent.id, name: agent.name, status: result.alreadyInstalled ? 'already-installed' : 'installed', path: result.path, note: result.note });
    } catch (e) { results.push({ agent: agent.id, name: agent.name, status: 'error', error: e instanceof Error ? e.message : String(e) }); }
  }
  return results;
}
