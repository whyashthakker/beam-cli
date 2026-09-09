import { access } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Event } from "./core.js";
const definitions = [
  { agent: "claude-code", name: "Claude Code", configs: [".claude/settings.json"], artifacts: [".claude/projects"], integration: "Beam stdin hook" },
  { agent: "codex", name: "Codex", configs: [".codex/config.toml"], artifacts: [".codex/sessions"], integration: "Custom capture; hook trust may be required" },
  { agent: "cursor", name: "Cursor", configs: [".cursor/mcp.json", ".cursor/hooks.json"], artifacts: [".cursor/projects"], integration: "Custom capture; check upstream coverage" },
  { agent: "gemini", name: "Gemini CLI", configs: [".gemini/settings.json"], artifacts: [".gemini/tmp"], integration: "Custom hooks" },
  { agent: "copilot", name: "Copilot CLI", configs: [".copilot/config.json"], artifacts: [".copilot/session-state"], integration: "Artifact import; check upstream coverage" },
  { agent: "opencode", name: "OpenCode", configs: [".config/opencode/opencode.json"], artifacts: [".local/share/opencode"], integration: "Custom capture; check upstream coverage" },
];
export async function inventory(events: Event[], home = homedir()) {
  const exists = async (paths: string[]) => (await Promise.all(paths.map(async p => { try { await access(join(home, p)); return true; } catch { return false; } }))).some(Boolean);
  return Promise.all(definitions.map(async d => {
    const matches = events.filter(e => e.agent === d.agent || e.agent === d.agent.replace("-code", ""));
    const last = matches.reduce<string | null>((value, e) => !value || e.receivedAt > value ? e.receivedAt : value, null);
    return { agent: d.agent, name: d.name, configPresent: await exists(d.configs), artifactsPresent: await exists(d.artifacts), captureStatus: last ? "records received" : "not verified", lastReceived: last, integration: d.integration };
  }));
}
