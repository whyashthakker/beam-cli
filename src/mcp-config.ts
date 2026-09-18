import { copyFile, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

type Obj = Record<string, unknown>;
const CONFIGS = [".claude.json", ".cursor/mcp.json", ".gemini/settings.json", ".config/claude/mcp.json"];

function isObj(value: unknown): value is Obj { return Boolean(value && typeof value === "object" && !Array.isArray(value)); }
function serverMap(doc: Obj): Obj | undefined {
  for (const key of ["mcpServers", "mcp_servers", "servers"]) if (isObj(doc[key])) return doc[key] as Obj;
  return undefined;
}
function alreadyWrapped(server: Obj): boolean {
  return server.command === "beam" && Array.isArray(server.args) && server.args[0] === "mcp" && server.args[1] === "proxy";
}

export interface McpInventory { name: string; command: string; args: string[]; configPath: string; status: "active" | "detected" }
export interface McpSetupResult { path: string; wrapped: number; skipped: number; servers: McpInventory[]; error?: string }

/** Wrap existing JSON MCP server commands without deleting the original configuration. */
export async function installMcpProxies(home = homedir()): Promise<McpSetupResult[]> {
  const results: McpSetupResult[] = [];
  for (const relative of CONFIGS) {
    const path = join(home, relative);
    let text: string;
    try { text = await readFile(path, "utf8"); } catch { continue; }
    let doc: Obj; try { doc = JSON.parse(text) as Obj; } catch { results.push({ path, wrapped: 0, skipped: 0, servers: [], error: "invalid JSON" }); continue; }
    const servers = serverMap(doc); if (!servers) continue;
    let wrapped = 0; let skipped = 0;
    const inventory: McpInventory[] = [];
    for (const [name, value] of Object.entries(servers)) {
      if (!isObj(value) || typeof value.command !== "string") { skipped++; continue; }
      const originalCommand = value.command;
      const originalArgs = Array.isArray(value.args) ? value.args.filter((arg): arg is string => typeof arg === "string") : [];
      inventory.push({ name, command: originalCommand, args: originalArgs, configPath: path, status: alreadyWrapped(value) ? "active" : "detected" });
      if (alreadyWrapped(value)) { skipped++; continue; }
      value.command = "beam";
      value.args = ["mcp", "proxy", originalCommand, ...originalArgs];
      wrapped++;
    }
    if (!wrapped) { results.push({ path, wrapped, skipped, servers: inventory }); continue; }
    try {
      await copyFile(path, `${path}.beam-mcp-backup`);
      await writeFile(path, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600 });
      results.push({ path, wrapped, skipped, servers: inventory });
    } catch (error) { results.push({ path, wrapped: 0, skipped, servers: inventory, error: error instanceof Error ? error.message : String(error) }); }
  }
  return results;
}
