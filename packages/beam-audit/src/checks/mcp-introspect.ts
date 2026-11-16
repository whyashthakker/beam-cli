// Live MCP tool enumeration: config-only checks in mcp.ts can't answer "how many tools does this
// server expose, which are write-shaped, could a read tool reach PII" -- that requires actually
// starting the server and calling the real MCP tools/list method. Gated behind --online since it is
// the one check in this package that starts a third-party process. The child is given a minimal,
// scrubbed environment (PATH only) so this probe itself cannot hand the scanner's real credentials to
// a potentially malicious server. No tool is ever invoked -- only the read-only tools/list handshake.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { agentConfigurations, readConfiguration } from '../config-files.js';
import type { AuditContext, Check } from '../types.js';

interface DiscoveredServer { file: string; name: string; command: string; args: string[]; }

function discoverStdioServers(ctx: AuditContext): DiscoveredServer[] {
  const files = [...new Set([...agentConfigurations(ctx).flatMap(a => a.paths), ...ctx.repos.map(r => join(r, '.mcp.json'))])].filter(existsSync);
  const out: DiscoveredServer[] = []; const seen = new Set<string>();
  for (const file of files) {
    let config: any; try { config = readConfiguration(file); } catch { continue; }
    const maps = [config.mcpServers, config.mcp_servers, config.mcp?.servers, config.mcp, config.servers, ...Object.values(config.projects ?? {}).slice(0, 500).map((p: any) => p?.mcpServers)];
    for (const servers of maps) if (servers && typeof servers === 'object') for (const [name, value] of Object.entries(servers).slice(0, 500)) {
      const server = value as any; if (!server || typeof server !== 'object') continue;
      const key = `${file}:${name}`; if (seen.has(key)) continue; seen.add(key);
      if (server.disabled === true || server.enabled === false) continue;
      const command = Array.isArray(server.command) ? server.command[0] : server.command;
      if (typeof command !== 'string') continue; // remote (url/httpUrl) servers are out of scope for this stdio probe
      const args = [...(Array.isArray(server.command) ? server.command.slice(1) : []), ...(Array.isArray(server.args) ? server.args : [])].filter((v: any) => typeof v === 'string') as string[];
      out.push({ file, name, command, args });
    }
  }
  return out.slice(0, 20);
}

type ToolListResult = { tools: Array<{ name: string; description: string }> } | { error: string };

function listTools(command: string, args: string[], timeoutMs = 8000): Promise<ToolListResult> {
  return new Promise(resolve => {
    let child; try { child = spawn(command, args, { stdio: ['pipe', 'pipe', 'ignore'], env: { PATH: process.env.PATH ?? '' } }); } catch (e: any) { resolve({ error: String(e?.message ?? e) }); return; }
    let buffer = ''; let settled = false;
    const done = (result: ToolListResult) => { if (settled) return; settled = true; clearTimeout(timer); try { child.kill(); } catch { /* already exited */ } resolve(result); };
    const timer = setTimeout(() => done({ error: 'Timed out waiting for a tools/list response.' }), timeoutMs);
    child.once('error', (e: any) => done({ error: String(e?.message ?? e) }));
    child.once('exit', (code) => done({ error: `Process exited (code ${code}) before a tools/list response arrived.` }));
    child.stdout?.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\n'); buffer = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim()) continue;
        let msg: any; try { msg = JSON.parse(line); } catch { continue; }
        if (msg.id === 1 && msg.result) {
          child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
          child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) + '\n');
        }
        if (msg.id === 2) {
          if (Array.isArray(msg.result?.tools)) done({ tools: msg.result.tools.map((t: any) => ({ name: String(t?.name ?? ''), description: String(t?.description ?? '') })) });
          else done({ error: 'Server responded to tools/list without a tools array.' });
        }
      }
    });
    try { child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'beam-audit', version: '0' } } }) + '\n'); }
    catch (e: any) { done({ error: String(e?.message ?? e) }); }
  });
}

function classify(name: string, description: string): 'write' | 'read' | 'unclear' {
  const text = `${name} ${description}`;
  if (/\b(write|create|delete|remove|update|insert|execute|run|post|put|patch|modify|send|upload|exec)\b/i.test(text)) return 'write';
  if (/\b(read|get|list|search|query|fetch|find|view)\b/i.test(text)) return 'read';
  return 'unclear';
}
const SENSITIVE_DATA = /customer|personal data|\bpii\b|\bphi\b|patient|social security|email address|credit card|\brecords?\b/i;

export async function mcpToolIntrospectionChecks(ctx: AuditContext): Promise<Check[]> {
  const base = { category: 'Third-party integrations and supply chain' as const, policySection: '3 / 7' };
  const servers = discoverStdioServers(ctx);
  if (!servers.length) return [{ ...base, id: 'mcp-tool-introspection', title: 'Live MCP tool enumeration', status: 'skip', detail: 'No local-process (stdio) MCP server declarations were found to introspect. Remote (URL-based) MCP servers are not probed by this check.' }];
  const out: Check[] = [];
  for (const s of servers) {
    const result = await listTools(s.command, s.args);
    if ('error' in result) { out.push({ ...base, id: `mcp-tools-${s.file}-${s.name}`, title: `MCP live tool list: ${s.name}`, status: 'skip', detail: `Could not enumerate tools (${result.error}). The server was started with a minimal environment (PATH only, no inherited credentials) for this probe; a server that requires other environment variables to start may fail here without that being a security problem on its own.`, evidence: [s.file] }); continue; }
    const classified = result.tools.map(t => ({ ...t, kind: classify(t.name, t.description) }));
    const writeTools = classified.filter(t => t.kind === 'write');
    const readTools = classified.filter(t => t.kind === 'read');
    const sensitiveReadTools = readTools.filter(t => SENSITIVE_DATA.test(t.description));
    out.push({
      ...base,
      id: `mcp-tools-${s.file}-${s.name}`,
      title: `MCP live tool list: ${s.name}`,
      status: sensitiveReadTools.length ? 'fail' : 'warn',
      detail: `${classified.length} tool(s) enumerated via a live tools/list call (no tool was invoked). ${writeTools.length} classified write-shaped by name/description, ${readTools.length} read-shaped, ${classified.length - writeTools.length - readTools.length} unclear. ${sensitiveReadTools.length} read-shaped tool(s) mention customer/personal-data-shaped terms in their own self-reported description${sensitiveReadTools.length ? `: ${sensitiveReadTools.map(t => t.name).join(', ')}` : ''}. Classification is by tool name/description text only -- it does not trace actual data access, and a server's self-reported description may not reflect its real behavior.`,
      evidence: [s.file, ...classified.map(t => `${t.kind.toUpperCase()}: ${t.name} - ${t.description.slice(0, 160)}`)],
    });
  }
  return out;
}
