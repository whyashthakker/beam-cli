// Live MCP tool enumeration: config-only checks in mcp.ts can't answer "how many tools does this
// server expose, which are write-shaped, could a read tool reach PII" -- that requires actually
// starting the server (stdio) or calling it directly (remote, over HTTP/SSE) and running the real
// MCP tools/list method. No tool is ever invoked -- only the read-only initialize/tools/list
// handshake.
//
// Two tiers, by default-safety:
//  - stdio servers always get probed, but with a minimal, scrubbed environment (PATH only) unless
//    --online is given -- a local spawn of a declared command is low-risk either way, but not
//    forwarding the server's own declared credentials is the conservative default.
//  - remote (url/httpUrl) servers, and the env passthrough stdio servers need to actually
//    authenticate (e.g. the common `npx mcp-remote <url> --header Authorization:${TOKEN}` bridge
//    pattern), require --online: unlike a local spawn, this makes a real authenticated network
//    request to a third-party SaaS endpoint using a live credential already sitting in the user's
//    own config file. Without --online, a remote/credentialed server still gets a row explaining why
//    it wasn't probed, instead of silently disappearing.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { agentConfigurations, readConfiguration } from '../config-files.js';
import type { AuditContext, Check } from '../types.js';

interface StdioServer { file: string; name: string; kind: 'stdio'; command: string; args: string[]; env: Record<string, string> }
interface RemoteServer { file: string; name: string; kind: 'remote'; url: string; headers: Record<string, string> }
type DiscoveredServer = StdioServer | RemoteServer;

function stringEnv(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter((e): e is [string, string] => typeof e[1] === 'string'));
}

// VS Code and some other clients let a header value reference a sibling `env` entry as
// `${NAME}`; others resolve that themselves before writing it to disk, so most config files we
// see already hold a literal value. Handle both rather than assume one.
function resolvePlaceholders(headers: Record<string, string>, env: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, v.replace(/\$\{([A-Za-z0-9_]+)\}/g, (m, name) => env[name] ?? m)]));
}

function discoverServers(ctx: AuditContext): DiscoveredServer[] {
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
      if (typeof command === 'string') {
        const args = [...(Array.isArray(server.command) ? server.command.slice(1) : []), ...(Array.isArray(server.args) ? server.args : [])].filter((v: any) => typeof v === 'string') as string[];
        out.push({ file, name, kind: 'stdio', command, args, env: stringEnv(server.env) });
        continue;
      }
      const url = typeof server.url === 'string' ? server.url : typeof server.httpUrl === 'string' ? server.httpUrl : undefined;
      if (url && /^https?:\/\//i.test(url)) {
        const env = stringEnv(server.env);
        out.push({ file, name, kind: 'remote', url, headers: resolvePlaceholders(stringEnv(server.headers), env) });
      }
      // Anything else (an unrecognized shape) is skipped rather than guessed.
    }
  }
  return out.slice(0, 20);
}

type ToolListResult = { tools: Array<{ name: string; description: string }> } | { error: string };

function listToolsStdio(command: string, args: string[], env: Record<string, string>, timeoutMs = 8000): Promise<ToolListResult> {
  return new Promise(resolve => {
    let child; try { child = spawn(command, args, { stdio: ['pipe', 'pipe', 'ignore'], env: { PATH: process.env.PATH ?? '', ...env } }); } catch (e: any) { resolve({ error: String(e?.message ?? e) }); return; }
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

// MCP's Streamable HTTP transport: POST the JSON-RPC body; the response is either a plain JSON
// object or a single-event SSE stream (`data: <json>`), and the server may hand back a session id
// to echo on subsequent calls. One POST for `initialize`, one for `tools/list` -- no tool is ever
// invoked.
async function postMcp(url: string, headers: Record<string, string>, body: unknown, timeoutMs: number): Promise<{ json?: any; status: number; sessionId?: string; wwwAuthenticate?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const sessionId = res.headers.get('mcp-session-id') ?? undefined;
    const wwwAuthenticate = res.headers.get('www-authenticate') ?? undefined;
    const text = await res.text();
    if (!text.trim()) return { status: res.status, sessionId, wwwAuthenticate };
    const contentType = res.headers.get('content-type') ?? '';
    if (contentType.includes('text/event-stream')) {
      const dataLine = text.split('\n').find(l => l.startsWith('data:'));
      if (!dataLine) return { status: res.status, sessionId, wwwAuthenticate };
      try { return { json: JSON.parse(dataLine.slice(5).trim()), status: res.status, sessionId, wwwAuthenticate }; }
      catch { return { status: res.status, sessionId, wwwAuthenticate }; }
    }
    try { return { json: JSON.parse(text), status: res.status, sessionId, wwwAuthenticate }; }
    catch { return { status: res.status, sessionId, wwwAuthenticate }; }
  } finally { clearTimeout(timer); }
}

async function listToolsRemote(url: string, headers: Record<string, string>, timeoutMs = 10000): Promise<ToolListResult> {
  try {
    const init = await postMcp(url, headers, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'beam-audit', version: '0' } } }, timeoutMs);
    if (init.status === 401 || init.status === 403) return { error: `Server requires authentication this probe doesn't have (HTTP ${init.status}${init.wwwAuthenticate ? `, ${init.wwwAuthenticate}` : ''}). This probe does not perform interactive OAuth flows.` };
    if (!init.json?.result) return { error: `No usable initialize response (HTTP ${init.status}).` };
    const sessionHeaders = init.sessionId ? { ...headers, 'Mcp-Session-Id': init.sessionId } : headers;
    await postMcp(url, sessionHeaders, { jsonrpc: '2.0', method: 'notifications/initialized' }, timeoutMs).catch(() => undefined);
    const list = await postMcp(url, sessionHeaders, { jsonrpc: '2.0', id: 2, method: 'tools/list' }, timeoutMs);
    if (list.status === 401 || list.status === 403) return { error: `Authentication was accepted for initialize but rejected for tools/list (HTTP ${list.status}).` };
    if (!Array.isArray(list.json?.result?.tools)) return { error: `No usable tools/list response (HTTP ${list.status}).` };
    return { tools: list.json.result.tools.map((t: any) => ({ name: String(t?.name ?? ''), description: String(t?.description ?? '') })) };
  } catch (e: any) {
    return { error: e?.name === 'AbortError' ? 'Timed out waiting for a response.' : String(e?.message ?? e) };
  }
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
  const servers = discoverServers(ctx);
  if (!servers.length) return [{ ...base, id: 'mcp-tool-introspection', title: 'Live MCP tool enumeration', status: 'skip', detail: 'No local-process (stdio) or remote (URL-based) MCP server declarations were found to introspect.' }];
  const out: Check[] = [];
  for (const s of servers) {
    const needsCredentials = s.kind === 'remote' || Object.keys(s.env).length > 0;
    if (needsCredentials && !ctx.online) {
      out.push({ ...base, id: `mcp-tools-${s.file}-${s.name}`, title: `MCP live tool list: ${s.name}`, status: 'skip', detail: `${s.kind === 'remote' ? 'This is a remote MCP server (reached over HTTP, not spawned locally).' : 'This stdio server declares its own environment variables (likely credentials it needs to connect to a remote service).'} Enumerating it requires sending its own declared credentials over the network, so it's skipped unless --online is given. Re-run with --online to probe it.`, evidence: [s.file] });
      continue;
    }
    const result = s.kind === 'stdio'
      ? await listToolsStdio(s.command, s.args, ctx.online ? s.env : {})
      : await listToolsRemote(s.url, s.headers);
    if ('error' in result) {
      const envNote = s.kind === 'stdio' && !ctx.online ? ' The server was started with a minimal environment (PATH only, no inherited credentials) for this probe; a server that requires other environment variables to start may fail here without that being a security problem on its own.' : '';
      out.push({ ...base, id: `mcp-tools-${s.file}-${s.name}`, title: `MCP live tool list: ${s.name}`, status: 'skip', detail: `Could not enumerate tools (${result.error}).${envNote}`, evidence: [s.file] });
      continue;
    }
    const classified = result.tools.map(t => ({ ...t, kind: classify(t.name, t.description) }));
    const writeTools = classified.filter(t => t.kind === 'write');
    const readTools = classified.filter(t => t.kind === 'read');
    const sensitiveReadTools = readTools.filter(t => SENSITIVE_DATA.test(t.description));
    out.push({
      ...base,
      id: `mcp-tools-${s.file}-${s.name}`,
      title: `MCP live tool list: ${s.name}`,
      status: sensitiveReadTools.length ? 'fail' : 'warn',
      detail: `${classified.length} tool(s) enumerated via a live tools/list call over ${s.kind === 'remote' ? 'HTTP' : 'stdio'} (no tool was invoked). ${writeTools.length} classified write-shaped by name/description, ${readTools.length} read-shaped, ${classified.length - writeTools.length - readTools.length} unclear. ${sensitiveReadTools.length} read-shaped tool(s) mention customer/personal-data-shaped terms in their own self-reported description${sensitiveReadTools.length ? `: ${sensitiveReadTools.map(t => t.name).join(', ')}` : ''}. Classification is by tool name/description text only -- it does not trace actual data access, and a server's self-reported description may not reflect its real behavior.`,
      evidence: [s.file, ...classified.map(t => `${t.kind.toUpperCase()}: ${t.name} - ${t.description.slice(0, 160)}`)],
    });
  }
  return out;
}
