import { existsSync, statSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { agentConfigurations, readConfiguration } from '../config-files.js';
import { literalCredential } from './agent-controls.js';
import type { AuditContext, Check } from '../types.js';
export function mcpChecks(ctx: AuditContext): Check[] {
 const files = [...new Set([...agentConfigurations(ctx).flatMap(a=>a.paths), ...ctx.repos.map(r=>join(r,'.mcp.json'))])].filter(existsSync);
 const out: Check[]=[];
 for(const file of files) {
  let config: any;
  try { config=readConfiguration(file); } catch { out.push({id:`mcp-parse-${file}`,category:'Scan coverage and evidence',policySection:'3 / Scope',title:'MCP configuration unreadable',status:'skip',detail:'Configuration is invalid, unreadable, or exceeds 2 MB; no servers inferred.',evidence:[file]});continue; }
  const maps=[config.mcpServers,config.mcp_servers,config.mcp?.servers,config.mcp,config.servers,...Object.values(config.projects??{}).slice(0,500).map((p:any)=>p?.mcpServers)];
  const seen=new Set<string>();
  for(const servers of maps) if(servers && typeof servers==='object') for(const [name,value] of Object.entries(servers).slice(0,500)) {
   const server=value as any; if(!server||typeof server!=='object'||seen.has(name))continue;
   if(!('command' in server)&&!('url' in server)&&!('httpUrl' in server)&&!('type' in server))continue;
   seen.add(name);
   const disabled=server.disabled===true||server.enabled===false;
   const destination=server.url??server.httpUrl;
   const remote=typeof destination==='string'; let insecure=false,unapprovedOrigin=false;
   if(remote)try{const url=new URL(destination);insecure=url.protocol!=='https:'||Boolean(url.username||url.password);unapprovedOrigin=Boolean(ctx.agentControls?.allowedEndpointOrigins&&!ctx.agentControls.allowedEndpointOrigins.some(origin=>new URL(origin).origin===url.origin));}catch{insecure=true;}
   const unapprovedName=ctx.agentControls?.allowedMcpServers!==undefined&&!ctx.agentControls.allowedMcpServers.includes(name);
   out.push({id:`mcp-${file}-${name}`,category:'Third-party integrations and supply chain',policySection:'3 / 7',title:`MCP server: ${name}`,status:!disabled&&(insecure||unapprovedOrigin||unapprovedName)?'fail':'warn',detail:`Configured ${remote?'remote':'local process'} integration${disabled?' (disabled declaration)':''}. ${insecure?'Remote endpoint is invalid, embeds credentials, or lacks HTTPS. ':''}${unapprovedOrigin?'Origin is outside the organization allowlist. ':''}${unapprovedName?'Server name is outside the organization allowlist. ':''}Configuration does not establish an active authenticated connection. Commands, arguments, endpoint values, headers, and credential values are omitted.`,evidence:[file]});
   const auto=server.trust===true||server.autoApprove===true||Array.isArray(server.autoApprove)&&server.autoApprove.length>0||Array.isArray(server.alwaysAllow)&&server.alwaysAllow.length>0;
   if(auto)out.push({id:`mcp-approval-${file}-${name}`,category:'Agent permissions and bypasses',policySection:'4.3 / 7',title:`MCP automatic tool approval: ${name}`,status:!disabled&&ctx.agentControls?.requireManualApproval?'fail':'warn',detail:'Trust or tool-auto-approval declarations exist. Review their applicability and required human approval before execution.',evidence:[file]});
   const command=Array.isArray(server.command)?server.command[0]:server.command;
   const args=[...(Array.isArray(server.command)?server.command.slice(1):[]),...(Array.isArray(server.args)?server.args:[])].filter((v:any)=>typeof v==='string') as string[];
   if(typeof command==='string'&&/(?:^|[/\\])npx(?:\.cmd|\.exe)?$/.test(command)){
    const packages=args.filter(a=>!a.startsWith('-')&&/^(?:@[\w.-]+\/)?[\w.-]+(?:@[^\s]+)?$/.test(a));
    const pinned=packages.length>0&&packages.every(p=>/@\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(p));
    out.push({id:`mcp-pinning-${file}-${name}`,category:'Third-party integrations and supply chain',policySection:'7',title:`MCP npm launcher pinning: ${name}`,status:pinned?'pass':!disabled&&ctx.agentControls?.requirePinnedMcpPackages?'fail':'warn',detail:pinned?'Recognized exact package release arguments. Registry provenance, package integrity and active process version remain unverified.':'No complete set of exact npm package release arguments could be established; tags, ranges and missing versions require review. No packages were downloaded or executed.',evidence:[file]});
   }
   if(typeof command==='string'&&isAbsolute(command))try{const st=statSync(command);out.push({id:`mcp-executable-${file}-${name}`,category:'Third-party integrations and supply chain',policySection:'7',title:`MCP local executable permissions: ${name}`,status:ctx.platform==='win32'?'skip':st.mode&0o022?'fail':'warn',detail:ctx.platform==='win32'?'Executable ACL verification requires additional evidence.':st.mode&0o022?'Referenced executable is group/world writable. Review who can modify the server code.':'No group/world write bits on the referenced executable. Its publisher, dependencies, parent directories and integrity are unverified.',evidence:[file]});}catch{out.push({id:`mcp-executable-${file}-${name}`,category:'Third-party integrations and supply chain',policySection:'7',title:`MCP local executable unavailable: ${name}`,status:'skip',detail:'Absolute executable path could not be inspected. No server was started.',evidence:[file]});}
   const inline=typeof command==='string'&&/(?:^|[/\\])(?:sh|bash|zsh|cmd|powershell|pwsh|node|python[\d.]*)$/.test(command)&&args.some(a=>['-c','-e','-Command','/c'].includes(a));
   if(inline)out.push({id:`mcp-inline-${file}-${name}`,category:'Third-party integrations and supply chain',policySection:'7',title:`MCP inline code launcher: ${name}`,status:'warn',detail:'The server launcher can execute inline code or shell commands. Review provenance and the full command locally; arguments are omitted and were not executed.',evidence:[file]});
   const env=server.env;
   if(env&&typeof env==='object'&&Object.entries(env).some(([key,v])=>/TOKEN|SECRET|PASSWORD|API_KEY/i.test(key)&&literalCredential(v)))out.push({id:`mcp-credential-${file}-${name}`,category:'Sensitive data exposure',policySection:'6.1',title:`MCP literal credential environment: ${name}`,status:'warn',detail:'Secret-named environment fields contain literal-looking values. Use approved secret references and inspect access permissions; all values omitted.',evidence:[file]});
  }
 }
 if(!out.length)out.push({id:'mcp-discovery',category:'Third-party integrations and supply chain',policySection:'3',title:'MCP server discovery',status:'skip',detail:'No declarations found in supported JSON/JSONC/TOML stores. Unsupported client stores and active connection status remain unverified.'});
 return out;
}
