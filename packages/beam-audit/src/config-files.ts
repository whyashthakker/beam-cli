import { readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parse as parseToml } from '@iarna/toml';
import { parse as parseJsonc, type ParseError } from 'jsonc-parser';
import type { AuditContext } from './types.js';
export function readConfiguration(file:string):any {
 if(statSync(file).size>2_000_000)throw new Error('Configuration exceeds 2 MB');
 const raw=readFileSync(file,'utf8');
 if(file.endsWith('.toml'))return parseToml(raw);
 const errors:ParseError[]=[]; const result=parseJsonc(raw,errors,{allowTrailingComma:true});
 if(errors.length||!result||typeof result!=='object'||Array.isArray(result))throw new Error('Invalid configuration');return result;
}
export function agentConfigurations(ctx:AuditContext){
 const env=ctx.environment??process.env;
 const codex=env.CODEX_HOME?resolve(env.CODEX_HOME):join(ctx.home,'.codex');
 const claude=env.CLAUDE_CONFIG_DIR?resolve(env.CLAUDE_CONFIG_DIR):join(ctx.home,'.claude');
 const app=ctx.platform==='win32'?join(ctx.home,'AppData/Roaming'):ctx.platform==='darwin'?join(ctx.home,'Library/Application Support'):join(ctx.home,'.config');
 return [
 {name:'Claude Code',paths:[join(ctx.home,'.claude.json'),join(claude,'settings.json'),join(claude,'settings.local.json'),...managedConfigurationPaths(ctx).filter(x=>x.agent==='Claude Code').map(x=>x.path),...ctx.repos.flatMap(r=>[join(r,'.claude/settings.json'),join(r,'.claude/settings.local.json')])]},
 {name:'Codex',paths:[join(codex,'config.toml'),...ctx.repos.map(r=>join(r,'.codex/config.toml'))]},
 {name:'Cursor',paths:[join(ctx.home,'.cursor/mcp.json'),join(app,'Cursor/User/settings.json'),...ctx.repos.map(r=>join(r,'.cursor/mcp.json'))]},
 {name:'Gemini CLI',paths:[join(ctx.home,'.gemini/settings.json'),...ctx.repos.map(r=>join(r,'.gemini/settings.json'))]},
 {name:'GitHub Copilot CLI',paths:[join(ctx.home,'.copilot/config.json')]},
 {name:'VS Code / Copilot / Cline / Roo',paths:[join(app,'Code/User/settings.json'),join(app,'Code/User/mcp.json'),join(app,'Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json'),join(app,'Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json'),...ctx.repos.flatMap(r=>[join(r,'.vscode/settings.json'),join(r,'.vscode/mcp.json')])]},
 {name:'OpenCode',paths:[join(ctx.home,'.config/opencode/opencode.json'),join(ctx.home,'.config/opencode/opencode.jsonc'),...ctx.repos.flatMap(r=>[join(r,'opencode.json'),join(r,'opencode.jsonc')])]},
 ];
}

export function managedConfigurationPaths(ctx: AuditContext): Array<{agent: string; path: string}> {
 const env=ctx.environment??process.env;
 const claude=ctx.platform==='win32'?join(env.ProgramFiles??'C:\\Program Files','ClaudeCode/managed-settings.json'):ctx.platform==='darwin'?'/Library/Application Support/ClaudeCode/managed-settings.json':'/etc/claude-code/managed-settings.json';
 return [{agent:'Claude Code',path:claude}, ...(ctx.platform==='win32'?[]:[{agent:'Codex',path:'/etc/codex/requirements.toml'}])];
}
