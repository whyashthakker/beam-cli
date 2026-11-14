import { existsSync, lstatSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { AuditContext, Check } from '../types.js';
export function agentAuthenticationChecks(ctx: AuditContext): Check[] {
 const env=ctx.environment??process.env;
 const files=[{agent:'Codex',file:join(env.CODEX_HOME?resolve(env.CODEX_HOME):join(ctx.home,'.codex'),'auth.json')},{agent:'Claude Code',file:join(env.CLAUDE_CONFIG_DIR?resolve(env.CLAUDE_CONFIG_DIR):join(ctx.home,'.claude'),'.credentials.json')},{agent:'Gemini CLI',file:join(ctx.home,'.gemini/oauth_creds.json')}];
 const checks:Check[]=[];
 for(const item of files)if(existsSync(item.file)){
  let st;try{st=lstatSync(item.file);if(!st.isFile()||st.isSymbolicLink())throw new Error('not regular');}catch{checks.push({id:`auth-file-unreadable-${item.agent}`,category:'Sensitive data exposure',policySection:'6.1',title:`${item.agent}: credential cache inspection`,status:'skip',detail:'Credential path is linked, inaccessible, or not a regular file. No credential values read.',evidence:[item.file]});continue;}
  let method='unverified';
  try{if(st.size<=262144){const data=JSON.parse(readFileSync(item.file,'utf8'));if(['api','apikey','chatgpt','oauth'].includes(data.auth_mode))method=data.auth_mode;else if(data.claudeAiOauth)method='oauth';}}catch{}
  checks.push({id:`agent-auth-cache-${item.agent}`,category:'Sensitive data exposure',policySection:'3 / 5.1 / 5.6 / 6.1',title:`${item.agent}: on-disk credential cache`,status:'warn',detail:`Credential cache exists; authentication metadata: ${method}. Existence does not prove active login selection, commercial API tier, SSO/MFA, ownership, permitted training use, or approved storage. Secret values are never reported.`,evidence:[item.file]});
  if(ctx.platform==='win32'){
   // Literal path is escaped inside a PowerShell single-quoted string, then encoded as UTF-16.
   const literal=item.file.replace(/'/g,"''");const script=`$ErrorActionPreference='Stop'; @((Get-Acl -LiteralPath '${literal}').Access | ForEach-Object { $sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; if($_.AccessControlType -eq 'Allow' -and $sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545')) { [string]$_.FileSystemRights } }) | ConvertTo-Json -Compress`;
   const result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8',timeout:10000});
   checks.push({id:`agent-auth-permissions-${item.agent}`,category:'Sensitive data exposure',policySection:'6.1',title:`${item.agent}: credential cache ACL`,status:result.status!==0?'skip':/Read|FullControl|Modify/i.test(result.stdout??'')?'fail':'warn',detail:result.status!==0?'Credential ACL evidence unavailable.':'Checked explicit allow entries for Everyone, Authenticated Users and local Users. No broad read match does not establish effective ACL access, deny-rule precedence, or secret-store approval.',evidence:[item.file]});
  }else checks.push({id:`agent-auth-permissions-${item.agent}`,category:'Sensitive data exposure',policySection:'6.1',title:`${item.agent}: credential cache permissions`,status:st.mode&0o077?'fail':'pass',detail:st.mode&0o077?'Credential cache grants group/other permissions. Restrict access and review possible exposure.':'Credential cache has no POSIX group/other permission bits. Extended ACLs and filesystem backups remain unverified.',evidence:[item.file]});
 }
 const names=['ANTHROPIC_API_KEY','OPENAI_API_KEY','GEMINI_API_KEY','GOOGLE_API_KEY','ANTHROPIC_AUTH_TOKEN'].filter(name=>Boolean(env[name]));
 checks.push({id:'agent-auth-environment',category:'Organization policy compliance',policySection:'3 / 6.1',title:'Agent credential environment signals',status:names.length?'warn':'skip',detail:`${names.length} recognized credential variables present in the scanner environment. Values are not read into the report. This does not identify the credentials selected by each running agent or how they were originally stored.`});
 return checks;
}
