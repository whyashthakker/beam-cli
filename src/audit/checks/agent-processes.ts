import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import type { AuditContext, Check } from '../types.js';

// Only flag names are returned. Prompts, arguments, tokens and raw command lines are never retained.
export function bypassArguments(args: string[]): string[] {
 const signals = new Set<string>();
 for (let i=0;i<args.length;i++) {
  const arg=args[i]!;if(arg==='--')break;
  if(['--dangerously-skip-permissions','--dangerously-bypass-approvals-and-sandbox','--yolo','--allow-all-tools','--allow-all-paths','--allow-all-urls','--full-auto','--autopilot'].includes(arg))signals.add(arg);
  for(const [flag,values] of [['--approval-policy',['never']],['--approval-mode',['yolo','auto_edit']],['--ask-for-approval',['never']],['--sandbox',['danger-full-access']],['--sandbox-mode',['danger-full-access']],['--permission-mode',['bypassPermissions','auto','acceptEdits']]] as const){
   if(arg===flag&&values.some(v=>v===args[i+1])||values.some(v=>arg===`${flag}=${v}`))signals.add(flag);
  }
  if((arg==='-c'||arg==='--config')&&/^(?:approval_policy\s*=\s*["']?never|sandbox_mode\s*=\s*["']?danger-full-access)/.test(args[i+1]??''))signals.add('configuration override');
 }
 return [...signals];
}
const known = new Set(['claude','codex','gemini','copilot','opencode','cursor']);
export function agentProcessChecks(ctx:AuditContext):Check[]{
 const checks:Check[]=[];const started=Date.now();let candidates=0;
 const add=(name:string,pid:number,args:string[],exact:boolean)=>{
  const flags=bypassArguments(args);
  checks.push({id:`agent-process-${pid}`,category:'Agent permissions and bypasses',policySection:'3 / 4.3',title:`Running agent candidate: ${name}`,status:'warn',detail:`Current-user process ${pid}; ${flags.length} bypass/automatic-approval argument signals${flags.length?`: ${flags.join(', ')}`:''}. ${exact?'Arguments read as separate OS tokens.':'Text command-line parsing is ambiguous; treat matches as review signals.'} Executable identity, inherited settings, flags inside positional input, and managed enforcement remain unverified. Prompts and command-line values omitted.`});
 };
 if(ctx.platform==='linux'||ctx.platform==='darwin'){
  const uid=process.getuid?.();
  const listing=spawnSync('ps',['-axo','uid=,pid=,comm='],{encoding:'utf8',timeout:3000,maxBuffer:2*1024*1024});
  if(listing.status===0&&uid!==undefined)for(const line of listing.stdout.split('\n')){
   if(candidates>=32||Date.now()-started>10000)break;
   const match=/^\s*(\d+)\s+(\d+)\s+(.+)$/.exec(line);if(!match||Number(match[1])!==uid)continue;
   const name=basename(match[3]!).toLowerCase();if(!known.has(name))continue;
   candidates++;const pid=Number(match[2]);
   if(ctx.platform==='linux')try{const raw=readFileSync(`/proc/${pid}/cmdline`);if(raw.length>262144)continue;add(name,pid,raw.toString('utf8').split('\0').filter(Boolean),true);}catch{}
   else {const result=spawnSync('ps',['-p',String(pid),'-o','args='],{encoding:'utf8',timeout:2000,maxBuffer:262144});if(result.status===0)add(name,pid,result.stdout.trim().split(/\s+/),false);}
  }
 }else if(ctx.platform==='win32'){
  const script="$ErrorActionPreference='Stop'; $me=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; @(Get-CimInstance Win32_Process | Where-Object {$_.Name -match '^(claude|codex|gemini|copilot|opencode|cursor)(\\.exe)?$'} | Select-Object -First 32 | ForEach-Object {$owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwner; if(($owner.Domain+'\\'+$owner.User) -eq $me){[pscustomobject]@{name=$_.Name;pid=$_.ProcessId;command=$_.CommandLine}}}) | ConvertTo-Json -Compress";
  const result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8',timeout:10000,maxBuffer:2*1024*1024});
  if(result.status===0)try{const data=JSON.parse(result.stdout);for(const item of Array.isArray(data)?data:[data])if(item&&typeof item.name==='string'&&Number.isSafeInteger(item.pid)&&typeof item.command==='string'){candidates++;add(item.name,item.pid,item.command.split(/\s+/),false);}}catch{}
 }
 checks.push({id:'agent-process-coverage',category:'Scan coverage and evidence',policySection:'Scope',title:'Running-agent inspection coverage',status:checks.length?'warn':'skip',detail:`${checks.length} current-user process candidates inspected; limit 32 candidates and a 10-second inspection budget. Node/Python wrappers, remote agents, other users, exited processes, and inaccessible metadata can be missed. No absence-of-bypass conclusion is inferred.`});
 return checks;
}
