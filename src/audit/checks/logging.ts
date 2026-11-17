import { readdirSync, lstatSync, openSync, readSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditContext, Check } from '../types.js';
export function loggingChecks(ctx:AuditContext):Check[] {
 const out:Check[]=[];
 for(const folder of ['.claude/projects','.codex/sessions','.gemini/tmp','.copilot/session-state']) {
  const root=join(ctx.home,folder);let count=0,unreadable=0,limited=false,worldReadable=0,writable=0;let newest=0,oldest=Infinity,visited=0;
  const fields=new Set<string>();
  function walk(dir:string,depth:number){if(depth>6||count>=200||visited++>=1000){limited=true;return;}
   let entries:string[];try{entries=readdirSync(dir);}catch{unreadable++;return;}
   for(const entry of entries){if(count>=200){limited=true;break;}const path=join(dir,entry);try{const st=lstatSync(path);if(st.isSymbolicLink())continue;if(st.isDirectory()){walk(path,depth+1);continue;}if(!/\.(jsonl?|log)$/i.test(entry))continue;
    count++;newest=Math.max(newest,st.mtimeMs);oldest=Math.min(oldest,st.mtimeMs);if(st.mode&0o004)worldReadable++;if(st.mode&0o200)writable++;
    const fd=openSync(path,'r');const buffer=Buffer.alloc(65536);let bytes=0;try{bytes=readSync(fd,buffer,0,buffer.length,0);}finally{closeSync(fd);}
    for(const line of buffer.toString('utf8',0,bytes).split('\n')){try{const event=JSON.parse(line);const keys=Object.keys(event);if(keys.some(k=>/timestamp|created_at|time$/i.test(k)))fields.add('timestamp');if(keys.some(k=>/session.?id/i.test(k)))fields.add('session');if(keys.some(k=>/user.?id|actor/i.test(k)))fields.add('actor');if(/tool_use|tool_call|function_call/.test(line))fields.add('tool event');if(/tool_result|function_call_output|exit_code/.test(line))fields.add('tool outcome');}catch{/* partial or non-JSON line */}}
   }catch{unreadable++;}}
  }
  walk(root,0);
  out.push({id:`log-evidence-${folder}`,category:'Logging and incident traceability',policySection:'8.2',title:`Audit trail evidence: ${folder}`,status:count?'warn':'skip',detail:count?`${count} files sampled; observed fields: ${[...fields].join(', ')||'none recognized'}. File modification span: ${new Date(oldest).toISOString()} to ${new Date(newest).toISOString()}. ${writable} owner-writable files; local history alone does not provide tamper protection. Retention policy and central collection require organization evidence. ${limited?'Sampling limit reached. ':''}${unreadable} inaccessible paths.`:'No readable supported log files found. This does not establish that logging is disabled.',evidence:count?[root]:[]});
  if(count&&ctx.platform!=='win32')out.push({id:`log-permissions-${folder}`,category:'Logging and incident traceability',policySection:'8.2',title:`Local log confidentiality: ${folder}`,status:worldReadable?'warn':'pass',detail:`${worldReadable} of ${count} sampled files grant world-read permission. ACLs and inherited access were not evaluated.`,evidence:[root]});
 }
 return out;
}
