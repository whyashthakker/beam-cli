import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { readConfiguration } from '../config-files.js';
import { confidentHits, phiHits, CONFIDENTIAL_MARKER } from '../detectors.js';
import type { AuditContext, Check } from '../types.js';
export function agentMemoryAndPluginChecks(ctx:AuditContext):Check[]{
 const checks:Check[]=[];const env=ctx.environment??process.env;
 const claude=env.CLAUDE_CONFIG_DIR?resolve(env.CLAUDE_CONFIG_DIR):join(ctx.home,'.claude');
 const codex=env.CODEX_HOME?resolve(env.CODEX_HOME):join(ctx.home,'.codex');
 const memoryRoots=[join(codex,'memories')];
 const projects=join(claude,'projects');
 try{const dirs=readdirSync(projects);for(const dir of dirs.slice(0,200))memoryRoots.push(join(projects,dir,'memory'));if(dirs.length>200)checks.push({id:'agent-memory-project-cap',category:'Scan coverage and evidence',policySection:'Scope',title:'Claude memory project cap',status:'warn',detail:'Only the first 200 project directory entries were considered for memory inspection.'});}catch{}
 const started=Date.now();
 let inspected=0,excluded=0,unreadable=0;const evidence:string[]=[];
 for(const root of memoryRoots){if(inspected>=500||Date.now()-started>10000){excluded++;break;}let files:string[];try{if(lstatSync(root).isSymbolicLink()){excluded++;continue;}files=readdirSync(root);}catch{continue;}
  for(const file of files.slice(0,100)){if(inspected>=500||Date.now()-started>10000){excluded++;break;}const path=join(root,file);try{const st=lstatSync(path);if(!st.isFile()||st.isSymbolicLink()||st.size>262144||! /\.(?:md|txt|json|jsonl)$/i.test(file)){excluded++;continue;}const text=readFileSync(path,'utf8');inspected++;const kinds=[...new Set(confidentHits(text).map(h=>h.kind))];if(kinds.length||phiHits(text).length||CONFIDENTIAL_MARKER.test(text))evidence.push(`${path}: sensitive-shaped content or explicit confidentiality marker`);}catch{unreadable++;}}
  if(files.length>100)excluded+=files.length-100;
 }
 checks.push({id:'agent-memory-content',category:'Sensitive data exposure',policySection:'4.2 / 5.5',title:'Persistent memory content inspection',status:evidence.length||excluded||unreadable?'warn':inspected?'pass':'skip',detail:`${inspected} supported first-level memory files inspected (500-file / 10-second inspection budget); ${excluded} exclusions; ${unreadable} unreadable files. Sensitive content detection is heuristic. File existence does not prove memory is enabled. Clinical narrative, personal names, nested stores and other agents' memories are not exhaustively classified. Values omitted.`,evidence:evidence.slice(0,50)});
 const receipt=join(claude,'plugins/installed_plugins.json');
 if(existsSync(receipt))try{const data=readConfiguration(receipt);let count=0;for(const [name,value] of Object.entries(data.plugins??{}).slice(0,500)){
  if(!/^[\w.-]+(?:@[\w.-]+)?$/.test(name))continue;
  const records=Array.isArray(value)?value:[value];
  const pinned=records.length>0&&records.every(r=>r&&typeof r==='object'&&(typeof r.gitCommitSha==='string'&&/^[a-f0-9]{40}$/i.test(r.gitCommitSha)||typeof r.version==='string'&&/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(r.version)));
  const approved=ctx.agentControls?.allowedPlugins?.includes(name);
  checks.push({id:`agent-plugin-${name}`,category:'Third-party integrations and supply chain',policySection:'3 / 7',title:`Installed Claude plugin receipt: ${name}`,status:ctx.agentControls?.allowedPlugins&&!approved?'fail':'warn',detail:`Organization allowlist ${ctx.agentControls?.allowedPlugins?approved?'match':'mismatch':'not supplied'}; exact release/commit receipt ${pinned?'present':'not established'}. Receipts do not prove integrity, official provenance, activation, tool permissions or safe code. No plugin was loaded or executed.`,evidence:[receipt]});count++;
 }if(!count)checks.push({id:'agent-plugin-receipt-empty',category:'Third-party integrations and supply chain',policySection:'3 / 7',title:'Claude plugin receipts',status:'skip',detail:'Receipt store contains no supported plugin records.',evidence:[receipt]});
 }catch{checks.push({id:'agent-plugin-receipt-invalid',category:'Scan coverage and evidence',policySection:'Scope',title:'Claude plugin receipt unavailable',status:'skip',detail:'Plugin receipt is invalid, unreadable or oversized.',evidence:[receipt]});}
 return checks;
}
