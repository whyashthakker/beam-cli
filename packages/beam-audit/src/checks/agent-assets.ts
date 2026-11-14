import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { join, dirname, resolve, relative, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { parse as parseYaml } from 'yaml';
import { agentConfigurations, readConfiguration } from '../config-files.js';
import { CONFIDENTIAL_MARKER, confidentHits } from '../detectors.js';
import type { AuditContext, Check } from '../types.js';
function inScope(root:string,file:string):boolean { const r=relative(root,file);return !r.startsWith('..')&&!isAbsolute(r); }
export function compareRelease(installed:string, minimum:string):number|null {
 if(!/^\d+\.\d+\.\d+$/.test(installed)||!/^\d+\.\d+\.\d+$/.test(minimum))return null;
 const a=installed.split('.').map(Number), b=minimum.split('.').map(Number);
 if([...a,...b].some(x=>!Number.isSafeInteger(x)))return null;
 for(let i=0;i<3;i++)if(a[i]!==b[i])return a[i]!<b[i]!?-1:1;
 return 0;
}
export function extensionInventoryChecks(ctx:AuditContext):Check[]{
 const out:Check[]=[];
 const reportedAgents=new Set<string>();
 const identities:Record<string,string>={"anthropic.claude-code":"Claude Code","openai.chatgpt":"Codex","github.copilot":"GitHub Copilot","github.copilot-chat":"GitHub Copilot","saoudrizwan.claude-dev":"Cline","rooveterinaryinc.roo-cline":"Roo Code","continue.continue":"Continue","amazonwebservices.amazon-q-vscode":"Amazon Q","codeium.codeium":"Windsurf / Codeium","tabnine.tabnine-vscode":"Tabnine"};
 for(const root of [join(ctx.home,'.vscode/extensions'),join(ctx.home,'.vscode-insiders/extensions'),join(ctx.home,'.cursor/extensions')]){
  let names:string[];try{names=readdirSync(root);}catch{continue;}
  for(const name of names.slice(0,1000))try{
   const file=join(root,name,'package.json');if(statSync(file).size>2_000_000)continue;
   const text=readFileSync(file,'utf8');const pkg=JSON.parse(text);
   if(typeof pkg.publisher!=='string'||typeof pkg.name!=='string'||typeof pkg.version!=='string')continue;
   const id=`${pkg.publisher}.${pkg.name}`.toLowerCase();
   if(!/^[\w-]+\.[\w-]+$/.test(id))continue;
   const agent=identities[id.toLowerCase()];
   if(agent&&!reportedAgents.has(agent)){reportedAgents.add(agent);out.push({id:`inventory-${agent}`,category:'AI agent discovery and configuration',policySection:'3',title:`${agent}: extension installation signal`,status:'warn',detail:'A matching extension manifest is installed. Activation, genuine publisher identity and account ownership are not verified.',evidence:[file]});}
   const allowed=ctx.agentControls?.allowedExtensions;
   out.push({id:`extension-inventory-${root}-${name}`,category:'AI agent discovery and configuration',policySection:'3',title:`Installed extension: ${id}`,status:allowed?allowed.some(x=>x.toLowerCase()===id)?'pass':'fail':'warn',detail:`Manifest version: ${/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(pkg.version)?pkg.version:'unrecognized'}. ${allowed?'Compared declared identity with the organization extension allowlist.':'No organization extension allowlist supplied.'} Installation does not prove activation, publisher authenticity, or whether the extension transmits source code.`,evidence:[file,`Manifest SHA-256: ${createHash('sha256').update(text).digest('hex')}`]});
   const minimum=Object.entries(ctx.agentControls?.minimumExtensionVersions??{}).find(([key])=>key.toLowerCase()===id)?.[1];
   if(minimum){const compared=compareRelease(pkg.version,minimum);out.push({id:`extension-version-${root}-${name}`,category:'Updates and vulnerability management',policySection:'3',title:`Required extension release: ${id}`,status:compared===null?'skip':compared<0?'fail':'pass',detail:compared===null?'Release format or prerelease cannot be safely compared.':`Compared installed manifest release with configured minimum ${minimum}. Active version and Marketplace provenance were not independently verified.`,evidence:[file]});}
  }catch{/* Non-extension, unreadable or invalid manifest. */}
  if(names.length>1000)out.push({id:`extension-cap-${root}`,category:'Scan coverage and evidence',policySection:'Scope',title:'Extension manifest inspection cap',status:'warn',detail:'Only the first 1000 directory entries were inspected.',evidence:[root]});
 }
 return out.length?out:[{id:'extension-inventory-unavailable',category:'AI agent discovery and configuration',policySection:'3',title:'Installed extension manifest discovery',status:'skip',detail:'No readable extension manifests found in supported VS Code, Insiders, or Cursor locations. Remote extension hosts and other profiles may have additional installations.'}];
}
export function subagentChecks(ctx:AuditContext):Check[]{
 const out:Check[]=[];const files=new Set<string>();
 for(const root of [join(ctx.home,'.claude/agents'),join(ctx.home,'.codex/agents'),join(ctx.home,'.gemini/agents'),...ctx.repos.flatMap(r=>[join(r,'.claude/agents'),join(r,'.codex/agents'),join(r,'.gemini/agents')])]){
  let names:string[];try{if(lstatSync(root).isSymbolicLink())continue;names=readdirSync(root);}catch{continue;}
  for(const name of names.slice(0,200))if(/\.(?:md|toml)$/i.test(name))files.add(join(root,name));
  if(names.length>200)out.push({id:`subagent-cap-${root}`,category:'Scan coverage and evidence',policySection:'Scope',title:'Sub-agent directory inspection cap',status:'warn',detail:'First 200 entries inspected; definitions may remain uninspected.',evidence:[root]});
 }
 for(const definition of agentConfigurations(ctx).filter(a=>a.name==='Codex'))for(const file of definition.paths)if(existsSync(file))try{
  const config=readConfiguration(file);
  for(const role of Object.values(config.agents??{}).slice(0,200) as any[])if(role&&typeof role.config_file==='string'){
   const path=resolve(dirname(file),role.config_file);let approved=false;
   try{const real=realpathSync(path);approved=[ctx.home,...ctx.roots].some(root=>inScope(realpathSync(root),real));}catch{}
   if(approved)files.add(path);else out.push({id:`subagent-outside-${file}-${out.length}`,category:'Scan coverage and evidence',policySection:'Scope',title:'Referenced sub-agent file not inspected',status:'skip',detail:'Referenced file is inaccessible or outside the current user/scan roots. No definition content read.',evidence:[file]});
  }
 }catch{}
 for(const file of [...files].slice(0,1000))try{
  const st=lstatSync(file);if(st.isSymbolicLink()||!st.isFile()||st.size>262144)throw new Error('unsupported');
  let metadata:any;
  if(file.endsWith('.toml'))metadata=readConfiguration(file);else {const text=readFileSync(file,'utf8');const front=/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(text);if(!front)throw new Error('no metadata');metadata=parseYaml(front[1]!,{maxAliasCount:20});}
  const mode=metadata?.permissionMode??metadata?.approval_policy;
  const permissive=['bypassPermissions','acceptEdits','auto','never'].includes(mode);
  const memory=metadata?.memory!==undefined&&metadata?.memory!==false&&metadata?.memory!=='none';
  const modelBad=typeof metadata?.model==='string'&&metadata.model!=='inherit'&&ctx.agentControls?.allowedModels&&!ctx.agentControls.allowedModels.includes(metadata.model);
  const bad=permissive&&ctx.agentControls?.requireManualApproval||memory&&ctx.agentControls?.forbidPersistentMemory||modelBad;
  out.push({id:`subagent-definition-${file}`,category:'Third-party integrations and supply chain',policySection:'3 / 4.3 / 5.5',title:'Sub-agent configuration definition',status:bad?'fail':'warn',detail:`Metadata inspected: permissive approval declaration ${permissive?'present':'not recognized'}, memory declaration ${memory?'present':'not recognized'}. Model allowlist ${modelBad?'mismatch':'not mismatched or not configured'}. Definition existence does not prove activation, inherited tool scope, runtime model, or independent approval enforcement. Instructions and credential values omitted.`,evidence:[file]});
 }catch{out.push({id:`subagent-unreadable-${file}`,category:'Scan coverage and evidence',policySection:'Scope',title:'Sub-agent definition not inspected',status:'skip',detail:'Definition is unreadable, oversized, linked, malformed, or has no supported metadata.',evidence:[file]});}
 return out.length?out:[{id:'subagent-discovery',category:'Third-party integrations and supply chain',policySection:'3 / 4.3',title:'Sub-agent definition discovery',status:'skip',detail:'No definitions found in supported user/project directories or Codex role references. Other versions, remote agents, and dynamic delegation remain unverified.'}];
}
export function agentInstructionChecks(ctx:AuditContext):Check[]{
 const out:Check[]=[];
 const candidates=[join(ctx.home,'.claude/CLAUDE.md'),join(ctx.home,'.codex/AGENTS.md'),join(ctx.home,'.codex/AGENTS.override.md'),join(ctx.home,'.gemini/GEMINI.md'),...ctx.repos.flatMap(r=>['AGENTS.md','AGENTS.override.md','CLAUDE.md','GEMINI.md','.github/copilot-instructions.md','.windsurfrules','.clinerules'].map(n=>join(r,n)))];
 for(const repo of ctx.repos)for(const relativeRoot of ['.cursor/rules','.github/instructions','.roo/rules']){const root=join(repo,relativeRoot);try{for(const name of readdirSync(root).slice(0,200))if(/\.(?:md|mdc|txt)$/i.test(name))candidates.push(join(root,name));}catch{}}
 for(const root of [join(ctx.home,'.agents/skills'),join(ctx.home,'.claude/skills'),join(ctx.home,'.codex/skills'),...ctx.repos.flatMap(r=>[join(r,'.agents/skills'),join(r,'.claude/skills')])])try{for(const name of readdirSync(root).slice(0,200)){const dir=join(root,name);if(!lstatSync(dir).isSymbolicLink())candidates.push(join(dir,'SKILL.md'));}}catch{}
 for(const file of candidates)if(existsSync(file))try{const st=lstatSync(file);if(!st.isFile()||st.size>262144)throw new Error('limit');const text=readFileSync(file,'utf8');
 const suspicious=/ignore (?:all |previous )?(?:security|safety|polic(?:y|ies))|disable (?:all )?(?:guardrails|security checks)|exfiltrat/i.test(text);
 const credentials=confidentHits(text).some(h=>['API_KEY','OAUTH_TOKEN','PRIVATE_KEY'].includes(h.kind));
 out.push({id:`agent-instructions-${file}`,category:'Third-party integrations and supply chain',policySection:'4.2 / 7',title:'Agent instruction file inspection',status:suspicious||credentials||CONFIDENTIAL_MARKER.test(text)?'warn':'pass',detail:`Bypass-shaped instruction wording ${suspicious?'found':'not recognized'}; credential-shaped content ${credentials?'found':'not recognized'}; explicit confidentiality marker ${CONFIDENTIAL_MARKER.test(text)?'found':'not recognized'}. These are heuristics; instructions were never followed or executed, and text values are omitted.`,evidence:[file]});
 }catch{out.push({id:`agent-instructions-unreadable-${file}`,category:'Scan coverage and evidence',policySection:'Scope',title:'Instruction file inspection unavailable',status:'skip',detail:'Instruction file is oversized, unreadable, or not a regular file.',evidence:[file]});}
 return out;
}
