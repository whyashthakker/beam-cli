import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { join, dirname, resolve, relative, isAbsolute, basename, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { agentConfigurations, readConfiguration } from '../config-files.js';
import { CONFIDENTIAL_MARKER, confidentHits } from '../detectors.js';
// Same monorepo: use the real, already-shipped skill engine (richer than anything worth
// reimplementing here -- it also runs the full rule-catalog.ts builtin rules against skill text,
// not just the risk/injection subset) instead of maintaining a second copy in beam-audit.
import { scanSkillDir } from '../../../../dist/skill-scan.js';
import { discoverAllSkills } from '../../../../dist/skill-inventory.js';
import type { AuditContext, Check } from '../types.js';
function inScope(root:string,file:string):boolean { const r=relative(root,file);return !r.startsWith('..')&&!isAbsolute(r); }
export function compareRelease(installed:string, minimum:string):number|null {
 if(!/^\d+\.\d+\.\d+$/.test(installed)||!/^\d+\.\d+\.\d+$/.test(minimum))return null;
 const a=installed.split('.').map(Number), b=minimum.split('.').map(Number);
 if([...a,...b].some(x=>!Number.isSafeInteger(x)))return null;
 for(let i=0;i<3;i++)if(a[i]!==b[i])return a[i]!<b[i]!?-1:1;
 return 0;
}
// One row for "installed extensions" and one for "required release versions" across the whole
// machine, not one full block per extension -- a profile with 40 extensions used to produce 40
// near-identical "Installed extension: x" blocks (same boilerplate detail, differing only by
// manifest hash), which read as noise rather than a report. Aggregated the same way
// repository-enforcement.ts's checks are: worst status wins, affected extensions go in
// `evidence` as plain "id@version" (the hash/path evidence per extension wasn't adding anything
// the aggregate reader needed), and `detail` carries the counts.
export function extensionInventoryChecks(ctx:AuditContext):Check[]{
 const out:Check[]=[];
 const reportedAgents=new Set<string>();
 const identities:Record<string,string>={"anthropic.claude-code":"Claude Code","openai.chatgpt":"Codex","github.copilot":"GitHub Copilot","github.copilot-chat":"GitHub Copilot","saoudrizwan.claude-dev":"Cline","rooveterinaryinc.roo-cline":"Roo Code","continue.continue":"Continue","amazonwebservices.amazon-q-vscode":"Amazon Q","codeium.codeium":"Windsurf / Codeium","tabnine.tabnine-vscode":"Tabnine"};
 const allowed=ctx.agentControls?.allowedExtensions;
 const extensions:{id:string;version:string}[]=[];
 const belowMinimum:string[]=[];const unverifiedMinimum:string[]=[];let minimumChecked=0;
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
   extensions.push({id,version:/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(pkg.version)?pkg.version:'unrecognized'});
   const minimum=Object.entries(ctx.agentControls?.minimumExtensionVersions??{}).find(([key])=>key.toLowerCase()===id)?.[1];
   if(minimum){minimumChecked++;const compared=compareRelease(pkg.version,minimum);
    if(compared===null)unverifiedMinimum.push(`${id}@${pkg.version} (cannot compare against required ${minimum})`);
    else if(compared<0)belowMinimum.push(`${id}@${pkg.version} (required ${minimum})`);}
  }catch{/* Non-extension, unreadable or invalid manifest. */}
  if(names.length>1000)out.push({id:`extension-cap-${root}`,category:'Scan coverage and evidence',policySection:'Scope',title:'Extension manifest inspection cap',status:'warn',detail:'Only the first 1000 directory entries were inspected.',evidence:[root]});
 }
 if(extensions.length===0)return out.length?out:[{id:'extension-inventory-unavailable',category:'AI agent discovery and configuration',policySection:'3',title:'Installed extension manifest discovery',status:'skip',detail:'No readable extension manifests found in supported VS Code, Insiders, or Cursor locations. Remote extension hosts and other profiles may have additional installations.'}];

 const disallowed=allowed?extensions.filter(e=>!allowed.some(x=>x.toLowerCase()===e.id)):[];
 out.push({id:'extension-inventory',category:'AI agent discovery and configuration',policySection:'3',title:'Installed extensions',
  status:allowed?disallowed.length?'fail':'pass':'warn',
  detail:`${extensions.length} extension${extensions.length===1?'':'s'} installed. `
   +(allowed?`${disallowed.length} not on the organization extension allowlist.`:'No organization extension allowlist supplied.')
   +' Installation does not prove activation, publisher authenticity, or whether the extension transmits source code.',
  evidence:(allowed?disallowed:extensions).map(e=>`${e.id}@${e.version}`).slice(0,100)});

 if(minimumChecked>0)out.push({id:'extension-version',category:'Updates and vulnerability management',policySection:'3',title:'Required extension release versions',
  status:belowMinimum.length?'fail':unverifiedMinimum.length?'skip':'pass',
  detail:`${minimumChecked} installed extension${minimumChecked===1?' has':'s have'} a configured minimum release. `
   +(belowMinimum.length?`${belowMinimum.length} below the required minimum.`:'None below their required minimum.')
   +(unverifiedMinimum.length?` ${unverifiedMinimum.length} could not be compared (unrecognized release format).`:'')
   +' Active version and Marketplace provenance were not independently verified.',
  evidence:[...belowMinimum,...unverifiedMinimum].slice(0,100)});

 return out;
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
// Mirrors the main beam-cli product's skill-inventory.ts discovery: a whole-filesystem walk (bounded
// by a directory/time budget) that finds every folder containing a SKILL.md, not just the known
// per-agent skill directories -- those are also where a nested/vendored skill or a project-local
// skill would otherwise be missed.
function classifySkillAgent(dir: string): string {
 const p = dir.split(sep);
 if (p.includes('.claude')) return 'Claude Code';
 if (p.includes('.codex')) return 'Codex';
 if (p.includes('.cursor')) return 'Cursor';
 if (p.includes('.gemini')) return 'Gemini CLI';
 if (p.includes('.copilot')) return 'GitHub Copilot CLI';
 if (p.includes('.opencode')) return 'OpenCode';
 if (p.includes('.windsurf') || p.includes('.codeium')) return 'Windsurf';
 if (p.includes('.continue')) return 'Continue';
 if (p.includes('.agents')) return 'Universal (.agents)';
 return 'Unknown';
}

export async function skillChecks(ctx: AuditContext): Promise<Check[]> {
 const out: Check[] = [];
 const { found, truncated } = await discoverAllSkills({ roots: [...new Set([ctx.home, ...ctx.roots])] });
 if (truncated) out.push({ id: 'skill-discovery-truncated', category: 'Scan coverage and evidence', policySection: 'Scope', title: 'Whole-filesystem skill discovery limit', status: 'warn', detail: 'The skill discovery walk hit its directory/time budget before finishing; some skills under the scanned roots may not have been found.' });
 const bySkillName = new Map<string, Array<{ agent: string; dir: string; hash: string }>>();
 for (const { dir } of found.slice(0, 500)) {
  const agent = classifySkillAgent(dir);
  const name = basename(dir);
  let scan; try { scan = await scanSkillDir(dir, name); } catch { out.push({ id: `skill-unreadable-${dir}`, category: 'Scan coverage and evidence', policySection: 'Scope', title: 'Skill scan unavailable', status: 'skip', detail: 'The skill could not be scanned by the shared engine (unreadable, oversized, or malformed).', evidence: [dir] }); continue; }
  const status: Check['status'] = scan.level === 'CRITICAL' || scan.level === 'HIGH' ? 'fail' : scan.level === 'MEDIUM' ? 'warn' : scan.findings.length ? 'warn' : 'pass';
  const evidence = scan.findings.slice(0, 10).map(f => `${f.file}${f.line ? `:${f.line}` : ''} -- ${f.title} [${f.severity}]: ${f.evidence || '(no single-line evidence)'} -- ${f.explanation}`);
  out.push({
   id: `skill-risk-${dir}`, category: 'Third-party integrations and supply chain', policySection: '3 / 4.3 / 7',
   title: `Skill risk scan: ${name} (${agent})`, status,
   detail: `${scan.filesScanned} file(s) scanned${scan.skipped.length ? `, ${scan.skipped.length} skipped (oversized)` : ''}; risk score ${scan.score}/100 (${scan.level}); ${scan.findings.length} finding(s) using the shared beam-cli skill-risk engine (privilege escalation, persistence, credential/exfil access, obfuscation, dynamic/decode-then-execute code, download-and-run, unpinned installs, broad destructive commands, prompt-injection phrasing, and the general secret/PII rule set). Detection is heuristic pattern matching on the skill's own text and bundled scripts -- nothing in the skill was ever executed, and a clever rewording can still evade a pattern. See evidence for the exact file, line, and matched text.`,
   evidence, fix: scan.findings.length ? 'Open each listed file/line and confirm the flagged command or phrasing is actually needed and intentional before trusting this skill.' : undefined,
  });
  const file = join(dir, 'SKILL.md');
  try {
   const text = readFileSync(file, 'utf8');
   const front = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(text);
   const metadata: any = front ? parseYaml(front[1]!, { maxAliasCount: 20 }) : {};
   const allowedTools = Array.isArray(metadata?.['allowed-tools']) ? metadata['allowed-tools'] as string[] : typeof metadata?.['allowed-tools'] === 'string' ? [metadata['allowed-tools']] : [];
   const wildcard = allowedTools.some(t => typeof t === 'string' && (/\*/.test(t) || /^Bash$/i.test(t)));
   const bad = wildcard && ctx.agentControls?.requireManualApproval;
   out.push({ id: `skill-definition-${file}`, category: 'Third-party integrations and supply chain', policySection: '3 / 4.3', title: `Skill configuration: ${typeof metadata?.name === 'string' ? metadata.name : name}`, status: bad ? 'fail' : allowedTools.length ? 'warn' : 'skip', detail: allowedTools.length ? `Declared allowed-tools frontmatter: ${allowedTools.length} entrie(s)${wildcard ? ', including an unrestricted/wildcard tool grant' : ''}. A declaration does not prove the tool scope is actually enforced at runtime.` : 'No allowed-tools frontmatter field recognized; this Skill either declares no tool restriction or uses an unsupported metadata format.', evidence: [file] });
  } catch { /* SKILL.md itself unreadable; scan above still ran against whatever files were readable */ }
  const key = (typeof name === 'string' ? name : basename(dir)).toLowerCase();
  bySkillName.set(key, [...(bySkillName.get(key) ?? []), { agent, dir, hash: scan.hash }]);
 }
 for (const [name, entries] of bySkillName) {
  if (entries.length < 2) continue;
  const hashes = new Set(entries.map(e => e.hash));
  out.push({ id: `skill-cross-agent-${name}`, category: 'Third-party integrations and supply chain', policySection: '3', title: `Skill consistency across agents: ${name}`, status: hashes.size > 1 ? 'warn' : 'pass', detail: hashes.size > 1 ? `Found ${entries.length} installation(s) of a skill named "${name}" across ${new Set(entries.map(e => e.agent)).size} agent location(s) with differing content. A skill with the same name can carry different instructions per agent/location.` : `Found ${entries.length} installation(s) of a skill named "${name}" with identical content across agent locations.`, evidence: entries.map(e => `${e.agent}: ${e.dir}`) });
 }
 if (!found.length) out.push({ id: 'skill-discovery', category: 'Third-party integrations and supply chain', policySection: '3', title: 'Skill discovery', status: 'skip', detail: 'No SKILL.md definitions found in the scanned roots.' });
 return out;
}
export function agentInstructionChecks(ctx:AuditContext):Check[]{
 const out:Check[]=[];
 const candidates=[join(ctx.home,'.claude/CLAUDE.md'),join(ctx.home,'.codex/AGENTS.md'),join(ctx.home,'.codex/AGENTS.override.md'),join(ctx.home,'.gemini/GEMINI.md'),...ctx.repos.flatMap(r=>['AGENTS.md','AGENTS.override.md','CLAUDE.md','GEMINI.md','.github/copilot-instructions.md','.windsurfrules','.clinerules'].map(n=>join(r,n)))];
 for(const repo of ctx.repos)for(const relativeRoot of ['.cursor/rules','.github/instructions','.roo/rules']){const root=join(repo,relativeRoot);try{for(const name of readdirSync(root).slice(0,200))if(/\.(?:md|mdc|txt)$/i.test(name))candidates.push(join(root,name));}catch{}}
 // SKILL.md is intentionally NOT scanned here: skillChecks() already runs the real, far more
 // capable shared skill-risk engine (full rule-catalog + injection rules, not just this file's
 // three regexes) against every SKILL.md. Scanning it again here with the weaker heuristic would
 // just add a near-always-"not recognized" duplicate card that dilutes the real skill findings.
 for(const file of candidates)if(existsSync(file))try{const st=lstatSync(file);if(!st.isFile()||st.size>262144)throw new Error('limit');const text=readFileSync(file,'utf8');
 const suspicious=/ignore (?:all |previous )?(?:security|safety|polic(?:y|ies))|disable (?:all )?(?:guardrails|security checks)|exfiltrat/i.test(text);
 const credentials=confidentHits(text).some(h=>['API_KEY','OAUTH_TOKEN','PRIVATE_KEY'].includes(h.kind));
 out.push({id:`agent-instructions-${file}`,category:'Third-party integrations and supply chain',policySection:'4.2 / 7',title:'Agent instruction file inspection',status:suspicious||credentials||CONFIDENTIAL_MARKER.test(text)?'warn':'pass',detail:`Bypass-shaped instruction wording ${suspicious?'found':'not recognized'}; credential-shaped content ${credentials?'found':'not recognized'}; explicit confidentiality marker ${CONFIDENTIAL_MARKER.test(text)?'found':'not recognized'}. These are heuristics; instructions were never followed or executed, and text values are omitted.`,evidence:[file]});
 }catch{out.push({id:`agent-instructions-unreadable-${file}`,category:'Scan coverage and evidence',policySection:'Scope',title:'Instruction file inspection unavailable',status:'skip',detail:'Instruction file is oversized, unreadable, or not a regular file.',evidence:[file]});}
 return out;
}
