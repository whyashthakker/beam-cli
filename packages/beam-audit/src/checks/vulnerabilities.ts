import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { installedPackages, type PackageVersion } from './supply-chain.js';
import type { AuditContext,Check } from '../types.js';
export function lockPackages(repo:string):PackageVersion[]{
 try{const lock=JSON.parse(readFileSync(join(repo,'package-lock.json'),'utf8'));const out:PackageVersion[]=[];
 for(const [path,value] of Object.entries(lock.packages??{})){const p=value as any;if(!path.includes('node_modules/')||typeof p.version!=='string'||p.link)continue;const name=p.name??path.slice(path.lastIndexOf('node_modules/')+13);if(typeof name==='string'&&/^\d+\.\d+\.\d+/.test(p.version))out.push({name,version:p.version});}return out;
 }catch{return [];}
}
export async function vulnerabilityChecks(ctx:AuditContext, request:typeof fetch=fetch):Promise<Check[]>{
 const all=[...installedPackages(ctx.home).filter(p=>p.source!=="extension"),...ctx.repos.flatMap(lockPackages)];
 const unique=[...new Map(all.map(p=>[`${p.name}@${p.version}`,p])).values()];
 const base={id:'known-vulnerabilities',category:'Updates and vulnerability management' as const,policySection:'7',title:'Known package vulnerabilities (OSV)'};
 if(!ctx.online)return [{...base,status:'skip',detail:`${unique.length} installed npm package and npm lockfile versions discovered. Use --online to send package names and versions to OSV. No source or credential values are sent.`}];
 if(!unique.length)return [{...base,status:'skip',detail:'No supported exact package versions discovered. No advisory request made.'}];
 const selected=unique.slice(0,1000);const evidence:string[]=[];let reviewed=0,failed=0;
 for(let start=0;start<selected.length;start+=100){const batch=selected.slice(start,start+100);try{
  const response=await request('https://api.osv.dev/v1/querybatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({queries:batch.map(p=>({package:{name:p.name,ecosystem:'npm'},version:p.version}))}),signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error('OSV request failed');const body=await response.json() as any;
  if(!Array.isArray(body.results)||body.results.length!==batch.length)throw new Error('Invalid response');
  body.results.forEach((result:any,i:number)=>{if(result.next_page_token){failed++;return;} reviewed++;for(const vuln of result.vulns??[])if(typeof vuln.id==='string')evidence.push(`${batch[i]!.name}@${batch[i]!.version}: ${vuln.id}`);});
 }catch{failed+=batch.length;}}
 return [{...base,status:evidence.length?'fail':failed||selected.length<unique.length?'warn':'pass',detail:`${reviewed} exact npm package versions checked; ${evidence.length} advisory matches; ${failed} incomplete queries. ${unique.length-selected.length} versions excluded by the 1000-package limit. No match means no OSV match at scan time, not proof of safety. IDE extension manifests are excluded from npm advisory queries; extension advisories require separate evidence.`,evidence:evidence.slice(0,100)}];
}

export async function releaseChecks(ctx:AuditContext,request:typeof fetch=fetch):Promise<Check[]>{
 const approvedNames=new Set(['@anthropic-ai/claude-code','@openai/codex','@google/gemini-cli','@github/copilot','opencode-ai']);
 const packages=installedPackages(ctx.home).filter(p=>approvedNames.has(p.name));
 const base={id:'agent-release-versions',category:'Updates and vulnerability management' as const,policySection:'3, 6.3',title:'Installed npm agent release currency'};
 if(!ctx.online)return [{...base,status:'skip',detail:'Use --online to compare discovered official npm agent package versions with npm registry latest tags.'}];
 if(!packages.length)return [{...base,status:'skip',detail:'No official agent npm manifests discovered in supported user installation directories. Native binaries and other package managers require separate evidence.'}];
 const out:Check[]=[];
 for(const pkg of packages.slice(0,30))try{
  const r=await request(`https://registry.npmjs.org/${encodeURIComponent(pkg.name)}/latest`,{signal:AbortSignal.timeout(10000)});if(!r.ok)throw new Error('Registry unavailable');const body=await r.json() as any;if(typeof body.version!=='string')throw new Error('Invalid registry response');
  out.push({...base,id:`release-${pkg.name}`,title:`Release currency: ${pkg.name}`,status:pkg.version===body.version?'pass':'warn',detail:`Installed ${pkg.version}; registry latest tag ${body.version}. A difference may represent an approved pin or alternate release channel; compare against organization policy.`});
 }catch{out.push({...base,id:`release-${pkg.name}`,title:`Release currency: ${pkg.name}`,status:'skip',detail:'Registry version evidence unavailable.'});}
 return out;
}
