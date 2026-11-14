import { readFileSync, existsSync, readdirSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditContext,Check } from '../types.js';
export interface PackageVersion {name:string;version:string; source?: "npm" | "extension";}
export function installedPackages(home:string):PackageVersion[]{
 const roots=[join(home,'.vscode/extensions'),join(home,'.cursor/extensions'),join(home,'.local/lib/node_modules'),join(home,'AppData/Roaming/npm/node_modules')];
 const out:PackageVersion[]=[];
 for(const root of roots){let dirs:string[];try{dirs=readdirSync(root);}catch{continue;}for(const dir of dirs.slice(0,500)){
  const paths=dir.startsWith('@')?(()=>{try{return readdirSync(join(root,dir)).map(x=>join(root,dir,x));}catch{return [];}})():[join(root,dir)];
  for(const path of paths)try{const p=JSON.parse(readFileSync(join(path,'package.json'),'utf8'));if(typeof p.name==='string'&&typeof p.version==='string')out.push({name:p.name,version:p.version,source:root.endsWith("extensions")?"extension":"npm"});}catch{}}
 }
 return out;
}
export function supplyChainChecks(ctx:AuditContext):Check[]{
 const out:Check[]=[];
 for(const repo of ctx.repos){const file=join(repo,'package.json');if(!existsSync(file))continue;try{
  const pkg=JSON.parse(readFileSync(file,'utf8'));const deps={...pkg.dependencies,...pkg.devDependencies};const unpinned=Object.values(deps).filter(v=>typeof v==='string'&&!/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(v)).length;
  const lock=['package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb'].some(x=>existsSync(join(repo,x)));
  out.push({id:`dependency-pinning-${repo}`,category:'Third-party integrations and supply chain',policySection:'7',title:'Dependency reproducibility',status:Object.keys(deps).length&&!lock?'fail':unpinned?'warn':'pass',detail:`${Object.keys(deps).length} direct dependencies; ${unpinned} non-exact declarations; ${lock?'lockfile present (integrity not validated)':'no recognized lockfile'}. No install scripts executed.`,evidence:[file]});
 }catch{out.push({id:`dependency-parse-${repo}`,category:'Third-party integrations and supply chain',policySection:'7',title:'Dependency manifest inspection',status:'skip',detail:'Manifest unreadable or malformed.',evidence:[file]});}}
 for(const root of [join(ctx.home,'.claude/skills'),join(ctx.home,'.agents/skills'),join(ctx.home,'.codex/skills'),...ctx.repos.map(r=>join(r,'.claude/skills'))]){
  let entries:string[];try{entries=readdirSync(root);}catch{continue;}let writable=0;for(const name of entries.slice(0,500))try{if(lstatSync(join(root,name)).mode&0o002)writable++;}catch{}
  out.push({id:`skills-${root}`,category:'Third-party integrations and supply chain',policySection:'7',title:'Installed skills directory',status:writable?'fail':'warn',detail:`${entries.length} entries found; ${writable} sampled entries world-writable. Provenance and skill instructions require review. Symlinks are not traversed.`,evidence:[root]});
 }
 return out;
}
