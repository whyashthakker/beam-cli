import { spawnSync } from 'node:child_process';
import type { AuditContext,Check } from '../types.js';
export type ProviderRunner = (command:string,args:string[]) => { status:number|null; stdout:string };
const providerRun:ProviderRunner=(command,args)=>{const r=spawnSync(command,args,{encoding:'utf8',timeout:15000,maxBuffer:2*1024*1024});return {status:r.status,stdout:typeof r.stdout==='string'?r.stdout:''};};
export function remoteEnforcementChecks(ctx:AuditContext,run:ProviderRunner=providerRun):Check[]{
 const out:Check[]=[];
 for(const repo of ctx.repos){const base={id:`branch-enforcement-${repo}`,category:'Git and repository safeguards' as const,policySection:'6.2',title:'Default branch protection and bypass controls',evidence:[repo]};
 if(!ctx.online){out.push({...base,status:'skip',detail:'Use --online to inspect GitHub branch protection with the authenticated gh CLI.'});continue;}
 const remote=run('git',['-C',repo,'remote','get-url','origin']);const match=/^(?:https:\/\/github\.com\/|git@github\.com:)([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(remote.stdout?.trim()??'');
 if(!match){out.push({...base,status:'skip',detail:'No supported GitHub origin found. Other providers require separate evidence.'});continue;}
 const slug=`${match[1]}/${match[2]}`;
 function api(path:string):any{const r=run('gh',['api',path]);if(r.status!==0)throw new Error('Unavailable API evidence');return JSON.parse(r.stdout);}
 try{const info=api(`repos/${slug}`);const branch=encodeURIComponent(info.default_branch);const protection=api(`repos/${slug}/branches/${branch}/protection`);
 const required=protection.required_status_checks;const hasChecks=(required?.contexts?.length??0)+(required?.checks?.length??0)>0;
 const reviews=(protection.required_pull_request_reviews?.required_approving_review_count??0)>0;const admins=protection.enforce_admins?.enabled===true;const bypass=protection.required_pull_request_reviews?.bypass_pull_request_allowances;const bypassCount=(bypass?.users?.length??0)+(bypass?.teams?.length??0)+(bypass?.apps?.length??0);
 out.push({...base,status:hasChecks&&reviews&&admins&&!bypassCount?'pass':'fail',detail:`Classic branch protection: required checks ${hasChecks?'present':'missing'}, approval requirement ${reviews?'present':'missing'}, administrator enforcement ${admins?'enabled':'disabled'}, review bypass allowances ${bypassCount}. Rulesets and organization-wide override rights are not evaluated.`});
 }catch{out.push({...base,status:'skip',detail:'Could not retrieve classic branch protection (missing authentication, permissions, no classic protection, or API failure). Rulesets may enforce protections separately; no compliance conclusion inferred.'});}
 }
 return out;
}
