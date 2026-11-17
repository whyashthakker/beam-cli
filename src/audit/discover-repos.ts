import { readdirSync, lstatSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
const SKIP_DIRS = new Set(['node_modules','.git','dist','build','.next','.cache','coverage','.Trash','.npm','.nvm','.cargo','.rustup','venv','.venv','__pycache__','.Spotlight-V100','.fseventsd','.DocumentRevisions-V100','proc','sys','dev']);
export interface Discovery { repos:string[]; visited:number; excluded:number; inaccessible:string[]; depthLimited:number; capped:boolean; }
export function discoverReposDetailed(roots:string[], options:{maxDepth?:number;maxRepos?:number;maxDirectories?:number}={}):Discovery {
 const result:Discovery={repos:[],visited:0,excluded:0,inaccessible:[],depthLimited:0,capped:false};
 const seen=new Set<string>(); const maxDepth=options.maxDepth??12; const maxRepos=options.maxRepos??500; const maxDirectories=options.maxDirectories??100000;
 function walk(dir:string,depth:number):void {
  if(result.repos.length>=maxRepos||result.visited>=maxDirectories){result.capped=true;return;}
  if(depth>maxDepth){result.depthLimited++;return;}
  let entries:string[];
  try {if(lstatSync(dir).isSymbolicLink()){result.excluded++;return;}const real=realpathSync(dir);if(seen.has(real))return;seen.add(real); entries=readdirSync(dir);result.visited++;}catch{result.inaccessible.push(dir);return;}
  if(entries.includes('.git'))result.repos.push(dir);
  for(const entry of entries){if(SKIP_DIRS.has(entry)){result.excluded++;continue;}const path=join(dir,entry);try {if(lstatSync(path).isDirectory())walk(path,depth+1);}catch{result.inaccessible.push(path);}}
 }
 for(const root of roots)walk(root,0);
 return result;
}
export function discoverRepos(roots:string[],options:{maxDepth?:number;maxRepos?:number}={}):string[]{return discoverReposDetailed(roots,options).repos;}
