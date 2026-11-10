import { dirname, basename, isAbsolute, join, resolve } from "node:path";
import { existsSync, readFileSync, statSync } from "node:fs";
import { shellActionCommands } from "./credential-egress.js";
import { readOriginRemote, registriesIn, type RepoRemote, type RegistryRef } from "./repo-remote.js";
export type { RepoRemote, RegistryRef } from "./repo-remote.js";

export type ActionOperation = "file-read" | "file-search" | "source-search" | "environment-lookup" | "environment-dump" | "file-write" | "delete" | "network-request" | "network-scan" | "git-change" | "mcp-call" | "command";
export type ClassifiedAction = {
  operation: ActionOperation; evidence: "tool-arguments" | "shell-syntax";
  target?: string; resolvedPath?: string; variableNames?: string[];
  scope?: "file-content" | "requested-lines" | "matching-output" | "named-variables" | "all-exported";
  lineStart?: number; lineEnd?: number; executable?: string;
  origin?: "inline-assignment" | "inherited-environment";
  privileged?: boolean; insecureTransport?: boolean;
};
export type ActionContext = {
  schemaVersion: 1; workingDirectory?: string;
  repository?: { root: string; name: string; branch?: string; commit?: string; remote?: RepoRemote };
  /** Container registries (AWS ECR, GHCR, Docker Hub, ...) the command pushes to or pulls from. */
  registries?: RegistryRef[];
  actions: ClassifiedAction[]; truncated: boolean;
};
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const isDynamic = (value: string) => /[$`*?{}()[\]~]/.test(value);
const asString = (value: unknown) => typeof value === "string" ? value : "";
const positive = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value <= 1_000_000_000 ? value : undefined;
function smallFile(path: string): string | undefined {
  try { const s = statSync(path); return s.isFile() && s.size <= 8192 ? readFileSync(path,"utf8").trim() : undefined; } catch { return undefined; }
}
function repositoryAt(cwd: string, safe: (s: string) => string): ActionContext["repository"] {
  if (!isAbsolute(cwd) || isDynamic(cwd)) return undefined;
  let root = cwd;
  for (let depth=0;depth<24;depth++) {
    const marker=join(root,".git");
    if(existsSync(marker)) {
      const pointer=smallFile(marker)?.match(/^gitdir:\s*(.+)$/m)?.[1];
      const gitdir=pointer?resolve(root,pointer):marker;
      const head=smallFile(join(gitdir,"HEAD"));
      const ref=head?.match(/^ref:\s*(refs\/heads\/[A-Za-z0-9_./-]+)$/)?.[1];
      const common=smallFile(join(gitdir,"commondir"));
      const refRoot=common?resolve(gitdir,common):gitdir;
      const commit=ref?smallFile(join(refRoot,ref)):head;
      const remote=readOriginRemote(refRoot);
      return {root:safe(root),name:safe(basename(root)),branch:ref?safe(ref.slice(11)):undefined,commit:commit && /^[a-f0-9]{40,64}$/i.test(commit)?commit:undefined,...(remote?{remote}:{})};
    }
    const parent=dirname(root);if(parent===root)break;root=parent;
  }
  return undefined;
}

/** Describe requested operations only. No command execution, secret-file reads,
 * output inspection, or inferred successful key access occurs here. */
export function classifyActionContext(tool: string, input: Record<string,unknown>, cwd: string, command: string, safe: (s:string)=>string, includeRepository = true, depth = 0): ActionContext {
  const actions: ClassifiedAction[]=[];let working=cwd;let omitted=false;
  if(depth>4)return {schemaVersion:1,actions:[],truncated:true};
  const add=(action:ClassifiedAction)=> { if(actions.length>=12){omitted=true;return;} actions.push(action); };
  const file=(operation:ActionOperation,target:string,extra:Partial<ClassifiedAction>={})=>add({operation,evidence:command?"shell-syntax":"tool-arguments",target:safe(target),resolvedPath:!isDynamic(target)&&working&&isAbsolute(working)?safe(resolve(working,target)):isAbsolute(target)&&!isDynamic(target)?safe(target):undefined,...extra});
  const path=asString(input.file_path??input.path??input.filePath);
  if(/^(?:read|read_file|read_text_file|view)$/i.test(tool)&&path) {
    const start=positive(input.start_line)??(tool.toLowerCase()==="read"?positive(input.offset):undefined);
    const end=positive(input.end_line)??(start&&positive(input.limit)?start+Number(input.limit)-1:undefined);
    file("file-read",path,{scope:start||end?"requested-lines":"file-content",lineStart:start,lineEnd:end});
  } else if(/^(?:write|edit|write_file|apply_patch|multiedit)$/i.test(tool)&&path) file("file-write",path);
  else if(/^mcp(?:__|:|\.)/i.test(tool))add({operation:"mcp-call",evidence:"tool-arguments",target:safe(tool)});
  else if(!command && /^web(?:__|\.)|^(?:webfetch|websearch|fetch|browse)$/i.test(tool))add({operation:"network-request",evidence:"tool-arguments",target:safe(asString(input.url)||tool)});
  if(command) for(const c of shellActionCommands(command)) {
    const tokens=c.tokens;let at=0;let privileged=false;const inlineNames=new Set<string>();
    while(/^[A-Za-z_]\w*=/.test(tokens[at]?.value??"")) {
      const token=tokens[at]; const name=token.value.split("=",1)[0];
      if(!/[$`]/.test(token.raw))inlineNames.add(name);
      at++;
    }
    if(tokens[at]?.value==="sudo"){privileged=true;at++;if(tokens[at]?.value.startsWith("-")){add({operation:"command",evidence:"shell-syntax",executable:"sudo",privileged:true});continue;}}
    const cmd=basename(tokens[at]?.value??"").toLowerCase();const args=tokens.slice(at+1).map(t=>t.value);
    if(!cmd)continue;
    if(/^(?:bash|sh|zsh)$/.test(cmd) && args.length===2 && /^-[a-z]*c[a-z]*$/.test(args[0])) {
      const code=tokens[at+2];
      if(code && (code.raw.startsWith("'") || code.raw.startsWith('"')&&!/[$`]/.test(code.raw))) {
        const nested=classifyActionContext("Bash",{},working,code.value,safe,false,depth+1);
        for(const action of nested.actions)add(action.operation==="environment-lookup" && action.variableNames?.every(name=>inlineNames.has(name))?{...action,origin:"inline-assignment"}:action);
        omitted ||= nested.truncated;continue;
      }
    }
    if(cmd==="cd"){working=args[0]&&!isDynamic(args[0])&&!c.pipe?resolve(working||cwd,args[0]):"";continue;}
    if(/^(?:echo|printf)$/.test(cmd)) {
      const redirect=args.findIndex(a=>a===">"||a===">>");
      const target=redirect>=0?args[redirect+1]:args.find(a=>/^>/.test(a))?.replace(/^>+/,"");
      if(target)file("file-write",target,{executable:cmd,privileged});
      continue;
    }
    if(cmd==="env"||cmd==="printenv"||cmd==="export"&&args.includes("-p")) {
      const names=args.filter(a=>!a.startsWith("-")&&a.length<=128&&ENV_NAME.test(a));
      if(args.some(a=>/^(?:--help|--version|-h)$/.test(a)) || cmd==="printenv" && args.some(a=>!a.startsWith("-")&&!names.includes(a))){add({operation:"command",evidence:"shell-syntax",executable:cmd,privileged});continue;}
      if(cmd==="env"&&args.length) { add({operation:"command",evidence:"shell-syntax",executable:cmd,privileged});continue; }
      add({operation:names.length?"environment-lookup":"environment-dump",evidence:"shell-syntax",target:"process environment",variableNames:names.length?names.slice(0,12):undefined,origin:names.length&&names.every(name=>inlineNames.has(name))?"inline-assignment":"inherited-environment",scope:names.length?"named-variables":"all-exported",executable:cmd,privileged});continue;
    }
    if(/^(?:node|bun|python[23]?)$/.test(cmd)) {
      const flag=args.findIndex(a=>/^(?:-e|-p|--eval|--print|-c)$/.test(a));
      const code=flag>=0?(args[flag+1]??"").trim():"";
      const js=/^(?:console\.(?:log|info)\(\s*)?process\.env(?:\.([A-Za-z_][A-Za-z0-9_]{0,127})|\[['"]([A-Za-z_][A-Za-z0-9_]{0,127})['"]\])\s*\)?;?$/.exec(code);
      const py=/^import\s+os\s*;\s*print\(\s*os\.(?:environ\[['"]([A-Za-z_][A-Za-z0-9_]{0,127})['"]\]|getenv\(['"]([A-Za-z_][A-Za-z0-9_]{0,127})['"]\))\s*\)\s*;?$/.exec(code);
      const key=/^(?:node|bun)$/.test(cmd)?js?.[1]??js?.[2]:py?.[1]??py?.[2];
      if(key){add({operation:"environment-lookup",evidence:"shell-syntax",target:"process environment",variableNames:[key],origin:inlineNames.has(key)?"inline-assignment":"inherited-environment",scope:"named-variables",executable:cmd,privileged});continue;}
    }
    if(/^(?:grep|rg)$/.test(cmd)) {
      let pattern:string|undefined;const paths:string[]=[];
      for(let i=0;i<args.length;i++){
        const arg=args[i];if(/^(?:-e|--regexp)$/.test(arg)){pattern=args[++i];continue;}
        if(/^(?:-A|-B|-C|-m|--max-count|--glob|-g|-f|--file)$/.test(arg)){i++;continue;}
        if(arg.startsWith("-"))continue;if(pattern===undefined)pattern=arg;else if(!/^[012]?>|^\d>&/.test(arg))paths.push(arg);
      }
      const key=pattern?.match(/^\^([A-Za-z_][A-Za-z0-9_]{0,127})=/)?.[1];
      for(const target of paths.length?paths:["standard input"]){
        const sourceSearch=Boolean(pattern&&/(?:process\.env|os\.environ|System\.getenv)/.test(pattern)&&!/(?:^|\/)\.env(?:\.|$)/.test(target));
        if(target==="standard input")add({operation:"file-search",evidence:"shell-syntax",target,scope:"matching-output",variableNames:key?[key]:undefined,executable:cmd,privileged});
        else file(sourceSearch?"source-search":"file-search",target,{scope:"matching-output",variableNames:key?[key]:undefined,executable:cmd,privileged});
      }
      continue;
    }
    if(/^(?:cat|head|tail|sed)$/.test(cmd)) {
      if(tokens.some(t=>/^>/.test(t.value))){const redirect=args.findIndex(a=>a===">"||a===">>");const target=redirect>=0?args[redirect+1]:args.find(a=>/^>/.test(a))?.replace(/^>+/,"");if(target)file("file-write",target,{executable:cmd,privileged});continue;}
      let candidates=args.filter(a=>!a.startsWith("-")&&!/^\d+$/.test(a)&&!/^\d?>/.test(a));
      if(cmd==="sed")candidates=candidates.slice(1);
      for(const target of candidates)file("file-read",target,{scope:"file-content",executable:cmd,privileged});continue;
    }
    if(cmd==="rm"){for(const target of args.filter(a=>!a.startsWith("-")))file("delete",target,{executable:cmd,privileged});continue;}
    if(/^(?:curl|wget|scp|rsync)$/.test(cmd)){const destination=args.find(a=>/^https?:\/\//i.test(a))??args.find(a=>/^[^/\s]+@[^/\s]+:/.test(a));add({operation:"network-request",evidence:"shell-syntax",target:destination?safe(destination):undefined,executable:cmd,privileged,insecureTransport:args.some(a=>a==="-k"||a==="--insecure"||a==="--no-check-certificate")});continue;}
    if(/^(?:nmap|masscan|rustscan)$/.test(cmd)){add({operation:"network-scan",evidence:"shell-syntax",target:safe(args.filter(a=>!a.startsWith("-")).join(" ")).slice(0,300),executable:cmd,privileged});continue;}
    if(cmd==="git"&&/^(?:push|reset|clean|filter-branch|filter-repo)$/.test(args[0]??"")){add({operation:"git-change",evidence:"shell-syntax",target:safe(args[0]),executable:cmd,privileged});continue;}
    if(!/^(?:echo|printf|ls|mkdir|true|head|wc)$/.test(cmd))add({operation:"command",evidence:"shell-syntax",executable:safe(cmd),privileged});
  }
  const registries=command?registriesIn(command):[];
  return {schemaVersion:1,workingDirectory:cwd?safe(cwd):undefined,repository:includeRepository?repositoryAt(cwd,safe):undefined,...(registries.length?{registries}:{}),actions,truncated:omitted};
}
