import type { ActionContext } from "./action-context.js";
import type { Severity } from "./rule-catalog.js";

const routineName = (name:string) => /^(?:AWS_REGION|AWS_DEFAULT_REGION|NODE_ENV|PORT|HOST|LANG|TZ|CI|TERM|PWD)$/.test(name);
const privatePath = (path:string) => /(?:^|[/\\])\.env(?:[.\\/]|rc\b|$)|\.ssh[/\\]|\.aws[/\\]credentials\b|id_(?:rsa|ed25519)|\.npmrc\b|\.netrc\b|kubeconfig|\.pgpass\b|credentials\.json/i.test(path);
function scopedTemporaryConfiguration(path:string):boolean {
  if(/[$`*?{}()[\]~]/.test(path)||path.split(/[\\/]/).some(p=>p==="."||p===".."))return false;
  const match=/^\/(?:tmp|private\/tmp|var\/tmp)\/([A-Za-z0-9._-]+)\//.exec(path);
  return !!match && /(?:^|[-_.])(?:test|tests|temp|tmp|scratch|verify)(?:$|[-_.])/i.test(match[1]) && !/(?:^|[-_.])(?:prod|production|credentials?|secrets?|backups?)(?:$|[-_.])/i.test(match[1]);
}
export type AccessAssessment={severity:Severity;explanation:string}|{suppress:true};
export function environmentRisk(context:ActionContext):AccessAssessment|undefined {
  const actions=context.actions;
  if(context.truncated)return undefined;
  if(actions.some(a=>a.operation==="environment-dump"||(a.target??"").includes("/proc/self/environ")))return {severity:"high",explanation:"The request accesses the exported process environment without restricting it to named entries. Returned values and exposure are not established by this request alone."};
  const lookups=actions.filter(a=>a.operation==="environment-lookup");
  // Unknown commands may contain additional environment access that the parser
  // cannot classify. Preserve the stronger fallback instead of guessing.
  if(lookups.length && !actions.some(a=>a.operation==="command")) {
    if(lookups.some(a=>a.origin!=="inline-assignment"&&(!a.variableNames?.length || a.variableNames.some(name=>!routineName(name)))))return {severity:"medium",explanation:"The request looks up named inherited environment variables that may contain credentials or unclassified private configuration. It does not dump the whole environment; review authorization and returned output."};
    if(lookups.every(a=>a.origin==="inline-assignment"))return {severity:"info",explanation:"The request looks up named values supplied as literal inline assignments in the same command. This lookup does not access inherited values for those names; recorded values remain redacted."};
    return {severity:"info",explanation:"The request looks up named environment configuration entries without a whole-environment dump. Only recognized routine configuration names were identified; this is recorded for visibility."};
  }
  if(actions.length && actions.every(a=>["file-read","file-search","source-search","file-write","delete","git-change","network-request","network-scan","mcp-call"].includes(a.operation)))return {suppress:true};
  return undefined;
}
export function assessAccessFinding(ruleId:string,context:ActionContext):AccessAssessment|undefined {
  if(ruleId==="credentials.environment")return environmentRisk(context);
  if(ruleId!=="source.private_files"&&ruleId!=="credentials.access")return undefined;
  if(context.truncated)return undefined;
  const reads=context.actions.filter(a=>["file-read","file-search","file-write"].includes(a.operation)&&privatePath(a.resolvedPath??a.target??""));
  if(reads.length && !context.actions.some(a=>a.operation==="command") && reads.every(a=>scopedTemporaryConfiguration(a.resolvedPath??a.target??"")))return {severity:"medium",explanation:"The request targets a private configuration location under a narrowly scoped temporary test directory. Its contents are not verified as fake or harmless; review access and returned output."};
  if(context.actions.length&&context.actions.every(a=>a.operation==="source-search"))return ruleId==="source.private_files"?{suppress:true}:{severity:"info",explanation:"The request searches source code for credential-related text. This reference alone does not establish a credential-file read or disclosure."};
  return undefined;
}
