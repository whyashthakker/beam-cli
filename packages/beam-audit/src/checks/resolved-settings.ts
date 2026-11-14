import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { managedConfigurationPaths, readConfiguration } from '../config-files.js';
import type { AuditContext, Check } from '../types.js';
export interface SettingsLayer { scope: 'user'|'project'|'local'|'managed'; data: Record<string, any>; file: string; }
function merge(target: Record<string, any>, source: Record<string, any>, appendArrays: boolean): void {
 for (const [key, value] of Object.entries(source)) {
  if (['__proto__','constructor','prototype'].includes(key)) continue;
  if (Array.isArray(value)) target[key] = appendArrays && Array.isArray(target[key]) ? [...target[key], ...value] : [...value];
  else if (value && typeof value === 'object') { if (!target[key] || typeof target[key] !== 'object' || Array.isArray(target[key])) target[key] = Object.create(null); merge(target[key], value, appendArrays); }
  else target[key] = value;
 }
}
export function resolveFileSettings(agent: 'Claude Code'|'Codex', layers: SettingsLayer[]): { settings: Record<string, any>; ignoredDeclarations: number } {
 const settings: Record<string, any> = Object.create(null); let ignoredDeclarations = 0;
 for (const layer of layers) {
  const data: Record<string, any> = Object.create(null); merge(data, layer.data, false);
  if (layer.scope === 'project' || layer.scope === 'local') {
   if (agent === 'Claude Code' && ['auto','bypassPermissions'].includes(data.permissions?.defaultMode)) { delete data.permissions.defaultMode; ignoredDeclarations++; }
   if (agent === 'Codex') for (const key of ['model_provider','model_providers','openai_base_url','chatgpt_base_url','notify','profile','profiles','otel']) if (key in data) { delete data[key]; ignoredDeclarations++; }
  }
  merge(settings, data, agent === 'Claude Code');
 }
 if (agent === 'Codex' && typeof settings.profile === 'string' && settings.profiles?.[settings.profile]) merge(settings, settings.profiles[settings.profile], false);
 return { settings, ignoredDeclarations };
}
export function resolvedSettingsChecks(ctx: AuditContext): Check[] {
 const env = ctx.environment ?? process.env;
 const roots = { claude: env.CLAUDE_CONFIG_DIR ? resolve(env.CLAUDE_CONFIG_DIR) : join(ctx.home,'.claude'), codex: env.CODEX_HOME ? resolve(env.CODEX_HOME) : join(ctx.home,'.codex') };
 const scopes: Array<string|undefined> = [undefined, ...ctx.repos.slice(0,500)];
 const checks: Check[] = []; const cache = new Map<string, Record<string, any>|null>();
 function read(file:string) { if (!cache.has(file)) { try { cache.set(file, readConfiguration(file)); } catch { cache.set(file,null); } } return cache.get(file); }
 for (const agent of ['Claude Code','Codex'] as const) for (const repo of scopes) {
  const candidates: Array<{scope:SettingsLayer['scope'];file:string}> = agent === 'Claude Code'
   ? [{scope:'user',file:join(roots.claude,'settings.json')}, ...(repo ? [{scope:'project' as const,file:join(repo,'.claude/settings.json')},{scope:'local' as const,file:join(repo,'.claude/settings.local.json')}] : []), ...managedConfigurationPaths(ctx).filter(p=>p.agent===agent).map(p=>({scope:'managed' as const,file:p.path}))]
   : [{scope:'user',file:join(roots.codex,'config.toml')}, ...(repo ? [{scope:'project' as const,file:join(repo,'.codex/config.toml')}] : [])];
  const layers: SettingsLayer[] = [];
  for (const candidate of candidates) if (existsSync(candidate.file)) { const data = read(candidate.file); if (data) layers.push({...candidate,data}); }
  if (!layers.length) continue;
  const {settings,ignoredDeclarations} = resolveFileSettings(agent,layers);
  const approval = agent==='Claude Code' ? settings.permissions?.defaultMode : settings.approval_policy;
  const sandbox = agent==='Claude Code' ? settings.sandbox?.enabled : settings.sandbox_mode;
  const unsafeApproval = ['bypassPermissions','auto','acceptEdits','never'].includes(approval);
  const unsafeSandbox = sandbox===false || sandbox==='danger-full-access';
  const violated = ctx.agentControls?.requireManualApproval && unsafeApproval || ctx.agentControls?.requireSandbox && unsafeSandbox;
  const label = (v: unknown, known: unknown[]) => known.includes(v) ? String(v) : v===undefined ? 'not declared' : 'custom/unrecognized';
  const hasPromptHook=Array.isArray(settings.hooks?.UserPromptSubmit)&&settings.hooks.UserPromptSubmit.some((group:any)=>Array.isArray(group?.hooks)&&group.hooks.some((hook:any)=>typeof hook?.command==='string'&&hook.command.trim()));
  if(agent==='Claude Code'&&ctx.agentControls?.requirePromptHooks)checks.push({id:`agent-required-prompt-hooks-${agent}-${repo??'user'}`,category:'Agent permissions and bypasses',policySection:'4.2',title:`${agent}: required prompt hook declaration`,status:hasPromptHook&&settings.disableAllHooks!==true?'pass':'fail',detail:hasPromptHook&&settings.disableAllHooks!==true?'Supported file-derived settings contain a nonempty UserPromptSubmit command. Its actual interception behavior is not verified.':'Supported file-derived settings do not provide an enabled nonempty UserPromptSubmit command. PreToolUse alone does not inspect directly typed prompts.',evidence:layers.map(l=>l.file)});
  if(ctx.agentControls?.forbidPersistentMemory){const disabled=agent==='Claude Code'?settings.autoMemoryEnabled===false:settings.memories?.generate_memories===false&&settings.memories?.use_memories===false;const enabled=agent==='Claude Code'?settings.autoMemoryEnabled===true:settings.memories?.generate_memories===true||settings.memories?.use_memories===true;checks.push({id:`agent-memory-config-${agent}-${repo??'user'}`,category:'Sensitive data exposure',policySection:'5.5',title:`${agent}: memory restriction declaration`,status:enabled?'fail':disabled?'pass':'skip',detail:enabled?'File-derived configuration explicitly enables persistent memory.':disabled?'Supported file-derived memory generation/use settings explicitly disable memory. Existing files and runtime overrides need separate verification.':'Explicit memory-disable settings were not established. Defaults and managed/runtime state were not inferred.',evidence:layers.map(l=>l.file)});}
  if(ctx.agentControls?.requireSandbox)checks.push({id:`agent-sandbox-config-${agent}-${repo??'user'}`,category:'Agent permissions and bypasses',policySection:'4.3',title:`${agent}: sandbox restriction declaration`,status:unsafeSandbox?'fail':sandbox===true||['read-only','workspace-write'].includes(sandbox)?'pass':'skip',detail:'Evaluated the file-derived sandbox declaration. This does not attest to the actual OS sandbox or all external tool paths.',evidence:layers.map(l=>l.file)});
  checks.push({ id:`agent-file-resolution-${agent}-${repo??'user'}`,category:'Agent permissions and bypasses',policySection:'3 / 4.3',title:`${agent}: file-derived settings ${repo?'for project':'for user defaults'}`,status:violated?'fail':'warn',detail:`${layers.length} supported layers resolved independently for this scope. Approval: ${label(approval,['default','plan','acceptEdits','auto','bypassPermissions','on-request','untrusted','never','granular'])}; sandbox: ${label(sandbox,[true,false,'read-only','workspace-write','danger-full-access'])}; ${ignoredDeclarations} known scope-inapplicable declarations ignored. This is a file-derived candidate, not effective-runtime proof: trust, CLI/UI session overrides, cloud/MDM restrictions, and version differences remain unverified.`,evidence:layers.map(l=>l.file) });
 }
 return checks;
}
