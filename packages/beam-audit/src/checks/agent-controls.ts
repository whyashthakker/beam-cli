import { existsSync, lstatSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { agentConfigurations, managedConfigurationPaths, readConfiguration } from '../config-files.js';
import type { AuditContext, Check } from '../types.js';

type Entry = { path: string; value: unknown };
export function configurationEntries(value: unknown): { entries: Entry[]; limited: boolean } {
  const entries: Entry[] = []; let limited = false;
  function visit(node: unknown, path: string, depth: number): void {
    if (entries.length >= 10000 || depth > 12) { limited = true; return; }
    if (Array.isArray(node)) { entries.push({ path, value: node }); return; }
    if (node && typeof node === 'object') { if (path) entries.push({path,value:node}); for (const [key, child] of Object.entries(node)) visit(child, path ? `${path}.${key}` : key, depth + 1); }
    else entries.push({ path, value: node });
  }
  visit(value, '', 0); return { entries, limited };
}
export function literalCredential(value: unknown): boolean {
  return typeof value === 'string' && value.length >= 8 && !/^\s*(?:\$|op:\/\/|vault:|@Microsoft\.KeyVault|process\.env\.|env:)/i.test(value);
}
const credentialKey = /(?:^|\.)(?:api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|AWS_SECRET_ACCESS_KEY)$/i;
const bypassKey = /(?:^|\.)(?:defaultMode|permissionMode|initialPermissionMode|approval_policy|approvalMode|autoApprove|auto_approve|yolo|dangerouslySkipPermissions|dangerouslyAllowAllCommands|allowAllTools|autoApproveAll|autoApproveEdits|autoApproveCommands|alwaysAllowWrite|alwaysAllowExecute|chat\.tools\.global\.autoApprove)$/i;
const memoryKeys = new Set(['autoMemoryEnabled', 'memories.generate_memories', 'memories.use_memories', 'features.memory_tool']);
const endpointKey = /(?:^|\.)(?:base_url|baseURL|apiEndpoint|openai_base_url|chatgpt_base_url|ANTHROPIC_BASE_URL|OPENAI_BASE_URL|GOOGLE_GEMINI_BASE_URL|url|httpUrl)$/i;
const approvalValue = (v: unknown) => v === true || typeof v === 'string' && ['never','bypassPermissions','auto','yolo','acceptEdits','always'].includes(v);

export function agentControlChecks(ctx: AuditContext): Check[] {
  const checks: Check[] = [];
  const controls = ctx.agentControls ?? {};
  const add = (id: string, category: Check['category'], title: string, status: Check['status'], detail: string, files: string[] = []) => checks.push({ id, category, policySection: category === 'Sensitive data exposure' ? '4.2 / 6.1' : category === 'Network and data destinations' ? '3 / 6.5' : '3 / 4.3 / 5.5', title, status, detail, evidence: files });
  const managed = managedConfigurationPaths(ctx);
  for (const agent of agentConfigurations(ctx)) {
    const files = [...new Set(agent.paths.filter(existsSync))];
    for (const file of files) {
      let data: any;
      try { data = readConfiguration(file); } catch { continue; } // Inventory reports malformed inputs.
      const { entries, limited } = configurationEntries(data);
      if (limited) add(`control-truncation-${file}`, 'Scan coverage and evidence', `${agent.name}: configuration inspection limit`, 'warn', 'Nested configuration inspection reached its depth or entry limit.', [file]);
      const bypasses = entries.filter(e => bypassKey.test(e.path) && approvalValue(e.value));
      const hooksDisabled = entries.some(e => /(?:^|\.)(?:disableAllHooks|disable_user_hooks)$/.test(e.path) && e.value === true);
      const broadTools = entries.filter(e => /(?:permissions\.allow|tools\.allowed|autoApprove|auto_approve|autoApproveTools)$/.test(e.path) && (Array.isArray(e.value) ? e.value.some(x => typeof x === 'string' && /^(?:\*|Bash\(\*\)|Read\(\*\)|Write\(\*\)|Edit\(\*\)|mcp__.*\*)$/.test(x)) : e.value && typeof e.value === 'object' && Object.values(e.value).some(x => x === true)));
      const sandboxDisabled = entries.some(e => /(?:^|\.)(?:sandbox_mode|sandbox)$/.test(e.path) && ['danger-full-access', false, 'none'].includes(e.value as any) || /(?:^|\.)sandbox\.enabled$/.test(e.path) && e.value === false);
      const networkAllowed = entries.some(e => /(?:^|\.)(?:network_access|networkAccessEnabled|dangerouslyDisableSandbox)$/.test(e.path) && e.value === true);
      const unsafe = bypasses.length > 0 || broadTools.length > 0;
      add(`agent-approval-${file}`, 'Agent permissions and bypasses', `${agent.name}: automatic approval declarations`, unsafe ? controls.requireManualApproval ? 'fail' : 'warn' : 'pass', unsafe ? `${bypasses.length} permissive mode declarations and ${broadTools.length} broad tool grants found. Policy evaluates declarations; selected profiles, runtime flags, managed constraints, and project trust may change applicability.` : 'No recognized permissive approval declarations in this parsed file. This does not prove manual review or runtime enforcement.', [file]);
      add(`agent-sandbox-${file}`, 'Agent permissions and bypasses', `${agent.name}: sandbox and network declarations`, sandboxDisabled ? controls.requireSandbox ? 'fail' : 'warn' : networkAllowed ? 'warn' : 'pass', sandboxDisabled ? 'An explicit sandbox-disable or unrestricted-access declaration exists. It is not a runtime sandbox attestation.' : networkAllowed ? 'An explicit network-access or sandbox escape declaration requires review.' : 'No recognized sandbox-disable declaration. Missing sandbox settings do not establish that a sandbox is active.', [file]);
      const memory = entries.filter(e => memoryKeys.has(e.path));
      if (memory.length) add(`agent-memory-${file}`, 'Sensitive data exposure', `${agent.name}: persistent memory declarations`, memory.some(e => e.value === true) ? controls.forbidPersistentMemory ? 'fail' : 'warn' : 'pass', `${memory.filter(e => e.value === true).length} enabled and ${memory.filter(e => e.value === false).length} disabled memory declarations observed. Default behavior and other memory stores remain separate checks.`, [file]);
      if (hooksDisabled) add(`agent-hooks-disabled-${file}`, 'Agent permissions and bypasses', `${agent.name}: hook-disabling declaration`, controls.requirePromptHooks ? 'fail' : 'warn', 'A hook-disabling declaration exists. Review its scope and precedence against required managed and user hooks.', [file]);
      const hooks = data.hooks;
      if (agent.name === 'Claude Code' && !file.endsWith('.claude.json')) {
        const events = hooks && typeof hooks === 'object' ? Object.keys(hooks).filter(k => ['PreToolUse','UserPromptSubmit'].includes(k)) : [];
        const nonempty = events.filter(k => Array.isArray(hooks[k]) && hooks[k].some((group: any) => Array.isArray(group?.hooks) && group.hooks.some((h: any) => h && typeof h.command === 'string' && h.command.trim())));
        add(`agent-prompt-hooks-${file}`, 'Agent permissions and bypasses', `${agent.name}: prompt/tool hook declarations`, hooksDisabled ? 'warn' : nonempty.length ? 'pass' : 'skip', `${nonempty.length} supported events contain nonempty hook commands. Commands are not executed; empty hook arrays do not establish protection. Actual hook effect, load errors, and managed precedence require execution evidence.`, [file]);
      }
      const literals = entries.filter(e => credentialKey.test(e.path) && literalCredential(e.value));
      if (literals.length) add(`agent-literal-credentials-${file}`, 'Sensitive data exposure', `${agent.name}: literal credential settings`, 'warn', `${literals.length} credential fields contain literal-looking values rather than recognized secret references. Confirm whether they are real, rotate exposed credentials, and move them to approved storage. Values and field paths are omitted.`, [file]);
      if (entries.some(e => /(?:^|\.)(?:apiKeyHelper|headersHelper)$/.test(e.path))) add(`agent-credential-helper-${file}`, 'Agent permissions and bypasses', `${agent.name}: credential helper commands`, 'warn', 'A credential/header helper declaration exists. Its provenance and access scope need review. The scanner did not execute it.', [file]);
      for (const e of entries.filter(e => endpointKey.test(e.path) && typeof e.value === 'string' && (!/(?:^|\.)(?:url|httpUrl)$/.test(e.path) || /mcp|provider/i.test(e.path)))) {
        const value = e.value as string;
        if (/^\s*(?:\$|env:)/.test(value)) { add(`agent-endpoint-reference-${file}-${checks.length}`, 'Network and data destinations', `${agent.name}: endpoint reference unresolved`, 'skip', 'Endpoint is an environment reference; no destination approval inferred.', [file]); continue; }
        let safe = false, approved: boolean | undefined;
        try { const url = new URL(value); safe = url.protocol === 'https:' && !url.username && !url.password; approved = controls.allowedEndpointOrigins ? controls.allowedEndpointOrigins.some(origin => new URL(origin).origin === url.origin) : undefined; } catch { /* invalid or non-URL reference */ }
        add(`agent-endpoint-${file}-${checks.length}`, 'Network and data destinations', `${agent.name}: configured endpoint policy`, !safe || approved === false ? 'fail' : approved ? 'pass' : 'warn', !safe ? 'A supported endpoint field is invalid, embeds credentials, or does not use HTTPS. Value omitted.' : approved === false ? 'Configured destination origin is outside the organization allowlist. Value omitted.' : approved ? 'Configured HTTPS origin matches the organization allowlist. Actual traffic and TLS negotiation were not inspected.' : 'HTTPS destination declaration found; no organization endpoint allowlist supplied.', [file]);
      }
      const models = entries.filter(e => /(?:^|\.)(?:model|model_name|defaultModel)$/.test(e.path) && typeof e.value === 'string');
      if (controls.allowedModels && models.length) add(`agent-models-${file}`, 'Organization policy compliance', `${agent.name}: model allowlist`, models.some(e => !controls.allowedModels!.includes(e.value as string)) ? 'fail' : 'pass', 'Compared explicit model declarations with the policy list. Runtime model selection and provider defaults are not verified; values omitted.', [file]);
      const auth = entries.filter(e => /(?:forced_login_method|cli_auth_credentials_store|security\.auth\.selectedType)$/.test(e.path));
      if (auth.length) add(`agent-auth-${file}`, 'Organization policy compliance', `${agent.name}: authentication restrictions and storage`, auth.some(e => e.value === 'file' || e.value === 'auto') ? 'warn' : 'skip', `${auth.length} supported authentication/storage declarations observed. File/auto credential storage can leave credential files. Configuration does not prove commercial account tier, SSO, MFA, organization ownership, or training/retention terms.`, [file]);
      const externalRoots = entries.filter(e => /(?:additionalDirectories|writable_roots|includeDirectories)$/.test(e.path));
      if (externalRoots.length) add(`agent-extra-roots-${file}`, 'Agent permissions and bypasses', `${agent.name}: additional filesystem access`, 'warn', 'Additional directory/writable-root declarations exist. Confirm they exclude customer data, credential stores, and unrelated projects. Runtime filesystem access was not measured.', [file]);
      if (data.profiles && typeof data.profiles === 'object') add(`agent-profiles-${file}`, 'Agent permissions and bypasses', `${agent.name}: selectable profiles`, 'warn', `${Object.keys(data.profiles).length} named profiles found. Their settings were inspected as declarations; the runtime-selected profile is not established.`, [file]);
    }
  }
  for (const item of managed) {
    add(`agent-managed-${item.agent}`, 'Organization policy compliance', `${item.agent}: managed policy source discovery`, existsSync(item.path) ? 'warn' : 'skip', existsSync(item.path) ? 'Known managed file exists. Administrator ownership, ACLs, cloud/MDM policy, applicability, and loaded enforcement are not independently verified.' : 'No file found at this supported managed location. Cloud or MDM policy may still apply.', [item.path]);
    if (existsSync(item.path)) try {
      const config=readConfiguration(item.path);const st=statSync(item.path);
      if(ctx.platform!=='win32')add(`agent-managed-write-${item.agent}`, 'Organization policy compliance', `${item.agent}: managed file write permissions`, st.mode&0o022?'fail':st.uid===0?'pass':'warn', st.mode&0o022?'Managed file is group/world writable.':st.uid===0?'Managed file is root-owned without group/world write bits. Extended ACLs and parent-directory access remain unverified.':'Managed file is not root-owned; verify administrator control and effective ACLs.',[item.path]);
      if(item.agent==='Codex') {
        const approval=Array.isArray(config.allowed_approval_policies)?config.allowed_approval_policies:[];
        const sandbox=Array.isArray(config.allowed_sandbox_modes)?config.allowed_sandbox_modes:[];
        const bad=Boolean(controls.requireManualApproval&&approval.includes('never')||controls.requireSandbox&&sandbox.includes('danger-full-access'));
        add('codex-managed-constraints','Agent permissions and bypasses','Codex: managed approval/sandbox constraints',bad?'fail':approval.length&&sandbox.length?'warn':'skip',bad?'Managed file explicitly permits a mode prohibited by the supplied organization agent policy.':'Constraint declarations inspected; actual loading, cloud/MDM requirements, profile selection and enforcement are unverified.',[item.path]);
      }
    } catch { add(`agent-managed-unreadable-${item.agent}`,'Scan coverage and evidence',`${item.agent}: managed file inspection unavailable`,'skip','Managed file could not be read or parsed.',[item.path]); }
  }
  const env = ctx.environment ?? process.env;
  const overrides = ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','REQUESTS_CA_BUNDLE'].filter(k => Boolean(env[k]));
  if (overrides.length) add('agent-network-environment', 'Network and data destinations', 'Proxy/custom CA environment signals', 'warn', `${overrides.length} proxy or trust-store variables are set in the scanner environment. Verify organization approval and the environment actually inherited by each extension. Values omitted.`);
  add('agent-runtime-enforcement', 'Agent permissions and bypasses', 'Runtime and merged-policy verification boundary', 'skip', 'Parsed declarations do not establish the effective runtime configuration. CLI flags, profile selection, project trust, managed/cloud settings, environment overrides, and per-session UI changes require correlated runtime evidence.');
  return checks;
}
