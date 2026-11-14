import { readFileSync, statSync } from 'node:fs';
import type { Check } from './types.js';
export interface AgentControlsPolicy {
  requireManualApproval?: boolean;
  requireSandbox?: boolean;
  forbidPersistentMemory?: boolean;
  requirePromptHooks?: boolean;
  requirePinnedMcpPackages?: boolean;
  allowedEndpointOrigins?: string[];
  allowedMcpServers?: string[];
  allowedModels?: string[];
  allowedExtensions?: string[];
  allowedPlugins?: string[];
  minimumExtensionVersions?: Record<string, string>;
}
export interface AuditPolicy {
  version: 1;
  requiredChecks: string[];
  allowedAgents?: string[];
  allowedPlatforms?: string[];
  validUntil?: string;
  agentControls?: AgentControlsPolicy;
  evidence?: Record<string, { reference: string; expires: string }>;
}
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(v => typeof v === 'string' && v.length > 0 && v.length <= 500);
export function loadPolicy(path: string): AuditPolicy {
  if (statSync(path).size > 1_000_000) throw new Error('Audit policy exceeds 1 MB');
  const p = JSON.parse(readFileSync(path, 'utf8'));
  if (!p || p.version !== 1 || !strings(p.requiredChecks)) throw new Error('Policy requires version 1 and requiredChecks string array');
  for (const key of Object.keys(p)) if (!['version','requiredChecks','allowedAgents','allowedPlatforms','validUntil','agentControls','evidence'].includes(key)) throw new Error(`Unknown policy field: ${key}`);
  for (const field of ['allowedAgents', 'allowedPlatforms']) if (p[field] !== undefined && !strings(p[field])) throw new Error(`Invalid policy ${field}`);
  if (p.validUntil !== undefined && (typeof p.validUntil !== 'string' || !Number.isFinite(Date.parse(p.validUntil)))) throw new Error('Invalid policy validUntil');
  if (p.agentControls !== undefined) {
    const controls = p.agentControls;
    if (!controls || typeof controls !== 'object' || Array.isArray(controls)) throw new Error('Invalid agentControls');
    const booleans = ['requireManualApproval', 'requireSandbox', 'forbidPersistentMemory', 'requirePromptHooks', 'requirePinnedMcpPackages'];
    const lists = ['allowedEndpointOrigins', 'allowedMcpServers', 'allowedModels', 'allowedExtensions', 'allowedPlugins'];
    for (const key of Object.keys(controls)) if (![...booleans, ...lists, 'minimumExtensionVersions'].includes(key)) throw new Error(`Unknown agent control: ${key}`);
    for (const key of booleans) if (controls[key] !== undefined && typeof controls[key] !== 'boolean') throw new Error(`Invalid agent control: ${key}`);
    for (const key of lists) if (controls[key] !== undefined && !strings(controls[key])) throw new Error(`Invalid agent control: ${key}`);
    for (const value of controls.allowedEndpointOrigins ?? []) {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Allowed endpoint origins must be credential-free HTTPS origins');
    }
    if (controls.minimumExtensionVersions !== undefined && (!controls.minimumExtensionVersions || typeof controls.minimumExtensionVersions !== 'object' || Array.isArray(controls.minimumExtensionVersions) || Object.values(controls.minimumExtensionVersions).some(v => typeof v !== 'string' || !/^\d+\.\d+\.\d+$/.test(v)))) throw new Error('Minimum extension versions require exact three-part releases');
  }
  if (p.evidence !== undefined) {
    if (!p.evidence || typeof p.evidence !== 'object' || Array.isArray(p.evidence)) throw new Error('Invalid policy evidence');
    for (const e of Object.values(p.evidence) as any[]) if (!e || typeof e.reference !== 'string' || !e.reference.trim() || typeof e.expires !== 'string' || !Number.isFinite(Date.parse(e.expires))) throw new Error('Evidence requires reference and ISO expiry');
  }
  return p;
}
export function evaluatePolicy(checks: Check[], policy?: AuditPolicy, now = Date.now(), platform: NodeJS.Platform = process.platform): Check[] {
  if (!policy) return [{ id: 'organization-policy', policySection: 'Organization policy compliance', title: 'Organization policy supplied', status: 'skip', detail: 'No organization policy supplied. Baseline checks cannot establish organization compliance.' }];
  const out: Check[] = [];
  for (const id of policy.requiredChecks) {
    const check = checks.find(c => c.id === id);
    out.push({ id: `required-${id}`, policySection: 'Organization policy compliance', title: `Required control: ${id}`, status: check?.status === 'pass' ? 'pass' : 'fail', detail: check ? `Observed status: ${check.status}. A required control must be verified as passing.` : 'Unknown required check ID; control was not evaluated.' });
  }
  if (policy.validUntil) out.push({ id: 'policy-validity', policySection: '2.3, 8.4 / Organization policy compliance', title: 'Policy engagement approval period', status: Date.parse(policy.validUntil) > now ? 'pass' : 'fail', detail: Date.parse(policy.validUntil) > now ? 'Configured policy validity date has not expired; signed approval contents were not verified.' : 'Policy validity date has expired. Obtain an updated approval before relying on this policy.' });
  if (policy.allowedPlatforms) out.push({ id: 'approved-platform', policySection: '3 / Organization policy compliance', title: 'Approved operating system family', status: policy.allowedPlatforms.includes(platform) ? 'pass' : 'fail', detail: 'Compared OS family with policy. Exact OS edition and supported release lifecycle require separate evidence.' });
  for (const [id, e] of Object.entries(policy.evidence ?? {})) out.push({ id: `attestation-${id}`, policySection: 'Organization policy compliance', title: `External attestation: ${id}`, status: Date.parse(e.expires) > now ? 'warn' : 'fail', detail: Date.parse(e.expires) > now ? 'Unexpired organization-supplied evidence reference; its contents were not independently verified.' : 'Organization-supplied evidence has expired.' });
  if (policy.allowedAgents) for (const c of checks.filter(c => c.id.startsWith('inventory-') && c.status !== 'skip')) {
    const name = c.id.slice('inventory-'.length);
    out.push({ id: `approved-${name}`, policySection: '3 / Organization policy compliance', title: `Approved agent: ${name}`, status: policy.allowedAgents.includes(name) ? 'pass' : 'fail', detail: 'Compared discovered configuration or executable-name signal with the agent allowlist. This does not establish binary authenticity.' });
  }
  return out;
}
