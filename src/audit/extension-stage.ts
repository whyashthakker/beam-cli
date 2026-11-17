import { launchIsolatedVsCode } from './vscode-launch.js';
import { runExtensionUiTests, type ExtensionAdapter } from './checks/extension-ui.js';
import { unavailableExtensionReview } from './checks/extension-review.js';
import { EXTENSION_PROBES } from './extension-probes.js';
import type { AuditContext, Check } from './types.js';
import type { NamedMatrix } from './report.js';

export async function runExtensionStage(
  ctx: AuditContext,
  options: { launch: boolean; endpoint?: string; adapters: ExtensionAdapter[] },
  dependencies = { launch: launchIsolatedVsCode, run: runExtensionUiTests },
): Promise<{ checks: Check[]; matrices: NamedMatrix[] }> {
  const checks: Check[] = [];
  if (!options.launch && !options.endpoint) return { checks, matrices: [] };
  const title = 'Actual VS Code extension UI · prohibited data (policy 4.2)';
  try {
    let endpoint = options.endpoint;
    let reviewWorkspace: string | undefined;
    if (options.launch) {
      const session = await dependencies.launch(ctx);
      endpoint = session.endpoint;
      reviewWorkspace = session.workspace;
      checks.push({ id: 'isolated-vscode-environment', category: 'Scan coverage and evidence', policySection: 'Scope', title: 'Isolated VS Code test environment', status: 'warn', detail: 'Tests use a separate temporary VS Code profile and synthetic workspace. User settings are copied when available. Existing conversations, authentication databases, and production project settings are not copied. Results do not establish protection in the working window.', evidence: [session.workspace] });
      ctx.log('Open empty Claude and Codex chats in the separate window. Authentication or initial setup may require attention.');
    }
    const cells = await dependencies.run(ctx, endpoint!, options.adapters, { waitForUiMs: options.launch ? 60000 : 0, reviewWorkspace });
    return { checks, matrices: [{ title, cells: cells.filter(c=>c.dataCategory!=="Code review") }, ...(cells.some(c=>c.dataCategory==="Code review") ? [{ title: "Actual VS Code extension UI · code review requirements (policy 4.3)", cells: cells.filter(c=>c.dataCategory==="Code review") }] : [])] };
  } catch {
    ctx.log('Extension UI stage unavailable; preserving workstation findings and recording untested extension rows.');
    checks.push({ id: 'extension-stage-unavailable', category: 'Scan coverage and evidence', policySection: '4.2 / Scope', title: 'Extension UI stage unavailable', status: 'skip', detail: 'VS Code could not be launched, attached, or inspected. Other scan findings are preserved; no extension blocking result is inferred.' });
    return { checks, matrices: [{ title, cells: options.adapters.flatMap(adapter => EXTENSION_PROBES.map(probe => ({ surface: adapter.agent === 'Claude' ? 'VS Code · Claude extension' as const : 'VS Code · Codex extension' as const, label: `${probe.category} / ${probe.label}`, dataCategory: probe.category, blocked: null, detail: 'Extension UI stage unavailable; this sample was not tested.' }))) }, { title: 'Actual VS Code extension UI · code review requirements (policy 4.3)', cells: options.adapters.map(adapter=>unavailableExtensionReview(adapter,'Extension UI stage unavailable; edit review test not submitted.')) }] };
  }
}
