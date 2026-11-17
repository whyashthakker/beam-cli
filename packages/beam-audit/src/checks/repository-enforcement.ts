import { spawnSync } from 'node:child_process';
import { accessSync, constants, readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { confidentHits } from '../detectors.js';
import type { AuditContext, Check } from '../types.js';
function git(repo: string, args: string[]) { return spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024 }); }

// One row per rule across the whole machine, not one per repo -- a device with 50 clones used to
// produce 50 near-identical "Effective pre-commit hook" rows and 50 "Recent Git history credential
// patterns" rows, which read as noise rather than a report. Aggregated the same way
// repo-hygiene.ts's precommitHookCheck/publicRepoVisibilityCheck already do: worst status wins,
// affected repos go in `evidence`, and `detail` carries the count.
export function repositoryEnforcementChecks(ctx: AuditContext): Check[] {
  const checks: Check[] = [];
  const label = (repo: string) => relative(ctx.home, repo) || repo;

  const hookFailed: string[] = []; // couldn't determine (git/hook path lookup failed)
  const hookInactive: string[] = []; // no secret-scanning hook
  const hookActive: string[] = []; // hook present, referenced a scanner, but unexecuted
  const historyFailed: string[] = []; // history inspection failed or exceeded limits
  const historyHits: string[] = []; // credential-shaped patterns found

  for (const repo of ctx.repos) {
    const hook = git(repo, ['rev-parse', '--git-path', 'hooks/pre-commit']);
    if (hook.status !== 0) hookFailed.push(label(repo));
    else {
      let active = false;
      try {
        const path = resolve(repo, hook.stdout.trim());
        accessSync(path, ctx.platform === 'win32' ? constants.R_OK : constants.X_OK);
        active = readFileSync(path, 'utf8').split('\n').some(line => !line.trim().startsWith('#') && /git-secrets|trufflehog|detect-secrets|gitleaks|\bbeam\b/i.test(line));
      } catch { /* Missing or inaccessible hook. */ }
      (active ? hookActive : hookInactive).push(label(repo));
    }

    const history = git(repo, ['log', '--all', '-n', '100', '--format=commit:%h', '--patch', '--no-ext-diff', '--no-textconv']);
    if (history.status !== 0) historyFailed.push(label(repo));
    else {
      const kinds = [...new Set(confidentHits(history.stdout).filter(h => ['API_KEY', 'OAUTH_TOKEN', 'PRIVATE_KEY', 'SERVICE_ACCOUNT'].includes(h.kind)).map(h => h.kind))];
      if (kinds.length) historyHits.push(`${label(repo)}: ${kinds.join(', ')}`);
    }
  }

  if (ctx.repos.length === 0) {
    checks.push({ id: 'effective-hook', policySection: '6.2 / Git safeguards and bypasses', title: 'Effective pre-commit hook', status: 'skip', detail: 'No repositories scanned.' });
    checks.push({ id: 'history', policySection: '6.2 / Sensitive data exposure', title: 'Recent Git history credential patterns', status: 'skip', detail: 'No repositories scanned.' });
  } else {
    checks.push({
      id: 'effective-hook',
      policySection: '6.2 / Git safeguards and bypasses',
      title: 'Effective pre-commit hook',
      status: hookInactive.length ? 'fail' : hookActive.length ? 'warn' : 'skip',
      detail: `${hookInactive.length} of ${ctx.repos.length} repositories have no verifiable effective executable secret-scanning pre-commit hook. `
        + `${hookActive.length} have an effective hook referencing a secret scanner (its behavior was not executed; local hooks remain bypassable with --no-verify or alternate hooksPath).`
        + (hookFailed.length ? ` ${hookFailed.length} could not be checked.` : ''),
      evidence: [...hookInactive, ...hookFailed.map(r => `${r} (could not be checked)`)].slice(0, 50),
    });
    checks.push({
      id: 'history',
      policySection: '6.2 / Sensitive data exposure',
      title: 'Recent Git history credential patterns',
      status: historyHits.length ? 'fail' : historyFailed.length === ctx.repos.length ? 'skip' : 'pass',
      detail: `Inspected up to 100 commits across refs in each of ${ctx.repos.length} repositories; `
        + (historyHits.length ? `credential-shaped patterns found in ${historyHits.length} repositories.` : 'no recognized high-confidence credential patterns found.')
        + (historyFailed.length ? ` ${historyFailed.length} repositories' history inspection failed or exceeded output/time limits.` : '')
        + ' Older commits, unreachable objects, and LFS contents are outside this check. Values are never reported.',
      evidence: [...historyHits, ...historyFailed.map(r => `${r} (inspection failed)`)].slice(0, 50),
    });
    checks.push({
      id: 'remote-enforcement',
      policySection: '6.2 / Git safeguards and bypasses',
      title: 'Remote branch enforcement',
      status: 'skip',
      detail: 'Required reviews, status checks, branch rules, and administrator bypass rights require authenticated provider evidence. Local hook presence does not establish remote enforcement.',
      evidence: ctx.repos.map(label).slice(0, 50),
    });
  }

  if (process.env.HUSKY === '0' || process.env.PRE_COMMIT_ALLOW_NO_CONFIG || process.env.SKIP) checks.push({ id: 'hook-bypass-environment', policySection: '6.2 / Git safeguards and bypasses', title: 'Hook bypass environment signals', status: 'warn', detail: 'HUSKY, SKIP, or PRE_COMMIT_ALLOW_NO_CONFIG indicates possible hook suppression. Values omitted.' });
  return checks;
}
