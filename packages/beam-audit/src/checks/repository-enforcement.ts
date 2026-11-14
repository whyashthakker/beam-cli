import { spawnSync } from 'node:child_process';
import { accessSync, constants, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { confidentHits } from '../detectors.js';
import type { AuditContext, Check } from '../types.js';
function git(repo: string, args: string[]) { return spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024 }); }
export function repositoryEnforcementChecks(ctx: AuditContext): Check[] {
  const checks: Check[] = [];
  for (const repo of ctx.repos) {
    const hook = git(repo, ['rev-parse', '--git-path', 'hooks/pre-commit']);
    let active = false;
    if (hook.status === 0) try {
      const path = resolve(repo, hook.stdout.trim());
      accessSync(path, ctx.platform === 'win32' ? constants.R_OK : constants.X_OK);
      active = readFileSync(path, 'utf8').split('\n').some(line => !line.trim().startsWith('#') && /git-secrets|trufflehog|detect-secrets|gitleaks|\bbeam\b/i.test(line));
    } catch { /* Missing or inaccessible hook. */ }
    checks.push({ id: `effective-hook-${repo}`, policySection: '6.2 / Git safeguards and bypasses', title: 'Effective pre-commit hook', status: hook.status !== 0 ? 'skip' : active ? 'warn' : 'fail', detail: active ? 'Effective executable hook references a secret scanner. Its behavior was not executed. Local hooks remain bypassable with --no-verify or alternate hooksPath.' : 'No verifiable effective executable secret-scanning pre-commit hook.', evidence: [repo] });
    const history = git(repo, ['log', '--all', '-n', '100', '--format=commit:%h', '--patch', '--no-ext-diff', '--no-textconv']);
    const kinds = history.status === 0 ? [...new Set(confidentHits(history.stdout).filter(h => ['API_KEY', 'OAUTH_TOKEN', 'PRIVATE_KEY', 'SERVICE_ACCOUNT'].includes(h.kind)).map(h => h.kind))] : [];
    checks.push({ id: `history-${repo}`, policySection: '6.2 / Sensitive data exposure', title: 'Recent Git history credential patterns', status: history.status !== 0 ? 'skip' : kinds.length ? 'fail' : 'pass', detail: history.status !== 0 ? 'History inspection failed or exceeded output/time limits.' : `Inspected up to 100 commits across refs; ${kinds.length ? 'credential-shaped patterns found: ' + kinds.join(', ') : 'no recognized high-confidence credential patterns found'}. Older commits, unreachable objects, and LFS contents are outside this check. Values are never reported.`, evidence: [repo] });
    checks.push({ id: `remote-enforcement-${repo}`, policySection: '6.2 / Git safeguards and bypasses', title: 'Remote branch enforcement', status: 'skip', detail: 'Required reviews, status checks, branch rules, and administrator bypass rights require authenticated provider evidence. Local hook presence does not establish remote enforcement.', evidence: [repo] });
  }
  if (process.env.HUSKY === '0' || process.env.PRE_COMMIT_ALLOW_NO_CONFIG || process.env.SKIP) checks.push({ id: 'hook-bypass-environment', policySection: '6.2 / Git safeguards and bypasses', title: 'Hook bypass environment signals', status: 'warn', detail: 'HUSKY, SKIP, or PRE_COMMIT_ALLOW_NO_CONFIG indicates possible hook suppression. Values omitted.' });
  return checks;
}
