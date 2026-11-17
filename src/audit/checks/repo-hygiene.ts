// Policy 6.2 Repository Controls: a pre-commit secret-scanning hook, and no public hosting of
// engagement code without approval.
import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { spawnSync } from "node:child_process";
import type { AuditContext, Check } from "../types.js";

const SECRET_SCANNERS = /git-secrets|trufflehog|detect-secrets|gitleaks|\bbeam\b/i;

function hasSecretScanningHook(repo: string): boolean {
  const hookPath = join(repo, ".git", "hooks", "pre-commit");
  if (existsSync(hookPath)) {
    try {
      if (SECRET_SCANNERS.test(readFileSync(hookPath, "utf8"))) return true;
    } catch { /* unreadable hook */ }
  }
  for (const cfg of [".pre-commit-config.yaml", ".pre-commit-config.yml", ".husky/pre-commit"]) {
    try {
      if (SECRET_SCANNERS.test(readFileSync(join(repo, cfg), "utf8"))) return true;
    } catch { /* not present or unreadable */ }
  }
  return false;
}

export function precommitHookCheck(ctx: AuditContext): Check {
  const missing = ctx.repos.filter(r => !hasSecretScanningHook(r)).map(r => relative(ctx.home, r) || r);
  return {
    id: "6.2-precommit-hook",
    policySection: "6.2 (Repository Controls)",
    title: "Pre-commit secret-scanning hook configured",
    status: ctx.repos.length === 0 ? "skip" : missing.length > 0 ? "fail" : "pass",
    detail: ctx.repos.length === 0
      ? "No repositories scanned."
      : missing.length > 0
        ? `${missing.length} of ${ctx.repos.length} repositories have no pre-commit hook referencing a secret scanner (git-secrets, truffleHog, detect-secrets, gitleaks, or beam).`
        : `All ${ctx.repos.length} repositories have a pre-commit hook referencing a recognised secret scanner.`,
    evidence: missing.slice(0, 50),
    fix: missing.length > 0 ? "Install a pre-commit secret scanner (e.g. `beam setup`, or gitleaks/git-secrets/detect-secrets) so commits made outside an agent session are still scanned." : undefined,
  };
}

function remoteUrl(repo: string): string | null {
  const res = spawnSync("git", ["-C", repo, "remote", "get-url", "origin"], { encoding: "utf8", timeout: 5_000 });
  if (res.status !== 0 || typeof res.stdout !== "string") return null;
  return res.stdout.trim() || null;
}

function ghAvailable(): boolean {
  return spawnSync(process.platform === "win32" ? "where" : "which", ["gh"], { encoding: "utf8", timeout: 5_000 }).status === 0;
}

export function publicRepoVisibilityCheck(ctx: AuditContext): Check {
  const base = { id: "6.2-public-hosting", policySection: "6.2 (Repository Controls)", title: "Repositories are not publicly hosted" };
  const ghRepos: Array<{ repo: string; slug: string }> = [];
  const unresolvable: string[] = [];
  for (const repo of ctx.repos) {
    const url = remoteUrl(repo);
    if (!url) continue;
    const m = /github\.com[:/]+([^/\s]+\/[^/\s]+?)(?:\.git)?\/?$/i.exec(url);
    if (m) ghRepos.push({ repo, slug: m[1]! });
    else if (/gitlab\.com|bitbucket\.org/i.test(url)) unresolvable.push(`${relative(ctx.home, repo) || repo} -> ${url} (visibility not checked: only GitHub is queried automatically)`);
  }

  if (ghRepos.length === 0) {
    return { ...base, status: unresolvable.length > 0 ? "warn" : "pass", detail: unresolvable.length > 0 ? "No GitHub-hosted repositories found to auto-check; other hosts need manual confirmation." : "No hosted-provider remotes found among scanned repositories.", evidence: unresolvable };
  }

  if (!ghAvailable()) {
    return { ...base, status: "warn", detail: `${ghRepos.length} GitHub-hosted repositories found, but the \`gh\` CLI is not installed, so visibility could not be checked automatically.`, evidence: ghRepos.map(r => r.slug), fix: "Install the GitHub CLI and run `gh auth login`, then re-run." };
  }

  const publicRepos: string[] = [];
  const checkFailed: string[] = [];
  for (const { repo, slug } of ghRepos) {
    const res = spawnSync("gh", ["repo", "view", slug, "--json", "visibility", "-q", ".visibility"], { encoding: "utf8", timeout: 10_000 });
    const visibility = typeof res.stdout === "string" ? res.stdout.trim().toUpperCase() : "";
    if (res.status !== 0 || !visibility) checkFailed.push(`${relative(ctx.home, repo) || repo} (${slug})`);
    else if (visibility === "PUBLIC") publicRepos.push(`${relative(ctx.home, repo) || repo} -> ${slug} is PUBLIC`);
  }

  return {
    ...base,
    status: publicRepos.length > 0 ? "fail" : checkFailed.length > 0 ? "warn" : "pass",
    detail: publicRepos.length > 0
      ? `${publicRepos.length} repositories are hosted PUBLICLY on GitHub. Policy 6.2 prohibits public hosting of engagement code unless explicitly approved.`
      : checkFailed.length > 0
        ? `${checkFailed.length} repositories could not be checked (not signed in to \`gh\`, or no access).`
        : `All ${ghRepos.length} GitHub-hosted repositories checked are private.`,
    evidence: [...publicRepos, ...checkFailed].slice(0, 50),
    fix: publicRepos.length > 0 ? "Make the repository private (Settings > Danger zone) or get written approval from the security lead. Treat anything already pushed as potentially exposed." : undefined,
  };
}
