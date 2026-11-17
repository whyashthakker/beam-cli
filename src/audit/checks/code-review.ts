// Policy 4.3 Code Review Requirements -- the two bullets that aren't a live round-trip test:
// Security Review (static analysis wired in) and Workspace Isolation (no customer data sitting in
// the same VS Code workspace Claude Code is active in).
import { existsSync, readFileSync, readdirSync, lstatSync } from "node:fs";
import { join, relative } from "node:path";
import type { AuditContext, Check } from "../types.js";
import { CUSTOMER_DATA_NAME } from "./repo-scan.js";
import { connectedVsCodeWorkspace } from "../live-helpers.js";

const SAST_MARKER = /semgrep|snyk|codeql|sonarcloud|sonarqube/i;

function hasSastConfigured(repo: string): boolean {
  for (const f of [".semgrep.yml", ".semgrep.yaml", "semgrep.yml", ".snyk"]) {
    if (existsSync(join(repo, f))) return true;
  }
  const workflowsDir = join(repo, ".github", "workflows");
  if (existsSync(workflowsDir)) {
    try {
      for (const file of readdirSync(workflowsDir)) {
        if (!/\.ya?ml$/i.test(file)) continue;
        try {
          if (SAST_MARKER.test(readFileSync(join(workflowsDir, file), "utf8"))) return true;
        } catch { /* unreadable workflow file */ }
      }
    } catch { /* unreadable workflows dir */ }
  }
  const pkg = join(repo, "package.json");
  try {
    if (SAST_MARKER.test(readFileSync(pkg, "utf8"))) return true;
  } catch { /* no package.json or unreadable */ }
  return false;
}

export function securityReviewCheck(ctx: AuditContext): Check {
  const missing = ctx.repos.filter(r => !hasSastConfigured(r));
  return {
    id: "4.3-security-review-sast",
    policySection: "4.3 (Security Review)",
    title: "Static analysis configured for security-sensitive code",
    status: missing.length === 0 ? "pass" : missing.length === ctx.repos.length ? "fail" : "warn",
    detail: missing.length === 0
      ? `All ${ctx.repos.length} scanned repositories reference a recognised SAST tool (Semgrep, Snyk, CodeQL, or SonarQube/SonarCloud).`
      : `${missing.length} of ${ctx.repos.length} scanned repositories have no recognisable SAST tool configured. Policy 4.3 requires AI-generated auth/crypto/input-handling/API code be "reviewed with particular diligence, or subjected to static analysis prior to commit" -- this only checks for the tool, not that it actually covers the sensitive files.`,
    evidence: missing.slice(0, 50).map(r => relative(ctx.home, r) || r),
    fix: missing.length > 0 ? "Add Semgrep, Snyk, or CodeQL to CI (e.g. a .github/workflows job) for repositories that handle authentication, cryptography, or external API calls." : undefined,
  };
}

// Same fixture exclusion as repo-scan.ts: policy 4.1 explicitly permits synthetic test fixtures, and
// a security tool's own test scenarios (safety-bench/, etc.) are the canonical case.
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".cache", "coverage", "venv", ".venv", "__pycache__",
  "tests", "test", "__tests__", "__fixtures__", "fixtures", "fixture", "safety-bench", "test-data", "testdata", "mocks", "mock", "examples", "samples",
]);

function findCustomerDataFiles(dir: string, depth = 0, found: string[] = []): string[] {
  if (depth > 6 || found.length >= 20) return found;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return found;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry) || entry.startsWith(".")) continue;
    const full = join(dir, entry);
    let st;
    try {
      st = lstatSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) { findCustomerDataFiles(full, depth + 1, found); continue; }
    if (CUSTOMER_DATA_NAME.test(entry)) found.push(full);
    if (found.length >= 20) break;
  }
  return found;
}

export function workspaceIsolationLiveCheck(ctx: AuditContext): Check {
  const base = { id: "4.3-workspace-isolation", policySection: "4.3 (Workspace Isolation)", title: "Customer data in the active VS Code workspace" };
  const workspace = connectedVsCodeWorkspace(ctx);
  if (!workspace) {
    return { ...base, status: "skip", detail: "VS Code isn't currently open with the Claude extension connected, so there's no active workspace to check. Open a project in VS Code and re-run." };
  }
  const hits = findCustomerDataFiles(workspace);
  return {
    ...base,
    status: hits.length > 0 ? "fail" : "pass",
    detail: hits.length > 0
      ? `${hits.length} customer/production-data-shaped file(s) found directly in the VS Code workspace Claude Code is currently connected to (${workspace}). Policy 4.3 requires this data be excluded from the workspace unless confirmed fully scrubbed.`
      : `No customer/production-data-shaped files found in the active VS Code workspace (${workspace}).`,
    evidence: hits.slice(0, 20),
    fix: hits.length > 0 ? "Move this data out of the workspace, or open a separate VS Code window without Claude Code active for it, per policy 4.3 Workspace Isolation." : undefined,
  };
}
