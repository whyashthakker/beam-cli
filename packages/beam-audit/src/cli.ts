#!/usr/bin/env node
// `beam-audit`: standalone, zero-beam-cli-install scanner for policy 4.2 ("Data Prohibited from
// Sharing with Claude Code"). Checks the global and every per-repo Claude Code config found on the
// machine, then runs two real, live round-trip tests against the user's own already-installed
// Claude Code (a real network call is made on every run).
import { homedir } from "node:os";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { discoverRepos } from "./discover-repos.js";
import { globalConfigCheck, memorySurfaceCheck } from "./checks/global-config.js";
import { repoDataExposureCheck } from "./checks/repo-scan.js";
import { vscodeExtensionCheck, workspaceAutoIncludeTest } from "./checks/vscode-test.js";
import { runPiiMatrix } from "./checks/matrix-test.js";
import { runReviewMatrix } from "./checks/review-matrix.js";
import { securityReviewCheck, workspaceIsolationLiveCheck } from "./checks/code-review.js";
import { formatReport, exitCode, type NamedMatrix } from "./report.js";
import { renderHtmlReport } from "./report-html.js";
import type { AuditContext, Check } from "./types.js";

function parseArgs(argv: string[]): { roots: string[]; maxRepos: number; json?: string; html?: string; open: boolean; skipLive: boolean } {
  const roots: string[] = [];
  let maxRepos = 500;
  let json: string | undefined;
  let html: string | undefined;
  let open = false;
  let skipLive = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--root" && argv[i + 1]) roots.push(resolve(argv[++i]));
    else if (arg === "--max-repos" && argv[i + 1]) maxRepos = Number.parseInt(argv[++i], 10) || maxRepos;
    else if (arg === "--json" && argv[i + 1]) json = resolve(argv[++i]);
    else if (arg === "--html") html = argv[i + 1] && !argv[i + 1].startsWith("--") ? resolve(argv[++i]) : resolve("beam-audit-report.html");
    else if (arg === "--open") open = true;
    else if (arg === "--skip-live") skipLive = true;
    else if (arg === "--help" || arg === "-h") {
      console.log("Usage: beam-audit [--root <dir> ...] [--max-repos <n>] [--json <file>] [--html [file]] [--open] [--skip-live]");
      process.exit(0);
    }
  }
  if (roots.length === 0) roots.push(homedir());
  return { roots, maxRepos, json, html, open, skipLive };
}

async function main(): Promise<void> {
  const { roots, maxRepos, json, html, open, skipLive } = parseArgs(process.argv.slice(2));
  const home = homedir();
  const log = (msg: string) => process.stderr.write(`[beam-audit] ${msg}\n`);

  log(`discovering repositories under: ${roots.join(", ")}`);
  const repos = discoverRepos(roots, { maxRepos });
  log(`found ${repos.length} repositories`);

  const ctx: AuditContext = { roots, repos, home, platform: process.platform, log };

  const checks: Check[] = [];
  log("checking global and per-repo Claude Code configuration");
  checks.push(...globalConfigCheck(ctx));
  checks.push(memorySurfaceCheck(ctx));
  log("scanning repositories for prohibited data categories");
  checks.push(...repoDataExposureCheck(ctx));
  checks.push(vscodeExtensionCheck(ctx));
  log("checking for static analysis tooling (policy 4.3 Security Review)");
  checks.push(securityReviewCheck(ctx));
  checks.push(workspaceIsolationLiveCheck(ctx));

  const matrices: NamedMatrix[] = [];
  if (!skipLive) {
    log("running the per-data-type block/fail matrix against Claude Code CLI and VS Code (real API calls)");
    matrices.push({ title: "Data Prohibited from Sharing (policy 4.2)", cells: runPiiMatrix(ctx) });
    log("running the code-review-requirements matrix: auto-accept and blind execution (real API calls)");
    matrices.push({ title: "Code Review Requirements (policy 4.3)", cells: runReviewMatrix(ctx) });
    log("running workspace-auto-include live test (real API call)");
    checks.push(workspaceAutoIncludeTest(ctx));
  } else {
    log("skipping live tests (--skip-live)");
  }

  const report = formatReport(checks, matrices);
  console.log(report);

  if (json) {
    writeFileSync(json, JSON.stringify({ roots, repos, checks, matrices }, null, 2), "utf8");
    log(`wrote raw findings to ${json}`);
  }

  if (html) {
    const page = renderHtmlReport(checks, matrices, { roots, repoCount: repos.length, generatedAt: new Date().toISOString(), liveTestsRun: !skipLive });
    writeFileSync(html, page, "utf8");
    log(`wrote HTML report to ${html}`);
    if (open) {
      const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
      spawnSync(opener, [html], { shell: process.platform === "win32" });
    }
  }

  process.exitCode = exitCode(checks, matrices);
}

main().catch(err => {
  console.error("[beam-audit] fatal error:", err);
  process.exitCode = 2;
});
