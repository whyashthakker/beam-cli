#!/usr/bin/env node
// `beam-audit`: standalone, zero-beam-cli-install scanner for policy 4.2 ("Data Prohibited from
// Sharing with Claude Code"). Checks the global and every per-repo Claude Code config found on the
// machine. Real Claude Code calls require --live; external evidence queries require --online.
import { agentProcessChecks } from "./checks/agent-processes.js";
import { agentMemoryAndPluginChecks } from "./checks/agent-memory-plugins.js";
import { agentControlChecks } from "./checks/agent-controls.js";
import { resolvedSettingsChecks } from "./checks/resolved-settings.js";
import { extensionInventoryChecks, subagentChecks, agentInstructionChecks } from "./checks/agent-assets.js";
import { agentAuthenticationChecks } from "./checks/agent-auth.js";
import { parseArgs } from "./args.js";
import { runExtensionStage } from "./extension-stage.js";
import { loadExtensionAdapters, validateCdpEndpoint } from "./checks/extension-ui.js";
import { categorySummary, categoryFor } from "./categories.js";
import { loggingChecks } from "./checks/logging.js";
import { supplyChainChecks } from "./checks/supply-chain.js";
import { vulnerabilityChecks, releaseChecks } from "./checks/vulnerabilities.js";
import { remoteEnforcementChecks } from "./checks/remote-enforcement.js";
import { platformSecurityChecks } from "./checks/platform-security.js";
import { looseFileChecks } from "./checks/loose-files.js";
import { mcpChecks } from "./checks/mcp.js";
import { loadPolicy, evaluatePolicy } from "./policy.js";
import { repositoryEnforcementChecks } from "./checks/repository-enforcement.js";
import { homedir } from "node:os";
import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { discoverReposDetailed } from "./discover-repos.js";
import { globalConfigCheck, memorySurfaceCheck } from "./checks/global-config.js";
import { repoDataExposureCheck } from "./checks/repo-scan.js";
import { vscodeExtensionCheck, workspaceAutoIncludeTest } from "./checks/vscode-test.js";
import { runPiiMatrix } from "./checks/matrix-test.js";
import { runReviewMatrix } from "./checks/review-matrix.js";
import { securityReviewCheck, workspaceIsolationLiveCheck } from "./checks/code-review.js";
import { unofficialClientCheck } from "./checks/unofficial-client.js";
import { tlsVerificationCheck, apiEndpointCheck } from "./checks/network-transport.js";
import { apiKeyStorageCheck } from "./checks/api-key-storage.js";
import { precommitHookCheck, publicRepoVisibilityCheck } from "./checks/repo-hygiene.js";
import { workstationChecks } from "./checks/workstation.js";
import { promptInjectionScan } from "./checks/prompt-injection.js";
import { agentPostureChecks } from "./checks/agent-posture.js";
import { manualItems } from "./checks/manual-items.js";
import { formatReport, exitCode, type NamedMatrix } from "./report.js";
import { renderHtmlReport } from "./report-html.js";
import type { AuditContext, Check } from "./types.js";


async function main(): Promise<void> {
  const { roots, maxRepos, json, html, open, skipLive, policy: policyPath, online, maxDepth, maxFiles, wholePc, vscodeCdp: requestedCdp, uiAdapters, extensionsOnly, launchVscode, extensionAgent } = parseArgs(process.argv.slice(2));
  const vscodeCdp = requestedCdp ? validateCdpEndpoint(requestedCdp) : undefined;
  if (launchVscode && requestedCdp) throw new Error("Choose --launch-vscode or --vscode-cdp, not both");
  const adapters = loadExtensionAdapters(uiAdapters).filter(a => extensionAgent === "all" || a.agent.toLowerCase() === extensionAgent);
  if (!adapters.length) throw new Error("No matching extension adapters");
  if (extensionsOnly && ((!vscodeCdp && !launchVscode) || !skipLive)) throw new Error("--extensions-only requires --vscode-cdp and cannot be combined with --live CLI tests");
  if (uiAdapters && !vscodeCdp && !launchVscode) throw new Error("--ui-adapters requires --vscode-cdp");
  const policy = policyPath ? loadPolicy(policyPath) : undefined;
  const home = homedir();
  const log = (msg: string) => process.stderr.write(`[beam-audit] ${msg}\n`);

  log(extensionsOnly ? "extension-only mode: no workstation or repository scan" : `discovering repositories under: ${roots.join(", ")}`);
  const discovery = extensionsOnly ? { repos: [] as string[], visited: 0, excluded: 0, inaccessible: [] as string[], depthLimited: 0, capped: false } : discoverReposDetailed(roots, { maxRepos, maxDepth });
  const repos = discovery.repos;
  log(`found ${repos.length} repositories`);

  const ctx: AuditContext = { roots, repos, home, platform: process.platform, log, online, maxFiles, agentControls: policy?.agentControls };

  const checks: Check[] = [];
  checks.push({ id: "scan-components", category: "Scan coverage and evidence", policySection: "Scope", title: "Components included in this scan", status: "warn", detail: `Workstation/repository/configuration checks: ${extensionsOnly ? "excluded by --extensions-only" : "included"}; Claude CLI live tests: ${skipLive ? "not requested" : "requested"}; actual extension UI tests: ${launchVscode || requestedCdp ? "requested" : "not requested"}; external evidence queries: ${online ? "enabled" : "disabled"}. Test completion and coverage limits are reported separately.` });
  if (!extensionsOnly) {
  log("checking global and per-repo Claude Code configuration");
  checks.push(...globalConfigCheck(ctx));
  checks.push(memorySurfaceCheck(ctx));
  log("scanning repositories for prohibited data categories");
  checks.push(...repoDataExposureCheck(ctx));
  checks.push(vscodeExtensionCheck(ctx));
  log("checking for static analysis tooling (policy 4.3 Security Review)");
  checks.push(securityReviewCheck(ctx));
  checks.push(workspaceIsolationLiveCheck(ctx));
  log("checking for unofficial clients, TLS/endpoint config, API key storage, repo hygiene, and workstation security");
  checks.push(unofficialClientCheck(ctx));
  checks.push(tlsVerificationCheck(ctx));
  checks.push(apiEndpointCheck());
  checks.push(apiKeyStorageCheck(ctx));
  checks.push(precommitHookCheck(ctx));
  if (online) checks.push(publicRepoVisibilityCheck(ctx));
  else checks.push({ id: "6.2-public-hosting", policySection: "6.2", title: "Repository visibility", status: "skip", detail: "Use --online to query GitHub visibility." });
  checks.push(...workstationChecks(ctx));
  checks.push(promptInjectionScan(ctx));
  checks.push(...manualItems());
  checks.push(...agentPostureChecks(ctx));
  log("checking agent controls, per-project settings, auth caches, extensions, sub-agents and instruction files");
  checks.push(...agentControlChecks(ctx), ...resolvedSettingsChecks(ctx), ...agentAuthenticationChecks(ctx), ...extensionInventoryChecks(ctx), ...subagentChecks(ctx), ...agentInstructionChecks(ctx), ...agentMemoryAndPluginChecks(ctx));
  log("checking current-user running agent argument signals (values omitted)");
  checks.push(...agentProcessChecks(ctx));
  checks.push(...mcpChecks(ctx));
  checks.push(...repositoryEnforcementChecks(ctx));
  checks.push(...loggingChecks(ctx), ...supplyChainChecks(ctx), ...platformSecurityChecks(ctx), ...remoteEnforcementChecks(ctx));
  log("scanning non-repository credential patterns within roots");
  checks.push(...await looseFileChecks(ctx));
  log("checking package vulnerability evidence");
  checks.push(...await vulnerabilityChecks(ctx));
  checks.push(...await releaseChecks(ctx));
  checks.push({ id: "discovery-coverage", category: "Scan coverage and evidence", policySection: "Scope", title: "Repository discovery coverage", status: discovery.capped || discovery.inaccessible.length || discovery.depthLimited ? "warn" : "pass", detail: `${discovery.visited} directories visited; ${discovery.excluded} excluded entries; ${discovery.inaccessible.length} inaccessible paths; ${discovery.depthLimited} depth-limited paths; cap reached: ${discovery.capped}. Scope: ${wholePc ? "filesystem roots" : "selected roots"}. Symlinks and generated/cache directories excluded.`, evidence: discovery.inaccessible.slice(0, 50) });

  }

  const matrices: NamedMatrix[] = [];
  if (!skipLive) {
    log("running the per-data-type block/fail matrix against Claude Code CLI and VS Code (real API calls)");
    matrices.push({ title: "Data Prohibited from Sharing (policy 4.2)", cells: runPiiMatrix(ctx) });
    log("running the code-review-requirements matrix: auto-accept and blind execution (real API calls)");
    matrices.push({ title: "Code Review Requirements (policy 4.3)", cells: runReviewMatrix(ctx) });
    log("running workspace-auto-include live test (real API call)");
    checks.push(workspaceAutoIncludeTest(ctx));
  } else {
    log("skipping Claude CLI live tests; extension UI tests are controlled separately");
  }

  const extensionStage = await runExtensionStage(ctx, { launch: launchVscode, endpoint: vscodeCdp, adapters });
  checks.push(...extensionStage.checks);
  matrices.push(...extensionStage.matrices);

  for (const matrix of matrices) for (const cell of matrix.cells) checks.push({
    id: `live-${matrix.title}-${cell.surface}-${cell.label}`,
    category: matrix.title.includes("4.3") ? "Agent permissions and bypasses" : "Sensitive data exposure",
    policySection: matrix.title.includes("4.3") ? "4.3" : "4.2",
    title: `${cell.surface}: ${cell.label}`,
    status: cell.blocked === null ? "skip" : cell.blocked ? "pass" : matrix.title.includes("4.3") ? "fail" : "warn",
    detail: cell.detail,
    evidence: [cell.artifactPath ? `Synthetic edit proof: ${cell.artifactPath}` : "", cell.testId ? `Test ID: ${cell.testId}` : "", cell.responseSha256 ? `Assistant response SHA-256: ${cell.responseSha256}` : ""].filter(Boolean),
  });
  checks.push(...evaluatePolicy(checks, policy));
  for (const check of checks) check.category = categoryFor(check);
  const generatedAt = new Date().toISOString();
  const report = formatReport(checks, matrices);
  console.log(report);

  if (json) {
    writeFileSync(json, JSON.stringify({ generatedAt, platform: process.platform, roots, repos, discovery, categories: categorySummary(checks), checks, matrices }, null, 2), "utf8");
    log(`wrote raw findings to ${json}`);
  }

  if (html) {
    const page = renderHtmlReport(checks, matrices, { roots, repoCount: repos.length, generatedAt, liveTestsRun: !skipLive || launchVscode || Boolean(vscodeCdp) });
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
