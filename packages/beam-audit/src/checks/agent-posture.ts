import { agentConfigurations, readConfiguration } from "../config-files.js";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { delimiter, join } from "node:path";
import type { AuditContext, Check } from "../types.js";

// Only known configuration locations are read. Never execute discovered plugins or print values.
export function agentPostureChecks(ctx: AuditContext): Check[] {
  const agents = agentConfigurations(ctx);
  const checks: Check[] = [];
  const add = (id: string, category: string, title: string, status: Check["status"], detail: string, evidence: string[] = []) => checks.push({ id, policySection: category, title, status, detail, evidence });
  for (const agent of agents) {
    const files = agent.paths.filter(existsSync);
    const commands: Record<string, string[]> = { "Claude Code": ["claude"], "Codex": ["codex"], "Cursor": ["cursor"], "Gemini CLI": ["gemini"], "GitHub Copilot CLI": ["copilot"], "OpenCode": ["opencode"], "VS Code / Copilot / Cline / Roo": ["code"] };
    const executable = (commands[agent.name] ?? []).some(command => (process.env.PATH ?? "").split(delimiter).some(dir => (ctx.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""]).some(ext => existsSync(join(dir, command + ext)))));
    add(`${agent.name === "VS Code / Copilot / Cline / Roo" ? "editor-configuration" : "inventory"}-${agent.name}`, "3 / Agent inventory", `${agent.name}: configuration discovery`, files.length || executable ? "warn" : "skip", files.length || executable ? `Discovery signals: ${files.length} configuration files; executable-name candidate on PATH: ${executable}. Binary identity, account ownership, and running state require separate verification.` : "No known configuration or executable-name candidate found; this does not prove the agent is absent.", files);
    for (const file of files) {
      let content: string;
      try { if (statSync(file).size > 2_000_000) throw new Error("oversized"); content = JSON.stringify(readConfiguration(file)); }
      catch { add(`unreadable-${file}`, "Coverage", "Agent configuration could not be inspected", "skip", "Unreadable, invalid, or larger than the 2 MB inspection limit.", [file]); continue; }
      const bypass = /(?:bypassPermissions|dangerously-skip-permissions|danger-full-access|yolo|"autoApprove"\s*:\s*true|approval_policy["']?\s*[:=]\s*["']never["'])/i.test(content);
      add(`permissions-${file}`, "4.3 / Permissions and bypasses", `${agent.name}: permissive configuration signals`, bypass ? "warn" : "pass", bypass ? "A permissive setting or bypass reference was found. Review its effective scope and organization approval; a textual match alone does not establish that it is active." : "No recognized bypass patterns in this file. Runtime flags and effective merged settings were not verified.", [file]);
      const integrations = /mcpServers|mcp_servers|plugins|extensions/i.test(content);
      add(`integrations-${file}`, "3 / Third-party integrations", `${agent.name}: external integrations`, integrations ? "warn" : "pass", integrations ? "Integration declarations found. Review server provenance, permissions, credential scope, and version pinning. Values are omitted to protect secrets." : "No recognized integration declaration in this file; other configuration locations may exist.", [file]);
      const endpoint = /(?:base_url|baseURL|ANTHROPIC_BASE_URL|apiEndpoint)/i.test(content);
      add(`destinations-${file}`, "3, 6.5 / Network destinations", `${agent.name}: endpoint overrides`, endpoint ? "warn" : "pass", endpoint ? "Endpoint override declaration found; verify against the organization allowlist." : "No recognized endpoint override in this file. Actual network traffic was not inspected.", [file]);
    }
  }
  for (const folder of [".claude/projects", ".codex/sessions", ".gemini/tmp"]) {
    const path = join(ctx.home, folder);
    let populated = false;
    try { populated = readdirSync(path).length > 0; } catch { /* Report missing evidence honestly. */ }
    add(`logs-${folder}`, "8.2 / Logging and incident traceability", `Local history: ${folder}`, populated ? "warn" : "skip", populated ? "History artifacts exist. Completeness, tool-event coverage, attribution, retention, and protection against deletion have not been verified." : "No accessible history artifacts found at this known location.", populated ? [path] : []);
  }
  const manual: Array<[string, string, string]> = [
    ["identity", "Identity and access", "Verify organization account ownership, SSO/MFA, access revocation, and credential least privilege."],
    ["updates", "Updates and vulnerability management", "Compare installed agents, extensions, and MCP packages with trusted release and advisory sources. Supported package advisory queries are reported separately; unsupported components still require review."],
    ["network", "Network and data destinations", "Verify firewall, proxy enforcement, VPN requirements, and outbound destination restrictions using organization network evidence."],
    ["logging", "Logging and incident traceability", "Verify timestamped user/session/tool events, command outcomes, central collection, retention, redaction, and tamper protection."],
    ["history", "6.2 / Repository safeguards", "Review Git history for secrets and verify remote branch protections and required CI checks. Local hooks alone can be bypassed."],
    ["supply-chain", "7 / Supply chain", "Verify dependency pinning, registry trust, plugin provenance, and installed skill or MCP executable permissions."],
    ["exceptions", "2.3, 8.4 / Organization policy", "Verify policy ownership, approved exceptions, expiry dates, engagement renewal, and change approvals."],
  ];
  for (const [id, category, detail] of manual) add(`unverified-${id}`, category, `${category}: additional evidence required`, "skip", detail);
  add("scan-coverage", "Scan coverage and evidence", "Inspection boundaries", "warn", `Repository discovery is scoped to ${ctx.roots.length} root(s), with depth and repository limits. Permission failures, ignored directories, other user profiles, containers, remote hosts, and unsupported agents are not fully inspected. A passing check applies only to its stated evidence.`, ctx.roots);
  return checks;
}
