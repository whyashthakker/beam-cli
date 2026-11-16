# Beam Product Breakdown vs. Unbound

As of 2026-11-16.

## Overview

Beam has two codebases that do different jobs, and this breakdown covers both:

- **`beam` (root `src/`)** — the runtime product. It hooks into agent sessions (Claude Code, Cursor, Codex, Copilot, Gemini CLI, Windsurf, Cline) and makes live ALLOW/ASK/BLOCK/REDACT/AUDIT decisions, runs an approval workflow, drafts incident records, and watches for anomalous behavior.
- **`beam-audit` (`packages/beam-audit/`)** — a point-in-time scanner. It inspects a workstation or repo once and reports what agents, credentials, configs, and supply-chain risks are present, without intercepting anything live.

The comparison below is against [Unbound](https://www.getunbound.ai/)'s public feature page, since that's the most complete public description of a competing product in this space.

## Feature comparison

| Unbound feature | Status | Where in Beam |
|---|---|---|
| Agent/MCP/skill discovery, unofficial-version detection | **Done** | `agents.ts`, `mcp-config.ts`, `skill-inventory.ts`, `agent-installers.ts`; `beam-audit/checks/agent-assets.ts`, `unofficial-client.ts`, `mcp.ts`, `mcp-introspect.ts` |
| Block risky actions pre-execution, terminal-level interruption | **Done** | `policy.ts` (ALLOW/ASK/BLOCK/REDACT/AUDIT, `enforce` mode), `hook-adapters.ts`, `git-gate.ts`, `skill-gate.ts` |
| Plain-language explanations for drift/risk | **Done** | `plain-explain.ts` |
| Approval workflows (manager/security/admin escalation) | **Done** — more granular than Unbound's Slack approval, with risk scoring, TTL grants, levels | `approvals.ts`, `approved-actions.ts` |
| Org-level policy rules (e.g. "warn on destructive DB commands") | **Done** | `policy.ts`, `rule-catalog.ts`, `custom-rules.ts`, `destructive-risk.ts` |
| Session monitoring with semantic classification, evidence trails | **Done** | `monitor.ts`, `monitor-pipeline.ts`, `monitor-rules.ts`, `activity.ts`, `incidents.ts` |
| Behavioral/pattern anomaly detection (burst of risky actions) | **Done**, arguably ahead of what Unbound describes | `behavioral-anomaly.ts` |
| Prompt-injection / hidden-instruction detection | **Done** | `prompt-attacks.ts` |
| PII/secret handling, redaction, vaulting | **Done**, deeper than Unbound's page mentions | `pii-vault.ts`, `pii-validators.ts`, `entity-redaction.ts`, `credential-egress.ts`, `data-detectors.ts` |
| Credential/secret exposure checks (static) | **Done** | `beam-audit/checks/agent-auth.ts`, `loose-files.ts`, `repo-scan.ts`, `api-key-storage.ts` |
| Supply-chain / dependency pinning / known CVEs | **Done** (not on Unbound's page either) | `cve.ts`, `package-scan.ts`, `package-risk-rules.ts`; `beam-audit/checks/supply-chain.ts`, `vulnerabilities.ts` |
| Repo/branch protection, pre-commit hygiene | **Done** | `beam-audit/checks/repository-enforcement.ts`, `repo-hygiene.ts`, `remote-enforcement.ts` |
| Workstation security (disk encryption, platform hardening) | **Done** | `beam-audit/checks/workstation.ts`, `platform-security.ts` |
| Multi-agent support (Claude Code, Cursor, Codex, Copilot, Gemini CLI, Windsurf, Cline, JetBrains AI) | **Done** | `agent-installers.ts`, `agent-hook-install.ts`; spread across most `beam-audit` checks |
| Spend-to-shipped-work correlation | **Not found** — no cost/spend tracking module | — |
| Enablement: capture best-performer workflows into reusable skills/playbooks | **Partial** — skill management exists (`skills.ts`, `skill-sync.ts`, `skill-gate.ts`) but no "distribute top performer's habits" feature specifically | — |
| IdP integration (Okta, Microsoft Entra) | **Not found** | — |
| LLM gateway integration (LiteLLM, Portkey) | **Not found** | — |
| MDM integration (Jamf, Intune, Kandji) | **Not found** | — |
| SIEM export for audit trails | **Unconfirmed** — `forward.ts`, `share.ts`, `collector-health.ts` exist but it's unverified whether output is SIEM-formatted | `forward.ts`, `share.ts`, `collector-health.ts` |

## Bottom line

At the discovery/audit layer (what agents exist, what they can reach, credential exposure, supply chain, repo safeguards), Beam already matches or exceeds Unbound's public feature list, and covers things Unbound doesn't mention (secrets scanning, CVEs, workstation hardening).

The runtime-governance layer that looked missing in an audit-only comparison is **not** actually missing — `beam`'s `policy.ts`/`approvals.ts`/`incidents.ts`/`behavioral-anomaly.ts` already cover live blocking, approval escalation, and session-pattern detection, in more depth than Unbound's page describes (risk scoring, approval tiers, PII vaulting, incident drafting with regulatory timers).

The real gaps are narrower:
1. **Spend/cost correlation** — nothing ties agent cost to shipped work.
2. **Enterprise integrations** — no IdP (Okta/Entra), MDM (Jamf/Intune/Kandji), or LLM gateway (LiteLLM/Portkey) integration found.
3. **SIEM export** — unclear if `forward.ts`/`share.ts` output is SIEM-compatible; needs verification before calling it done or missing.
