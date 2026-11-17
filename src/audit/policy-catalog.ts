import type { Category } from "./categories.js";

// Checks were originally labeled with policySection (e.g. "4.2", "6.3") -- section numbers from
// the customer-supplied policy document this package was first built to audit against. Citing
// someone else's numbering in Beam's own report/dashboard reads like Beam doesn't have its own
// opinion on what it's checking. This catalog gives each of Beam's own CATEGORIES (categories.ts)
// a Beam-owned id and a plain-language explanation, shown instead -- categoryFor() already assigns
// one of these to every check deterministically, so nothing about an individual check needs to
// change; only what the report displays for it does.
export interface BeamPolicy { id: string; title: Category; description: string }

export const BEAM_POLICIES: Record<Category, BeamPolicy> = {
  "AI agent discovery and configuration": {
    id: "BP-01",
    title: "AI agent discovery and configuration",
    description: "Which AI agents, MCP servers, and skills are actually present on this machine, where they came from, and how they're configured -- including whether a client claiming to be official is really the genuine build.",
  },
  "Agent permissions and bypasses": {
    id: "BP-02",
    title: "Agent permissions and bypasses",
    description: "Whether an agent can act without a human in the loop: auto-accept settings, required review hooks, sandbox and network restrictions, and other ways its default guardrails could be routed around.",
  },
  "Git and repository safeguards": {
    id: "BP-03",
    title: "Git and repository safeguards",
    description: "Whether version control itself would catch a mistake before it ships -- branch protection, and whether a pre-commit secret-scanning hook is not just present on disk but actually effective.",
  },
  "Workstation security": {
    id: "BP-04",
    title: "Workstation security",
    description: "Whether the machine an agent runs on is itself hardened: full-disk encryption, OS-level security settings, and other platform baseline checks.",
  },
  "Sensitive data exposure": {
    id: "BP-05",
    title: "Sensitive data exposure",
    description: "What sensitive data an agent could actually read if it tried: credentials, PII/PHI/financial-data-shaped content in tracked files, confidentiality markers, and database schemas with sensitive field names.",
  },
  "Organization policy compliance": {
    id: "BP-06",
    title: "Organization policy compliance",
    description: "Whether a workspace's own supplied policy is actually being enforced on this device. Without one supplied, coverage here is explicitly partial, not a pass.",
  },
  "Scan coverage and evidence": {
    id: "BP-07",
    title: "Scan coverage and evidence",
    description: "What this scan itself actually covered and what it didn't -- its own scope, limits, and caps, so results aren't read as more complete than they are.",
  },
  "Third-party integrations and supply chain": {
    id: "BP-08",
    title: "Third-party integrations and supply chain",
    description: "What's in the dependency tree and whether it's pinned, reproducible, and free of known vulnerabilities -- including what an MCP server's own tools expose once actually queried.",
  },
  "Network and data destinations": {
    id: "BP-09",
    title: "Network and data destinations",
    description: "Where data can actually leave to: TLS and API endpoint configuration, hosts-file overrides, and other checks on where traffic is really headed.",
  },
  "Updates and vulnerability management": {
    id: "BP-10",
    title: "Updates and vulnerability management",
    description: "Whether known vulnerabilities in installed packages are being tracked, and whether the software itself is current.",
  },
  "Logging and incident traceability": {
    id: "BP-11",
    title: "Logging and incident traceability",
    description: "Whether there would be a record to go back to after something happens -- audit trail evidence, retention, and whether an incident would actually be traceable on this device.",
  },
};

export function beamPolicyFor(category: Category): BeamPolicy {
  return BEAM_POLICIES[category];
}
