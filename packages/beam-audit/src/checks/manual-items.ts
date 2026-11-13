// Policy clauses that describe vendor facts, human behavior, or paperwork rather than
// machine-observable state. Listed explicitly as "skip" so the report stays complete against the
// full policy document instead of silently dropping clauses no scanner can verify.
import type { Check } from "../types.js";

export function manualItems(): Check[] {
  const items: Array<Pick<Check, "id" | "policySection" | "title" | "detail" | "fix">> = [
    {
      id: "5.1-training-data-use",
      policySection: "5.1 (Model Training and Data Use)",
      title: "Commercial API tier in use (prompts not used for training)",
      detail: "Vendor fact, not observable from this machine. Confirm the credential in use is a commercial Anthropic API key, not a consumer claude.ai login, in the Anthropic Console.",
    },
    {
      id: "5.3-data-retention",
      policySection: "5.3 (Data Retention)",
      title: "Anthropic's data retention terms",
      detail: "Vendor policy, changes independently of this machine. Check Anthropic's current Privacy Policy for the authoritative retention schedule.",
    },
    {
      id: "5.4-compliance-certs",
      policySection: "5.4 (Compliance Certifications)",
      title: "Anthropic SOC 2 Type II status",
      detail: "Vendor certification status, verify at trust.anthropic.com; cannot be checked from a local scan.",
    },
    {
      id: "6.4-session-controls",
      policySection: "6.4 (Session Controls)",
      title: "Sessions closed when not in use; no unauthorized screen-sharing",
      detail: "Behavioral, not a point-in-time filesystem/OS fact. Best handled as a developer self-attestation at the monthly review checkpoint.",
    },
    {
      id: "6.5-network-trust",
      policySection: "6.5 (Network Requirements)",
      title: "Used only on trusted networks / VPN on public Wi-Fi",
      detail: "The network in use at any past session can't be reconstructed from this machine after the fact. Confirm an approved VPN client is installed as a proxy signal, but this doesn't confirm it was used.",
    },
    {
      id: "8.1-regulatory-alignment",
      policySection: "8.1 (Regulatory and Framework Alignment)",
      title: "NIST SP 800-53 / OWASP alignment",
      detail: "A framework-alignment attestation, not a single technical control this scanner can check pass/fail.",
    },
    {
      id: "8.2-incident-reporting",
      policySection: "8.2 (Incident Reporting)",
      title: "4-hour incident reporting process exists",
      detail: "Process/contact requirement. Confirm a security-lead contact and escalation path is documented so any FAIL in this report can be escalated within the required window.",
    },
    {
      id: "8.3-monthly-checkpoint",
      policySection: "8.3 (Monthly Review Checkpoint)",
      title: "Monthly review checkpoint conducted",
      detail: "Calendar/process requirement, not a technical state.",
    },
    {
      id: "9-approval-signoff",
      policySection: "9 (Approval and Sign-Off)",
      title: "Policy signed off by developer and security lead",
      detail: "Paperwork, not a technical control.",
    },
  ];
  return items.map(i => ({ ...i, status: "skip" as const, evidence: [] }));
}
