import type { Event, Finding, RuleCategory, Severity } from "./core.js";

export interface SequenceRule {
  id: string; title: string; severity: Severity; category: RuleCategory; explanation: string;
  /** Ordered step predicates; a match requires each to be satisfied by a later-or-equal event
   *  than the previous step, not necessarily consecutively. */
  steps: ((e: Event) => boolean)[];
}

// A single risky-looking action can be routine. Two specific actions in the same session, in
// order, are what actually matters -- neither built-in single-event rule nor a 3-line text
// window can see across separate tool calls the way this can.
export const sequenceRuleCatalog: SequenceRule[] = [
  {
    id: "chain.secret_then_egress",
    title: "Credential read followed by network activity",
    severity: "critical",
    category: "exfil",
    explanation: "A credential or secret was read in one action, and network activity followed later in the same session. Neither step alone is unusual; review what the second action actually sent.",
    steps: [
      e => e.findings.some(f => f.id === "credentials.access"),
      e => /https?:\/\/|\bcurl\b|\bwget\b|\bupload\b|\bwebhook\b/i.test(e.summary) || e.type === "browser.navigate",
    ],
  },
  {
    id: "chain.recon_then_exec",
    title: "Network reconnaissance followed by remote execution",
    severity: "critical",
    category: "exec",
    explanation: "A network or host scan was followed by code fetched and run from a remote source in the same session.",
    steps: [
      e => e.findings.some(f => f.id === "recon.network_sweep"),
      e => e.findings.some(f => f.id === "execution.remote"),
    ],
  },
];

const WINDOW = 50; // only the most recent N events per session are considered

// Scans one session's events (any order) for completed step sequences and returns the finding
// each completed match should attach to its final (most recent) matching event. Idempotent: the
// caller should skip attaching a finding an event already has -- re-running over the same
// history must never duplicate a chain finding.
export function detectSequenceFindings(sessionEvents: Event[]): Map<string, Finding[]> {
  const ordered = [...sessionEvents].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp)).slice(-WINDOW);
  const attach = new Map<string, Finding[]>();
  for (const rule of sequenceRuleCatalog) {
    let stepIndex = 0;
    for (const event of ordered) {
      if (!rule.steps[stepIndex](event)) continue;
      stepIndex++;
      if (stepIndex < rule.steps.length) continue;
      if (!event.findings.some(f => f.id === rule.id)) {
        const finding: Finding = {
          id: rule.id, title: rule.title, severity: rule.severity, explanation: rule.explanation,
          evidence: `Matched a ${rule.steps.length}-step sequence across events in session "${event.session}".`,
        };
        const list = attach.get(event.id) ?? [];
        list.push(finding);
        attach.set(event.id, list);
      }
      stepIndex = 0; // allow another, later match of the same rule in the same session
    }
  }
  return attach;
}
