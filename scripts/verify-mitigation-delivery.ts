// Preview: bun scripts/verify-mitigation-delivery.ts
// Send one clearly labelled synthetic finding: bun scripts/verify-mitigation-delivery.ts --send
// Commands are inert test data. Uses Beam's existing authenticated forwarding API.
import { randomUUID } from "node:crypto";
import { normalize } from "../src/core.js";
import { forwardEvents } from "../src/forward.js";
import { beamVersion } from "../src/version.js";

const args = process.argv.slice(2);
if (args.some(arg => arg !== "--send")) throw new Error("Usage: bun scripts/verify-mitigation-delivery.ts [--send]");
const runId = randomUUID();
const command = `python3 -c "from pathlib import Path; Path('beam-regex-production-check.html').write_text('verification only')"`;
const event = normalize({
  event_id: `beam-regex-check-${runId}`,
  record_type: "finding", source_agent: "codex", source_type: "verification",
  session_id: `beam-regex-check-${runId}`, event_type: "command.exec", tool_name: "exec_command",
  command, tool_input: { cmd: command }, timestamp: new Date().toISOString(),
  rule_id: "beam.mitigation-verification",
  title: "Synthetic: production regex delivery check",
  severity: "medium",
});
if (!event.mitigationCandidate?.pattern) throw new Error("No regex generated; refusing to send an incomplete verification event.");
const regex = new RegExp(event.mitigationCandidate.pattern, "i");
if (!regex.test(command) || regex.test("")) throw new Error("Generated regex failed the original-command validation.");
if (!regex.test(command.replace("verification only", "another edit"))) throw new Error("Regex pinned the changing payload.");
if (regex.test(command.replace("beam-regex-production-check.html", "unrelated.html"))) throw new Error("Regex matched an unrelated target.");

const report: Record<string, unknown> = {
  runId, eventId: event.id, agent: event.agent, sourceVersion: beamVersion(),
  title: event.findings.find(finding => finding.id === "beam.mitigation-verification")?.title,
  commandExecuted: false, regex: event.mitigationCandidate.pattern,
  checks: { originalCommand: true, changedPayload: true, unrelatedTargetExcluded: true },
  sent: false,
};
if (args.includes("--send")) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const response = await originalFetch(input, init);
    report.endpoint = new URL(String(input)).origin;
    report.httpStatus = response.status;
    try {
      const acknowledgement = await response.clone().json() as Record<string, unknown>;
      report.acknowledgement = Object.fromEntries(["accepted", "duplicates", "skipped", "error"].filter(key => acknowledgement[key] !== undefined).map(key => [key, acknowledgement[key]]));
    } catch { /* HTTP status is retained for non-JSON responses. */ }
    return response;
  };
  try { report.sent = await forwardEvents(event); }
  finally { globalThis.fetch = originalFetch; }
  if (!report.sent) process.exitCode = 1;
}
console.log(JSON.stringify(report, null, 2));
