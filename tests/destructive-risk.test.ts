import { describe, expect, it } from "@jest/globals";
import { detect, risk, ruleCatalog, scanText } from "../src/core.js";
import { evaluate } from "../src/policy.js";
const deletion = (s: string) => detect(s).find(f => f.id === "destructive.delete");

describe("contextual destructive-operation severity", () => {
  it.each([
    'rm -rf /tmp/beam-anomaly-test',
    'rm -r -f /tmp/beam-test/results',
    'rm --recursive --force /private/tmp/verify-anomaly',
    'rm -fr -- /var/tmp/scratch-build',
    'rm -rf "/tmp/test-fixture"',
    'rm -rf /tmp/test-one /tmp/test-two',
    'cd /repo\nmkdir -p /tmp/beam-anomaly-test\nbun /tmp/verify-anomaly.ts\nrm /tmp/verify-anomaly.ts\nrm -rf /tmp/beam-anomaly-test',
  ])("still reports narrow temporary test cleanup at MEDIUM: %s", input => {
    expect(deletion(input)?.severity).toBe("medium");
    expect(risk(detect(input))).toBe("medium");
    expect(evaluate(null, { agent: "claude", tool: "Bash", command: input })).toMatchObject({riskScore: 35, riskLevel: "MEDIUM"});
  });
  it.each([
    'rm -rf /', 'rm -rf /tmp', 'rm -rf /tmp/*', 'rm -rf /tmp/test-*',
    'rm -rf /tmp/test/../../home', 'rm -rf /tmp/test/.',
    'rm -rf /tmp/test /home/user/project',
    'rm -rf "$TMPDIR/test"', 'rm -rf /tmp/test-$(whoami)',
    'rm -rf /tmp/test; rm -rf /home/user',
    'rm -rf /tmp/test; DROP TABLE users',
    'rm -rf /tmp/test; redis-cli FLUSHALL',
    'rm -rf /tmp/test; find /home/user -delete',
    'sudo rm -rf /tmp/test', 'rm -rf ./test',
    'rm -rf /tmp/test-credentials', 'rm -rf /tmp/test/backups',
    'rm -rf /tmp/unclassified-data',
    'bash -c "rm -rf /tmp/test"',
  ])("retains HIGH for broad, uncertain or mixed destruction: %s", input => {
    expect(deletion(input)?.severity).toBe("high");
  });
  it("does not introduce recursive-delete findings for plain file removal", () => {
    expect(deletion('rm /tmp/verify-anomaly.ts')).toBeUndefined();
  });
  it("keeps the highest severity across scan windows", () => {
    const findings = scanText('SKILL.md', 'rm -rf /tmp/test\n\n\n\nrm -rf /home/user/project', 'skill').findings;
    expect(findings.find(f => f.id === 'destructive.delete')?.severity).toBe('high');
  });
  it("does not serialize the dynamic severity function into catalog metadata", () => {
    expect(ruleCatalog().find(r => r.id === 'destructive.delete')).not.toHaveProperty('severityFor');
  });
  it("still honors an explicit block for a temporary cleanup", () => {
    expect(evaluate({ version: 1, notAfter: null, rules: { mode: 'enforce', blockedTools: [], disabledAgents: [], blockedCommandPatterns: [], rules: [{id: 'block', commandLine: 'rm -rf /tmp/test', action: 'BLOCK'}] } }, {agent:'claude', tool:'Bash', command:'rm -rf /tmp/test'}).action).toBe('deny');
  });
});
