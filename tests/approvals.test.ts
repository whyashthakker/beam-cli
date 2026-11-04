import { describe, expect, it } from "@jest/globals";
import { applyApproval, approvalStillValid, clampGrantMinutes, createApprovalRequest, DEFAULT_GRANT_MINUTES, LocalApproverResolver, MAX_GRANT_MINUTES, MIN_GRANT_MINUTES } from "../src/approvals.js";

const input = { user: "Rahul", role: "Developer", approver: ["Engineering Lead"], level: "MANAGER" as const, mode: "SINGLE" as const, agent: "claude-code", tool: "Bash", command: "git push", args: ["origin", "main"], policy_version: 2, risk_score: 62, risk_level: "MEDIUM" as const, risk_factors: ["protected branch"] };
describe("approvals", () => {
  it("creates, approves, and binds a request to the exact action", () => { const r = createApprovalRequest(input); const approved = applyApproval(r, "APPROVE_ONCE", "Engineering Lead"); expect(approved.status).toBe("APPROVED"); expect(approvalStillValid(approved, input)).toBe(true); expect(approvalStillValid(approved, { ...input, command: "git push --force" })).toBe(false); });
  it("rejects self-approval and unauthorized approvers", () => { const r = createApprovalRequest({ ...input, approver: ["Engineering Lead"] }); expect(applyApproval(r, "APPROVE_ONCE", "Rahul").status).toBe("DENIED"); expect(applyApproval(r, "APPROVE_ONCE", "Other").status).toBe("DENIED"); });
  it("expires without allowing continuation", () => { const r = createApprovalRequest(input, 1); expect(applyApproval(r, "APPROVE_ONCE", "Engineering Lead", Date.now() + 2).status).toBe("EXPIRED"); });
  it("resolves a manager locally", () => { const resolver = new LocalApproverResolver({ Rahul: { user: "Rahul", manager: "Engineering Lead" } }); expect(resolver.getApprovers(createApprovalRequest(input), { level: "MANAGER" })).toEqual(["Engineering Lead"]); });
  it("carries the approver's decision reason through on approve and deny", () => {
    const approved = applyApproval(createApprovalRequest(input), "APPROVE_ONCE", "Engineering Lead", Date.now(), "known safe branch, go ahead");
    expect(approved.decision_reason).toBe("known safe branch, go ahead");
    const denied = applyApproval(createApprovalRequest(input), "DENY", "Engineering Lead", Date.now(), "not this week, freeze is on");
    expect(denied.decision_reason).toBe("not this week, freeze is on");
  });
  it("never attaches a decision reason to a fail-closed guard rejection", () => {
    const r = createApprovalRequest({ ...input, approver: ["Engineering Lead"] });
    const bySelf = applyApproval(r, "APPROVE_ONCE", "Rahul", Date.now(), "trying to self-approve");
    expect(bySelf.status).toBe("DENIED");
    expect(bySelf.decision_reason).toBeUndefined();
    const byOther = applyApproval(r, "APPROVE_ONCE", "Random Person", Date.now(), "not actually the approver");
    expect(byOther.status).toBe("DENIED");
    expect(byOther.decision_reason).toBeUndefined();
  });

  it("clampGrantMinutes keeps a value in range, and defaults when unset or not a number", () => {
    expect(clampGrantMinutes(30)).toBe(30);
    expect(clampGrantMinutes(5)).toBe(MIN_GRANT_MINUTES);
    expect(clampGrantMinutes(500)).toBe(MAX_GRANT_MINUTES);
    expect(clampGrantMinutes(undefined)).toBe(DEFAULT_GRANT_MINUTES);
    expect(clampGrantMinutes(NaN)).toBe(DEFAULT_GRANT_MINUTES);
  });

  it("an approval carries the approver's chosen, clamped grant duration; denial and expiry never do", () => {
    const approved = applyApproval(createApprovalRequest(input), "APPROVE_ONCE", "Engineering Lead", Date.now(), undefined, 45);
    expect(approved.grant_minutes).toBe(45);
    const outOfRange = applyApproval(createApprovalRequest(input), "APPROVE_ONCE", "Engineering Lead", Date.now(), undefined, 500);
    expect(outOfRange.grant_minutes).toBe(MAX_GRANT_MINUTES);
    const defaulted = applyApproval(createApprovalRequest(input), "APPROVE_ONCE", "Engineering Lead");
    expect(defaulted.grant_minutes).toBe(DEFAULT_GRANT_MINUTES);
    const denied = applyApproval(createApprovalRequest(input), "DENY", "Engineering Lead", Date.now(), undefined, 45);
    expect(denied.grant_minutes).toBeUndefined();
    const expired = applyApproval(createApprovalRequest(input, 1), "APPROVE_ONCE", "Engineering Lead", Date.now() + 2, undefined, 45);
    expect(expired.grant_minutes).toBeUndefined();
  });
});
