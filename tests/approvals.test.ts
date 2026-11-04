import { describe, expect, it } from "@jest/globals";
import { applyApproval, approvalStillValid, createApprovalRequest, LocalApproverResolver } from "../src/approvals.js";

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
});
