import { describe, expect, it } from "@jest/globals";
import { applyApproval, approvalStillValid, createApprovalRequest, LocalApproverResolver } from "../src/approvals.js";

const input = { user: "Rahul", role: "Developer", approver: ["Engineering Lead"], level: "MANAGER" as const, mode: "SINGLE" as const, agent: "claude-code", tool: "Bash", command: "git push", args: ["origin", "main"], policy_version: 2, risk_score: 62, risk_level: "MEDIUM" as const, risk_factors: ["protected branch"] };
describe("approvals", () => {
  it("creates, approves, and binds a request to the exact action", () => { const r = createApprovalRequest(input); const approved = applyApproval(r, "APPROVE_ONCE", "Engineering Lead"); expect(approved.status).toBe("APPROVED"); expect(approvalStillValid(approved, input)).toBe(true); expect(approvalStillValid(approved, { ...input, command: "git push --force" })).toBe(false); });
  it("rejects self-approval and unauthorized approvers", () => { const r = createApprovalRequest({ ...input, approver: ["Engineering Lead"] }); expect(applyApproval(r, "APPROVE_ONCE", "Rahul").status).toBe("DENIED"); expect(applyApproval(r, "APPROVE_ONCE", "Other").status).toBe("DENIED"); });
  it("expires without allowing continuation", () => { const r = createApprovalRequest(input, 1); expect(applyApproval(r, "APPROVE_ONCE", "Engineering Lead", Date.now() + 2).status).toBe("EXPIRED"); });
  it("resolves a manager locally", () => { const resolver = new LocalApproverResolver({ Rahul: { user: "Rahul", manager: "Engineering Lead" } }); expect(resolver.getApprovers(createApprovalRequest(input), { level: "MANAGER" })).toEqual(["Engineering Lead"]); });
});
