import { createHash, randomUUID } from "node:crypto";

export type ApprovalLevel = "USER" | "MANAGER" | "SECURITY" | "ADMIN";
export type ApprovalMode = "SINGLE";
export type ApprovalStatus = "PENDING" | "APPROVED" | "DENIED" | "EXPIRED";
export type ApprovalDecision = "APPROVE_ONCE" | "APPROVE_SESSION" | "DENY" | "EXPIRE";
export interface ApproverUser { user: string; role?: string; department?: string; manager?: string }
export interface ApprovalRequest {
  request_id: string; user?: string; role?: string; approver: string[]; level: ApprovalLevel;
  mode: ApprovalMode; agent: string; tool: string; command: string; args?: string[]; path?: string; url?: string;
  repository?: string; branch?: string; policy_id?: string; policy_version: number; risk_score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; risk_factors: string[]; created_at: string; expires_at: string;
  status: ApprovalStatus; decision?: ApprovalDecision; fingerprint: string;
}
export interface ApprovalPolicy { level: ApprovalLevel; approver?: string; timeoutMs?: number; securityApprover?: string; adminApprover?: string }
export interface ApproverResolver { getManager(user: string): string | undefined; getApprovers(request: ApprovalRequest, policy: ApprovalPolicy): string[] }
export class LocalApproverResolver implements ApproverResolver {
  constructor(private readonly users: Record<string, ApproverUser>, private readonly escalation: { security?: string; admin?: string } = {}) {}
  getManager(user: string): string | undefined { return this.users[user]?.manager; }
  getApprovers(request: ApprovalRequest, policy: ApprovalPolicy): string[] {
    if (policy.approver) return [policy.approver];
    if (policy.level === "USER") return request.user ? [request.user] : [];
    if (policy.level === "MANAGER") return request.user ? [this.getManager(request.user)].filter((x): x is string => Boolean(x)) : [];
    if (policy.level === "SECURITY") return this.escalation.security || policy.securityApprover ? [policy.securityApprover || this.escalation.security!].filter(Boolean) : [];
    if (policy.level === "ADMIN") return this.escalation.admin || policy.adminApprover ? [policy.adminApprover || this.escalation.admin!].filter(Boolean) : [];
    return [];
  }
}
export function riskLevel(score: number): ApprovalRequest["risk_level"] { return score >= 90 ? "CRITICAL" : score >= 70 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW"; }
export function approvalFingerprint(input: Omit<ApprovalRequest, "request_id" | "created_at" | "expires_at" | "status" | "fingerprint">): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}
export function createApprovalRequest(input: Omit<ApprovalRequest, "request_id" | "created_at" | "expires_at" | "status" | "fingerprint">, timeoutMs = 60_000): ApprovalRequest {
  validateApprovalInput(input);
  const request = { ...input, request_id: randomUUID(), created_at: new Date().toISOString(), expires_at: new Date(Date.now() + timeoutMs).toISOString(), status: "PENDING" as ApprovalStatus, fingerprint: "" };
  request.fingerprint = approvalFingerprint(input); return request;
}
function validateApprovalInput(input: Pick<ApprovalRequest, "approver" | "level" | "mode" | "policy_version" | "risk_score">) {
  if (input.mode !== "SINGLE" || !["USER", "MANAGER", "SECURITY", "ADMIN"].includes(input.level)) throw new Error("Invalid approval policy: only SINGLE approval with a known level is supported.");
  if (!Number.isInteger(input.policy_version) || input.policy_version < 1 || !Number.isFinite(input.risk_score)) throw new Error("Invalid approval policy metadata.");
  if (!Array.isArray(input.approver) || input.approver.length !== 1 || !input.approver[0]) throw new Error("Invalid approval request: exactly one approver is required.");
}
export function validateApprovalRequest(request: ApprovalRequest): boolean {
  try { validateApprovalInput(request); return Boolean(request.request_id && request.created_at && request.expires_at && request.fingerprint && ["PENDING", "APPROVED", "DENIED", "EXPIRED"].includes(request.status)); } catch { return false; }
}
export function approvalAuditEvent(previous: ApprovalRequest, next: ApprovalRequest, approver: string): string {
  if (!validateApprovalRequest(previous)) return "approval_invalid";
  if (Date.parse(previous.expires_at) <= Date.now() || next.status === "EXPIRED") return "approval_expired";
  if (previous.level !== "USER" && previous.user && approver === previous.user) return "self_approval_rejected";
  if (!previous.approver.includes(approver)) return "approver_not_authorized";
  if (next.status === "DENIED") return "approval_denied";
  return "approved";
}
export function formatApprovalRequest(request: ApprovalRequest): string {
  const resource = request.path || request.url || request.command || request.tool;
  return `[${request.level}] ${request.agent} ${request.tool}: ${resource} (risk ${request.risk_score}/100 ${request.risk_level})`;
}
export function applyApproval(request: ApprovalRequest, decision: ApprovalDecision, approver: string, now = Date.now()): ApprovalRequest {
  if (!validateApprovalRequest(request)) return { ...request, status: "DENIED", decision: "DENY" };
  if (Date.parse(request.expires_at) <= now || decision === "EXPIRE") return { ...request, status: "EXPIRED", decision: "EXPIRE" };
  if (request.level !== "USER" && approver === request.user) return { ...request, status: "DENIED", decision: "DENY" };
  if (!request.approver.includes(approver)) return { ...request, status: "DENIED", decision: "DENY" };
  if (decision === "DENY") return { ...request, status: "DENIED", decision };
  if (request.status !== "PENDING") return request;
  return { ...request, status: "APPROVED", decision };
}
export function approvalStillValid(request: ApprovalRequest, current: Omit<ApprovalRequest, "request_id" | "created_at" | "expires_at" | "status" | "fingerprint">, now = Date.now()): boolean {
  return request.status === "APPROVED" && Date.parse(request.expires_at) > now && request.fingerprint === approvalFingerprint(current);
}
