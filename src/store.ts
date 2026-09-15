import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Event, Scan } from "./core.js";
import { detectSequenceFindings } from "./sequences.js";
import { approvalAuditEvent, validateApprovalRequest } from "./approvals.js";
import type { ApprovalRequest, ApprovalDecision } from "./approvals.js";
export type ApprovalAudit = { event: string; request_id: string; policy_id?: string; user?: string; agent: string; decision?: string; timestamp: string; reason?: string };

export class Store {
  events: Event[] = [];
  scans: Scan[] = [];
  reviews: Record<string, boolean> = {};
  approvals: ApprovalRequest[] = [];
  approvalAudit: ApprovalAudit[] = [];
  private queue: Promise<unknown> = Promise.resolve();
  readonly maxEvents = 10_000;
  constructor(readonly directory: string) {}
  async init() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await chmod(this.directory, 0o700);
    for (const name of ["events", "scans", "reviews", "approvals", "approval-audit"] as const) {
      const file = join(this.directory, `${name}.ndjson`);
      let contents = "";
      try { if ((await stat(file)).size > 64_000_000) throw new Error(`${name} store exceeds 64 MB; archive it before starting.`); contents = await readFile(file, "utf8"); await chmod(file, 0o600); }
      catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
      const lines = contents.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (!lines[i].trim()) continue;
        try {
          const row = JSON.parse(lines[i]);
          if (name === "events") this.events.push(row);
          else if (name === "scans") this.scans.push(row);
          else if (name === "reviews") this.reviews[row.id] = row.reviewed;
          else if (name === "approvals") {
            if (!validateApprovalRequest(row)) throw new Error(`Invalid approval record at line ${i + 1}; refuse to load it.`);
            this.approvals.push(row);
          }
          else this.approvalAudit.push(row);
        } catch { throw new Error(`Invalid ${name} store at line ${i + 1}; preserve and repair this file before restarting.`); }
      }
    }
    this.events = this.events.slice(-this.maxEvents);
    this.scans = this.scans.slice(-500);
  }
  addApproval(request: ApprovalRequest) { return this.serialized(async () => { if (!validateApprovalRequest(request)) throw new Error("Invalid approval request; refusing to persist it."); this.approvals = [...this.approvals.filter(r => r.request_id !== request.request_id), request].slice(-1000); await this.replace("approvals", this.approvals); const audit = { event: "approval_requested", request_id: request.request_id, policy_id: request.policy_id, user: request.user, agent: request.agent, timestamp: new Date().toISOString() }; this.approvalAudit = [...this.approvalAudit, audit].slice(-5000); await this.replace("approval-audit", this.approvalAudit); return request; }); }
  auditApproval(event: ApprovalAudit) { return this.serialized(async () => { this.approvalAudit = [...this.approvalAudit, event].slice(-5000); await this.replace("approval-audit", this.approvalAudit); return event; }); }
  resolveApproval(requestId: string, decision: ApprovalDecision, approver: string, apply: (request: ApprovalRequest, decision: ApprovalDecision, approver: string) => ApprovalRequest) {
    return this.serialized(async () => { const request = this.approvals.find(r => r.request_id === requestId); if (!request) throw new Error("Approval request not found."); const next = apply(request, decision, approver); const event = approvalAuditEvent(request, next, approver); const timestamp = new Date().toISOString(); const audit = { event, request_id: requestId, policy_id: next.policy_id, user: next.user, agent: next.agent, decision: next.decision || decision, timestamp, reason: event === "approval_invalid" ? "Malformed or unsupported approval record." : undefined }; const records = event === "approved" ? [audit, { ...audit, event: "approval_approved", reason: "Legacy compatibility alias for approved." }] : [audit]; this.approvals = this.approvals.map(r => r.request_id === requestId ? next : r); await this.replace("approvals", this.approvals); this.approvalAudit = [...this.approvalAudit, ...records].slice(-5000); await this.replace("approval-audit", this.approvalAudit); return next; });
  }
  private serialized<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.queue.then(fn);
    this.queue = result.catch(() => {});
    return result;
  }
  private async replace(name: string, rows: unknown[]) {
    const target = join(this.directory, `${name}.ndjson`);
    const temp = `${target}.tmp`;
    await writeFile(temp, rows.map(r => JSON.stringify(r)).join("\n") + "\n", { mode: 0o600 });
    await rename(temp, target);
  }
  addEvents(rows: Event[]) {
    return this.serialized(async () => {
      const ids = new Set(this.events.map(e => e.id));
      const fresh = rows.filter(r => { if (ids.has(r.id)) return false; ids.add(r.id); return true; });
      let next = [...this.events, ...fresh].slice(-this.maxEvents);
      if (fresh.length) {
        // Re-evaluate cross-event sequence rules, but only for sessions this batch actually
        // touched -- bounds the cost regardless of total store size.
        const touchedSessions = new Set(fresh.map(e => e.session));
        const bySession = new Map<string, Event[]>();
        for (const e of next) {
          if (!touchedSessions.has(e.session)) continue;
          const list = bySession.get(e.session);
          if (list) list.push(e); else bySession.set(e.session, [e]);
        }
        for (const sessionEvents of bySession.values()) {
          const attach = detectSequenceFindings(sessionEvents);
          if (attach.size) next = next.map(e => attach.has(e.id) ? { ...e, findings: [...e.findings, ...attach.get(e.id)!] } : e);
        }
        // Atomic replacement bounds disk use and makes retry after uncertain delivery idempotent.
        await this.replace("events", next);
        this.events = next;
      }
      return { accepted: fresh.length, duplicates: rows.length - fresh.length };
    });
  }
  addScan(scan: Scan) {
    return this.serialized(async () => {
      const next = [...this.scans, scan].slice(-500);
      await this.replace("scans", next); this.scans = next; return scan;
    });
  }
  review(id: string, reviewed: boolean) {
    return this.serialized(async () => {
      if (!this.events.some(e => e.id === id)) throw new Error("Event not found.");
      const next = { ...this.reviews, [id]: reviewed };
      const ids = new Set(this.events.map(e => e.id));
      const rows = Object.entries(next).filter(([key]) => ids.has(key)).map(([key, value]) => ({ id: key, reviewed: value }));
      await this.replace("reviews", rows); this.reviews = Object.fromEntries(rows.map(r => [r.id, r.reviewed]));
    });
  }
}
