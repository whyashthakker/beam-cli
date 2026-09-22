import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Event, Scan } from "./core.js";
import { detectSequenceFindings } from "./sequences.js";
import { approvalAuditEvent, validateApprovalRequest } from "./approvals.js";
import type { ApprovalRequest, ApprovalDecision } from "./approvals.js";
export type ApprovalAudit = { event: string; request_id: string; policy_id?: string; user?: string; agent: string; decision?: string; timestamp: string; reason?: string };

// core.normalize()'s id already collapses two hook firings for the *same* tool call when both
// carry an identical tool_use_id -- but a wrapping agent (e.g. Cursor's own preToolUse hook
// firing for a tool call that also went through the Claude Agent SDK's own hook loading, which
// reads the same ~/.claude/settings.json Claude Code uses regardless of which product embeds the
// SDK) mints its own tool_use_id rather than forwarding the inner agent's, so that id-based dedup
// never engages and the same physical command shows up twice under two different "agent" labels.
// This is a second, looser pass: two events from *different* agents, same phase/type/summary/
// project, within a few seconds of each other are almost certainly one physical action observed
// by two hooks, not two independent runs.
const CROSS_AGENT_DEDUP_WINDOW_MS = 3000;
const CROSS_AGENT_DEDUP_SCAN_WINDOW = 200;
function findCrossAgentDuplicate(candidate: Event, pool: Event[]): Event | undefined {
  const t = Date.parse(candidate.timestamp);
  if (!Number.isFinite(t)) return undefined;
  return pool.find(e => e.agent !== candidate.agent
    && e.phase === candidate.phase && e.type === candidate.type
    && e.summary === candidate.summary && e.project === candidate.project
    && Math.abs(Date.parse(e.timestamp) - t) <= CROSS_AGENT_DEDUP_WINDOW_MS);
}
// "claude-code" is what the Claude Agent SDK's own hook echo reports itself as, even when it's
// actually firing from inside another product (Cursor, etc.) built on that SDK rather than a real
// standalone Claude Code session -- never a more specific agent's own self-report. When a
// duplicate pair disagrees, whichever label isn't the generic SDK echo is the one actually
// driving the action, so it should win the surviving event's display name regardless of which of
// the two hook firings the collector happened to receive first.
function preferSpecificAgent(existing: string, incoming: string): string {
  return existing === "claude-code" && incoming !== "claude-code" ? incoming : existing;
}

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
      const byId = new Map(this.events.map(e => [e.id, e]));
      // Recent tail only: a cross-agent duplicate is always close in time to its twin, and this
      // keeps the scan cheap even once the store holds thousands of events.
      const recentTail = this.events.slice(-CROSS_AGENT_DEDUP_SCAN_WINDOW);
      const fresh: Event[] = [];
      // Duplicates already persisted (in recentTail, not this batch) whose agent label needs
      // upgrading from the generic SDK echo to the more specific agent -- keyed by the id of the
      // persisted event being corrected, since the incoming duplicate is otherwise dropped.
      const relabeled = new Map<string, Event>();
      const relabelExisting = (existing: Event, incoming: Event) => {
        const preferred = preferSpecificAgent(existing.agent, incoming.agent);
        if (preferred === existing.agent) return;
        const corrected = { ...existing, agent: preferred };
        const freshIndex = fresh.findIndex(e => e.id === existing.id);
        if (freshIndex !== -1) fresh[freshIndex] = corrected;
        else relabeled.set(existing.id, corrected);
        byId.set(existing.id, corrected);
      };
      for (const r of rows) {
        // core.normalize() already collapsed some cross-agent duplicates onto the same id (e.g.
        // matching tool_use_id) before this ever reaches the store -- that still needs the same
        // agent-preference treatment below, not a bare skip, or whichever hook fired first always
        // wins the label regardless of which agent is actually the specific one.
        const exact = byId.get(r.id);
        if (exact) { relabelExisting(exact, r); continue; }
        const dup = findCrossAgentDuplicate(r, recentTail) ?? findCrossAgentDuplicate(r, fresh);
        if (dup) { relabelExisting(dup, r); continue; }
        byId.set(r.id, r);
        fresh.push(r);
      }
      let next = [...this.events, ...fresh].slice(-this.maxEvents);
      if (relabeled.size) next = next.map(e => relabeled.has(e.id) ? relabeled.get(e.id)! : e);
      if (fresh.length || relabeled.size) {
        // Re-evaluate cross-event sequence rules, but only for sessions this batch actually
        // touched -- bounds the cost regardless of total store size.
        const touchedSessions = new Set([...fresh, ...relabeled.values()].map(e => e.session));
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
      // events: genuinely new records this call added -- what the caller should forward to the
      // workspace dashboard (never the raw input batch, which may include cross-agent duplicates
      // already suppressed above). relabeled: previously-forwarded duplicates whose agent label
      // just got corrected, forwarded again so the dashboard can upsert the same id in place.
      return { accepted: fresh.length, duplicates: rows.length - fresh.length, events: fresh, relabeled: [...relabeled.values()] };
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
