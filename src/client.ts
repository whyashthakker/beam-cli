import { spoolHookEvent } from "./hook-spool.js";
import { hookKind } from "./hook-catalog.js";
import { activityFor, commandOf } from "./activity.js";
import { classifyActionContext } from "./action-context.js";
import { environmentRisk } from "./access-risk.js";
import { mkdir, open, readdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { spawnSync } from "node:child_process";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { getApiUrl, getBeamHome, getCollectorUrl, getDataDirectory } from "./config.js";
import { normalize, scanText, setIgnoredRules, type Event, type Scan } from "./core.js";
import { adaptHookPayload } from "./hook-adapters.js";
import { forwardEvents } from "./forward.js";
import { evaluate, readPolicy, type Decision } from "./policy.js";
import { extractAgent } from "./extract.js";
import { readIdentity, type Identity } from "./enroll.js";
import { loadCustomRules } from "./custom-rules.js";
import { configureDetectors, detectSensitive, redactSensitive, type DataFinding } from "./data-detectors.js";
import { countNetwork, networkMode, TOPOLOGY_KINDS } from "./network-detectors.js";
import { ensurePrecommit } from "./precommit.js";
import { applyGitGate, gitGateMode } from "./git-gate.js";
import { takeWrapperNotices } from "./wrapper-notice.js";
import { recordNetwork, recordEvent, takeTurnSummary, vaultScope, attachLedgerOutput, commandSendsOverNetwork, maskVaulted, promptFindings, recordSubstitution, redactAndVault, resolvePlaceholders, takeUnreportedLedger } from "./pii-vault.js";
import { addNotice, flushNotices, resetNotices, summarizeFindings, withNotice } from "./hook-notice.js";
import { redactWithSessionEntities } from "./entity-redaction.js";
import { recordAndCheckAnomaly } from "./behavioral-anomaly.js";
import { applyJevHook } from "./jev.js";
import { applyJudgeHook } from "./judge.js";
import { isPathTrusted, readTrustedPaths } from "./trusted-paths.js";
import { addBlockedTarget, isTargetBlocked, readBlockedTargets } from "./blocked-targets.js";
import { promptTty } from "./tty-prompt.js";
import { gateSkill } from "./skill-gate.js";
import { notePrompt, sessionContextFor, sessionTitlesEnabled } from "./session-title.js";
import { clampGrantMinutes, createApprovalRequest, type ApprovalDecision, type ApprovalLevel, type ApprovalRequest } from "./approvals.js";
import { consumeApprovedAction, recordApprovedAction } from "./approved-actions.js";

export async function readToken(): Promise<string> {
  if (process.env.BEAM_TOKEN) return process.env.BEAM_TOKEN;
  const tokenPath = join(getDataDirectory(), "token");
  try { return (await readFile(tokenPath, "utf8")).trim(); }
  catch { throw new Error(`No token file at ${tokenPath}. Run 'beam start' first.`); }
}

async function send(route: string, body: string): Promise<unknown> {
  const url = getCollectorUrl();
  const response = await fetch(`${url.origin}${route}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${await readToken()}`, "Content-Type": "application/json" },
    body,
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) throw new Error(`Collector rejected request: ${await response.text()}`);
  return response.json();
}

async function get(route: string): Promise<unknown> {
  const url = getCollectorUrl();
  const response = await fetch(`${url.origin}${route}`, {
    headers: { Authorization: `Bearer ${await readToken()}` },
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) throw new Error(`Collector rejected request: ${await response.text()}`);
  return response.json();
}

async function boundedFile(filePath: string): Promise<string> {
  const stats = await stat(filePath);
  if (stats.size > 2_000_000) throw new Error("File exceeds 2 MB. Split it into batches.");
  return readFile(filePath, "utf8");
}

export async function importEvents(filePath: string): Promise<unknown> {
  return send("/ingest", await boundedFile(filePath));
}

export interface RuleReloadResult { path: string; loaded: number; errors: string[] }

export async function reloadRemoteRules(): Promise<RuleReloadResult> {
  return send("/rules/reload", "{}") as Promise<RuleReloadResult>;
}

// Human-in-the-loop exception to a policy block: file a request with the running collector and
// wait for an admin to resolve it (`beam policy approve`/`reject`, or the dashboard). Blocks this
// process for up to `timeoutMs` -- fine for an explicit CLI invocation with nowhere else to be,
// unlike the pre-action hook path, which never waits on a human (see client.ts's main hook
// handler) because the host agent imposes its own short timeout on that process.
export interface AskApprovalOptions {
  agent: string; tool: string; reason: string;
  command?: string; path?: string; url?: string;
  approver?: string; level?: ApprovalLevel;
  /** How long to wait for a decision before giving up and reporting EXPIRED. Default 10 minutes. */
  timeoutMs?: number;
  pollMs?: number;
}
// The remote collector's ApprovalRequest row (apps/collector, Postgres/Prisma -- camelCase,
// `id` as its key, no `fingerprint`). Distinct from this file's own snake_case ApprovalRequest
// (approvals.ts, `request_id` as its key), which is what the rest of the CLI displays and what
// the local-only resolveApproval()/listPendingApprovals() below speak. Mapped once here so
// askApproval()'s caller only ever deals with one shape regardless of which path answered.
interface RemoteApprovalRequest {
  id: string; agent: string; tool: string; command: string | null; path: string | null; url: string | null;
  level: ApprovalLevel; approver: string[];
  riskScore: number; riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; riskFactors: string[];
  reason: string | null;
  status: ApprovalRequest["status"]; decision: ApprovalDecision | null; decisionReason: string | null;
  grantMinutes?: number | null;
  expiresAt: string; createdAt: string;
}
function fromRemoteApproval(remote: RemoteApprovalRequest): ApprovalRequest {
  return {
    request_id: remote.id, approver: remote.approver, level: remote.level, mode: "SINGLE",
    agent: remote.agent, tool: remote.tool, command: remote.command ?? "",
    path: remote.path ?? undefined, url: remote.url ?? undefined,
    policy_version: 1, risk_score: remote.riskScore, risk_level: remote.riskLevel, risk_factors: remote.riskFactors,
    created_at: remote.createdAt, expires_at: remote.expiresAt,
    status: remote.status, decision: remote.decision ?? undefined,
    fingerprint: "", // approvalStillValid()'s dedup concept never applies to a remote-filed request
    reason: remote.reason ?? undefined, decision_reason: remote.decisionReason ?? undefined,
    grant_minutes: remote.grantMinutes ?? undefined,
  };
}

// An enrolled device's request needs a workspace admin to see and resolve it, which only ever
// happens on the shared collector -- same getApiUrl() + device-secret precedent as
// forwardMcpInventory/forwardSkillInventory in forward.ts, never the local loopback server (which
// has no concept of "another person" to ask). The collector's own /v1/approvals is
// device-authenticated and device-scoped on purpose: a device can file and poll its own request,
// but there is deliberately no device-authenticated way to resolve one -- that would let a device
// approve its own blocked action. Resolution is an admin action in the dashboard (or, for a
// single, unenrolled machine, the local `beam policy approve`/`reject` below).
async function askRemoteApproval(identity: Identity, options: AskApprovalOptions, timeoutMs: number): Promise<ApprovalRequest> {
  const base = getApiUrl();
  const auth = { Authorization: `Bearer ${identity.deviceSecret}` };
  const postRes = await fetch(`${base}/v1/approvals`, {
    method: "POST", signal: AbortSignal.timeout(5000),
    headers: { ...auth, "Content-Type": "application/json" },
    body: JSON.stringify({
      agent: options.agent, tool: options.tool, command: options.command, path: options.path, url: options.url,
      reason: options.reason, level: options.level, approver: options.approver ? [options.approver] : undefined,
      timeoutSeconds: Math.max(1, Math.min(3600, Math.round(timeoutMs / 1000))),
    }),
  });
  if (!postRes.ok) throw new Error(`Collector rejected request: ${await postRes.text()}`);
  const filed = fromRemoteApproval(await postRes.json() as RemoteApprovalRequest);
  const pollMs = options.pollMs ?? 2000;
  for (;;) {
    const listRes = await fetch(`${base}/v1/approvals`, { headers: auth, signal: AbortSignal.timeout(5000) });
    if (!listRes.ok) throw new Error(`Collector rejected request: ${await listRes.text()}`);
    const all = (await listRes.json() as RemoteApprovalRequest[]).map(fromRemoteApproval);
    const current = all.find(r => r.request_id === filed.request_id);
    if (!current) throw new Error("The collector lost track of this approval request.");
    if (current.status !== "PENDING") return current;
    if (Date.parse(current.expires_at) <= Date.now()) return { ...current, status: "EXPIRED", decision: "EXPIRE" };
    await new Promise(resolve => setTimeout(resolve, pollMs));
  }
}

async function askLocalApproval(options: AskApprovalOptions, timeoutMs: number): Promise<ApprovalRequest> {
  const request = createApprovalRequest({
    approver: [options.approver ?? "admin"],
    level: options.level ?? "ADMIN",
    mode: "SINGLE",
    agent: options.agent,
    tool: options.tool,
    command: options.command ?? "",
    path: options.path,
    url: options.url,
    policy_version: 1,
    risk_score: 50,
    risk_level: "MEDIUM",
    risk_factors: [],
    reason: options.reason,
  }, timeoutMs);
  await send("/approvals", JSON.stringify(request));
  const pollMs = options.pollMs ?? 2000;
  for (;;) {
    const all = await get("/approvals") as ApprovalRequest[];
    const current = all.find(r => r.request_id === request.request_id);
    if (!current) throw new Error("The collector lost track of this approval request.");
    if (current.status !== "PENDING") return current;
    if (Date.parse(current.expires_at) <= Date.now()) return { ...current, status: "EXPIRED", decision: "EXPIRE" };
    await new Promise(resolve => setTimeout(resolve, pollMs));
  }
}

export async function askApproval(options: AskApprovalOptions): Promise<ApprovalRequest> {
  const timeoutMs = options.timeoutMs ?? 10 * 60_000;
  const identity = await readIdentity();
  const result = identity ? await askRemoteApproval(identity, options, timeoutMs) : await askLocalApproval(options, timeoutMs);
  // Closes the loop: the agent's retry of this exact action goes straight through next time,
  // without filing a second request -- see approved-actions.ts. The approver's own chosen
  // duration (10-60 minutes, grant_minutes) drives how long the retry window stays open; an
  // older collector/dashboard that never set it falls back to DEFAULT_GRANT_MINUTES.
  if (result.status === "APPROVED") {
    const ttlMs = clampGrantMinutes(result.grant_minutes) * 60_000;
    await recordApprovedAction({ agent: options.agent, tool: options.tool, command: options.command, path: options.path, url: options.url }, ttlMs).catch(() => {});
  }
  return result;
}

// Local-machine only, deliberately: see askRemoteApproval()'s comment above for why an enrolled
// device has no remote equivalent of these two yet (that's an admin-authenticated dashboard
// surface, not this device-authenticated collector).
export async function listPendingApprovals(): Promise<ApprovalRequest[]> {
  const all = await get("/approvals") as ApprovalRequest[];
  return all.filter(r => r.status === "PENDING");
}

export async function resolveApproval(requestId: string, decision: ApprovalDecision, approver: string, decisionReason?: string, grantMinutes?: number): Promise<ApprovalRequest> {
  return send("/approvals/resolve", JSON.stringify({ request_id: requestId, decision, approver, decision_reason: decisionReason, grant_minutes: grantMinutes })) as Promise<ApprovalRequest>;
}

export interface ScanOptions { mcp?: boolean; save?: boolean }

export async function scanFile(filePath: string, options: ScanOptions = {}, beamHome = getBeamHome()): Promise<Scan | unknown> {
  const content = await boundedFile(filePath);
  const kind = options.mcp ? "mcp" : "skill";
  if (options.save) return send("/scan", JSON.stringify({ name: filePath, content, kind }));
  // Offline scanning should flag the same things the live collector would -- load any custom
  // rules from disk first, same as the server does at startup. Note: beamHome is ~/.beam, not
  // the OS home directory -- distinct from extractPreview/extractSave's `home` below.
  await loadCustomRules(beamHome);
  return scanText(filePath, content, kind);
}

const INGEST_BATCH_SIZE = 2000; // matches the collector's own per-request record cap

export interface ExtractPreviewResult { found: number; previewed: number; events: Event[] }
export interface ExtractSaveResult { found: number; accepted: number; duplicates: number; skipped: number }

// Without --save: extract and normalize locally (so redaction still applies) without touching
// the collector at all -- a read-only preview of what would be imported. `home` is the OS home
// directory (where ~/.claude, ~/.codex etc. live); `beamHome` is the separate ~/.beam config
// root that rules.json lives under -- passing one where the other belongs silently loads zero
// custom rules instead of erroring, so keep them distinct rather than reusing one parameter.
export async function extractPreview(agentId: string, limit = 200, home = homedir(), beamHome = getBeamHome()): Promise<ExtractPreviewResult> {
  await loadCustomRules(beamHome);
  setIgnoredRules((await readPolicy().catch(() => null))?.rules.ignoredRules ?? [], agentId);
  const records = await extractAgent(agentId, home);
  const events: Event[] = [];
  for (const record of records) { try { events.push(normalize(record)); } catch { /* skip a record normalize() can't accept */ } }
  return { found: events.length, previewed: Math.min(events.length, limit), events: events.slice(0, limit) };
}

// With --save: send the raw (pre-normalize) records to /ingest so the server's own pipeline --
// dedupe by event_id, redact, bounded persistence -- handles them exactly like a live hook would.
export async function extractSave(agentId: string, home = homedir()): Promise<ExtractSaveResult> {
  const records = await extractAgent(agentId, home);
  const totals = { accepted: 0, duplicates: 0, skipped: 0 };
  for (let i = 0; i < records.length; i += INGEST_BATCH_SIZE) {
    const batch = records.slice(i, i + INGEST_BATCH_SIZE);
    const result = await send("/ingest", JSON.stringify(batch)) as { accepted: number; duplicates: number; skipped: number };
    totals.accepted += result.accepted; totals.duplicates += result.duplicates; totals.skipped += result.skipped;
  }
  return { found: records.length, ...totals };
}

// PreToolUse fires with no model field of its own, but Claude Code has already appended the
// assistant turn that proposed this tool call to its own session transcript by the time the hook
// runs. Walk back a bounded number of lines from the tail of that session's file (named
// <session_id>.jsonl under some ~/.claude/projects/<encoded-cwd>/ subdirectory -- the encoding
// isn't ours to reproduce, so we search rather than construct the path) to recover it.
const MODEL_LOOKUP_TAIL_LINES = 200;

async function findClaudeCodeModel(home: string, sessionId: string): Promise<string> {
  if (!sessionId) return "";
  const projectsDir = join(home, ".claude", "projects");
  let dirs: string[];
  try { dirs = await readdir(projectsDir); } catch { return ""; }
  for (const dir of dirs) {
    let content: string;
    try { content = await readFile(join(projectsDir, dir, `${sessionId}.jsonl`), "utf8"); }
    catch { continue; }
    const lines = content.split("\n");
    for (let i = lines.length - 1; i >= 0 && i >= lines.length - MODEL_LOOKUP_TAIL_LINES; i--) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        const row = JSON.parse(line) as Record<string, unknown>;
        const message = row.message && typeof row.message === "object" ? row.message as Record<string, unknown> : {};
        if (row.type === "assistant" && typeof message.model === "string" && message.model) return message.model;
      } catch { /* skip a malformed line */ }
    }
    return "";
  }
  return "";
}

// Claude Code logs one JSONL row per streamed content block, not one row per API response -- a
// single assistant turn that requests N tool calls (each firing its own PreToolUse hook) shows up
// as N separate "assistant" rows sharing one message.id, and every one of them repeats that same
// turn's full usage. Naively taking "whatever usage is in the most recent row" for every one of
// those N hook firings sums the same tokens N times. usage-cursor.json remembers the last
// message id already attributed per session so only the first hook firing for a given turn
// reports its usage; the rest correctly report nothing new.
type UsageCursorFile = {
  claude?: Record<string, string>;
  codex?: Record<string, { input_tokens: number; output_tokens: number }>;
};

async function loadUsageCursor(): Promise<UsageCursorFile> {
  try { return JSON.parse(await readFile(join(getDataDirectory(), "usage-cursor.json"), "utf8")) as UsageCursorFile; }
  catch { return {}; }
}

async function saveUsageCursor(cursor: UsageCursorFile): Promise<void> {
  try {
    const dir = getDataDirectory();
    await mkdir(dir, { recursive: true });
    const target = join(dir, "usage-cursor.json");
    const temp = `${target}.${process.pid}.tmp`;
    await writeFile(temp, JSON.stringify(cursor));
    await rename(temp, target);
  } catch { /* best-effort enrichment only */ }
}

async function findClaudeCodeUsage(home: string, sessionId: string, toolUseId: string | undefined, cursor: UsageCursorFile): Promise<{ input_tokens?: number; output_tokens?: number }> {
  if (!sessionId) return {};
  const projectsDir = join(home, ".claude", "projects");
  let dirs: string[]; try { dirs = await readdir(projectsDir); } catch { return {}; }
  for (const dir of dirs) {
    let content: string; try { content = await readFile(join(projectsDir, dir, `${sessionId}.jsonl`), "utf8"); } catch { continue; }
    const lines = content.split("\n");
    const start = Math.max(0, lines.length - MODEL_LOOKUP_TAIL_LINES);
    let matched: { messageId: string; usage: Record<string, unknown> } | undefined;
    for (let i = lines.length - 1; i >= start; i--) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        const row = JSON.parse(line) as Record<string, unknown>;
        if (row.type !== "assistant") continue;
        const message = row.message && typeof row.message === "object" ? row.message as Record<string, unknown> : {};
        const messageId = typeof message.id === "string" ? message.id : undefined;
        const usage = message.usage && typeof message.usage === "object" ? message.usage as Record<string, unknown> : undefined;
        if (!messageId || !usage || (typeof usage.input_tokens !== "number" && typeof usage.output_tokens !== "number")) continue;
        // A PreToolUse hook can match this row to its own tool_use_id -- pin to that exact row
        // rather than "whichever assistant row happens to be last" once one is available.
        if (toolUseId) {
          const blocks = Array.isArray(message.content) ? message.content as Record<string, unknown>[] : [];
          if (!blocks.some(b => b && b.type === "tool_use" && b.id === toolUseId)) continue;
        }
        matched = { messageId, usage };
        break;
      } catch { /* skip malformed transcript rows */ }
    }
    if (!matched) return {};
    if (cursor.claude?.[sessionId] === matched.messageId) return {}; // already attributed by an earlier tool call in this same turn
    cursor.claude = { ...cursor.claude, [sessionId]: matched.messageId };
    return { input_tokens: typeof matched.usage.input_tokens === "number" ? matched.usage.input_tokens : undefined, output_tokens: typeof matched.usage.output_tokens === "number" ? matched.usage.output_tokens : undefined };
  }
  return {};
}

// Codex rollouts live in ~/.codex/sessions/YYYY/MM/DD/rollout-<start time>-<id>.jsonl, and heavy
// users have gigabytes of them. Hooks run on every tool call, so lookups never walk the whole
// tree or read whole files: only the newest date directories are listed, and only a file's head
// (where session_meta is) and tail (the latest turn_context and token_count) are read.
const CODEX_CANDIDATES = 50;
const HEAD_BYTES = 64 * 1024;
const TAIL_BYTES = 512 * 1024;

async function newestRollouts(home: string): Promise<string[]> {
  const out: string[] = [];
  const descend = async (dir: string, depth: number): Promise<void> => {
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => b.name.localeCompare(a.name)); // dates and start times: newest first
    for (const entry of entries) {
      if (out.length >= CODEX_CANDIDATES) return;
      const full = join(dir, entry.name);
      if (entry.isDirectory() && depth < 3) await descend(full, depth + 1);
      else if (entry.isFile() && entry.name.endsWith(".jsonl")) out.push(full);
    }
  };
  await descend(join(home, ".codex", "sessions"), 0);
  await descend(join(home, ".codex", "archived_sessions"), 3);
  // A long session started days ago is still the most recently written: order by write time.
  const stamped = await Promise.all(out.map(async path => ({ path, mtimeMs: await stat(path).then(s => s.mtimeMs, () => 0) })));
  return stamped.sort((a, b) => b.mtimeMs - a.mtimeMs).slice(0, CODEX_MODEL_LOOKUP_MAX_FILES).map(f => f.path);
}

/** The start and end of a file, without reading the middle of a large transcript. */
async function headAndTail(path: string): Promise<{ head: string; tail: string }> {
  const file = await open(path, "r");
  try {
    const { size } = await file.stat();
    const read = async (position: number, length: number) => {
      const buffer = Buffer.alloc(Math.max(0, length));
      const { bytesRead } = await file.read(buffer, 0, buffer.length, position);
      return buffer.subarray(0, bytesRead).toString("utf8");
    };
    if (size <= HEAD_BYTES + TAIL_BYTES) { const all = await read(0, size); return { head: all, tail: all }; }
    // Drop the first, partial line of the tail.
    const tail = await read(size - TAIL_BYTES, TAIL_BYTES);
    return { head: await read(0, HEAD_BYTES), tail: tail.slice(tail.indexOf("\n") + 1) };
  } finally {
    await file.close();
  }
}

/** transcript_path from the hook payload, accepted only inside ~/.codex since it's untrusted input. */
function codexTranscript(home: string, transcriptPath: string | undefined): string | undefined {
  if (!transcriptPath) return undefined;
  const root = resolve(join(home, ".codex"));
  const resolved = resolve(transcriptPath);
  return resolved !== root && resolved.startsWith(`${root}${sep}`) ? resolved : undefined;
}

const codexRows = (text: string) => text.split("\n").flatMap(line => {
  const trimmed = line.trim();
  if (!trimmed) return [];
  try {
    const row = JSON.parse(trimmed) as Record<string, unknown>;
    return [{ type: row.type, payload: row.payload && typeof row.payload === "object" ? row.payload as Record<string, unknown> : {} }];
  } catch { return []; }
});
const isSession = (text: string, sessionId: string) =>
  codexRows(text).some(r => r.type === "session_meta" && (r.payload.session_id === sessionId || r.payload.id === sessionId));
const latestModel = (text: string) =>
  codexRows(text).reduce((model, r) => (r.type === "turn_context" && typeof r.payload.model === "string" && r.payload.model ? r.payload.model : model), "");

// Codex's PreToolUse payload has no model field (same verified shape as Claude Code's), and
// unlike Claude Code's session file, a rollout file isn't named after the session id -- it's
// keyed by a "session_meta" record inside it. Best-effort only: the "turn_context" record's
// model field isn't part of Codex's schema this codebase has verified (extract.ts only reads
// session_meta/response_item) -- if that assumption is wrong this silently yields "" rather than
// forwarding a bogus value.
const CODEX_MODEL_LOOKUP_MAX_FILES = 10;

async function findCodexModel(home: string, sessionId: string, transcriptPath?: string): Promise<string> {
  if (!sessionId) return "";
  const own = codexTranscript(home, transcriptPath);
  if (own) {
    try { const model = latestModel((await headAndTail(own)).tail); if (model) return model; } catch { /* fall back to the scan */ }
  }
  for (const path of await newestRollouts(home)) {
    let parts;
    try { parts = await headAndTail(path); } catch { continue; }
    if (!isSession(parts.head, sessionId)) continue;
    return latestModel(parts.tail);
  }
  return "";
}

// Codex's own "last_token_usage" is a per-turn delta, but a turn that makes several tool calls
// (each firing its own PreToolUse hook) can have 2+ hooks fire before Codex writes the *next*
// token_count event -- every one of those hooks would then read the exact same delta and
// double-count it. total_token_usage is cumulative for the whole session instead, so subtracting
// the amount usage-cursor.json already attributed for this session yields the real, un-double-
// counted increment, and reading it twice before it changes correctly yields a zero delta.
function totalTokenUsageFromTokenCountLines(content: string, requireSessionId?: string): { matchesSession: boolean; total?: { input_tokens: number; output_tokens: number } } {
  let matchesSession = !requireSessionId;
  let total: { input_tokens: number; output_tokens: number } | undefined;
  for (const line of content.split("\n")) {
    let row: Record<string, unknown>; try { row = JSON.parse(line) as Record<string, unknown>; } catch { continue; }
    const payload = row.payload && typeof row.payload === "object" ? row.payload as Record<string, unknown> : {};
    if (requireSessionId && row.type === "session_meta" && (payload.session_id === requireSessionId || payload.id === requireSessionId)) matchesSession = true;
    const info = payload.info && typeof payload.info === "object" ? payload.info as Record<string, unknown> : {};
    const totalUsage = info.total_token_usage && typeof info.total_token_usage === "object" ? info.total_token_usage as Record<string, unknown> : undefined;
    if (row.type === "event_msg" && payload.type === "token_count" && totalUsage
      && typeof totalUsage.input_tokens === "number" && typeof totalUsage.output_tokens === "number") {
      total = { input_tokens: totalUsage.input_tokens, output_tokens: totalUsage.output_tokens };
    }
  }
  return { matchesSession, total };
}

async function findCodexUsage(home: string, sessionId: string, transcriptPath: string | undefined, cursor: UsageCursorFile): Promise<{ input_tokens?: number; output_tokens?: number }> {
  // Every Codex hook payload carries transcript_path pointing at exactly this session's rollout
  // file (learn.chatgpt.com/docs/hooks) -- reading that directly is both simpler and more
  // reliable than guessing which of the most-recently-modified files under ~/.codex/sessions
  // belongs to this session. Still constrained to ~/.codex, since the path rides in untrusted
  // hook input. Falls back to the mtime-scan below when a payload doesn't carry it (older Codex
  // builds, or tests).
  let total: { input_tokens: number; output_tokens: number } | undefined;
  const own = codexTranscript(home, transcriptPath);
  if (own) {
    try { total = totalTokenUsageFromTokenCountLines((await headAndTail(own)).tail).total; } catch { /* fall through to scan */ }
  }
  if (!total && sessionId) {
    for (const path of await newestRollouts(home)) {
      let parts;
      try { parts = await headAndTail(path); } catch { continue; }
      if (!isSession(parts.head, sessionId)) continue;
      total = totalTokenUsageFromTokenCountLines(parts.tail).total;
      break;
    }
  }
  if (!total || !sessionId) return {};
  const prev = cursor.codex?.[sessionId] ?? { input_tokens: 0, output_tokens: 0 };
  const deltaInput = Math.max(0, total.input_tokens - prev.input_tokens);
  const deltaOutput = Math.max(0, total.output_tokens - prev.output_tokens);
  cursor.codex = { ...cursor.codex, [sessionId]: total };
  if (deltaInput === 0 && deltaOutput === 0) return {};
  return { input_tokens: deltaInput, output_tokens: deltaOutput };
}

async function readStdin(limitBytes: number): Promise<string> {
  let input = "";
  // A hook is launched with piped stdin. Explicitly resume the stream so the
  // async iterator keeps the short-lived CLI process alive until the payload
  // has been consumed and a policy decision is emitted.
  process.stdin.resume();
  for await (const chunk of process.stdin) {
    input += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (input.length > limitBytes) throw new Error(`Hook exceeds ${Math.floor(limitBytes / 1000)} KB.`);
  }
  return input;
}

// Never throws: best-effort capture must not suppress configured policy enforcement.
export async function captureHook(sourceAgent = "claude-code", home = homedir(), suppliedEvent?: string): Promise<void> {
  let canBlock = suppliedEvent === undefined || hookKind(suppliedEvent) === "pre";
  resetNotices();
  try {
    const input = await readStdin(2_000_000);
    const raw = JSON.parse(input) as Record<string, unknown>;
    let data = adaptHookPayload(sourceAgent, raw, suppliedEvent);
    sourceAgent = String(data.source_agent ?? sourceAgent);
    data.source_agent = sourceAgent;
    data.source_type = "hook";
    // Network topology: how it is treated is a policy setting. Beam's own logs always omit it; the model
    // only loses it in "redact"/"block" mode. Addresses are never put in a notice, only kinds and counts.
    const startPolicy = await readPolicy().catch(() => null);
    const netMode = networkMode(startPolicy?.rules.networkTopology, process.env.BEAM_NETWORK_TOPOLOGY);
    configureDetectors({ skipKinds: netMode === "off" ? TOPOLOGY_KINDS : undefined });
    const modelSkip = netMode === "redact" || netMode === "block" || netMode === "off" ? undefined : TOPOLOGY_KINDS;

    const eventKind = hookKind(String(data.hook_event_name ?? ""));
    try { if (eventKind === "prompt" || eventKind === "pre") ensurePrecommit(String(data.cwd ?? ""), { policyValue: startPolicy?.rules.autoPrecommit }); } catch { /* never block a hook on setup */ }
    const promptGate = eventKind === "prompt" && ["claude-code", "codex", "cursor", "gemini"].includes(sourceAgent);
    canBlock = eventKind === "pre" || promptGate;
    if (eventKind === "prompt" && typeof data.prompt === "string") {
      data.event_type = "prompt.submit";
      data.tool_name = data.tool_name ?? data.hook_event_name;
      data.command = data.prompt;
      // A prompt hook can only block or annotate -- the agent cannot rewrite what the user typed,
      // so sensitive values in it have already been sent to the model. Say so rather than stay quiet.
      if (process.env.BEAM_WRAPPER_ID) for (const note of await takeWrapperNotices(process.env.BEAM_WRAPPER_ID).catch(() => [])) {
        addNotice(note.replace(/^Beam's /, ""));
        await recordEvent(vaultScope(String(data.session_id ?? "")), `your prompt: ${note.replace(/^Beam's terminal wrapper replaced /, "replaced ").replace(/ in your prompt with vault placeholders before it reached Claude\..*$/, " before it reached Claude")}`).catch(() => {});
      }
      const promptPolicy = await readPolicy().catch(() => null);
      const promptMode = promptPolicy?.rules.piiPrompt ?? (["block", "warn", "off"].includes(process.env.BEAM_PII_PROMPT ?? "") ? process.env.BEAM_PII_PROMPT as "block" | "warn" | "off" : "block");
      const found = promptMode === "off" ? { blocking: [], advisory: [] } : promptFindings(data.prompt, promptPolicy?.rules.customDetectors, netMode === "block");
      const promptSession = vaultScope(String(data.session_id ?? data.sessionId ?? ""));
      if (netMode !== "off") await recordNetwork(promptSession, "your prompt", countNetwork(data.prompt)).catch(() => {});
      if (promptMode === "block" && promptGate && found.blocking.length && promptSession) {
        // The agent can't rewrite a typed prompt, so the only way the model never sees these values is
        // to stop the prompt: vault the real values and hand the user a placeholder version to resend.
        const vaulted = await redactAndVault(data.prompt, promptSession, promptPolicy?.rules.customDetectors);
        const copied = copyToClipboard(vaulted.text);
        const reason = `stored ${summarizeFindings(found.blocking)} in Beam's local vault and blocked this prompt so the model never saw them. ${copied ? "The placeholder version is on your clipboard: paste it (Cmd/Ctrl+V) and press Enter." : "Resend it with the placeholders below."} Beam swaps in the real values only when a shell command runs, and masks them in the output:\n\n${vaulted.text}`;
        data.policy_decision = { action: "deny", rule: "beam.pii-prompt", reason };
        await recordEvent(promptSession, `blocked a prompt containing ${summarizeFindings(found.blocking)} (stored in the vault)`).catch(() => {});
        if (sourceAgent === "claude-code") {
          // Exit 0 with JSON (not exit 2) so `suppressOriginalPrompt` applies: otherwise Claude Code appends
          // "Original prompt: <the real value>" to the block message and writes it to the transcript on disk.
          process.stdout.write(JSON.stringify({ decision: "block", reason: `Beam: ${reason}`, suppressOriginalPrompt: true, hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true } }));
        } else {
          emitDeny(sourceAgent, reason, String(data.hook_event_name ?? "UserPromptSubmit"));
        }
        await captureActivity(data);
        return;
      }
      const promptAll = [...found.blocking, ...found.advisory];
      if (promptAll.length) addNotice(`your prompt contains ${summarizeFindings(promptAll)}. It was sent to the model as typed (prompts can't be rewritten); Beam redacts it in its own logs.${promptMode === "warn" ? "" : " (Not blocked: this agent cannot block prompts, there is no session id, or the values are low-confidence kinds.)"}`);
      if (sessionTitlesEnabled()) await notePrompt(String(data.session_id ?? ""), data.prompt, String(data.cwd ?? "")).catch(() => {});
    }
    // Completed actions, permission notifications, and lifecycle callbacks are observation only.
    // They must never run pre-action policy, skill approval, or action-judge gates.
    if (!canBlock) {
      if (eventKind === "post" && sourceAgent === "claude-code") {
        const bundle = await readPolicy().catch(() => null);
        // Keep what the command printed (masked) so the end-of-turn summary can show it.
        try {
          const toolUseId = typeof data.tool_use_id === "string" ? data.tool_use_id : "";
          const scope = vaultScope(String(data.session_id ?? ""));
          const resp = data.tool_response as Record<string, unknown> | string | undefined;
          const printed = typeof resp === "string" ? resp : typeof resp?.stdout === "string" ? resp.stdout : "";
          if (toolUseId && printed) await attachLedgerOutput(scope, toolUseId, (await redactAndVault((await maskVaulted(printed, scope)).text, scope, bundle?.rules.customDetectors, undefined, true, modelSkip)).text.trim());
        } catch { /* the summary just omits the output */ }
        if (netMode !== "off") await recordNetwork(vaultScope(String(data.session_id ?? "")), "tool output", countNetwork(JSON.stringify(data.tool_response ?? ""))).catch(() => {});
        await emitRedactedOutput(sourceAgent, data.tool_response, vaultScope(String(data.session_id ?? "")), bundle?.rules.customDetectors, modelSkip)
          .catch(() => addNotice("could not check this tool's output for sensitive data; it may contain unredacted values."));
      }
      await captureActivity(data);
      if (String(data.hook_event_name ?? "").toLowerCase() === "stop") {
        const turn = await takeTurnSummary(vaultScope(String(data.session_id ?? ""))).catch(() => ({ events: [] as string[], commands: [] as Array<{ command: string; ids: string[]; output?: string }>, network: {} as Record<string, Record<string, number>> }));
        const clip = (text: string, n: number) => text.length > n ? `${text.slice(0, n)}…` : text;
        const parts = [
          ...turn.events,
          ...turn.commands.map(r => `ran \`${clip(r.command, 100)}\` with ${r.ids.join(", ")} substituted${r.output ? ` → output: \`${clip(r.output, 120)}\`` : ""}`),
        ];
        const seen = Object.entries(turn.network).map(([source, counts]) => `${source}: ${Object.entries(counts).map(([kind, n]) => `${n}× ${kind}`).join(", ")}`);
        if (seen.length) parts.push(`network addresses seen (${seen.join("; ")}) — ${netMode === "report" ? "reported only; internal addresses are kept out of Beam's logs, public IPs are not touched" : netMode === "redact" ? "internal addresses were replaced with placeholders; public IPs are not touched" : "internal addresses are blocked in prompts and replaced elsewhere; public IPs are not touched"}`);
        if (parts.length) addNotice(`this turn: ${parts.join(" · ")}.${turn.events.length || turn.commands.length ? " The model only saw placeholders." : ""}`);
      }
      flushNotices(sourceAgent, String(data.hook_event_name ?? ""));
      if (sourceAgent === "cline") process.stdout.write(JSON.stringify({ cancel: false }));
      if (sourceAgent === "antigravity" && eventKind === "assistant") process.stdout.write(JSON.stringify({ decision: "stop" }));
      return;
    }

    // Model and token-usage backfill are independent: a newer agent build (Codex 0.155.1+ sends
    // `model` as a common field on every hook event -- see learn.chatgpt.com/docs/hooks) can
    // already provide data.model while still never sending input_tokens/output_tokens. Gating
    // both lookups on `!data.model` together meant that once an agent started self-reporting its
    // model, this silently stopped backfilling tokens too -- each needs its own guard.
    if (!data.model || (data.input_tokens === undefined && data.output_tokens === undefined)) {
      try {
        const sessionId = String(data.session_id ?? data.sessionId ?? "");
        const needsUsage = data.input_tokens === undefined && data.output_tokens === undefined;
        const cursor = needsUsage ? await loadUsageCursor() : undefined;
        if (sourceAgent === "claude-code") {
          if (!data.model) data.model = await findClaudeCodeModel(home, sessionId);
          if (cursor) {
            const toolUseId = typeof data.tool_use_id === "string" ? data.tool_use_id : undefined;
            const usage = await findClaudeCodeUsage(home, sessionId, toolUseId, cursor);
            if (usage.input_tokens !== undefined) data.input_tokens = usage.input_tokens;
            if (usage.output_tokens !== undefined) data.output_tokens = usage.output_tokens;
          }
        } else if (sourceAgent === "codex") {
          const transcriptPath = typeof data.transcript_path === "string" ? data.transcript_path : undefined;
          if (!data.model) data.model = await findCodexModel(home, sessionId, transcriptPath);
          if (cursor) {
            const usage = await findCodexUsage(home, sessionId, transcriptPath, cursor);
            if (usage.input_tokens !== undefined) data.input_tokens = usage.input_tokens;
            if (usage.output_tokens !== undefined) data.output_tokens = usage.output_tokens;
          }
        }
        if (cursor) await saveUsageCursor(cursor);
      } catch { /* best-effort enrichment only -- never block the hook on this */ }
    }

    // 1. Enforcement first — a local file read, so it works even if the collector is down.
    //    General rules follow advisory/enforce mode. Explicit mandatory mitigation
    //    blocks can deny matching calls while unrelated calls remain in observe mode.
    const toolInput = data.tool_input && typeof data.tool_input === "object"
      ? (data.tool_input as Record<string, unknown>) : {};
    const command = commandOf(data);
    // Beam's own escape hatch: an agent blocked by policy -- even a fully disabled agent or a
    // workspace-wide "blockedTools: [Bash]" -- must still be able to ask a human for an
    // exception, or the block is a dead end with no way out. This unconditionally skips every
    // check below (policy evaluate(), self-protection, risk escalation, anomaly tracking) for
    // exactly that one command, before any of them run.
    if (isApprovalEscapeHatch(String(data.tool_name ?? ""), command)) {
      data.policy_decision = { action: "allow", rule: "beam.approval-escape-hatch" };
      await captureActivity(data);
      if (["cline", "antigravity"].includes(sourceAgent)) emitAllow(sourceAgent, undefined, String(data.hook_event_name ?? "PreToolUse"));
      return;
    }
    const policyBundle = await readPolicy().catch(() => null);
    setIgnoredRules(policyBundle?.rules.ignoredRules ?? [], sourceAgent);
    // Vault substitution: a shell command that carries this session's placeholders ([SSN_001]) is
    // evaluated, and later run, with the real values. The model only ever wrote the placeholder.
    // `command`/`data` keep the placeholder form so nothing the model or the log sees has the value.
    const substitution = await resolveVaultedInput(eventKind === "pre" ? data : {}, toolInput);
    const evalInput = substitution?.input ?? toolInput;
    const evalCommand = substitution ? String(commandOf({ tool_input: evalInput })) : command;
    let decision = evaluate(policyBundle, {
      agent: sourceAgent,
      eventType: promptGate ? "prompt.submit" : undefined,
      input: evalInput,
      tool: String(data.tool_name ?? ""),
      command: evalCommand,
      args: Array.isArray(evalInput.args) ? evalInput.args.map(String) : evalCommand.split(/\s+/).slice(1),
      path: String(toolInput.file_path ?? toolInput.path ?? data.file_path ?? ""),
      url: String(toolInput.url ?? data.url ?? ""),
      role: typeof data.role === "string" ? data.role : undefined,
      user: typeof data.user === "string" ? data.user : undefined,
      cwd: typeof toolInput.workdir === "string" ? toolInput.workdir : typeof data.cwd === "string" ? data.cwd : undefined,
      repository: typeof data.repository === "string" ? data.repository : undefined,
      branch: typeof data.branch === "string" ? data.branch : undefined,
      environment: typeof data.environment === "string" ? data.environment : undefined,
      time: typeof data.timestamp === "string" ? data.timestamp : undefined,
    });
    if (substitution) {
      // The decision must never echo a real value back to the model or the log.
      const scrub = async (text?: string) => text === undefined ? text : (await maskVaulted(text, vaultScope(String(data.session_id ?? "")))).text;
      decision = { ...decision, reason: await scrub(decision.reason), command, args: undefined, riskFactors: await Promise.all(decision.riskFactors.map(f => scrub(f) as Promise<string>)) };
      if (commandSendsOverNetwork(evalCommand) && decision.action !== "deny") {
        decision = { ...decision, action: "deny", rule: "beam.vault-egress", reason: `${substitution.ids.length} vaulted value(s) would be substituted into a command that sends data over the network. Beam does not do that: run it yourself, or remove the network step.` };
      }
    }
    const readsEnvironment = isEnvironmentAccess(String(data.tool_name ?? ""), command, String(toolInput.file_path ?? toolInput.path ?? data.file_path ?? ""), toolInput);
    if (readsEnvironment && decision.mode === "observe" && decision.action === "allow") {
      // Allow-all still records this sensitive read as a risk, without turning it into an approval gate.
      decision = { ...decision, riskScore: Math.max(decision.riskScore, 35), riskLevel: decision.riskScore >= 70 ? decision.riskLevel : "MEDIUM", riskFactors: [...new Set([...decision.riskFactors, "sensitive environment data"])], reason: "Sensitive environment data access was allowed and flagged for review." };
      addNotice("this action reads environment data that may hold credentials; allowed and flagged for review (observe mode).");
    } else if (decision.mode !== "observe" && (decision.action === "allow" || decision.action === "warn") && readsEnvironment) {
      // Sensitive data is always promoted to an approval gate in protective policy modes.
      decision = { ...decision, action: "ask", reason: "Reading environment variables or .env files requires approval." };
    }
    const workspace = String(data.cwd ?? "");
    const targetPath = String(toolInput.file_path ?? toolInput.path ?? data.file_path ?? "");
    if (isBeamSelfProtectionTarget(String(data.tool_name ?? ""), command, targetPath)) {
      decision = {
        ...decision,
        action: "deny",
        rule: "beam.self-protection",
        reason: "Beam protection cannot be disabled, removed, or modified by an agent.",
      };
    }

    // Behavioral anomaly: a burst of high/critical-severity actions from one session, independent
    // of whether any single one was individually blocked -- the shape an agent shows when it's
    // been talked into a chain of risky actions (injection, a compromised skill, a confused
    // multi-step plan), even if each step alone only ever rated "ask". Recorded regardless of this
    // action's own decision (a blocked/asked action still happened and still counts), but only
    // ever escalates a decision that's currently allow/warn -- never downgrades an existing ask/deny.
    try {
      const anomaly = await recordAndCheckAnomaly(String(data.session_id ?? data.sessionId ?? ""), decision.riskLevel);
      if (anomaly.triggered) {
        const reason = `${anomaly.count} high/critical-severity actions from this session in the last ${anomaly.windowMinutes} minutes.`;
        if (decision.mode === "observe" && decision.action === "allow") {
          decision = { ...decision, riskFactors: [...new Set([...decision.riskFactors, "behavioral anomaly: action burst"])], reason };
          addNotice(`unusual burst: ${reason} Allowed and flagged for review (observe mode).`);
        } else if (decision.mode !== "observe" && (decision.action === "allow" || decision.action === "warn")) {
          decision = { ...decision, action: "ask", rule: "beam.behavioral-anomaly", reason };
        }
      }
    } catch { addNotice("burst detection failed for this action, so it was not counted toward the anomaly check."); }
    if (eventKind === "pre" && netMode !== "off") await recordNetwork(vaultScope(String(data.session_id ?? "")), "a command", countNetwork(command)).catch(() => {});
    // Git gate: scan what a `git commit` / `git push` / `git add` would commit, publish or stage.
    if (eventKind === "pre" && SHELL_TOOL.test(String(data.tool_name ?? ""))) {
      decision = applyGitGate(decision, {
        command: evalCommand,
        cwd: typeof toolInput.workdir === "string" ? toolInput.workdir : String(data.cwd ?? ""),
        mode: gitGateMode(policyBundle?.rules.gitGate, process.env.BEAM_GIT_GATE, decision.mode),
        custom: policyBundle?.rules.customDetectors,
        ignore: policyBundle?.rules.gitGateIgnore,
      });
    }
    const policyMode = decision.mode;
    if (decision.action === "allow" && workspace) {
      const escaping = outsideWorkspacePaths(workspace, targetPath, command);
      if (policyMode === "observe" && escaping.length) {
        decision = { ...decision, riskScore: Math.max(decision.riskScore, 35), riskLevel: decision.riskScore >= 70 ? decision.riskLevel : "MEDIUM", riskFactors: [...new Set([...decision.riskFactors, "access outside the current workspace"])], reason: "Access outside the current workspace was allowed and flagged for review." };
        addNotice("this action accesses a path outside the current workspace; allowed and flagged for review (observe mode).");
      }
      if (policyMode !== "observe") {
      if (escaping.length) {
        // A human can pre-approve specific outside-workspace paths with `beam trust <path>`
        // (~/.beam/data/trusted-paths.json) so this ask doesn't fire again for them. The agent
        // can't write that file itself -- isBeamSelfProtectionTarget above blocks it.
        const trusted = await readTrustedPaths().catch(() => []);
        const untrusted = escaping.filter(path => !isPathTrusted(path, trusted));
        if (untrusted.length) {
          // Hooks run as child processes while the host agent owns the terminal. Reading
          // /dev/tty here steals input from the host UI and can stall the session until timeout.
          // Return ASK promptly so the host can show its own permission prompt instead.
          decision = { ...decision, action: "ask", reason: "This action accesses a path outside the current workspace." };
        }
      }
      }
    }

    // Skill gate: any call that loads a skill (the Skill tool, or a read of SKILL.md / skills.md)
    // is scanned first, and its 0-100 risk score is surfaced in the approval prompt. Never
    // downgrades a decision that already denies/asks, and a scan failure must not break the hook.
    if (decision.action === "allow" || decision.action === "warn") {
      try {
        const skill = await gateSkill(String(data.tool_name ?? ""), toolInput, workspace, policyMode === "enforce");
        if (skill) {
          decision = { ...decision, riskScore: Math.max(decision.riskScore, skill.scan.score), riskLevel: skill.scan.level, riskFactors: [...decision.riskFactors, ...skill.scan.findings.slice(0, 5).map(f => f.title)] };
          if (skill.action !== "allow" && policyMode !== "observe") decision = { ...decision, action: skill.action, rule: "beam.skill-scan", reason: skill.reason };
          else if (skill.reason) { process.stderr.write(`\n⚠ Beam skill scan: ${skill.reason}\n`); addNotice(`skill scan: ${skill.reason}`); }
        }
      } catch { addNotice("the skill scan could not read this skill, so it was not scanned."); }
    }

    const jev = await applyJevHook(decision, data);
    decision = jev.decision;
    if (jev.judgment) { process.stderr.write(`Beam Jev: ${JSON.stringify(jev.judgment)}\n`); addNotice(`Jev judged this action: ${noticeJudgment(jev.judgment)}`); }
    const judged = await applyJudgeHook(decision, data);
    decision = judged.decision;
    if (judged.judgment) { process.stderr.write(`Beam judge: ${JSON.stringify(judged.judgment)}\n`); addNotice(`judge reviewed this action: ${noticeJudgment(judged.judgment)}`); }

    // "warn" only ever comes out of evaluate() when the policy's mode is neither "enforce" nor
    // "advisory" (see policy.ts) -- a manager's explicit ASK/BLOCK rule under either of those
    // modes already resolved to "ask"/"deny" above, untouched by this. A remote-configured
    // enforce/advisory policy from the collector therefore stays mandatory; this interactive
    // step only ever runs for Beam's own soft, non-mandatory fallback.
    if (decision.action === "warn") decision = await resolveWarnInteractively(decision, targetPath, command);

    // Retain redacted prompts and session identities now that prompt activity is part of capture.
    if (sessionTitlesEnabled() && data.session_id && eventKind !== "prompt") {
      const context = await sessionContextFor(sourceAgent, String(data.session_id), { home }).catch(() => null);
      if (context) { data.session_title = context.title; data.session_title_source = context.titleSource; data.turn = context.turn; data.turn_topic = context.topic; data.turn_shift = context.shift; }
    }

    // An admin already approved this exact action (via `beam policy ask`, resolved in the
    // dashboard or locally with `beam policy approve`) -- let the retry through instead of
    // blocking it again. Single-use (see approved-actions.ts) and never for self-protection, same
    // as the hint below: that guardrail isn't something this channel can grant an exception to.
    if ((decision.action === "deny" || decision.action === "ask") && decision.rule !== "beam.self-protection") {
      const granted = await consumeApprovedAction({ agent: sourceAgent, tool: String(data.tool_name ?? ""), command, path: targetPath, url: String(toolInput.url ?? data.url ?? "") }).catch(() => false);
      if (granted) decision = { ...decision, action: "allow", rule: "beam.approval-granted", reason: "Approved by a workspace admin." };
    }

    // Tell the agent its way out: a flat "no" with no next step just invites it to retry, rephrase,
    // or work around the block. Skipped for Beam's own self-protection -- that guardrail is never
    // meant to be appealed through this channel.
    if (decision.action === "deny" && decision.rule !== "beam.self-protection") {
      const target = (toolInput.file_path ?? toolInput.path ?? data.file_path ?? toolInput.url ?? data.url ?? command ?? "").toString().replace(/"/g, '\\"');
      // --agent/--tool must name the real agent and tool that's blocked here, not the CLI's own
      // "cli"/"Bash" defaults -- an approval is recorded under exactly those two fields
      // (approved-actions.ts), and the retry this is meant to unblock will report the real ones,
      // not the defaults. A mismatch here is why an approval silently fails to grant the retry.
      const toolName = String(data.tool_name ?? "Bash").replace(/"/g, '\\"');
      if (target) decision = { ...decision, reason: `${decision.reason ?? "Blocked by workspace policy."} If this is necessary, ask a workspace admin for an exception: beam policy ask "${target}" "<explain why you need this>" --agent "${sourceAgent}" --tool "${toolName}"` };
    }
    data.policy_decision = { action: decision.action, rule: decision.rule, reason: decision.reason, risk_score: decision.riskScore, risk_level: decision.riskLevel, risk_factors: decision.riskFactors };
    const hookEvent = String(data.hook_event_name ?? "PreToolUse");
    // The action itself isn't rewritten (a "redact" decision reports its own notice), but Beam still
    // strips sensitive values before storing or uploading it. Say so, with kinds and counts only.
    if (eventKind !== "prompt" && decision.action !== "redact" && decision.action !== "deny") {
      const actionStrings: string[] = [];
      const collect = (v: unknown): void => { if (typeof v === "string") actionStrings.push(v); else if (Array.isArray(v)) v.forEach(collect); else if (v && typeof v === "object") Object.values(v).forEach(collect); };
      collect(toolInput); if (command) actionStrings.push(command);
      const stored = detectSensitive([...new Set(actionStrings)].join("\n"), policyBundle?.rules.customDetectors);
      if (stored.length) addNotice(`${summarizeFindings(stored)} in this action will be redacted from Beam's activity log.`);
    }
    let event = safeNormalize(data);
    if (decision.action === "deny") {
      if (event) event = { ...event, findings: [...event.findings, blockedFinding(decision.reason)] };
      emitDeny(sourceAgent, decision.reason ?? "Blocked by workspace policy.", hookEvent);
    } else if (decision.action === "ask") {
      emitAsk(sourceAgent, decision.reason ?? "This action requires approval.", hookEvent);
    } else if (substitution && ["allow", "warn", "audit", "redact"].includes(decision.action)) {
      addNotice(`ran this command with ${substitution.ids.length} vaulted value${substitution.ids.length === 1 ? "" : "s"} substituted (${substitution.ids.join(", ")}). The model only sees the placeholders, and the output is masked again.`);
      await recordSubstitution(vaultScope(String(data.session_id ?? "")), { tool: String(data.tool_name ?? ""), command: command.slice(0, 300), ids: substitution.ids, toolUseId: typeof data.tool_use_id === "string" ? data.tool_use_id : undefined }).catch(() => addNotice("could not record this substitution for the end-of-turn summary."));
      emitRedacted(sourceAgent, { tool_input: substitution.input }, `Substituted ${substitution.ids.join(", ")} from Beam's vault.`, hookEvent);
    } else if (decision.action === "redact") {
      const transformed = await redactPayload(data, decision, String(data.session_id ?? data.sessionId ?? ""));
      if (transformed.changed) addNotice(`redacted ${summarizeFindings(transformed.findings)} from this action before it ran.`);
      if (!transformed.changed) {
        emitAllow(sourceAgent, decision.reason, hookEvent);
      } else {
        emitRedacted(sourceAgent, transformed.data, decision.reason, hookEvent);
        data = transformed.data;
      }
    } else if (decision.action === "warn") {
      // No TTY was available to ask interactively (headless run, CI, detached process) --
      // fail open with a visible warning rather than blocking a hook that has nowhere to
      // prompt.
      process.stderr.write(`\n⚠ Beam policy (advisory): ${decision.reason}\n`);
      addNotice(`policy (advisory): ${decision.reason}`);
    }

    if (["cline", "antigravity"].includes(sourceAgent) && ["allow", "audit", "warn"].includes(decision.action)) emitAllow(sourceAgent, decision.reason, hookEvent);

    // Capture every lifecycle event, including allowed prompts and tool completions.
    await captureActivity(data);
    flushNotices(sourceAgent, hookEvent);

    // 3. A policy-blocked action carries a finding the collector's own normalize() can't
    //    reconstruct (it only knows about *this* process's policy decision) -- forward it to the
    //    workspace immediately rather than folding it into the batch, so a manager sees a block
    //    without waiting on unrelated traffic to fill the batch.
    if (event && decision.action === "deny") { try { await forwardEvents(event); } catch { /* offline */ } }
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    // If a security policy exists, a hook-side failure must not become an implicit allow. The
    // vendor-specific response is still emitted where possible; exit 2 is the documented
    // fail-closed signal for Claude/Codex/Cursor/Copilot/Gemini (geminicli.com/docs/hooks/reference
    // confirms exit 2 blocks both BeforeTool and BeforeAgent, same as decision: "deny") and is
    // also treated as failure by OpenCode's native plugin wrapper.
    const policy = await readPolicy().catch(() => null);
    if (canBlock && policy && (policy.rules.mode === "enforce" || policy.errors?.length)) {
      // emitDeny already sets exit code 2 for the agents where that's the documented fail-closed
      // signal (see EXIT_2_FAILS_CLOSED above).
      emitDeny(sourceAgent, "Beam security policy could not complete safely; execution is denied.");
    }
  }
}

// Puts the placeholder version of a blocked prompt on the clipboard so resending is paste + Enter.
// Placeholders only, never a real value. Skipped under test, on unsupported platforms, or with BEAM_NO_CLIPBOARD=1.
function copyToClipboard(text: string): boolean {
  if (process.env.JEST_WORKER_ID || process.env.BEAM_NO_CLIPBOARD) return false;
  const tool = process.platform === "darwin" ? ["pbcopy"] : process.platform === "win32" ? ["clip"] : process.platform === "linux" ? ["xclip", "-selection", "clipboard"] : null;
  if (!tool) return false;
  try { return spawnSync(tool[0]!, tool.slice(1), { input: text, timeout: 2000 }).status === 0; } catch { return false; }
}

const SHELL_TOOL = /^(?:bash|shell|powershell|exec_command|run_shell_command|execute_bash|run_command|local_shell)$/i;
// Resolves this session's vault placeholders in every string of a shell tool's input. Null when the
// event isn't a shell call, has no session, or contains no known placeholder.
async function resolveVaultedInput(data: Record<string, unknown>, toolInput: Record<string, unknown>): Promise<{ input: Record<string, unknown>; ids: string[] } | null> {
  if (!SHELL_TOOL.test(String(data.tool_name ?? ""))) return null;
  const sessionId = vaultScope(String(data.session_id ?? data.sessionId ?? ""));
  if (!sessionId) return null;
  const ids: string[] = [];
  const walk = async (value: unknown): Promise<unknown> => {
    if (typeof value === "string") { const r = await resolvePlaceholders(value, sessionId); for (const id of r.ids) if (!ids.includes(id)) ids.push(id); return r.text; }
    if (Array.isArray(value)) return Promise.all(value.map(walk));
    if (value && typeof value === "object") return Object.fromEntries(await Promise.all(Object.entries(value).map(async ([k, v]) => [k, await walk(v)])));
    return value;
  };
  try {
    const input = await walk(toolInput) as Record<string, unknown>;
    return ids.length ? { input, ids } : null;
  } catch { return null; }
}

// Short, secret-free one-liner for a Jev/judge result shown in a user-facing notice.
function noticeJudgment(judgment: unknown): string {
  const j = judgment as Record<string, unknown> | null;
  const verdict = typeof j?.verdict === "string" ? j.verdict : typeof j?.decision === "string" ? j.decision : "see Beam dashboard";
  const reason = typeof j?.reason === "string" ? `, ${j.reason.slice(0, 120)}` : "";
  return `${verdict}${reason}`;
}

async function captureActivity(data: Record<string, unknown>): Promise<void> {
  try {
    const policy = await readPolicy().catch(() => null);
    const redacted = await redactPayload(data, { customDetectors: policy?.rules.customDetectors }, String(data.session_id ?? ""));
    const a = activityFor(redacted.data, value => redactSensitive(value, policy?.rules.customDetectors).text);
    if (!a) return;
    const projected: Record<string, unknown> = {};
    for (const field of ["source_agent", "source_type", "hook_event_name", "session_id", "parent_session_id", "tool_name", "tool_use_id", "event_type", "command", "file_path", "url", "cwd", "model", "timestamp", "session_title", "session_title_source", "turn", "turn_topic", "turn_shift", "input_tokens", "output_tokens", "policy_decision", "status", "error", "is_error", "reason", "decision", "permission_decision", "permissionDecision", "approval", "approved", "agent_id", "agent_type", "subagent_id", "child_session_id", "exit_code", "exitCode", "duration_ms"]) {
      const value = redacted.data[field];
      if (value !== undefined) projected[field] = typeof value === "string" ? value.slice(0, 4000) : value;
    }
    const details = a.details as Record<string, unknown> | undefined;
    if (details) for (const [key,value] of Object.entries(details)) projected[key] = value;
    projected.tool_input = a.input;
    projected.tool_response = a.output;
    projected.prompt = a.prompt;
    projected.assistant_text = a.assistant;
    projected.capture_truncated = a.truncated;
    try { await send("/ingest", JSON.stringify(projected)); }
    catch { await spoolHookEvent(projected); }
  } catch (e) {
    process.stderr.write(`Beam activity capture failed: ${e instanceof Error ? e.message : String(e)}\n`);
    addNotice("could not record this action in Beam's activity log.");
  }
}

function safeNormalize(data: Record<string, unknown>): Event | null {
  try { return normalize(data); } catch { return null; }
}

// Resolves a "warn" decision by asking a human at the terminal what to do, since a stderr-only
// warning is easy to miss and the action proceeds either way. Falls back to leaving the decision
// as "warn" (handled the old way -- printed to stderr, action proceeds) when there's no TTY to
// prompt on, or a previous "Block always" choice already covers this exact target.
async function resolveWarnInteractively(decision: Decision, targetPath: string, command: string): Promise<Decision> {
  const blocked = await readBlockedTargets().catch(() => []);
  if (blocked.length && isTargetBlocked({ path: targetPath || undefined, command }, blocked)) {
    return { ...decision, action: "deny", rule: "beam.block-always", reason: `${decision.reason ?? "Blocked by workspace policy."} (blocked always by a previous choice)` };
  }
  const choice = await promptTty(
    `⚠ Beam policy (advisory): ${decision.reason ?? "This action was flagged for review."}`,
    [
      { key: "c", label: "Continue -- allow this one action" },
      { key: "s", label: "Stop -- block this one action" },
      { key: "b", label: "Block always -- remember this and block it on every future run" },
      { key: "r", label: "Redact -- strip sensitive data from this action, then continue" },
    ],
  );
  if (choice === "c") return { ...decision, action: "allow" };
  if (choice === "s") return { ...decision, action: "deny", reason: decision.reason ?? "Blocked by user choice." };
  if (choice === "b") {
    await addBlockedTarget(targetPath || command).catch(() => {});
    return { ...decision, action: "deny", rule: "beam.block-always", reason: decision.reason ?? "Blocked by user choice (always)." };
  }
  if (choice === "r") return { ...decision, action: "redact" };
  return decision;
}

// Free-text fields that describe an action to the user (e.g. Bash `description`) but are never executed or read.
const PROSE_INPUT_FIELDS = new Set(["description", "activeForm"]);
function isEnvironmentAccess(tool: string, command: string, path: string, input: Record<string, unknown>): boolean {
  const text = `${tool} ${command} ${path} ${Object.entries(input).filter(([key, value]) => typeof value === "string" && !PROSE_INPUT_FIELDS.has(key)).map(([, value]) => value).join(" ")}`;
  const context=classifyActionContext(tool,{...input,file_path:path},"",command,v=>v,false);
  const scoped=environmentRisk(context);
  if(context.actions.length && context.actions.every(a=>a.operation==="source-search"))return false;
  // File reads: .env, .env.local, .env.prod, etc. Also catch common env/config
  // locations that contain exported credentials.
  if (/(^|[\\/\s"'])\.env(?:\.[\w.-]+)?(?:$|[\\/\s"'])/i.test(text)) return true;
  if (/(^|[\\/\s"'])\.aws[\\/]credentials(?:$|[\\/\s"'])|(^|[\\/\s"'])\.config[\\/]gcloud(?:$|[\\/\s"'])/i.test(text)) return true;
  if(scoped && ("suppress" in scoped || "severity" in scoped && scoped.severity==="info"))return false;
  // Shell/process environment reads: env, printenv, set, export -p, $FOO,
  // process.env, os.environ and equivalent tool arguments.
  return /\b(?:printenv|env|export\s+-p|process\.env|os\.environ|System\.getenv)\b/i.test(text)
    || /\$\{?(?:[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|PRIVATE|API)[A-Z0-9_]*)\}?/.test(text);
}

// Returns the resolved absolute paths, if any, that a candidate path/command references outside
// `cwd` -- empty when nothing escapes the workspace.
function outsideWorkspacePaths(cwd: string, target: string, command: string): string[] {
  if (!cwd) return [];
  const text = `${target} ${command}`;
  const candidates = [
    ...(isAbsolute(target) ? [target] : []),
    ...[...text.matchAll(/(?:^|\s)(\/[^\s"';&|]+)/g)].map(match => match[1]),
  ];
  const root = resolve(cwd);
  return candidates
    .map(candidate => resolve(root, candidate))
    .filter(path => {
      const escaped = relative(root, path);
      return escaped === ".." || escaped.startsWith(`..${sep}`) || isAbsolute(escaped);
    });
}

// Exempts exactly `beam policy ask`/`pending` from every policy check -- filing or reading a
// request is harmless and must always be reachable, even for a fully disabled agent. Deliberately
// NOT `approve`/`reject`: those decide a request rather than merely file or read one, and exempting
// them would let an agent on an unenrolled, single-machine setup file its own request and
// immediately self-approve it, defeating the whole point of asking a human.
function isApprovalEscapeHatch(tool: string, command: string): boolean {
  if (!/^(?:bash|shell|terminal|exec_command|shell_command|run_shell_command|command|execute_bash|run_command|run_terminal_cmd)$/i.test(tool)) return false;
  const trimmed = command.trim();
  // Command substitution ($(...) and backticks) stays live even inside double quotes in a POSIX
  // shell, so a malicious payload hidden in the reason/target argument -- `beam policy ask
  // "$(rm -rf /)" "x"` -- can't be waved through just because it's quoted; checked against the
  // raw string, before anything is stripped.
  if (/\$\(|`/.test(trimmed)) return false;
  // Control operators (; & | < > newline) lose their meaning once quoted, so a legitimate reason
  // like "deploy; already reviewed" must not trip this -- checked with quoted spans stripped out
  // first. Anything left outside quotes (real chaining, e.g. `beam policy ask x y && rm -rf /`)
  // still gets caught.
  const unquoted = trimmed.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, "");
  if (/[;&|<>\n]/.test(unquoted)) return false;
  return /^(?:\S*[\\/])?beam(?:\.exe)?\s+policy\s+(?:ask\s+\S[\s\S]*|pending\b(?:\s+--?[\w-]+(?:\s+\S+)?)*\s*)$/i.test(trimmed);
}

function isBeamSelfProtectionTarget(tool: string, command: string, target: string): boolean {
  const beamHome = resolve(getBeamHome());
  const beamData = resolve(getDataDirectory());
  const text = `${tool} ${command} ${target}`;
  const targetPath = target ? resolve(target) : "";
  const touchesBeamFiles = Boolean(targetPath && (targetPath === beamHome || targetPath.startsWith(`${beamHome}${sep}`) || targetPath === beamData || targetPath.startsWith(`${beamData}${sep}`))) || /(?:^|[\s"'\/])\.beam(?:[\/\s"']|$)|beam[\\/]data[\\/]policy\.json/i.test(text);
  const stopsBeam = /\b(?:beam\s+(?:service\s+(?:stop|uninstall)|(?:jev|judge)\s+(?:configure|disable)|uninstall)|(?:launchctl|systemctl|pkill|killall)\b[^\n]*\bbeam\b|npm\s+(?:uninstall|remove)\b[^\n]*@?agent-beam|rm\b[^\n]*(?:\.beam|beam-cli|@agent-beam))/i.test(text);
  return touchesBeamFiles || stopsBeam;
}

function blockedFinding(reason = "Blocked by workspace policy."): Event["findings"][number] {
  return { id: "policy.blocked", title: "Blocked by workspace policy", severity: "high", explanation: reason, evidence: "" };
}

async function redactPayload(data: Record<string, unknown>, decision: { customDetectors?: Array<{ name: string; pattern: string; replacement: string }> }, sessionId: string): Promise<{ data: Record<string, unknown>; changed: boolean; findings: DataFinding[] }> {
  const copy = structuredClone(data); let changed = false; const findings: DataFinding[] = [];
  const redactValue = async (value: unknown): Promise<unknown> => {
    if (typeof value === "string") { const result = await redactWithSessionEntities(value, sessionId, decision.customDetectors); changed ||= result.text !== value; findings.push(...result.findings); return result.text; }
    if (Array.isArray(value)) return Promise.all(value.map(redactValue));
    if (value && typeof value === "object") return Object.fromEntries(await Promise.all(Object.entries(value).map(async ([k, v]) => [k, await redactValue(v)])));
    return value;
  };
  const redacted = await redactValue(copy) as Record<string, unknown>;
  return { data: redacted, changed, findings };
}

// Claude Code and Codex use the same hookSpecificOutput.permissionDecision contract for every
// hook event -- only the echoed hookEventName differs per event (verified against
// code.claude.com/docs/en/hooks for PreToolUse, UserPromptSubmit, and PostToolUse).
function claudeStyleHookEventName(event: string): string {
  return event === "UserPromptSubmit" || event === "PostToolUse" ? event : "PreToolUse";
}

// A tool has already run by the time PostToolUse fires -- there is nothing left to block, only
// what Claude sees afterward to rewrite (hookSpecificOutput.updatedToolOutput). This is the
// counterpart to redactPayload()/emitRedacted() below, which redact a secret that was already in
// the *command text* before it runs; this instead catches a secret that only appears in a
// command's *output* (`cat .env` holding a real, un-migrated value; an app echoing its own
// resolved config) -- the input had nothing to redact, so PreToolUse redaction never saw it.
// Only wired for claude-code (see agents.ts notes): Codex's PostToolUse payload shape and
// updatedToolOutput support are unverified, and sending a rewrite a client doesn't honor would
// silently do nothing while looking like protection.
async function emitRedactedOutput(agent: string, toolResponse: unknown, sessionId: string, customDetectors?: Array<{ name: string; pattern: string; replacement: string }>, skipKinds?: ReadonlySet<string>): Promise<void> {
  if (agent !== "claude-code" || toolResponse === null || toolResponse === undefined) return;
  const outputFindings: DataFinding[] = []; const vaultedIds: string[] = [];
  const redactValue = async (value: unknown): Promise<unknown> => {
    if (typeof value === "string") {
      const masked = await maskVaulted(value, sessionId);
      for (const id of masked.ids) if (!vaultedIds.includes(id)) vaultedIds.push(id);
      const result = await redactAndVault(masked.text, sessionId, customDetectors, undefined, true, skipKinds);
      outputFindings.push(...result.findings); return result.text;
    }
    if (Array.isArray(value)) return Promise.all(value.map(redactValue));
    if (value && typeof value === "object") return Object.fromEntries(await Promise.all(Object.entries(value).map(async ([k, v]) => [k, await redactValue(v)])));
    return value;
  };
  const redacted = await redactValue(toolResponse);
  if (JSON.stringify(redacted) === JSON.stringify(toolResponse)) return; // nothing to rewrite
  const parts = [outputFindings.length ? `redacted ${summarizeFindings(outputFindings)}` : "", vaultedIds.length ? `masked ${vaultedIds.length} vaulted value${vaultedIds.length === 1 ? "" : "s"} back to ${vaultedIds.join(", ")}` : ""].filter(Boolean);
  addNotice(`${parts.join(" and ")} in this tool's output before the model saw it.`);
  await recordEvent(sessionId, `tool output: ${parts.join(" and ")}`).catch(() => {});
  process.stdout.write(JSON.stringify(withNotice(agent, { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: redacted } })));
}

function emitAsk(agent: string, reason: string, event = "PreToolUse"): void {
  if (agent === "claude-code" || agent === "codex") {
    process.stdout.write(JSON.stringify(withNotice(agent, { hookSpecificOutput: { hookEventName: claudeStyleHookEventName(event), permissionDecision: "ask", permissionDecisionReason: `Beam: ${reason}` } })));
  } else if (agent === "cursor" || agent === "copilot-cli") {
    // These hook contracts do not provide a reliable interactive approval channel in Beam's
    // command-hook path. Fail closed rather than silently allowing an ASK decision.
    emitDeny(agent, `${reason} Interactive approval is unavailable for this agent hook.`, event);
  } else if (agent === "gemini") {
    emitDeny(agent, `${reason} Interactive approval is unavailable for Gemini pre_tool_execution.`, event);
  } else {
    emitDeny(agent, reason, event);
  }
}

function emitRedacted(agent: string, data: Record<string, unknown>, reason?: string, event = "PreToolUse"): void {
  const input = data.tool_input;
  if (agent === "claude-code" || agent === "codex") process.stdout.write(JSON.stringify(withNotice(agent, { hookSpecificOutput: { hookEventName: claudeStyleHookEventName(event), permissionDecision: "allow", permissionDecisionReason: `Beam: ${reason ?? "Sensitive data redacted."}`, updatedInput: input } })));
  else if (agent === "cursor") process.stdout.write(JSON.stringify({ permission: "allow", updated_input: input }));
  else if (agent === "copilot-cli") process.stdout.write(JSON.stringify({ permissionDecision: "allow", updatedInput: input }));
  else emitDeny(agent, "Beam cannot safely return transformed input through this hook contract.", event);
}

function emitAllow(agent: string, reason?: string, event = "PreToolUse"): void {
  if (agent === "cline") { process.stdout.write(JSON.stringify({ cancel: false })); return; }
  if (agent === "antigravity") { process.stdout.write(JSON.stringify({ decision: "ask" })); return; }

  if (agent === "claude-code" || agent === "codex") process.stdout.write(JSON.stringify(withNotice(agent, { hookSpecificOutput: { hookEventName: claudeStyleHookEventName(event), permissionDecision: "allow", permissionDecisionReason: reason } })));
  else if (agent === "cursor" && event === "beforeSubmitPrompt") process.stdout.write(JSON.stringify({ continue: true }));
  else if (agent === "cursor") process.stdout.write(JSON.stringify({ permission: "allow" }));
  else if (agent === "copilot-cli") process.stdout.write(JSON.stringify({ permissionDecision: "allow", permissionDecisionReason: reason }));
  else if (agent === "gemini") process.stdout.write(JSON.stringify({ decision: "allow" }));
}

// Agents whose hook runner treats a non-zero exit code as an unconditional block, documented as
// stronger/more reliable than the JSON-only decision for at least one event type on each (e.g.
// Claude Code's own docs list exit code 2 as blocking UserPromptSubmit "regardless of JSON
// content", separately from the exit-0 hookSpecificOutput.permissionDecision path). Setting this
// alongside the JSON is belt-and-suspenders, not a replacement -- the JSON still carries the
// clean reason text; exit 2 just guarantees the block itself isn't silently skipped.
const EXIT_2_FAILS_CLOSED = new Set(["claude-code", "codex", "cursor", "copilot-cli", "gemini", "opencode", "openclaw", "hermes", "windsurf", "kimi", "qwen", "auggie", "kiro", "goose", "openhands", "crush", "junie"]);

// Claude Code / Codex hook contract: a JSON decision on stdout denies the tool call or prompt.
// Other agents get a stderr note only (their block contracts differ and aren't verified), except
// where noted below.
function emitDeny(agent: string, reason: string, event = "PreToolUse"): void {
  if (["claude-code", "codex", "muse", "vscode", "factory"].includes(agent)) {
    process.stdout.write(JSON.stringify(withNotice(agent, {
      hookSpecificOutput: {
        hookEventName: claudeStyleHookEventName(event),
        permissionDecision: "deny",
        permissionDecisionReason: `Beam: ${reason}`,
      },
    })));
  } else if (agent === "cursor" && event === "beforeSubmitPrompt") {
    // beforeSubmitPrompt's block contract is {continue: false, user_message} -- unlike
    // preToolUse/beforeShellExecution's {permission: "deny", ...} (verified against
    // cursor.com/docs/agent/hooks).
    process.stdout.write(JSON.stringify({ continue: false, user_message: `Beam: ${reason}` }));
  } else if (agent === "cursor") {
    process.stdout.write(JSON.stringify({ permission: "deny", user_message: `Beam: ${reason}`, agent_message: `Beam: ${reason}` }));
  } else if (agent === "copilot-cli") {
    // GitHub's docs state userPromptSubmitted's stdout is ignored entirely (no blocking
    // contract) -- this JSON only has an effect for preToolUse, where it's already verified.
    process.stdout.write(JSON.stringify({ permissionDecision: "deny", permissionDecisionReason: `Beam: ${reason}` }));
  } else if (agent === "gemini") {
    process.stdout.write(JSON.stringify({ decision: "deny", reason: `Beam: ${reason}` }));
  } else if (agent === "opencode" || agent === "openclaw") {
    process.stdout.write(JSON.stringify({ decision: "deny", reason: `Beam: ${reason}` }));
  } else if (agent === "hermes") {
    process.stdout.write(JSON.stringify({ action: "block", message: `Beam: ${reason}`, decision: "block", reason: `Beam: ${reason}` }));
  } else if (["pi", "kilo"].includes(agent)) {
    process.stdout.write(JSON.stringify({ block: true, reason: `Beam: ${reason}` }));
  } else if (agent === "cline") {
    process.stdout.write(JSON.stringify({ cancel: true, errorMessage: `Beam: ${reason}` }));
  } else if (agent === "amp") {
    process.stdout.write(JSON.stringify({ action: "reject-and-continue", message: `Beam: ${reason}` }));
  } else if (["antigravity", "grok"].includes(agent)) {
    process.stdout.write(JSON.stringify({ decision: "deny", reason: `Beam: ${reason}` }));
  } else if (agent === "devin") {
    process.stdout.write(JSON.stringify({ decision: "block", reason: `Beam: ${reason}` }));
  } else if (["windsurf", "kimi", "qwen", "auggie", "kiro", "goose", "openhands", "crush", "junie"].includes(agent)) {
    // These hosts use exit code 2, set below.
  } else {
    // OpenCode has no installed hook/plugin path in this repository. A message cannot block it.
    process.stderr.write(`\n✖ Beam cannot block this agent (${agent}): no verified enforcement adapter is installed.\n`);
  }
  if (EXIT_2_FAILS_CLOSED.has(agent)) {
    process.stderr.write(`Beam: ${reason}\n`);
    process.exitCode = 2;
  }
}
