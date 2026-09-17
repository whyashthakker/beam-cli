import { readdir, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { getBeamHome, getCollectorUrl, getDataDirectory } from "./config.js";
import { normalize, scanText, type Event, type Scan } from "./core.js";
import { adaptHookPayload } from "./hook-adapters.js";
import { forwardEvents } from "./forward.js";
import { evaluate, readPolicy } from "./policy.js";
import { extractAgent } from "./extract.js";
import { loadCustomRules } from "./custom-rules.js";
import { redactSensitive } from "./data-detectors.js";

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

async function walkJsonlFiles(dir: string, out: string[]): Promise<void> {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await walkJsonlFiles(full, out);
    else if (entry.isFile() && entry.name.endsWith(".jsonl")) out.push(full);
  }
}

// Codex's PreToolUse payload has no model field (same verified shape as Claude Code's), and
// unlike Claude Code's session file, a rollout file isn't named after the session id -- it's
// keyed by a "session_meta" record inside it. Best-effort only: the "turn_context" record's
// model field isn't part of Codex's schema this codebase has verified (extract.ts only reads
// session_meta/response_item) -- if that assumption is wrong this silently yields "" rather than
// forwarding a bogus value.
const CODEX_MODEL_LOOKUP_MAX_FILES = 10;

async function findCodexModel(home: string, sessionId: string): Promise<string> {
  if (!sessionId) return "";
  const files: { path: string; mtimeMs: number }[] = [];
  for (const root of [join(home, ".codex", "sessions"), join(home, ".codex", "archived_sessions")]) {
    const found: string[] = [];
    await walkJsonlFiles(root, found);
    for (const path of found) { try { files.push({ path, mtimeMs: (await stat(path)).mtimeMs }); } catch { /* skip */ } }
  }
  files.sort((a, b) => b.mtimeMs - a.mtimeMs);
  for (const { path } of files.slice(0, CODEX_MODEL_LOOKUP_MAX_FILES)) {
    let content: string;
    try { content = await readFile(path, "utf8"); } catch { continue; }
    let matchesSession = false; let model = "";
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let row: Record<string, unknown>;
      try { row = JSON.parse(trimmed) as Record<string, unknown>; } catch { continue; }
      const payload = row.payload && typeof row.payload === "object" ? row.payload as Record<string, unknown> : {};
      if (row.type === "session_meta" && (payload.session_id === sessionId || payload.id === sessionId)) matchesSession = true;
      if (row.type === "turn_context" && typeof payload.model === "string" && payload.model) model = payload.model;
    }
    if (matchesSession && model) return model;
  }
  return "";
}

async function readStdin(limitBytes: number): Promise<string> {
  let input = "";
  for await (const chunk of process.stdin) {
    input += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (input.length > limitBytes) throw new Error(`Hook exceeds ${Math.floor(limitBytes / 1000)} KB.`);
  }
  return input;
}

// Never throws: a Claude Code hook must not block or fail the agent if capture fails.
export async function captureHook(sourceAgent = "claude-code", home = homedir()): Promise<void> {
  try {
    const input = await readStdin(100_000);
    const raw = JSON.parse(input) as Record<string, unknown>;
    let data = adaptHookPayload(sourceAgent, raw);
    data.source_agent = sourceAgent;
    data.source_type = "hook";
    if (data.hook_event_name === "UserPromptSubmit" && typeof data.prompt === "string") {
      data.event_type = data.event_type ?? "prompt.submit";
      data.tool_name = data.tool_name ?? "UserPromptSubmit";
      data.command = data.command ?? data.prompt;
    }
    if (!data.model) {
      try {
        const sessionId = String(data.session_id ?? "");
        if (sourceAgent === "claude-code") data.model = await findClaudeCodeModel(home, sessionId);
        else if (sourceAgent === "codex") data.model = await findCodexModel(home, sessionId);
      } catch { /* best-effort enrichment only -- never block the hook on this */ }
    }

    // 1. Enforcement first — a local file read, so it works even if the collector is down.
    //    Only acts when a manager has set the policy to advisory/enforce; observe mode
    //    (the default) is a no-op and Beam stays observation-only.
    const toolInput = data.tool_input && typeof data.tool_input === "object"
      ? (data.tool_input as Record<string, unknown>) : {};
    const command = String(data.command ?? toolInput.command ?? "");
    const decision = evaluate(await readPolicy().catch(() => null), {
      agent: sourceAgent,
      tool: String(data.tool_name ?? ""),
      command,
      args: Array.isArray(toolInput.args) ? toolInput.args.map(String) : command.split(/\s+/).slice(1),
      path: String(toolInput.file_path ?? toolInput.path ?? data.file_path ?? ""),
      url: String(toolInput.url ?? data.url ?? ""),
      role: typeof data.role === "string" ? data.role : undefined,
      user: typeof data.user === "string" ? data.user : undefined,
      cwd: typeof data.cwd === "string" ? data.cwd : undefined,
      repository: typeof data.repository === "string" ? data.repository : undefined,
      branch: typeof data.branch === "string" ? data.branch : undefined,
      environment: typeof data.environment === "string" ? data.environment : undefined,
      time: typeof data.timestamp === "string" ? data.timestamp : undefined,
    });

    data.policy_decision = { action: decision.action, rule: decision.rule, reason: decision.reason, risk_score: decision.riskScore, risk_level: decision.riskLevel, risk_factors: decision.riskFactors };
    let event = safeNormalize(data);
    if (decision.action === "deny") {
      if (event) event = { ...event, findings: [...event.findings, blockedFinding(decision.reason)] };
      emitDeny(sourceAgent, decision.reason ?? "Blocked by workspace policy.");
    } else if (decision.action === "ask") {
      emitAsk(sourceAgent, decision.reason ?? "This action requires approval.");
    } else if (decision.action === "redact") {
      const transformed = redactPayload(data, decision);
      if (!transformed.changed) {
        emitAllow(sourceAgent, decision.reason);
      } else {
        emitRedacted(sourceAgent, transformed.data, decision.reason);
        data = transformed.data;
      }
    } else if (decision.action === "warn") {
      process.stderr.write(`\n⚠ Beam policy (advisory): ${decision.reason}\n`);
    }

    // 2. Local capture (best-effort — a failure here must not skip enforcement or throw). The
    //    running collector (serve.ts) also batches this event into its own workspace forward --
    //    see ForwardQueue in forward.ts -- so most events reach the dashboard in groups rather
    //    than one request per action.
    try { await send("/ingest", JSON.stringify(data)); }
    catch (e) { console.error(e instanceof Error ? e.message : String(e)); }

    // 3. A policy-blocked action carries a finding the collector's own normalize() can't
    //    reconstruct (it only knows about *this* process's policy decision) -- forward it to the
    //    workspace immediately rather than folding it into the batch, so a manager sees a block
    //    without waiting on unrelated traffic to fill the batch.
    if (event && decision.action === "deny") { try { await forwardEvents(event); } catch { /* offline */ } }
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    // If a security policy exists, a hook-side failure must not become an implicit allow. The
    // vendor-specific response is still emitted where possible; exit 2 is the documented
    // fail-closed signal for Claude/Cursor/Copilot and is also treated as failure by OpenCode's
    // native plugin wrapper. Gemini's runtime is documented fail-open for hook failures, so its
    // strongest available boundary is the denial JSON itself.
    const policy = await readPolicy().catch(() => null);
    if (policy && (policy.rules.mode === "enforce" || policy.errors?.length)) {
      emitDeny(sourceAgent, "Beam security policy could not complete safely; execution is denied.");
      if (["claude-code", "codex", "cursor", "copilot-cli", "opencode"].includes(sourceAgent)) process.exitCode = 2;
    }
  }
}

function safeNormalize(data: Record<string, unknown>): Event | null {
  try { return normalize(data); } catch { return null; }
}

function blockedFinding(reason = "Blocked by workspace policy."): Event["findings"][number] {
  return { id: "policy.blocked", title: "Blocked by workspace policy", severity: "high", explanation: reason, evidence: "" };
}

function redactPayload(data: Record<string, unknown>, decision: { customDetectors?: Array<{ name: string; pattern: string; replacement: string }> }): { data: Record<string, unknown>; changed: boolean } {
  const copy = structuredClone(data); let changed = false;
  const redactValue = (value: unknown): unknown => {
    if (typeof value === "string") { const result = redactSensitive(value, decision.customDetectors); changed ||= result.text !== value; return result.text; }
    if (Array.isArray(value)) return value.map(redactValue);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValue(v)]));
    return value;
  };
  return { data: redactValue(copy) as Record<string, unknown>, changed };
}

function emitAsk(agent: string, reason: string): void {
  if (agent === "claude-code" || agent === "codex") {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: `Beam: ${reason}` } }));
  } else if (agent === "cursor" || agent === "copilot-cli") {
    // These hook contracts do not provide a reliable interactive approval channel in Beam's
    // command-hook path. Fail closed rather than silently allowing an ASK decision.
    emitDeny(agent, `${reason} Interactive approval is unavailable for this agent hook.`);
  } else if (agent === "gemini") {
    emitDeny(agent, `${reason} Interactive approval is unavailable for Gemini pre_tool_execution.`);
  } else {
    emitDeny(agent, reason);
  }
}

function emitRedacted(agent: string, data: Record<string, unknown>, reason?: string): void {
  const input = data.tool_input;
  if (agent === "claude-code" || agent === "codex") process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: `Beam: ${reason ?? "Sensitive data redacted."}`, updatedInput: input } }));
  else if (agent === "cursor") process.stdout.write(JSON.stringify({ permission: "allow", updated_input: input }));
  else if (agent === "copilot-cli") process.stdout.write(JSON.stringify({ permissionDecision: "allow", updatedInput: input }));
  else emitDeny(agent, "Beam cannot safely return transformed input through this hook contract.");
}

function emitAllow(agent: string, reason?: string): void {
  if (agent === "claude-code" || agent === "codex") process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: reason } }));
  else if (agent === "cursor") process.stdout.write(JSON.stringify({ permission: "allow" }));
  else if (agent === "copilot-cli") process.stdout.write(JSON.stringify({ permissionDecision: "allow", permissionDecisionReason: reason }));
  else if (agent === "gemini") process.stdout.write(JSON.stringify({ decision: "allow" }));
}

// Claude Code / Codex PreToolUse contract: a JSON decision on stdout denies the tool call.
// Other agents get a stderr note only (their block contracts differ and aren't verified).
function emitDeny(agent: string, reason: string): void {
  if (agent === "claude-code" || agent === "codex") {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `Beam: ${reason}`,
      },
    }));
  } else if (agent === "cursor") {
    process.stdout.write(JSON.stringify({ permission: "deny", user_message: `Beam: ${reason}`, agent_message: `Beam: ${reason}` }));
  } else if (agent === "copilot-cli") {
    process.stdout.write(JSON.stringify({ permissionDecision: "deny", permissionDecisionReason: `Beam: ${reason}` }));
  } else if (agent === "gemini") {
    process.stdout.write(JSON.stringify({ decision: "deny", reason: `Beam: ${reason}` }));
  } else if (agent === "opencode") {
    process.stdout.write(JSON.stringify({ decision: "deny", reason: `Beam: ${reason}` }));
  } else {
    // OpenCode has no installed hook/plugin path in this repository. A message cannot block it.
    process.stderr.write(`\n✖ Beam cannot block this agent (${agent}): no verified enforcement adapter is installed.\n`);
  }
}
