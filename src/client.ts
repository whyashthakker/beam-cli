import { readdir, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { getBeamHome, getCollectorUrl, getDataDirectory } from "./config.js";
import { normalize, scanText, type Event, type Scan } from "./core.js";
import { adaptHookPayload } from "./hook-adapters.js";
import { forwardEvents } from "./forward.js";
import { evaluate, readPolicy } from "./policy.js";
import { extractAgent } from "./extract.js";
import { loadCustomRules } from "./custom-rules.js";
import { redactSensitive } from "./data-detectors.js";
import { applyJevHook } from "./jev.js";

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

async function findClaudeCodeUsage(home: string, sessionId: string): Promise<{ input_tokens?: number; output_tokens?: number }> {
  if (!sessionId) return {};
  const projectsDir = join(home, ".claude", "projects");
  let dirs: string[]; try { dirs = await readdir(projectsDir); } catch { return {}; }
  for (const dir of dirs) {
    let content: string; try { content = await readFile(join(projectsDir, dir, `${sessionId}.jsonl`), "utf8"); } catch { continue; }
    const lines = content.split("\n");
    for (let i = lines.length - 1; i >= 0 && i >= lines.length - MODEL_LOOKUP_TAIL_LINES; i--) {
      try {
        const row = JSON.parse(lines[i]) as Record<string, unknown>;
        const message = row.message && typeof row.message === "object" ? row.message as Record<string, unknown> : {};
        const usage = message.usage && typeof message.usage === "object" ? message.usage as Record<string, unknown> : {};
        if (row.type === "assistant" && (typeof usage.input_tokens === "number" || typeof usage.output_tokens === "number")) {
          return { input_tokens: typeof usage.input_tokens === "number" ? usage.input_tokens : undefined, output_tokens: typeof usage.output_tokens === "number" ? usage.output_tokens : undefined };
        }
      } catch { /* skip malformed transcript rows */ }
    }
    return {};
  }
  return {};
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

async function findCodexUsage(home: string, sessionId: string): Promise<{ input_tokens?: number; output_tokens?: number }> {
  if (!sessionId) return {};
  const files: { path: string; mtimeMs: number }[] = [];
  for (const root of [join(home, ".codex", "sessions"), join(home, ".codex", "archived_sessions")]) {
    const found: string[] = []; await walkJsonlFiles(root, found);
    for (const path of found) { try { files.push({ path, mtimeMs: (await stat(path)).mtimeMs }); } catch { /* skip */ } }
  }
  files.sort((a, b) => b.mtimeMs - a.mtimeMs);
  for (const { path } of files.slice(0, CODEX_MODEL_LOOKUP_MAX_FILES)) {
    let content: string; try { content = await readFile(path, "utf8"); } catch { continue; }
    let matchesSession = false; let usage: Record<string, unknown> | undefined;
    for (const line of content.split("\n")) {
      let row: Record<string, unknown>; try { row = JSON.parse(line) as Record<string, unknown>; } catch { continue; }
      const payload = row.payload && typeof row.payload === "object" ? row.payload as Record<string, unknown> : {};
      if (row.type === "session_meta" && (payload.session_id === sessionId || payload.id === sessionId)) matchesSession = true;
      const info = payload.info && typeof payload.info === "object" ? payload.info as Record<string, unknown> : {};
      const total = info.last_token_usage && typeof info.last_token_usage === "object" ? info.last_token_usage as Record<string, unknown> : undefined;
      if (row.type === "event_msg" && payload.type === "token_count" && total) usage = total;
    }
    if (matchesSession && usage) return { input_tokens: typeof usage.input_tokens === "number" ? usage.input_tokens : undefined, output_tokens: typeof usage.output_tokens === "number" ? usage.output_tokens : undefined };
  }
  return {};
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
        const sessionId = String(data.session_id ?? data.sessionId ?? "");
        if (sourceAgent === "claude-code") {
          data.model = await findClaudeCodeModel(home, sessionId);
          const usage = await findClaudeCodeUsage(home, sessionId);
          if (usage.input_tokens !== undefined) data.input_tokens = usage.input_tokens;
          if (usage.output_tokens !== undefined) data.output_tokens = usage.output_tokens;
        } else if (sourceAgent === "codex") {
          data.model = await findCodexModel(home, sessionId);
          const usage = await findCodexUsage(home, sessionId);
          if (usage.input_tokens !== undefined) data.input_tokens = usage.input_tokens;
          if (usage.output_tokens !== undefined) data.output_tokens = usage.output_tokens;
        }
      } catch { /* best-effort enrichment only -- never block the hook on this */ }
    }

    // 1. Enforcement first — a local file read, so it works even if the collector is down.
    //    Only acts when a manager has set the policy to advisory/enforce; observe mode
    //    (the default) is a no-op and Beam stays observation-only.
    const toolInput = data.tool_input && typeof data.tool_input === "object"
      ? (data.tool_input as Record<string, unknown>) : {};
    const command = String(data.command ?? toolInput.command ?? "");
    let decision = evaluate(await readPolicy().catch(() => null), {
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
    if (decision.action === "allow" && isEnvironmentAccess(String(data.tool_name ?? ""), command, String(toolInput.file_path ?? toolInput.path ?? data.file_path ?? ""), toolInput)) {
      decision = {
        ...decision,
        action: "ask",
        reason: "Reading environment variables or .env files requires approval.",
      };
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
    if (decision.action === "allow" && workspace && isOutsideWorkspace(workspace, targetPath, command)) {
      decision = {
        ...decision,
        action: "ask",
        reason: "This action accesses a path outside the current workspace.",
      };
    }

    const jev = await applyJevHook(decision, data);
    decision = jev.decision;
    if (jev.judgment) process.stderr.write(`Beam Jev: ${JSON.stringify(jev.judgment)}\n`);

    // Detection and policy enforcement above already ran against the real prompt text and
    // session id -- neither is forwarded to the local collector or the workspace dashboard from
    // this point on. event_type/tool_name still identify a prompt-submit event; the content and
    // the session identifier do not leave this machine. Scoped to prompt.submit only -- deleting
    // session_id on every event type broke session grouping (and the tool_use_id dedup in
    // core.ts, which is keyed per-hostname/phase but not per-session) for all other hook events.
    if (data.event_type === "prompt.submit") {
      delete data.prompt;
      delete data.command;
      delete data.session_id;
      delete data.sessionId;
      delete data.session;
    }

    data.policy_decision = { action: decision.action, rule: decision.rule, reason: decision.reason, risk_score: decision.riskScore, risk_level: decision.riskLevel, risk_factors: decision.riskFactors };
    const hookEvent = String(data.hook_event_name ?? "PreToolUse");
    let event = safeNormalize(data);
    if (decision.action === "deny") {
      if (event) event = { ...event, findings: [...event.findings, blockedFinding(decision.reason)] };
      emitDeny(sourceAgent, decision.reason ?? "Blocked by workspace policy.", hookEvent);
    } else if (decision.action === "ask") {
      emitAsk(sourceAgent, decision.reason ?? "This action requires approval.", hookEvent);
    } else if (decision.action === "redact") {
      const transformed = redactPayload(data, decision);
      if (!transformed.changed) {
        emitAllow(sourceAgent, decision.reason, hookEvent);
      } else {
        emitRedacted(sourceAgent, transformed.data, decision.reason, hookEvent);
        data = transformed.data;
      }
    } else if (decision.action === "warn") {
      process.stderr.write(`\n⚠ Beam policy (advisory): ${decision.reason}\n`);
    }

    // 2. Local capture (best-effort — a failure here must not skip enforcement or throw). The
    //    running collector (serve.ts) also batches this event into its own workspace forward --
    //    see ForwardQueue in forward.ts -- so most events reach the dashboard in groups rather
    //    than one request per action. Allowed prompt.submit events are skipped here: policy
    //    enforcement above already ran against them, but every keystroke-triggered prompt
    //    otherwise floods the Activity/Overview views with noise nobody reviews. A blocked
    //    prompt is still surfaced -- see step 3 below.
    if (data.event_type !== "prompt.submit" || decision.action === "deny") {
      try { await send("/ingest", JSON.stringify(data)); }
      catch (e) { console.error(e instanceof Error ? e.message : String(e)); }
    }

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
    if (policy && (policy.rules.mode === "enforce" || policy.errors?.length)) {
      // emitDeny already sets exit code 2 for the agents where that's the documented fail-closed
      // signal (see EXIT_2_FAILS_CLOSED above).
      emitDeny(sourceAgent, "Beam security policy could not complete safely; execution is denied.");
    }
  }
}

function safeNormalize(data: Record<string, unknown>): Event | null {
  try { return normalize(data); } catch { return null; }
}

function isEnvironmentAccess(tool: string, command: string, path: string, input: Record<string, unknown>): boolean {
  const text = `${tool} ${command} ${path} ${Object.values(input).filter(value => typeof value === "string").join(" ")}`;
  // File reads: .env, .env.local, .env.prod, etc. Also catch common env/config
  // locations that contain exported credentials.
  if (/(^|[\\/\s"'])\.env(?:\.[\w.-]+)?(?:$|[\\/\s"'])/i.test(text)) return true;
  if (/(^|[\\/\s"'])\.aws[\\/]credentials(?:$|[\\/\s"'])|(^|[\\/\s"'])\.config[\\/]gcloud(?:$|[\\/\s"'])/i.test(text)) return true;
  // Shell/process environment reads: env, printenv, set, export -p, $FOO,
  // process.env, os.environ and equivalent tool arguments.
  return /\b(?:printenv|env|export\s+-p|process\.env|os\.environ|System\.getenv)\b/i.test(text)
    || /\$\{?(?:[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|PRIVATE|API)[A-Z0-9_]*)\}?/.test(text);
}

function isOutsideWorkspace(cwd: string, target: string, command: string): boolean {
  if (!cwd) return false;
  const text = `${target} ${command}`;
  const candidates = [
    ...(isAbsolute(target) ? [target] : []),
    ...[...text.matchAll(/(?:^|\s)(\/[^\s"';&|]+)/g)].map(match => match[1]),
  ];
  const root = resolve(cwd);
  return candidates.some(candidate => {
    const path = resolve(root, candidate);
    const escaped = relative(root, path);
    return escaped === ".." || escaped.startsWith(`..${sep}`) || isAbsolute(escaped);
  });
}

function isBeamSelfProtectionTarget(tool: string, command: string, target: string): boolean {
  const beamHome = resolve(getBeamHome());
  const beamData = resolve(getDataDirectory());
  const text = `${tool} ${command} ${target}`;
  const targetPath = target ? resolve(target) : "";
  const touchesBeamFiles = Boolean(targetPath && (targetPath === beamHome || targetPath.startsWith(`${beamHome}${sep}`) || targetPath === beamData || targetPath.startsWith(`${beamData}${sep}`))) || /(?:^|[\s"'\/])\.beam(?:[\/\s"']|$)|beam[\\/]data[\\/]policy\.json/i.test(text);
  const stopsBeam = /\b(?:beam\s+(?:service\s+(?:stop|uninstall)|jev\s+(?:configure|disable)|uninstall)|(?:launchctl|systemctl|pkill|killall)\b[^\n]*\bbeam\b|npm\s+(?:uninstall|remove)\b[^\n]*@?agent-beam|rm\b[^\n]*(?:\.beam|beam-cli|@agent-beam))/i.test(text);
  return touchesBeamFiles || stopsBeam;
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

// Claude Code and Codex use the same hookSpecificOutput.permissionDecision contract for every
// hook event -- only the echoed hookEventName differs per event (verified against
// code.claude.com/docs/en/hooks for both PreToolUse and UserPromptSubmit).
function claudeStyleHookEventName(event: string): string {
  return event === "UserPromptSubmit" ? "UserPromptSubmit" : "PreToolUse";
}

function emitAsk(agent: string, reason: string, event = "PreToolUse"): void {
  if (agent === "claude-code" || agent === "codex") {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: claudeStyleHookEventName(event), permissionDecision: "ask", permissionDecisionReason: `Beam: ${reason}` } }));
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
  if (agent === "claude-code" || agent === "codex") process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: claudeStyleHookEventName(event), permissionDecision: "allow", permissionDecisionReason: `Beam: ${reason ?? "Sensitive data redacted."}`, updatedInput: input } }));
  else if (agent === "cursor") process.stdout.write(JSON.stringify({ permission: "allow", updated_input: input }));
  else if (agent === "copilot-cli") process.stdout.write(JSON.stringify({ permissionDecision: "allow", updatedInput: input }));
  else emitDeny(agent, "Beam cannot safely return transformed input through this hook contract.", event);
}

function emitAllow(agent: string, reason?: string, event = "PreToolUse"): void {
  if (agent === "claude-code" || agent === "codex") process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: claudeStyleHookEventName(event), permissionDecision: "allow", permissionDecisionReason: reason } }));
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
const EXIT_2_FAILS_CLOSED = new Set(["claude-code", "codex", "cursor", "copilot-cli", "gemini", "opencode"]);

// Claude Code / Codex hook contract: a JSON decision on stdout denies the tool call or prompt.
// Other agents get a stderr note only (their block contracts differ and aren't verified), except
// where noted below.
function emitDeny(agent: string, reason: string, event = "PreToolUse"): void {
  if (agent === "claude-code" || agent === "codex") {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: claudeStyleHookEventName(event),
        permissionDecision: "deny",
        permissionDecisionReason: `Beam: ${reason}`,
      },
    }));
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
  } else if (agent === "opencode") {
    process.stdout.write(JSON.stringify({ decision: "deny", reason: `Beam: ${reason}` }));
  } else {
    // OpenCode has no installed hook/plugin path in this repository. A message cannot block it.
    process.stderr.write(`\n✖ Beam cannot block this agent (${agent}): no verified enforcement adapter is installed.\n`);
  }
  if (EXIT_2_FAILS_CLOSED.has(agent)) {
    process.stderr.write(`Beam: ${reason}\n`);
    process.exitCode = 2;
  }
}
