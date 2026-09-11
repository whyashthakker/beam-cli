import { readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { getBeamHome, getCollectorUrl, getDataDirectory } from "./config.js";
import { normalize, scanText, type Event, type Scan } from "./core.js";
import { adaptHookPayload } from "./hook-adapters.js";
import { forwardEvents } from "./forward.js";
import { evaluate, readPolicy } from "./policy.js";
import { extractAgent } from "./extract.js";
import { loadCustomRules } from "./custom-rules.js";

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

async function readStdin(limitBytes: number): Promise<string> {
  let input = "";
  for await (const chunk of process.stdin) {
    input += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (input.length > limitBytes) throw new Error(`Hook exceeds ${Math.floor(limitBytes / 1000)} KB.`);
  }
  return input;
}

// Never throws: a Claude Code hook must not block or fail the agent if capture fails.
export async function captureHook(sourceAgent = "claude-code"): Promise<void> {
  try {
    const input = await readStdin(100_000);
    const raw = JSON.parse(input) as Record<string, unknown>;
    const data = adaptHookPayload(sourceAgent, raw);
    data.source_agent = sourceAgent;
    data.source_type = "hook";
    if (data.hook_event_name === "UserPromptSubmit" && typeof data.prompt === "string") {
      data.event_type = data.event_type ?? "prompt.submit";
      data.tool_name = data.tool_name ?? "UserPromptSubmit";
      data.command = data.command ?? data.prompt;
    }

    // 1. Enforcement first — a local file read, so it works even if the collector is down.
    //    Only acts when a manager has set the policy to advisory/enforce; observe mode
    //    (the default) is a no-op and Beam stays observation-only.
    const toolInput = data.tool_input && typeof data.tool_input === "object"
      ? (data.tool_input as Record<string, unknown>) : {};
    const decision = evaluate(await readPolicy().catch(() => null), {
      agent: sourceAgent,
      tool: String(data.tool_name ?? ""),
      command: String(data.command ?? toolInput.command ?? ""),
    });

    let event = safeNormalize(data);
    if (decision.action === "deny") {
      if (event) event = { ...event, findings: [...event.findings, blockedFinding(decision.reason)] };
      emitDeny(sourceAgent, decision.reason ?? "Blocked by workspace policy.");
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
  }
}

function safeNormalize(data: Record<string, unknown>): Event | null {
  try { return normalize(data); } catch { return null; }
}

function blockedFinding(reason = "Blocked by workspace policy."): Event["findings"][number] {
  return { id: "policy.blocked", title: "Blocked by workspace policy", severity: "high", explanation: reason, evidence: "" };
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
  } else {
    process.stderr.write(`\n✖ Beam policy would block this (${agent} enforcement not wired): ${reason}\n`);
  }
}
