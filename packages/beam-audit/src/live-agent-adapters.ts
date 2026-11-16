// Generalizes the live (real API call) tests beyond Claude Code. Each adapter knows how to find its
// binary and run one headless, non-interactive prompt, returning the final text response (or a
// failure reason, never a guess) -- same honest degrade-to-"not verified" pattern as the rest of
// this package. Only agents with a CLI *actually installed on this machine* and a *verified* (not
// guessed) headless invocation get an adapter here. Flags below were confirmed against each
// binary's own --help output, not recalled from memory -- Codex's exact flags in particular change
// between releases.
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import type { AuditContext } from "./types.js";

export interface RunPromptOptions { addDir?: string; sandbox?: "read-only" | "workspace-write"; disallowedTools?: string }
/** `text: null` means the prompt produced no usable/conclusive answer; `reason` is the best
 * available diagnostic for why (a parsed API error, a non-success subtype, a timeout), shown
 * verbatim in the report instead of a blanket "not conclusive" -- so a local account/model
 * misconfiguration reads as exactly that, not as a scanner defect. `permissionDenials` lists the
 * tool names (e.g. "Write", "Bash") the agent's own permission system blocked before they ran,
 * when the agent's output exposes that -- the one way a review-requirement test can conclusively
 * tell "paused for approval" apart from "failed for an unrelated reason" in a headless run that
 * has nobody to answer the approval prompt. */
export interface PromptRunResult { text: string | null; permissionDenials: string[]; reason?: string }
export interface LiveAgentAdapter {
  agent: string;
  findBinary(ctx: AuditContext): string | null;
  /** Runs one headless prompt. Never throws. */
  runPrompt(bin: string, cwd: string, prompt: string, opts?: RunPromptOptions): PromptRunResult;
}

function which(ctx: AuditContext, name: string): string | null {
  const res = spawnSync(ctx.platform === "win32" ? "where" : "which", [name], { encoding: "utf8", timeout: 5_000 });
  if (res.status !== 0 || typeof res.stdout !== "string") return null;
  return res.stdout.trim().split("\n")[0] || null;
}

export const claudeAdapter: LiveAgentAdapter = {
  agent: "Claude Code",
  findBinary: ctx => which(ctx, "claude"),
  runPrompt(bin, cwd, prompt, opts) {
    const res = spawnSync(bin, [
      "-p", prompt,
      "--model", "haiku",
      "--output-format", "json",
      ...(opts?.addDir ? ["--add-dir", opts.addDir] : []),
      "--disallowedTools", opts?.disallowedTools ?? "Read Write Edit WebFetch WebSearch Task Glob Grep",
      "--no-session-persistence",
      "--max-budget-usd", "0.08",
    ], { cwd, encoding: "utf8", timeout: 60_000, maxBuffer: 8 * 1024 * 1024 });
    if (res.error) return { text: null, permissionDenials: [], reason: res.error.message };
    if (typeof res.stdout !== "string" || !res.stdout.trim()) return { text: null, permissionDenials: [], reason: res.stderr?.toString().trim().slice(-400) || "No output." };
    try {
      const parsed = JSON.parse(res.stdout) as { result?: string; subtype?: string; is_error?: boolean; permission_denials?: { tool_name?: string }[] };
      const permissionDenials = (parsed.permission_denials ?? []).map(d => d.tool_name).filter((t): t is string => Boolean(t));
      if (parsed.subtype && parsed.subtype !== "success") return { text: null, permissionDenials, reason: `Claude Code reported subtype "${parsed.subtype}"${parsed.result ? `: ${parsed.result}`.slice(0, 300) : ""}.` };
      return { text: parsed.result ?? null, permissionDenials };
    } catch { return { text: null, permissionDenials: [], reason: "Could not parse Claude Code's JSON output." }; }
  },
};

// `codex exec` has no stable JSON "final answer" field worth parsing (--json emits a JSONL event
// stream); -o/--output-last-message writes just the agent's last message to a plain text file,
// which is the simplest reliable way to get the same "what did it say/do" signal the Claude adapter
// gets from `.result`. No --model override: this account's configured default may be rejected by
// the account tier (observed on this machine), and forcing a guessed model name would be worse than
// respecting whatever the user's own `codex` already uses successfully -- when that happens, the
// API's own error (surfaced below as `reason`) says so plainly instead of a blanket "not tested".
export const codexAdapter: LiveAgentAdapter = {
  agent: "Codex",
  findBinary: ctx => which(ctx, "codex"),
  runPrompt(bin, cwd, prompt, opts) {
    const outFile = join(mkdtempSync(join(tmpdir(), "beam-audit-codex-out-")), `${randomUUID().slice(0, 8)}.txt`);
    try {
      const res = spawnSync(bin, [
        "exec", prompt,
        "--sandbox", opts?.sandbox ?? "read-only",
        "-C", cwd,
        ...(opts?.addDir ? ["--add-dir", opts.addDir] : []),
        "--skip-git-repo-check",
        "--ephemeral",
        "-o", outFile,
      ], { encoding: "utf8", timeout: 60_000, maxBuffer: 8 * 1024 * 1024 });
      const errorLine = res.stderr?.toString().split("\n").reverse().find(l => l.trim().startsWith("ERROR:"));
      if (res.error) return { text: null, permissionDenials: [], reason: res.error.message };
      if (!existsSync(outFile)) return { text: null, permissionDenials: [], reason: errorLine?.trim().slice(0, 400) || "Codex produced no output file." };
      const text = readFileSync(outFile, "utf8").trim();
      if (text) return { text, permissionDenials: [] };
      return { text: null, permissionDenials: [], reason: errorLine?.trim().slice(0, 400) || "Codex's output file was empty." };
    } catch (err) { return { text: null, permissionDenials: [], reason: err instanceof Error ? err.message : String(err) }; }
    finally { try { rmSync(outFile, { force: true }); } catch { /* best effort */ } }
  },
};

/** Every adapter this package can run live tests against, plus the known registry agents it
 * deliberately does NOT attempt -- no verified non-interactive mode, so a guessed flag set would be
 * worse than an honest "not supported" row. Each entry's `isInstalled` is a conservative, verified
 * presence check (never a bare `which`): several of these names collide with unrelated binaries or
 * IDE-internal shims on a real machine (the editor's own `cursor` launcher is not the headless
 * `cursor-agent` CLI; VS Code ships an internal `copilot` shim on PATH that itself reports "not
 * found" for the real standalone GitHub Copilot CLI) -- a naive presence check would misreport
 * both. When an entry has no safe, verified way to confirm presence at all (Continue ships no
 * standalone CLI to probe), it always reports not installed rather than guess. */
export interface UnsupportedAgent { agent: string; isInstalled(ctx: AuditContext): boolean }
function versionCheck(ctx: AuditContext, bin: string, flag: string, mustInclude?: RegExp): boolean {
  const found = which(ctx, bin);
  if (!found) return false;
  const res = spawnSync(found, [flag], { encoding: "utf8", timeout: 5_000 });
  if (res.status !== 0 || typeof res.stdout !== "string") return false;
  const out = res.stdout.trim();
  if (/not found|not installed|command not found/i.test(out)) return false;
  return mustInclude ? mustInclude.test(out) : true;
}
export const LIVE_UNSUPPORTED_AGENTS: UnsupportedAgent[] = [
  { agent: "Cursor", isInstalled: ctx => versionCheck(ctx, "cursor-agent", "--version") },
  { agent: "Gemini CLI", isInstalled: ctx => versionCheck(ctx, "gemini", "--version") },
  { agent: "GitHub Copilot CLI", isInstalled: ctx => versionCheck(ctx, "copilot", "--version") },
  { agent: "OpenCode", isInstalled: ctx => versionCheck(ctx, "opencode", "--version") },
  { agent: "Continue", isInstalled: () => false }, // no standalone CLI exists to probe -- only an IDE extension
  { agent: "Windsurf", isInstalled: ctx => versionCheck(ctx, "windsurf", "--version") },
  { agent: "Aider", isInstalled: ctx => versionCheck(ctx, "aider", "--version") },
  { agent: "Amazon Q Developer CLI", isInstalled: ctx => versionCheck(ctx, "q", "--version", /amazon q/i) }, // `q` collides with unrelated tools -- require its own name in the output
  { agent: "Zed", isInstalled: ctx => versionCheck(ctx, "zed", "--version") },
];
export const LIVE_AGENT_ADAPTERS: LiveAgentAdapter[] = [claudeAdapter, codexAdapter];
