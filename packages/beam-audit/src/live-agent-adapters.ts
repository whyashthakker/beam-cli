// Generalizes the live (real API call) tests beyond Claude Code. Each adapter knows how to find its
// binary and run one headless, non-interactive prompt, returning the final text response (or null on
// any failure/ambiguity -- same honest degrade-to-"not verified" pattern as the rest of this package).
// Only agents with a CLI *actually installed on this machine* and a *verified* (not guessed) headless
// invocation get an adapter here. Flags below were confirmed against each binary's own --help output,
// not recalled from memory -- Codex's exact flags in particular change between releases.
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import type { AuditContext } from "./types.js";

export interface RunPromptOptions { addDir?: string; sandbox?: "read-only" | "workspace-write"; disallowedTools?: string }
export interface LiveAgentAdapter {
  agent: string;
  findBinary(ctx: AuditContext): string | null;
  /** Runs one headless prompt; returns the agent's final text reply, or null if it failed,
   * timed out, or produced no parseable/conclusive output. Never throws. */
  runPrompt(bin: string, cwd: string, prompt: string, opts?: RunPromptOptions): string | null;
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
    if (res.error || typeof res.stdout !== "string" || !res.stdout.trim()) return null;
    try {
      const parsed = JSON.parse(res.stdout) as { result?: string; subtype?: string };
      if (parsed.subtype && parsed.subtype !== "success") return null;
      return parsed.result ?? null;
    } catch { return null; }
  },
};

// `codex exec` has no stable JSON "final answer" field worth parsing (--json emits a JSONL event
// stream); -o/--output-last-message writes just the agent's last message to a plain text file,
// which is the simplest reliable way to get the same "what did it say/do" signal the Claude adapter
// gets from `.result`. No --model override: this account's configured default may be rejected by
// the account tier (observed on this machine), and forcing a guessed model name would be worse than
// respecting whatever the user's own `codex` already uses successfully.
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
      if (res.error || !existsSync(outFile)) return null;
      const text = readFileSync(outFile, "utf8").trim();
      return text || null;
    } catch { return null; }
    finally { try { rmSync(outFile, { force: true }); } catch { /* best effort */ } }
  },
};

/** Every adapter this package can run live tests against, plus the known registry agents it
 * deliberately does NOT attempt -- no CLI installed here, or no verified non-interactive mode, so a
 * guessed flag set would be worse than an honest "not supported" row. */
export const LIVE_AGENT_ADAPTERS: LiveAgentAdapter[] = [claudeAdapter, codexAdapter];
export const LIVE_UNSUPPORTED_AGENTS = ["Cursor", "Gemini CLI", "GitHub Copilot CLI", "OpenCode", "Continue", "Windsurf", "Aider", "Amazon Q Developer CLI", "Zed"];
