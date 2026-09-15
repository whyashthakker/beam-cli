// Kernel-enforced process-tree sandboxing for `beam run`. Wraps whichever agent binary the user
// launches (claude, codex, cursor-agent, opencode, gemini, or anything else -- this file has no
// agent-specific knowledge) so that BLOCK-rule commands are unreachable to *every* descendant of
// that process, independent of whether the agent itself cooperates with beam's PreToolUse hook.
//
// This is a second, independent layer underneath the existing hook contract (src/policy.ts
// evaluate()), not a replacement for it -- the hook still fires first and is what lets an agent
// explain *why* to the user. This is the backstop for when that cooperation doesn't happen.
//
// Fail-open by design everywhere: if the sandbox tool isn't installed, the platform isn't
// supported yet (Windows), or resolving a binary's path fails, `beam run` still runs the agent
// normally rather than refusing to launch it. Never let this be the thing that breaks an agent.
import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PolicyBundle } from "./policy.js";

export interface SandboxPlan {
  /** Human-readable summary of what's being enforced, printed once at launch. */
  summary: string;
  /** Prefix to prepend to the user's command: the real invocation becomes [...prefix, ...cmd]. */
  prefix: string[];
}

/**
 * Absolute, symlink-resolved paths on disk for every place `name` resolves to on PATH (there can
 * be more than one). Resolution matters: sandbox-exec's process-exec* and bwrap's bind-mount both
 * act on the real path the kernel execs, not a symlink pointing at it -- e.g. Homebrew installs
 * `/opt/homebrew/bin/git` as a symlink into `../Cellar/git/<version>/bin/git`, and a deny rule
 * written against the symlink path silently doesn't match the resolved exec.
 */
function resolveAllOnPath(name: string): string[] {
  try {
    const out = execFileSync("which", ["-a", name], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const found = out.split("\n").map(l => l.trim()).filter(Boolean);
    const real = found.map(p => { try { return realpathSync(p); } catch { return p; } });
    return Array.from(new Set([...found, ...real]));
  } catch {
    return [];
  }
}

function commandExists(bin: string): boolean {
  try {
    execFileSync("which", [bin], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** Binary names named directly by an enforce-mode BLOCK rule -- these are what get sandboxed. */
function blockedBinaryNames(bundle: PolicyBundle): string[] {
  if (bundle.rules.mode !== "enforce") return [];
  const names = new Set<string>();
  for (const rule of bundle.rules.rules ?? []) {
    if (rule.action === "BLOCK" && rule.command && !/[*?]/.test(rule.command)) names.add(rule.command);
  }
  return Array.from(names);
}

function macosPlan(binaries: string[]): SandboxPlan | null {
  if (!commandExists("sandbox-exec")) return null;
  const resolved = binaries.flatMap(resolveAllOnPath);
  if (!resolved.length) return null;
  const literals = resolved.map(p => `(literal "${p.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}")`).join(" ");
  const profile = `(version 1)\n(allow default)\n(deny process-exec* ${literals})\n(deny process-fork ${literals})\n`;
  const dir = mkdtempSync(join(tmpdir(), "beam-sandbox-"));
  const profilePath = join(dir, "profile.sb");
  writeFileSync(profilePath, profile, { mode: 0o600 });
  return {
    summary: `sandbox-exec: exec denied for ${resolved.join(", ")}`,
    prefix: ["sandbox-exec", "-f", profilePath, "--"],
  };
}

function linuxPlan(binaries: string[]): SandboxPlan | null {
  if (!commandExists("bwrap")) return null;
  const resolved = binaries.flatMap(resolveAllOnPath);
  if (!resolved.length) return null;
  // Bind-mount /bin/false (or /usr/bin/false) over each blocked binary's path, inside a private
  // mount namespace scoped to this process tree only -- the real binary and the rest of the
  // filesystem are untouched outside that namespace.
  const stub = commandExists("false") ? resolveAllOnPath("false")[0] : "/bin/false";
  if (!stub) return null;
  const binds = resolved.flatMap(p => ["--ro-bind", stub, p]);
  return {
    summary: `bwrap: exec masked for ${resolved.join(", ")}`,
    prefix: ["bwrap", "--bind", "/", "/", "--dev-bind", "/dev", "/dev", "--proc", "/proc", ...binds, "--"],
  };
}

/**
 * Best-effort sandbox plan for the current platform and policy. Returns null (no wrapping) if
 * there's nothing to block, the platform has no supported sandbox tool, or the tool isn't
 * installed -- callers should fall back to running the command directly in every null case.
 */
export function buildSandboxPlan(bundle: PolicyBundle | null): SandboxPlan | null {
  if (!bundle) return null;
  const binaries = blockedBinaryNames(bundle);
  if (!binaries.length) return null;
  try {
    if (process.platform === "darwin") return macosPlan(binaries);
    if (process.platform === "linux") return linuxPlan(binaries);
    return null; // Windows: no equivalent wired up yet; beam run still works, just unsandboxed.
  } catch {
    return null;
  }
}
