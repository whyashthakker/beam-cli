// Makes `claude`, `codex`, etc. sandboxed automatically -- no one has to remember to type
// `beam run claude`. A small shim directory goes at the *front* of PATH; each shim is a one-line
// script that execs the real agent binary through `beam run`. Shells resolve PATH left-to-right,
// so once the shim dir wins, typing the agent's normal name is enough.
//
// This only decides *whether an invocation goes through beam run* -- src/sandbox.ts still decides
// (per the current policy) whether that actually wraps anything. So installing a shim for an
// agent with no enforce-mode BLOCK rules is a harmless no-op, same as `beam run` itself.
import { chmodSync, mkdirSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { getBeamHome } from "./config.js";

// Binary name actually typed at a shell prompt, which can differ from the agent's own internal
// id (e.g. the "cursor" agent's CLI binary is `cursor-agent`, "claude-code"'s is `claude`).
export const AGENT_BINARIES: Record<string, string> = {
  "claude-code": "claude",
  codex: "codex",
  cursor: "cursor-agent",
  "copilot-cli": "copilot",
  gemini: "gemini",
  opencode: "opencode",
};

export function shimDir(): string {
  return join(getBeamHome(), "shims");
}

function resolveBeamBin(): string | null {
  try {
    const out = execFileSync("which", ["beam"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return out ? realpathSync(out) : null;
  } catch {
    return null;
  }
}

/** The real agent binary's path, skipping any match that's actually one of our own shims. */
function resolveRealBinary(name: string): string | null {
  const dir = shimDir();
  try {
    const out = execFileSync("which", ["-a", name], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const candidate = out.split("\n").map(l => l.trim()).find(p => p && !p.startsWith(dir));
    return candidate ? realpathSync(candidate) : null;
  } catch {
    return null;
  }
}

export interface ShimResult { agentId: string; binary: string; status: "installed" | "not-found" }

/** Writes shim scripts for the given agent ids (default: every known one) into shimDir(). */
export function installShims(agentIds: string[] = Object.keys(AGENT_BINARIES)): ShimResult[] {
  const beamBin = resolveBeamBin();
  if (!beamBin) throw new Error("Could not resolve the `beam` binary on PATH -- run this from a shell where `beam` already works.");
  mkdirSync(shimDir(), { recursive: true });

  return agentIds.map((agentId) => {
    const binary = AGENT_BINARIES[agentId];
    if (!binary) throw new Error(`Unknown agent id: ${agentId}`);
    const real = resolveRealBinary(binary);
    if (!real) return { agentId, binary, status: "not-found" as const };
    const script = `#!/bin/sh\n# Installed by \`beam shims install\` -- routes ${binary} through beam run's sandbox.\nexec "${beamBin}" run "${real}" "$@"\n`;
    const path = join(shimDir(), binary);
    writeFileSync(path, script, { mode: 0o755 });
    chmodSync(path, 0o755);
    return { agentId, binary, status: "installed" as const };
  });
}

export function uninstallShims(): void {
  try { rmSync(shimDir(), { recursive: true, force: true }); } catch { /* nothing to remove */ }
}

export function listShims(): string[] {
  try { return readdirSync(shimDir()); } catch { return []; }
}

/** Line to add to the shell's rc file so the shim dir wins PATH resolution. */
export function pathExportLine(): string {
  return `export PATH="${shimDir()}:$PATH"`;
}
