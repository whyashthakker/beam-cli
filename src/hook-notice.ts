// User-facing notices for things Beam does that would otherwise be silent: redacting a value,
// flagging a risk in observe mode, a guardrail failing open. A hook process must write exactly
// one JSON object to stdout, so notices are collected here during the run and attached to
// whichever object the emit* functions in client.ts write (`systemMessage`); if nothing else is
// written, flushNotices() writes a notice-only object. Notices never contain the real values --
// only kinds and counts.
import type { DataFinding } from "./data-detectors.js";

// Agents whose hook contract has a non-blocking, user-visible `systemMessage` field. Everyone
// else gets the notice on stderr, which is the best a command hook can do without a verified field.
const SYSTEM_MESSAGE_AGENTS = new Set(["claude-code", "codex", "gemini"]);

const state: { messages: string[]; delivered: boolean } = { messages: [], delivered: false };

export function resetNotices(): void { state.messages = []; state.delivered = false; }
export function addNotice(message: string): void { if (!state.messages.includes(message)) state.messages.push(message); }
export function pendingNotices(): string[] { return [...state.messages]; }

/** "2 values (1× PHONE, 1× SSN)" -- kinds and counts only. */
export function summarizeFindings(findings: Array<Pick<DataFinding, "kind">>): string {
  const counts = new Map<string, number>();
  for (const f of findings) counts.set(f.kind, (counts.get(f.kind) ?? 0) + 1);
  const parts = [...counts].map(([kind, n]) => `${n}× ${kind}`).join(", ");
  return `${findings.length} value${findings.length === 1 ? "" : "s"} (${parts})`;
}

export function supportsSystemMessage(agent: string): boolean { return SYSTEM_MESSAGE_AGENTS.has(agent); }

/** The text to attach as `systemMessage`, or undefined if there is nothing to say / the agent can't show it. */
export function takeSystemMessage(agent: string): string | undefined {
  if (!supportsSystemMessage(agent) || state.messages.length === 0) return undefined;
  state.delivered = true;
  return `Beam: ${state.messages.join(" | ")}`;
}

/** Adds `systemMessage` to an outgoing hook object when there are notices for this agent. */
export function withNotice<T extends Record<string, unknown>>(agent: string, output: T): T & { systemMessage?: string } {
  const systemMessage = takeSystemMessage(agent);
  return systemMessage ? { ...output, systemMessage } : output;
}

/**
 * Called once at the end of a hook run. If the notices were not already attached to an emitted
 * decision, deliver them now: a notice-only object for agents with `systemMessage`, stderr for
 * the rest. Never throws.
 */
export function flushNotices(agent: string, event: string): void {
  try {
    if (state.delivered || state.messages.length === 0) return;
    if (supportsSystemMessage(agent)) {
      const systemMessage = takeSystemMessage(agent)!;
      // Gemini's contract expects a decision alongside; Claude Code/Codex accept the common
      // `systemMessage` field on its own.
      process.stdout.write(JSON.stringify(agent === "gemini" ? { decision: "allow", systemMessage } : { systemMessage }));
    } else {
      process.stderr.write(`\nBeam: ${state.messages.join(" | ")}\n`);
      state.delivered = true;
    }
  } catch { /* a notice must never break the hook */ }
  void event;
}
