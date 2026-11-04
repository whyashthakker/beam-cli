import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { getDataDirectory } from "./config.js";

// Closes the loop an admin's "Approve" click starts: askApproval() (client.ts) records one of
// these the moment a request comes back APPROVED, and the next PreToolUse hook for the matching
// action consumes it instead of denying/asking again -- the agent's retry goes straight through,
// without a second round trip to a human. Lives under the data directory, the same one
// isBeamSelfProtectionTarget() protects from agent writes: the only way an entry gets added is by
// actually going through askApproval()'s real round trip (file a request, a human resolves it),
// never by an agent writing this file directly -- that write is self-protection-blocked, same as
// trusted-paths.json.
export interface ApprovedActionTarget { agent: string; tool: string; command?: string; path?: string; url?: string }
interface ApprovedActionEntry { fingerprint: string; expiresAt: string }

export function approvedActionsFile(): string { return join(getDataDirectory(), "approved-actions.json"); }

export function approvedActionFingerprint(target: ApprovedActionTarget): string {
  return createHash("sha256").update(JSON.stringify({
    agent: target.agent.toLowerCase(),
    tool: target.tool.toLowerCase(),
    command: target.command || "",
    path: target.path || "",
    url: target.url || "",
  })).digest("hex");
}

async function readApprovedActions(): Promise<ApprovedActionEntry[]> {
  try {
    const parsed = JSON.parse(await readFile(approvedActionsFile(), "utf8"));
    return Array.isArray(parsed)
      ? parsed.filter((e): e is ApprovedActionEntry => Boolean(e) && typeof e === "object" && typeof e.fingerprint === "string" && typeof e.expiresAt === "string")
      : [];
  } catch {
    return [];
  }
}

async function writeApprovedActions(entries: ApprovedActionEntry[]): Promise<void> {
  const dir = getDataDirectory();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const file = approvedActionsFile();
  const temp = `${file}.tmp`;
  await writeFile(temp, JSON.stringify(entries) + "\n", { mode: 0o600 });
  await rename(temp, file);
}

// Bounded (default 15 minutes) -- an approval is permission to proceed now, not a standing
// exception. Capped at 200 entries so a burst of asks can't grow this file unbounded.
export async function recordApprovedAction(target: ApprovedActionTarget, ttlMs = 15 * 60_000): Promise<void> {
  const live = (await readApprovedActions()).filter(e => Date.parse(e.expiresAt) > Date.now());
  live.push({ fingerprint: approvedActionFingerprint(target), expiresAt: new Date(Date.now() + ttlMs).toISOString() });
  await writeApprovedActions(live.slice(-200));
}

// Single-use: APPROVE_ONCE semantics (see approvals.ts) -- a match is removed on read so it can't
// silently re-authorize a later, unrelated repeat of the same command without asking again.
export async function consumeApprovedAction(target: ApprovedActionTarget): Promise<boolean> {
  const fingerprint = approvedActionFingerprint(target);
  const now = Date.now();
  const entries = await readApprovedActions();
  const match = entries.find(e => e.fingerprint === fingerprint && Date.parse(e.expiresAt) > now);
  if (!match) return false;
  await writeApprovedActions(entries.filter(e => e !== match && Date.parse(e.expiresAt) > now));
  return true;
}
