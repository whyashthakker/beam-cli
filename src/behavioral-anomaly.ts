// Behavioral anomaly detection: flags a burst of high/critical-severity actions from one agent
// session within a short window, independent of whether any single action was individually
// blocked. An agent that's been talked into a chain of risky actions (prompt injection, a
// compromised skill, a confused multi-step plan) often shows this shape even when each step
// individually only rates "ask" rather than "deny" -- worth a human's attention as a pattern,
// not just as isolated findings. Node-only (fs-backed session state), called from the CLI hook
// path in client.ts only -- same separation from data-detectors.ts/rule-catalog.ts as
// entity-redaction.ts, which stay pure so they can keep backing the edge-runtime SDK path.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getDataDirectory } from "./config.js";
import { withFileLock } from "./file-lock.js";

interface SessionActivity { events: number[] } // epoch ms of each recent high/critical event
type ActivityFile = Record<string, SessionActivity>;

function activityPath(home: string): string {
  return join(home, "behavioral-activity.json");
}

async function readActivity(home: string): Promise<ActivityFile> {
  try { return JSON.parse(await readFile(activityPath(home), "utf8")) as ActivityFile; }
  catch { return {}; }
}

async function writeActivity(map: ActivityFile, home: string): Promise<void> {
  const path = activityPath(home);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(map, null, 2)}\n`, { mode: 0o600 });
}

/** The rolling window an action burst is measured over. */
export const ANOMALY_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
/** High/critical-severity actions within the window that count as a burst. */
export const ANOMALY_THRESHOLD = 5;
// A session with no new high/critical event in this long is dropped entirely, so the file
// doesn't grow forever -- only timestamps live here, nothing sensitive either way.
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface AnomalyResult { triggered: boolean; count: number; windowMinutes: number }

/**
 * Records one HIGH/CRITICAL-severity action for `sessionId` (a LOW/MEDIUM `riskLevel` is a
 * no-op: it still prunes/persists housekeeping but never adds an event or can trigger), and
 * reports whether this session has hit `ANOMALY_THRESHOLD` such actions within
 * `ANOMALY_WINDOW_MS`. `home` is the beam data directory (injectable for tests).
 */
export async function recordAndCheckAnomaly(
  sessionId: string, riskLevel: string, home = getDataDirectory(),
): Promise<AnomalyResult> {
  if (!sessionId) return { triggered: false, count: 0, windowMinutes: ANOMALY_WINDOW_MS / 60_000 };

  // Locked end-to-end (read, mutate, write) so concurrent tool calls in the same turn -- each
  // spawning its own `beam hook` process -- don't lose each other's increments to a read-write
  // race (see file-lock.ts). Without this, a genuine 5-action parallel burst could collapse to
  // a single persisted event, since every process would independently read "0 prior events".
  return withFileLock(activityPath(home), async () => {
    const map = await readActivity(home);
    const now = Date.now();
    for (const [id, session] of Object.entries(map)) {
      const last = session.events.at(-1) ?? 0;
      if (now - last > SESSION_TTL_MS) delete map[id];
    }

    const session: SessionActivity = map[sessionId] ?? { events: [] };
    if (riskLevel === "HIGH" || riskLevel === "CRITICAL") session.events.push(now);
    session.events = session.events.filter(at => now - at <= ANOMALY_WINDOW_MS);
    map[sessionId] = session;

    await writeActivity(map, home).catch(() => { /* best-effort: must never block the agent on persistence failure */ });

    return { triggered: session.events.length >= ANOMALY_THRESHOLD, count: session.events.length, windowMinutes: ANOMALY_WINDOW_MS / 60_000 };
  });
}
