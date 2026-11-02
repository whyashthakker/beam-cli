// Session-consistent entity redaction: the same real secret value redacted twice in one session
// becomes the same placeholder both times (e.g. [SECRET_001]), and a *different* value of the
// same kind gets its own number ([SECRET_002]) -- unlike data-detectors.ts's redactSensitive(),
// which always emits the same static "[SECRET_REDACTED]" regardless of which value matched, so
// two different leaked secrets are indistinguishable in what the agent/reviewer sees. Only a
// truncated SHA-256 hash of each matched value is ever written to disk; the real value is hashed
// in memory and discarded immediately, never persisted or logged.
//
// Node-only (uses node:crypto and node:fs) -- kept out of data-detectors.ts on purpose, which
// stays pure/stateless so it can keep backing the edge-runtime SDK path (see its callers:
// monitor-rules.ts only imports its CustomDetector *type*, never calls its functions, at
// runtime). This module is only ever called from the CLI hook path in client.ts.
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getDataDirectory } from "./config.js";
import { detectSensitive, type CustomDetector, type DataFinding } from "./data-detectors.js";
import { withFileLock } from "./file-lock.js";

interface SessionEntities { updatedAt: string; counters: Record<string, number>; entries: Record<string, string> }
type EntityMapFile = Record<string, SessionEntities>;

function entityMapPath(home = getDataDirectory()): string {
  return join(home, "entity-map.json");
}

async function readMap(home: string): Promise<EntityMapFile> {
  try { return JSON.parse(await readFile(entityMapPath(home), "utf8")) as EntityMapFile; }
  catch { return {}; }
}

async function writeMap(map: EntityMapFile, home: string): Promise<void> {
  const path = entityMapPath(home);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(map, null, 2)}\n`, { mode: 0o600 });
}

// A session untouched this long is pruned so the file doesn't grow forever. Only hashes and
// counters live here, never a real value, but there's no reason to keep them past the session's
// useful life either.
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

/**
 * Same redaction `detectSensitive()`/`redactSensitive()` already do, except each distinct real
 * value gets a stable, numbered placeholder ([SECRET_001], [API_KEY_002], ...) that's consistent
 * for that exact value within `sessionId`, and distinct per different value of the same kind.
 * `home` is the beam data directory (injectable for tests); defaults to the real one.
 */
export async function redactWithSessionEntities(
  text: string, sessionId: string, custom: CustomDetector[] = [], home = getDataDirectory(),
): Promise<{ text: string; findings: DataFinding[] }> {
  const findings = detectSensitive(text, custom);
  if (findings.length === 0) return { text, findings: [] };

  // Locked end-to-end so concurrent tool calls in the same turn -- each spawning its own
  // `beam hook` process -- can't both read the same pre-update counter and independently assign
  // the same next id to two different values (see file-lock.ts / behavioral-anomaly.ts, which
  // has the identical read-modify-write race).
  return withFileLock(entityMapPath(home), async () => {
    const map = await readMap(home);
    const now = new Date().toISOString();
    const cutoff = Date.now() - SESSION_TTL_MS;
    for (const [id, session] of Object.entries(map)) if (Date.parse(session.updatedAt) < cutoff) delete map[id];

    const session: SessionEntities = map[sessionId] ?? { updatedAt: now, counters: {}, entries: {} };
    session.updatedAt = now;

    // detectSensitive() returns findings sorted start-descending (last match first) specifically
    // so a splice-based replace loop can apply them right-to-left without later offsets shifting
    // -- this loop relies on that same ordering.
    let result = text;
    const entityFindings: DataFinding[] = [];
    for (const finding of findings) {
      const value = text.slice(finding.start, finding.end);
      const hash = hashValue(value);
      let id = session.entries[hash];
      if (!id) {
        session.counters[finding.kind] = (session.counters[finding.kind] ?? 0) + 1;
        id = `${finding.kind}_${String(session.counters[finding.kind]).padStart(3, "0")}`;
        session.entries[hash] = id;
      }
      const replacement = `[${id}]`;
      result = result.slice(0, finding.start) + replacement + result.slice(finding.end);
      entityFindings.push({ ...finding, replacement });
    }

    map[sessionId] = session;
    await writeMap(map, home).catch(() => { /* best-effort: redaction must still succeed if persistence fails */ });

    return { text: result, findings: entityFindings };
  });
}
