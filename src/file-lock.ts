// A minimal, zero-dependency exclusive lock for a read-modify-write cycle against one JSON state
// file, used by behavioral-anomaly.ts and entity-redaction.ts. Without it, two `beam hook`
// processes racing (the common case: an agent issuing several tool calls in parallel in one turn,
// each spawning its own short-lived hook process) both read the same pre-update state, both
// compute their own "+1", and whichever writes last wins -- the other's update is silently lost.
// For the anomaly detector this is a real bypass: 5 genuinely concurrent high-risk actions can
// collapse to 1 persisted event, since each process independently sees itself as the first.
//
// Mechanism: `open(lockPath, "wx")` atomically fails with EEXIST if the lock file already exists
// (POSIX O_EXCL semantics, no race window), so creating it IS the acquisition. A short backoff
// retry loop waits for a concurrent holder to release it (by deleting the file). Fails open on a
// timeout or any error -- a hook must never hang or crash the agent's turn waiting on a lock; a
// worst-case missed increment is far better than a stuck tool call.
import { mkdir, open, rm, stat, unlink } from "node:fs/promises";
import { dirname } from "node:path";

const MAX_WAIT_MS = 2000;
const RETRY_DELAY_MS = 20;
// A lock older than this is assumed to belong to a process that crashed or was killed mid-update
// (hook processes are short-lived; nothing legitimate holds this lock for seconds) and is removed
// so a stuck lock file doesn't permanently block every future update.
const STALE_LOCK_MS = 5000;

export async function withFileLock<T>(path: string, fn: () => Promise<T>): Promise<T> {
  const lockPath = `${path}.lock`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 }).catch(() => {});

  const deadline = Date.now() + MAX_WAIT_MS;
  let acquired = false;
  while (Date.now() < deadline) {
    try {
      const handle = await open(lockPath, "wx");
      await handle.close();
      acquired = true;
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") break; // unexpected error: proceed unlocked rather than hang
      try {
        const info = await stat(lockPath);
        if (Date.now() - info.mtimeMs > STALE_LOCK_MS) await rm(lockPath, { force: true });
      } catch { /* lock vanished between the failed open and this check -- fine, loop will retry the open */ }
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS + Math.random() * RETRY_DELAY_MS));
    }
  }

  try {
    return await fn();
  } finally {
    if (acquired) await unlink(lockPath).catch(() => {});
  }
}
