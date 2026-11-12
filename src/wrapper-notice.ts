// The wrapper rewrites a prompt before Claude Code sees it, so the UserPromptSubmit hook later sees
// only placeholders and has nothing to report. The wrapper leaves a note here, keyed by its id, and the
// next hook run in that wrapper turns it into a user-visible message. Notes hold kinds and counts only.
import { appendFile, mkdir, readFile, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { getDataDirectory } from "./config.js";

const safe = (id: string) => id.replace(/[^A-Za-z0-9_-]/g, "");
const dir = (home: string) => join(home, "wrapper");

export async function addWrapperNotice(id: string, message: string, home = getDataDirectory()): Promise<void> {
  await mkdir(dir(home), { recursive: true, mode: 0o700 });
  await appendFile(join(dir(home), `${safe(id)}.jsonl`), `${JSON.stringify({ at: new Date().toISOString(), message })}\n`, { mode: 0o600 });
}

export async function takeWrapperNotices(id: string, home = getDataDirectory()): Promise<string[]> {
  const file = join(dir(home), `${safe(id)}.jsonl`);
  const taken = `${file}.${process.pid}.taken`;
  try { await rename(file, taken); } catch { return []; } // nothing pending, or another hook took it
  try {
    return (await readFile(taken, "utf8")).split("\n").filter(Boolean).map(line => { try { return String(JSON.parse(line).message); } catch { return ""; } }).filter(Boolean);
  } finally { await rm(taken, { force: true }); }
}
