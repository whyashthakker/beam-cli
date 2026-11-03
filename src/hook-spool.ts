import { mkdir, writeFile, readdir, readFile, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { getDataDirectory } from './config.js';
import type { Obj } from './agents.js';

// Only bounded, redacted capture projections enter this queue. One file per event
// avoids interleaved appends from concurrent agent processes.
export async function spoolHookEvent(event: Obj, directory = getDataDirectory()): Promise<void> {
  const dir = join(directory, 'hook-spool');
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const body = JSON.stringify(event);
  if (Buffer.byteLength(body) > 150000) throw new Error('Projected hook event exceeds queue limit.');
  const name = `${Date.now()}-${randomUUID()}`;
  const temp = join(dir, `${name}.tmp`);
  try { await writeFile(temp, body, { mode: 0o600, flag: 'wx' }); await rename(temp, join(dir, `${name}.json`)); }
  finally { await rm(temp, { force: true }); }
}
export async function drainHookSpool(directory: string, ingest: (events: Obj[]) => Promise<void>): Promise<number> {
  const dir = join(directory, 'hook-spool');
  let files: string[];
  try { files = await readdir(dir); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return 0; throw e; }
  let drained = 0;
  for (const name of files.filter(n => /^\d+-[\da-f-]+\.json$/.test(n)).sort().slice(0,200)) {
    const path = join(dir, name);
    let event: Obj;
    try { event = JSON.parse(await readFile(path, 'utf8')) as Obj; }
    catch { await rename(path, path + '.invalid').catch(() => {}); continue; }
    try { await ingest([event]); await rm(path); drained++; }
    catch { break; } // leave the event for the next poll on storage failure
  }
  return drained;
}
