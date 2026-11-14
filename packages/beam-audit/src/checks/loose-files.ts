import { lstat, readFile, opendir, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { confidentHits } from '../detectors.js';
import type { AuditContext, Check } from '../types.js';

export interface LooseScanOptions {
  maxMilliseconds?: number;
  maxEntries?: number;
  progressMilliseconds?: number;
}

// Async filesystem work keeps progress output responsive during large workstation scans.
export async function looseFileChecks(ctx: AuditContext, options: LooseScanOptions = {}): Promise<Check[]> {
  const started = Date.now();
  const budget = options.maxMilliseconds ?? 120_000;
  const entryCap = options.maxEntries ?? 200_000;
  const maxFiles = ctx.maxFiles ?? 20_000;
  const maxDepth = 12;
  const seen = new Set<string>();
  const repoSet = new Set(ctx.repos.map(r => resolve(r)));
  const skipNames = new Set(['node_modules', '.git', 'proc', 'sys', 'dev', '.Trash', '.cache', '.npm', '.Spotlight-V100', '.fseventsd', '.DocumentRevisions-V100']);
  // macOS exposes the Data volume twice. Never traverse its duplicate mount tree.
  const duplicateMount = resolve('/System/Volumes');
  let inspected = 0, excluded = 0, inaccessible = 0, entries = 0, dirs = 0;
  let stopped: string | undefined;
  let depthLimited = 0;
  const evidence: string[] = [];
  const exhausted = () => {
    if (stopped) return true;
    if (Date.now() - started >= budget) stopped = 'time budget';
    else if (entries >= entryCap) stopped = 'entry limit';
    else if (inspected >= maxFiles) stopped = 'file limit';
    return Boolean(stopped);
  };
  const progress = () => ctx.log(`non-repository scan: ${inspected} files inspected, ${dirs} directories, ${entries} entries, ${inaccessible} inaccessible, ${Math.round((Date.now() - started) / 1000)}s elapsed`);
  const ticker = setInterval(progress, options.progressMilliseconds ?? 2000);
  ticker.unref();
  async function walk(dir: string, depth: number): Promise<void> {
    if (exhausted()) return;
    if (depth > maxDepth) { depthLimited++; return; }
    if (repoSet.has(resolve(dir)) || (ctx.platform === 'darwin' && resolve(dir) === duplicateMount)) { excluded++; return; }
    let canonical: string;
    try {
      const st = await lstat(dir);
      if (st.isSymbolicLink()) { excluded++; return; }
      canonical = await realpath(dir);
    } catch { inaccessible++; return; }
    if (seen.has(canonical)) { excluded++; return; }
    seen.add(canonical);
    try {
      const directory = await opendir(dir);
      dirs++;
      for await (const entry of directory) {
        if (exhausted()) break;
        entries++;
        if (skipNames.has(entry.name) || entry.isSymbolicLink()) { excluded++; continue; }
        const path = join(dir, entry.name);
        if (entry.isDirectory()) { await walk(path, depth + 1); continue; }
        if (!entry.isFile() || !/(?:\.env(?:\.[\w-]+)?|\.(?:json|jsonl|csv|sql|toml|ya?ml|ini|conf|log|pem|key)|id_(?:rsa|ed25519))$/i.test(entry.name)) { excluded++; continue; }
        try {
          const st = await lstat(path);
          if (!st.isFile() || st.size > 262_144) { excluded++; continue; }
          // Abortable async reads avoid a synchronous read silently freezing progress output.
          const text = await readFile(path, { encoding: 'utf8', signal: AbortSignal.timeout(Math.min(2000, Math.max(1, budget - (Date.now() - started)))) });
          inspected++;
          if (text.includes('\0')) { excluded++; continue; }
          const kinds = [...new Set(confidentHits(text).filter(h => ['API_KEY', 'OAUTH_TOKEN', 'PRIVATE_KEY', 'SERVICE_ACCOUNT'].includes(h.kind)).map(h => h.kind))];
          if (kinds.length && evidence.length < 100) evidence.push(`${path}: ${kinds.join(', ')}`);
        } catch { inaccessible++; }
      }
    } catch { inaccessible++; }
  }
  try {
    for (const root of ctx.roots) {
      if (exhausted()) break;
      ctx.log(`non-repository scan: starting root ${root}`);
      await walk(root, 0);
    }
  } finally { clearInterval(ticker); }
  const incomplete = Boolean(stopped || depthLimited || inaccessible);
  const summary = `${inspected} supported text files inspected; ${entries} entries; ${excluded} exclusions; ${inaccessible} inaccessible paths; ${depthLimited} depth-limited directories. ${stopped ? `Stopped at ${stopped}; coverage is partial.` : 'Traversal finished within configured limits.'}`;
  ctx.log(`non-repository scan finished: ${summary}`);
  return [
    { id: 'loose-file-credentials', category: 'Sensitive data exposure', policySection: '4.2, 6.1', title: 'Credential patterns outside discovered repositories', status: evidence.length || incomplete ? 'warn' : 'pass', detail: `${summary} Credential patterns require review; presence does not establish agent access or disclosure. Values omitted.`, evidence },
    { id: 'loose-file-coverage', category: 'Scan coverage and evidence', policySection: 'Scope', title: 'Non-repository scan limits', status: incomplete ? 'warn' : 'pass', detail: `Budget ${budget / 1000}s, entry cap ${entryCap}, file cap ${maxFiles}, depth cap ${maxDepth}, file size cap 256 KiB. Overlapping roots are deduplicated. Binary files, symlinks, unsupported file types, macOS duplicate Data-volume mounts, and discovered repositories are excluded. ${summary}` },
  ];
}
