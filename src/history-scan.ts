// Scans past commits for credentials (policy 6.2: "commit history must be reviewed periodically").
// Only high-precision kinds (API keys, private keys) and committed credential files are reported, so a
// clean result is trustworthy and a hit is actionable. Output carries commit, file, kind and provider --
// never the value.
import { spawnSync } from "node:child_process";
import { detectSensitive } from "./data-detectors.js";
import { isPrivatePath } from "./secret-use.js";
import { PRIVATE_KEY_GUIDANCE, providerOf, type Provider } from "./secret-guidance.js";

export interface HistoryHit { commit: string; file: string; kind: "API_KEY" | "PRIVATE_KEY" | "CREDENTIAL_FILE"; provider: Provider | null }
export interface HistoryScan { hits: HistoryHit[]; commits: number; truncated: boolean; skipped?: string }

const LOCKFILE = /(?:^|\/)(?:package-lock\.json|bun\.lockb?|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|go\.sum)$|\.(?:min\.(?:js|css)|map)$/;

export function scanHistory(cwd: string, options: { maxCommits?: number; ignore?: RegExp[]; spawn?: typeof spawnSync } = {}): HistoryScan {
  const spawn = options.spawn ?? spawnSync; const max = options.maxCommits ?? 1000;
  const inside = spawn("git", ["-C", cwd, "rev-parse", "--is-inside-work-tree"], { encoding: "utf8" });
  if (inside.status !== 0) return { hits: [], commits: 0, truncated: false, skipped: "not a git repository" };
  const log = spawn("git", ["-C", cwd, "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--all", `-n`, String(max + 1), "--format=@@COMMIT %h"],
    { encoding: "utf8", maxBuffer: 128 * 1024 * 1024, timeout: 60_000 });
  if (log.status !== 0 || typeof log.stdout !== "string") return { hits: [], commits: 0, truncated: false, skipped: "git log failed or has no commits" };

  // Log runs newest to oldest, so a later write for the same file+kind is the commit that introduced it.
  const found = new Map<string, HistoryHit>();
  let commit = "", file = "", skip = true, commits = 0;
  for (const raw of log.stdout.split("\n")) {
    if (raw.startsWith("@@COMMIT ")) { commits++; if (commits > max) break; commit = raw.slice(9); continue; }
    if (raw.startsWith("diff --git ")) {
      file = /^diff --git a\/(.+?) b\/(.+)$/.exec(raw)?.[2] ?? "";
      skip = !file || LOCKFILE.test(file) || (options.ignore ?? []).some(re => re.test(file));
      if (!skip && isPrivatePath(file)) found.set(`${file}|CREDENTIAL_FILE`, { commit, file, kind: "CREDENTIAL_FILE", provider: null });
      continue;
    }
    if (skip || !raw.startsWith("+") || raw.startsWith("+++")) continue;
    const text = raw.slice(1);
    for (const f of detectSensitive(text)) {
      if (f.kind !== "API_KEY" && f.kind !== "PRIVATE_KEY") continue;
      found.set(`${file}|${f.kind}`, { commit, file, kind: f.kind, provider: f.kind === "PRIVATE_KEY" ? PRIVATE_KEY_GUIDANCE : providerOf(text.slice(f.start, f.end)) });
    }
  }
  return { hits: [...found.values()], commits: Math.min(commits, max), truncated: commits > max };
}
