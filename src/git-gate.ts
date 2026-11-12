// Git commit/push/add gate (policy 4.3 "no auto-accept", 6.2 repository controls). Every other guard
// covers what the model sees; this covers what leaves the machine through git. When an agent runs
// `git commit`, `git push` or `git add`, Beam scans exactly what would be committed, pushed or staged and
// reports file:line plus the KIND of each sensitive value -- never the value itself.
//
// What it can and can't see: only git commands the agent runs through its shell tool. A commit you run
// yourself in a terminal is not intercepted. Detection is per added line, so a secret split across
// lines or encoded is not caught.
import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { addNotice } from "./hook-notice.js";
import type { Decision } from "./policy.js";
import { promptFindings } from "./pii-vault.js";
import { isPrivatePath } from "./secret-use.js";
import type { CustomDetector } from "./data-detectors.js";

export type GitGateMode = "ask" | "block" | "warn" | "off";
export interface GitIntent { kind: "commit" | "push" | "add"; args: string[]; dir?: string; all: boolean; noVerify: boolean; force: boolean }
export interface GitFinding { file: string; line?: number; kind: string }
export interface GitScan { findings: GitFinding[]; privateFiles: string[]; skipped?: string }

const MAX_FINDINGS = 50;
const MAX_FILE_BYTES = 1_000_000;
// Lockfiles and generated files hold hashes, not secrets, and would only add noise.
const DEFAULT_IGNORE = [/(?:^|\/)(?:package-lock\.json|bun\.lockb?|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|go\.sum)$/, /\.min\.(?:js|css)$/, /\.map$/];

function tokenize(segment: string): string[] {
  return [...segment.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map(m => m[1] ?? m[2] ?? m[3] ?? "");
}

/** Finds `git commit|push|add` anywhere in a (possibly chained) shell command. */
export function parseGitCommands(command: string): GitIntent[] {
  const intents: GitIntent[] = [];
  for (const segment of command.split(/&&|\|\||;|\n|\|/)) {
    const tokens = tokenize(segment.trim());
    // `git` must be the command word (after env assignments and simple wrappers), not an argument
    // like in `echo git commit`.
    let at = 0;
    while (at < tokens.length && (/^[A-Za-z_]\w*=/.test(tokens[at]!) || ["sudo", "env", "command", "exec", "nohup", "time"].includes(tokens[at]!))) at++;
    if (!(tokens[at] === "git" || tokens[at]?.endsWith("/git"))) continue;
    let dir: string | undefined; let i = at + 1;
    // Global options that come before the subcommand.
    for (; i < tokens.length; i++) {
      const t = tokens[i]!;
      if (t === "-C") { dir = tokens[++i]; continue; }
      if (t === "-c" || t === "--git-dir" || t === "--work-tree" || t === "--exec-path") { i++; continue; }
      if (t.startsWith("--git-dir=") || t.startsWith("--work-tree=") || t === "--no-pager" || t === "-p" || t === "--paginate" || t === "--no-replace-objects") continue;
      break;
    }
    const sub = tokens[i];
    if (sub !== "commit" && sub !== "push" && sub !== "add") continue;
    const args = tokens.slice(i + 1);
    intents.push({
      kind: sub, args, dir,
      all: args.some(a => a === "--all" || /^-[a-zA-Z]*a[a-zA-Z]*$/.test(a)),
      noVerify: sub === "commit" && args.some(a => a === "--no-verify" || a === "-n"),
      force: sub === "push" && args.some(a => a === "--force" || a === "-f" || a.startsWith("--force-with-lease") || /^\+\S/.test(a)),
    });
  }
  return intents;
}

type Spawn = typeof spawnSync;
const git = (spawn: Spawn, cwd: string, args: string[]) =>
  spawn("git", ["-C", cwd, ...args], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 10_000 });

function ignored(file: string, extra: RegExp[]): boolean { return [...DEFAULT_IGNORE, ...extra].some(re => re.test(file)); }

/** Scans a unified diff (-U0) and records sensitive added lines and private files. */
export function scanDiff(diff: string, custom: CustomDetector[] | undefined, extraIgnore: RegExp[] = []): GitScan {
  const findings: GitFinding[] = []; const privateFiles = new Set<string>();
  let file = ""; let line = 0; let skipFile = false;
  for (const raw of diff.split("\n")) {
    if (raw.startsWith("diff --git ")) {
      const m = /^diff --git a\/(.+?) b\/(.+)$/.exec(raw);
      file = m?.[2] ?? ""; skipFile = !file || ignored(file, extraIgnore);
      if (file && !skipFile && isPrivatePath(file)) privateFiles.add(file);
      continue;
    }
    if (raw.startsWith("+++ ")) { if (raw === "+++ /dev/null") skipFile = true; continue; }
    if (raw.startsWith("--- ") || raw.startsWith("index ") || raw.startsWith("new file") || raw.startsWith("deleted file") || raw.startsWith("Binary files")) continue;
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(raw);
    if (hunk) { line = Number(hunk[1]); continue; }
    if (raw.startsWith("+") && !skipFile) {
      for (const f of promptFindings(raw.slice(1), custom).blocking) if (findings.length < MAX_FINDINGS) findings.push({ file, line, kind: f.kind });
      line++;
    }
  }
  return { findings, privateFiles: [...privateFiles] };
}

function scanFiles(cwd: string, paths: string[], custom: CustomDetector[] | undefined, extraIgnore: RegExp[]): GitScan {
  const findings: GitFinding[] = []; const privateFiles: string[] = [];
  for (const path of paths) {
    if (ignored(path, extraIgnore)) continue;
    if (isPrivatePath(path)) privateFiles.push(path);
    try {
      const full = isAbsolute(path) ? path : join(cwd, path);
      if (statSync(full).size > MAX_FILE_BYTES) continue;
      readFileSync(full, "utf8").split("\n").forEach((text, index) => {
        for (const f of promptFindings(text, custom).blocking) if (findings.length < MAX_FINDINGS) findings.push({ file: path, line: index + 1, kind: f.kind });
      });
    } catch { /* unreadable or a directory: nothing to scan */ }
  }
  return { findings, privateFiles };
}

export function scanGitIntent(intent: GitIntent, cwd: string, options: { custom?: CustomDetector[]; ignore?: RegExp[]; spawn?: Spawn } = {}): GitScan {
  const spawn = options.spawn ?? spawnSync; const extra = options.ignore ?? [];
  const dir = intent.dir ? resolve(cwd, intent.dir) : cwd;
  const inside = git(spawn, dir, ["rev-parse", "--is-inside-work-tree"]);
  if (inside.status !== 0) return { findings: [], privateFiles: [], skipped: "not a git repository" };
  const flags = ["--no-color", "--no-ext-diff", "-U0"];

  if (intent.kind === "commit") {
    let diff = git(spawn, dir, ["diff", intent.all ? "HEAD" : "--cached", ...flags]);
    if (diff.status !== 0 && intent.all) diff = git(spawn, dir, ["diff", "--cached", ...flags]); // no HEAD yet
    return scanDiff(diff.stdout ?? "", options.custom, extra);
  }
  if (intent.kind === "push") {
    // Commits that exist locally but on no remote: exactly what a push would publish.
    const log = git(spawn, dir, ["log", "-p", ...flags, "HEAD", "--not", "--remotes"]);
    return scanDiff(log.stdout ?? "", options.custom, extra);
  }
  // git add: dry-run to learn which files would be staged, then scan them.
  if (intent.args.some(a => a === "-p" || a === "--patch" || a === "-i" || a === "--interactive")) return { findings: [], privateFiles: [], skipped: "interactive add" };
  const dry = git(spawn, dir, ["add", "--dry-run", ...intent.args]);
  const paths = [...(dry.stdout ?? "").matchAll(/^(?:add|remove) '(.+)'$/gm)].map(m => m[1]!).filter((p, i, all) => all.indexOf(p) === i);
  return scanFiles(dir, paths, options.custom, extra);
}

/** The setting that applies: explicit policy/env value, else warn in observe mode and ask otherwise. */
export function gitGateMode(policyValue: string | undefined, envValue: string | undefined, mode: string): GitGateMode {
  const explicit = [policyValue, envValue].find(v => v === "ask" || v === "block" || v === "warn" || v === "off") as GitGateMode | undefined;
  return explicit ?? (mode === "observe" ? "warn" : "ask");
}

function describeScan(intent: GitIntent, scan: GitScan): string {
  const counts = new Map<string, number>();
  for (const f of scan.findings) counts.set(f.kind, (counts.get(f.kind) ?? 0) + 1);
  const kinds = [...counts].map(([k, n]) => `${n}× ${k}`).join(", ");
  const where = [...new Set(scan.findings.map(f => `${f.file}:${f.line}`))].slice(0, 5).join(", ");
  const parts: string[] = [];
  if (scan.findings.length) parts.push(`${scan.findings.length} sensitive value${scan.findings.length === 1 ? "" : "s"} (${kinds}) at ${where}${new Set(scan.findings.map(f => `${f.file}:${f.line}`)).size > 5 ? ", …" : ""}`);
  if (scan.privateFiles.length) parts.push(`private file${scan.privateFiles.length === 1 ? "" : "s"} ${scan.privateFiles.slice(0, 5).join(", ")}`);
  const verb = intent.kind === "commit" ? "git commit would include" : intent.kind === "push" ? "git push would publish commits containing" : "git add would stage";
  const review = intent.kind === "commit" ? "Review with `git diff --cached`." : intent.kind === "push" ? "Review with `git log -p --not --remotes`." : "Review the listed files first.";
  return `${verb} ${parts.join(" and ")}. ${review}`;
}

export interface GitGateContext { command: string; cwd: string; mode: GitGateMode; custom?: CustomDetector[]; ignore?: string[]; spawn?: Spawn }

/** Applies the gate to a decision. Never downgrades an existing ask/deny; never throws. */
export function applyGitGate(decision: Decision, context: GitGateContext): Decision {
  if (context.mode === "off" || !context.cwd) return decision;
  let next = decision;
  try {
    const ignore = (context.ignore ?? []).flatMap(p => { try { return [new RegExp(p)]; } catch { return []; } });
    for (const intent of parseGitCommands(context.command)) {
      if (intent.noVerify) addNotice("git commit --no-verify skips pre-commit hooks (including any secret scanner).");
      const scan = scanGitIntent(intent, context.cwd, { custom: context.custom, ignore, spawn: context.spawn });
      if (!scan.findings.length && !scan.privateFiles.length) continue;
      const reason = describeScan(intent, scan);
      addNotice(reason);
      next = { ...next, riskFactors: [...new Set([...next.riskFactors, `git ${intent.kind}: sensitive content`])] };
      if (next.action === "deny" || next.action === "ask") continue;
      if (context.mode === "block") next = { ...next, action: "deny", rule: "beam.git-gate", reason };
      else if (context.mode === "ask") next = { ...next, action: "ask", rule: "beam.git-gate", reason };
    }
  } catch { addNotice("the git gate could not scan this git command."); }
  return next;
}
