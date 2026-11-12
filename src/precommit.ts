// Pre-commit secret scanning for commits the agent does NOT run (policy 6.2). The git gate only sees
// `git commit` issued through an agent's shell tool; this installs a real git hook so a commit typed in
// any terminal is scanned too. It reuses the same scanner and never prints a value, only file:line + kind.
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, isAbsolute } from "node:path";
import { spawnSync } from "node:child_process";
import { scanGitIntent } from "./git-gate.js";
import { getDataDirectory } from "./config.js";
import { addNotice } from "./hook-notice.js";

const BEGIN = "# >>> beam pre-commit >>>";
const END = "# <<< beam pre-commit <<<";

// Environment markers set by agents' shell tools. A commit from your editor's Git panel or a normal
// terminal has none of them, so the hook lets it through: it exists to stop the agent, not you.
const AGENT_ENV = ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX", "CODEX_THREAD_ID", "CURSOR_AGENT", "GEMINI_CLI", "BEAM_WRAPPER_ID"];
export const isAgentProcess = (env: NodeJS.ProcessEnv = process.env) => AGENT_ENV.some(k => !!env[k]);

/** Scans the staged diff. Agent-only unless `everyone` is set. Returns a report and the hook exit code. */
export function scanStaged(cwd: string, options: { everyone?: boolean; env?: NodeJS.ProcessEnv } = {}): { code: number; report: string } {
  if (!options.everyone && !isAgentProcess(options.env)) return { code: 0, report: "" };
  const scan = scanGitIntent({ kind: "commit", args: [], all: false, noVerify: false, force: false }, cwd);
  if (scan.skipped) return { code: 0, report: "" };
  const lines = [
    ...scan.privateFiles.map(f => `  ${f}  (credential file)`),
    ...scan.findings.map(f => `  ${f.file}${f.line ? `:${f.line}` : ""}  ${f.kind}`),
  ];
  if (!lines.length) return { code: 0, report: "" };
  return { code: 1, report: `beam: staged changes contain sensitive data (values not shown):\n${lines.join("\n")}\nRemove it, or bypass once with --no-verify if you are sure.` };
}

export interface InstallResult { path: string; changed: boolean }

/** Adds (or refreshes) the Beam block in the repo's pre-commit hook, keeping any existing hook content. */
export function installPrecommit(cwd: string, beamCommand = "beam"): InstallResult {
  const git = (...a: string[]) => String(spawnSync("git", a, { cwd, encoding: "utf8" }).stdout ?? "").trim();
  const root = git("rev-parse", "--show-toplevel");
  if (!root) throw new Error("Not inside a git repository.");
  const dir = resolve(cwd, git("rev-parse", "--git-path", "hooks"));
  const file = join(dir, "pre-commit");
  const block = `${BEGIN}\nif command -v ${beamCommand} >/dev/null 2>&1; then ${beamCommand} git-scan || exit 1; fi\n${END}\n`;
  let existing = existsSync(file) ? readFileSync(file, "utf8") : "";
  let next: string;
  if (existing.includes(BEGIN)) next = existing.replace(new RegExp(`${BEGIN}[\\s\\S]*?${END}\\n?`), block);
  else next = (existing || "#!/bin/sh\n") + (existing && !existing.endsWith("\n") ? "\n" : "") + block;
  mkdirSync(dirname(file), { recursive: true });
  const changed = next !== existing;
  if (changed) writeFileSync(file, next);
  chmodSync(file, 0o755);
  return { path: file, changed };
}

const SCANNER = /gitleaks|trufflehog|detect-secrets|git-secrets|\bbeam\b/i;

/**
 * Auto-setup: the first time an agent session touches a git workspace, install the pre-commit hook once.
 * "Once" is per repo root and remembered in the data directory, so a hook you deliberately remove is not
 * put back. Skipped when a scanner is already configured, when hooks live outside the repo (a shared
 * global hooksPath), or when disabled by policy `autoPrecommit: "off"` / BEAM_AUTO_PRECOMMIT=0.
 */
export function ensurePrecommit(cwd: string, options: { policyValue?: string; env?: NodeJS.ProcessEnv; beamCommand?: string } = {}): InstallResult | null {
  const env = options.env ?? process.env;
  if (options.policyValue === "off" || env.BEAM_AUTO_PRECOMMIT === "0" || !cwd) return null;
  const git = (...a: string[]) => { const r = spawnSync("git", a, { cwd, encoding: "utf8", timeout: 5000 }); return r.status === 0 ? String(r.stdout).trim() : ""; };
  const root = git("rev-parse", "--show-toplevel");
  if (!root) return null;
  const stateFile = join(getDataDirectory(), "precommit-handled.json");
  let handled: string[] = [];
  try { handled = JSON.parse(readFileSync(stateFile, "utf8")); } catch { /* first run */ }
  if (handled.includes(root)) return null;
  const remember = () => { try { mkdirSync(dirname(stateFile), { recursive: true }); writeFileSync(stateFile, JSON.stringify([...handled, root])); } catch { /* best effort */ } };

  const hooksDir = resolve(realpathSync(cwd), git("rev-parse", "--git-path", "hooks"));
  const rel = relative(root, hooksDir);
  if (rel.startsWith("..") || isAbsolute(rel)) { remember(); return null; }
  const candidates = [join(hooksDir, "pre-commit"), join(root, ".husky", "pre-commit"), join(root, ".pre-commit-config.yaml")];
  if (candidates.some(f => { try { return SCANNER.test(readFileSync(f, "utf8")); } catch { return false; } })) { remember(); return null; }
  const result = installPrecommit(cwd, options.beamCommand);
  remember();
  addNotice(`installed a pre-commit secret scan in this repo (${rel ? rel + "/" : ""}pre-commit) so a commit an agent makes by any route is checked (your own commits are never blocked). Remove the "beam pre-commit" block to opt out; set autoPrecommit to "off" in policy.json to stop this.`);
  return result;
}
