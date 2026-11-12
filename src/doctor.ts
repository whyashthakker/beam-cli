// `beam doctor`: checks the local setup against the Claude Code Secure Usage Policy. Each check is
// independent, read-only, and reports pass / warn / fail / skip with a fix. Nothing here changes
// anything, and no secret value is ever printed -- only file paths and kinds.
//
// Checks that can't be verified from the machine (API tier, vendor terms, workstation baseline) are
// reported as `skip` with the reason, not silently passed.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { getDataDirectory } from "./config.js";
import { detectSensitive } from "./data-detectors.js";
import { readPolicy } from "./policy.js";
import { gitGateMode } from "./git-gate.js";
import { networkMode } from "./network-detectors.js";
import { isPrivatePath } from "./secret-use.js";
import { listIncidents, timeLeft, urgency } from "./incidents.js";
import { scanHistory } from "./history-scan.js";
import { rotationAdvice, GENERIC_ROTATION } from "./secret-guidance.js";

export type Status = "pass" | "warn" | "fail" | "skip";
export interface Check { id: string; policy: string; title: string; status: Status; detail: string; fix?: string }
export interface DoctorContext { cwd: string; home: string; env: NodeJS.ProcessEnv; dataDir: string; spawn: typeof spawnSync }

export function defaultContext(cwd = process.cwd()): DoctorContext {
  return { cwd, home: homedir(), env: process.env, dataDir: getDataDirectory(), spawn: spawnSync };
}

const run = (ctx: DoctorContext, cmd: string, args: string[], cwd = ctx.cwd) => ctx.spawn(cmd, args, { cwd, encoding: "utf8", timeout: 10_000, maxBuffer: 16 * 1024 * 1024 });
function readJson(path: string): Record<string, any> | null { try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; } }
const mode = (path: string) => { try { return statSync(path).mode & 0o777; } catch { return null; } };
const inRepo = (ctx: DoctorContext) => run(ctx, "git", ["rev-parse", "--is-inside-work-tree"]).status === 0;

// ---- individual checks ------------------------------------------------------------------------

function hooksInstalled(ctx: DoctorContext): Check {
  const base = { id: "hooks", policy: "3", title: "Beam hooks installed for Claude Code" };
  const settings = readJson(join(ctx.home, ".claude", "settings.json"));
  if (!settings) return { ...base, status: "fail", detail: "~/.claude/settings.json not found or unreadable.", fix: "Run `beam agent install claude-code`." };
  const wanted = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop"];
  const missing = wanted.filter(event => !JSON.stringify(settings.hooks?.[event] ?? "").includes("hook claude-code"));
  return missing.length
    ? { ...base, status: "fail", detail: `Missing Beam hook for: ${missing.join(", ")}.`, fix: "Run `beam agent install claude-code`, then restart Claude Code." }
    : { ...base, status: "pass", detail: `All ${wanted.length} hooks are registered.` };
}

async function policyEnforcement(): Promise<Check[]> {
  const bundle = await readPolicy().catch(() => null);
  const rules = bundle?.rules;
  const modeName = rules?.mode ?? "observe";
  const enforcing: Check = modeName === "observe"
    ? { id: "policy-mode", policy: "8.4", title: "Policy mode", status: "warn", detail: "Observe mode: Beam records and notifies but never asks or blocks.", fix: "Set `mode` to \"enforce\" in policy.json (or connect a workspace policy)." }
    : { id: "policy-mode", policy: "8.4", title: "Policy mode", status: "pass", detail: `Mode is ${modeName}.` };
  const pii = rules?.piiPrompt ?? "block";
  const piiCheck: Check = pii === "block"
    ? { id: "pii-prompt", policy: "4.2", title: "Sensitive data in prompts", status: "pass", detail: "Prompts with cards, IDs, PHI or credentials are blocked and vaulted (rewritten automatically under `beam claude`)." }
    : { id: "pii-prompt", policy: "4.2", title: "Sensitive data in prompts", status: pii === "off" ? "fail" : "warn", detail: `piiPrompt is "${pii}": sensitive prompt content reaches the model.`, fix: "Remove `piiPrompt` from policy.json (default is block)." };
  const net = networkMode(rules?.networkTopology, process.env.BEAM_NETWORK_TOPOLOGY);
  const netCheck: Check = net === "off"
    ? { id: "network-topology", policy: "4.2", title: "Network topology protection", status: "warn", detail: "Off: private IPs, CIDR ranges and internal hostnames are not detected.", fix: "Remove `networkTopology: \"off\"` from policy.json." }
    : { id: "network-topology", policy: "4.2", title: "Network topology protection", status: "pass", detail: net === "report" ? "Report-only: topology is kept out of Beam's logs and summarised each turn; the model still sees it. Public IPs are never touched." : net === "redact" ? "Redact: internal addresses are replaced in prompts (under `beam claude`) and tool output." : "Block: prompts containing internal addresses are blocked; topology is redacted elsewhere." };
  const gate = gitGateMode(rules?.gitGate, process.env.BEAM_GIT_GATE, modeName);
  const gateCheck: Check = gate === "off"
    ? { id: "git-gate", policy: "4.3", title: "Git commit/push gate", status: "fail", detail: "Git gate is off.", fix: "Remove `gitGate: \"off\"` from policy.json." }
    : gate === "warn"
      ? { id: "git-gate", policy: "4.3", title: "Git commit/push gate", status: "warn", detail: "Git gate only warns.", fix: "Set `gitGate` to \"ask\" or \"block\"." }
      : { id: "git-gate", policy: "4.3", title: "Git commit/push gate", status: "pass", detail: `Git gate will ${gate} when a commit, push or add contains sensitive data.` };
  return [enforcing, piiCheck, netCheck, gateCheck];
}

function vaultProtected(ctx: DoctorContext): Check {
  const base = { id: "vault-perms", policy: "6.1", title: "Vault and data directory permissions" };
  const loose = ["vault.json", "vault.key", "entity-map.json"].map(f => [f, mode(join(ctx.dataDir, f))] as const).filter(([, m]) => m !== null && (m & 0o077) !== 0);
  const dir = mode(ctx.dataDir);
  if (dir !== null && (dir & 0o077) !== 0) loose.push(["(data directory)", dir]);
  if (loose.length) return { ...base, status: "fail", detail: `Readable by other users: ${loose.map(([f, m]) => `${f} (${m!.toString(8)})`).join(", ")}.`, fix: `chmod 600 the files and chmod 700 ${ctx.dataDir}.` };
  return existsSync(join(ctx.dataDir, "vault.json")) ? { ...base, status: "pass", detail: "Vault files are owner-only (0600/0700)." } : { ...base, status: "pass", detail: "No vault yet; it is created owner-only on first use." };
}

function memoryDisabled(ctx: DoctorContext): Check {
  const base = { id: "memory", policy: "5.5", title: "Claude Code auto memory disabled" };
  if (ctx.env.CLAUDE_CODE_DISABLE_AUTO_MEMORY === "1") return { ...base, status: "pass", detail: "Disabled by CLAUDE_CODE_DISABLE_AUTO_MEMORY=1." };
  // Highest precedence wins: local project > project > user.
  const files = [join(ctx.cwd, ".claude", "settings.local.json"), join(ctx.cwd, ".claude", "settings.json"), join(ctx.home, ".claude", "settings.json")];
  for (const file of files) {
    const settings = readJson(file);
    if (settings?.env?.CLAUDE_CODE_DISABLE_AUTO_MEMORY === "1") return { ...base, status: "pass", detail: `Disabled by env in ${file}.` };
    if (typeof settings?.autoMemoryEnabled === "boolean") {
      return settings.autoMemoryEnabled
        ? { ...base, status: "fail", detail: `autoMemoryEnabled is true in ${file}.`, fix: "Set \"autoMemoryEnabled\": false in ~/.claude/settings.json, or export CLAUDE_CODE_DISABLE_AUTO_MEMORY=1." }
        : { ...base, status: "pass", detail: `autoMemoryEnabled is false in ${file}.` };
    }
  }
  return { ...base, status: "fail", detail: "Auto memory is on (Claude Code's default): Claude writes notes about you and your projects to ~/.claude/projects/*/memory and loads them in later sessions.", fix: "Set \"autoMemoryEnabled\": false in ~/.claude/settings.json, or export CLAUDE_CODE_DISABLE_AUTO_MEMORY=1. Policy 5.5 requires written approval to enable it." };
}

function networkEnv(ctx: DoctorContext): Check[] {
  const checks: Check[] = [];
  const tlsOff = ctx.env.NODE_TLS_REJECT_UNAUTHORIZED === "0";
  checks.push(tlsOff
    ? { id: "tls", policy: "3", title: "TLS verification", status: "fail", detail: "NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate checks.", fix: "Unset NODE_TLS_REJECT_UNAUTHORIZED." }
    : { id: "tls", policy: "3", title: "TLS verification", status: "pass", detail: "Certificate verification is not disabled." });
  const base = ctx.env.ANTHROPIC_BASE_URL;
  let trusted = true;
  if (base) { try { trusted = new URL(base).protocol === "https:" && new URL(base).hostname.endsWith("anthropic.com"); } catch { trusted = false; } }
  checks.push(base && !trusted
    ? { id: "endpoint", policy: "3, 5.6", title: "API endpoint", status: "fail", detail: "ANTHROPIC_BASE_URL points somewhere other than an https anthropic.com host.", fix: "Unset ANTHROPIC_BASE_URL (the policy allows Anthropic's official endpoints only)." }
    : { id: "endpoint", policy: "3, 5.6", title: "API endpoint", status: "pass", detail: base ? "Custom base URL is an Anthropic host." : "Using the default Anthropic endpoint." });
  return checks;
}

function claudeClient(ctx: DoctorContext): Check {
  const base = { id: "client", policy: "3", title: "Claude Code client" };
  const which = run(ctx, process.platform === "win32" ? "where" : "which", ["claude"]);
  if (which.status !== 0) return { ...base, status: "warn", detail: "`claude` is not on PATH.", fix: "Install the official Claude Code from Anthropic." };
  const version = run(ctx, "claude", ["--version"]);
  return { ...base, status: "pass", detail: `${String(which.stdout).trim().split("\n")[0]} (${String(version.stdout).trim() || "version unknown"}). Beam cannot verify it is the official build; policy 3 requires the Anthropic-distributed client.` };
}

function wrapperAvailable(ctx: DoctorContext): Check {
  const base = { id: "wrapper", policy: "4.2", title: "`beam claude` prompt rewriting available" };
  const py = run(ctx, "python3", ["-c", "import pty, termios, fcntl"]);
  return py.status === 0 ? { ...base, status: "pass", detail: "python3 with the pty module is available." } : { ...base, status: "warn", detail: "python3 (pty module) is missing, so `beam claude` falls back to the prompt-block hook.", fix: "Install python3, or accept the block-and-resend flow." };
}

function repoChecks(ctx: DoctorContext, ignore: RegExp[]): Check[] {
  if (!inRepo(ctx)) return [{ id: "repo", policy: "6.2", title: "Repository controls", status: "skip", detail: "Not inside a git repository; run `beam doctor` from your project." }];
  const checks: Check[] = [];
  const ignored = (name: string) => run(ctx, "git", ["check-ignore", "-q", name]).status === 0;
  const missing = [".env", ".env.local"].filter(n => !ignored(n));
  checks.push(missing.length
    ? { id: "gitignore", policy: "6.2", title: ".env files are git-ignored", status: "fail", detail: `Not ignored: ${missing.join(", ")}.`, fix: "Add `.env` and `.env.*` (with `!.env.example`) to .gitignore before the first commit." }
    : { id: "gitignore", policy: "6.2", title: ".env files are git-ignored", status: "pass", detail: ".env and .env.local are ignored." });

  const tracked = String(run(ctx, "git", ["ls-files", "-z"]).stdout).split("\0").filter(Boolean);
  const trackedPrivate = tracked.filter(f => isPrivatePath(f) && !ignore.some(re => re.test(f)));
  const realPrivate = trackedPrivate.filter(f => !/(?:^|\/)(?:tests?|__tests__|fixtures?|spec|examples?|samples?|scenarios?|testdata|mocks?|[\w-]*bench[\w-]*)\//i.test(f));
  checks.push(realPrivate.length
    ? { id: "tracked-secrets", policy: "6.2", title: "No secret files are tracked", status: "fail", detail: `Tracked: ${realPrivate.slice(0, 8).join(", ")}.`, fix: "`git rm --cached` them, rotate anything exposed, and review history (policy 6.2)." }
    : trackedPrivate.length
      ? { id: "tracked-secrets", policy: "6.2", title: "No secret files are tracked", status: "warn", detail: `Only under test/fixture directories (probably intentional fakes): ${trackedPrivate.length} files, e.g. ${trackedPrivate.slice(0, 3).join(", ")}.`, fix: "Confirm they hold no real credentials; add their path to `gitGateIgnore` to silence this." }
      : { id: "tracked-secrets", policy: "6.2", title: "No secret files are tracked", status: "pass", detail: "No .env, key or credential files are tracked." });

  const hooksPath = String(run(ctx, "git", ["config", "core.hooksPath"]).stdout).trim();
  const root = String(run(ctx, "git", ["rev-parse", "--show-toplevel"]).stdout).trim() || ctx.cwd;
  const hookDir = hooksPath ? join(root, hooksPath) : join(root, ".git", "hooks");
  const scanner = /gitleaks|trufflehog|detect-secrets|git-secrets|\bbeam\b/i;
  const candidates = [join(hookDir, "pre-commit"), join(root, ".husky", "pre-commit"), join(root, ".pre-commit-config.yaml")];
  const hasScanner = candidates.some(f => { try { return scanner.test(readFileSync(f, "utf8")); } catch { return false; } });
  checks.push(hasScanner
    ? { id: "precommit", policy: "6.2", title: "Pre-commit secret scanning", status: "pass", detail: "A pre-commit hook references a secret scanner." }
    : { id: "precommit", policy: "6.2", title: "Pre-commit secret scanning", status: "warn", detail: "No pre-commit hook references gitleaks, trufflehog, detect-secrets or git-secrets. Beam's git gate covers agent commits only, not commits you run yourself.", fix: "Install gitleaks (or detect-secrets) as a pre-commit hook." });

  // Hard-coded secrets in tracked files: high-precision kinds only, kinds and paths only in the output.
  const hits = new Map<string, Set<string>>();
  let scanned = 0;
  for (const file of tracked.slice(0, 4000)) {
    if (ignore.some(re => re.test(file)) || /(?:package-lock\.json|bun\.lockb?|yarn\.lock|pnpm-lock\.yaml)$/.test(file) || isPrivatePath(file)) continue;
    try {
      const full = join(root, file);
      if (statSync(full).size > 1_000_000) continue;
      const text = readFileSync(full, "utf8"); scanned++;
      for (const f of detectSensitive(text)) if (f.kind === "API_KEY" || f.kind === "PRIVATE_KEY") { const set = hits.get(file) ?? new Set(); set.add(f.kind); hits.set(file, set); }
    } catch { /* binary or unreadable */ }
  }
  const testLike = (f: string) => /(?:^|\/)(?:tests?|__tests__|fixtures?|spec|docs?|examples?|samples?|scenarios?|testdata|mocks?|[\w-]*bench[\w-]*)\/|\.(?:test|spec)\.|\.md$/i.test(f);
  const real = [...hits.keys()].filter(f => !testLike(f));
  const list = (files: string[]) => files.slice(0, 6).map(f => `${f} (${[...hits.get(f)!].join(", ")})`).join(", ");
  checks.push(real.length
    ? { id: "hardcoded-keys", policy: "6.1", title: "No hard-coded API keys in tracked files", status: "fail", detail: `Found in: ${list(real)}.`, fix: `Move them to environment variables or a secrets manager. ${GENERIC_ROTATION}` }
    : hits.size
      ? { id: "hardcoded-keys", policy: "6.1", title: "No hard-coded API keys in tracked files", status: "warn", detail: `Only in test/doc files (probably fixtures): ${list([...hits.keys()])}.`, fix: "Confirm they are fake; add them to `gitGateIgnore` if so." }
      : { id: "hardcoded-keys", policy: "6.1", title: "No hard-coded API keys in tracked files", status: "pass", detail: `Scanned ${scanned} tracked files; none contain an API key or private key.` });

  const history = scanHistory(root, { ignore });
  const fixtureDir = /(?:^|\/)(?:tests?|__tests__|fixtures?|spec|docs?|examples?|samples?|scenarios?|testdata|mocks?|[\w-]*bench[\w-]*)\//i;
  if (history.skipped) checks.push({ id: "history-secrets", policy: "6.2", title: "No secrets in commit history", status: "skip", detail: `History not scanned: ${history.skipped}.` });
  else {
    const real = history.hits.filter(h => !fixtureDir.test(h.file) && !(h.kind !== "CREDENTIAL_FILE" && testLike(h.file)));
    const fmt = (hs: typeof history.hits) => hs.slice(0, 6).map(h => `${h.file} @ ${h.commit} (${h.kind === "CREDENTIAL_FILE" ? "credential file" : h.provider ? h.provider.name + " key" : h.kind})`).join(", ") + (hs.length > 6 ? `, +${hs.length - 6} more` : "");
    const scope = `${history.commits} commits${history.truncated ? " (most recent only)" : ""}`;
    checks.push(real.length
      ? { id: "history-secrets", policy: "6.2", title: "No secrets in commit history", status: "fail", detail: `Found in ${scope}: ${fmt(real)}.`, fix: rotationAdvice(real.map(h => h.provider)) }
      : history.hits.length
        ? { id: "history-secrets", policy: "6.2", title: "No secrets in commit history", status: "warn", detail: `Only in test/doc files of ${scope} (probably fixtures): ${fmt(history.hits)}.`, fix: "Confirm they are fake; add the path to `gitGateIgnore` to silence this." }
        : { id: "history-secrets", policy: "6.2", title: "No secrets in commit history", status: "pass", detail: `Scanned ${scope}; no API keys, private keys or credential files were ever added.` });
  }

  // 6.2: engagement code must not be on a public repository. Uses the GitHub CLI when it is installed and
  // signed in; nothing else touches the network, and hosts we can't query are reported, not guessed.
  const remote = String(run(ctx, "git", ["remote", "get-url", "origin"]).stdout).trim();
  const vis = { id: "repo-visibility", policy: "6.2", title: "Repository is not public" };
  const gh = /github\.com[:/]+([^/\s]+\/[^/\s]+?)(?:\.git)?\/?$/i.exec(remote);
  if (!remote) checks.push({ ...vis, status: "pass", detail: "No remote configured; nothing is hosted." });
  else if (!gh) checks.push({ ...vis, status: "skip", detail: "The origin remote is not on GitHub, so its visibility can't be checked from here.", fix: "Confirm in your host's settings that the repository is private." });
  else {
    const r = run(ctx, "gh", ["repo", "view", gh[1]!, "--json", "visibility", "-q", ".visibility"]);
    const v = String(r.stdout).trim().toUpperCase();
    checks.push(r.status !== 0 || !v
      ? { ...vis, status: "skip", detail: `Could not read ${gh[1]}'s visibility (GitHub CLI missing or not signed in).`, fix: "Install and sign in with `gh auth login`, or confirm in GitHub settings that the repository is private." }
      : v === "PUBLIC"
        ? { ...vis, status: "fail", detail: `${gh[1]} is PUBLIC. Public hosting of engagement codebases is prohibited unless approved.`, fix: "Make it private (Settings > Danger zone), or get written approval from the security lead. Assume anything already pushed was read." }
        : { ...vis, status: "pass", detail: `${gh[1]} is ${v.toLowerCase()}.` });
  }
  return checks;
}

async function extensionCheck(ctx: DoctorContext): Promise<Check> {
  const base = { id: "extensions", policy: "3", title: "VS Code extensions are approved" };
  const policy = await readPolicy().catch(() => null);
  const approved = (policy?.rules as { approvedExtensions?: string[] } | undefined)?.approvedExtensions;
  const list = run(ctx, "code", ["--list-extensions"]);
  if (list.status !== 0) return { ...base, status: "skip", detail: "The `code` command is not available, so installed extensions can't be listed." };
  if (!approved) return { ...base, status: "warn", detail: "No `approvedExtensions` allowlist in policy.json, so there is nothing to compare against. Policy 3 bans extensions that relay code or prompts unless approved.", fix: "Add `approvedExtensions: [\"publisher.name\", ...]` to policy.json." };
  const allowed = new Set(approved.map(s => s.toLowerCase()));
  const extra = String(list.stdout).split("\n").map(s => s.trim()).filter(Boolean).filter(id => !allowed.has(id.toLowerCase()));
  return extra.length ? { ...base, status: "warn", detail: `Not on the allowlist: ${extra.slice(0, 10).join(", ")}${extra.length > 10 ? ", …" : ""}.`, fix: "Review them for code/prompt relaying, then approve or remove." } : { ...base, status: "pass", detail: "All installed extensions are on the allowlist." };
}

// 6.1: the key must live in an OS env var or secrets manager, never in a file. Reports paths only.
function apiKeyStorage(ctx: DoctorContext): Check {
  const base = { id: "api-key-storage", policy: "6.1", title: "Anthropic API key storage" };
  const keyRe = /(?:ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN)["']?\s*[:=]\s*["']?(?:sk-ant-|[A-Za-z0-9_-]{20,})/;
  const files = [join(ctx.cwd, ".claude", "settings.local.json"), join(ctx.cwd, ".claude", "settings.json"), join(ctx.home, ".claude", "settings.json"), join(ctx.cwd, ".env"), join(ctx.cwd, ".env.local")];
  const inFiles = files.filter(f => { try { return keyRe.test(readFileSync(f, "utf8")); } catch { return false; } });
  if (inFiles.length) return { ...base, status: "fail", detail: `API key stored in a file: ${inFiles.join(", ")}.`, fix: "Remove it, rotate the key with Anthropic (Console > Settings > API keys), and export ANTHROPIC_API_KEY from the OS environment or use `apiKeyHelper` with a secrets manager (1Password, Credential Manager, Key Vault)." };
  const helper = [join(ctx.cwd, ".claude", "settings.local.json"), join(ctx.cwd, ".claude", "settings.json"), join(ctx.home, ".claude", "settings.json")].some(f => typeof readJson(f)?.apiKeyHelper === "string");
  if (helper) return { ...base, status: "pass", detail: "Key is provided by apiKeyHelper (a secrets manager command); no key found in files." };
  if (ctx.env.ANTHROPIC_API_KEY) return { ...base, status: "pass", detail: "Key comes from the ANTHROPIC_API_KEY environment variable; no key found in settings or .env files." };
  return { ...base, status: "skip", detail: "No API key in the environment or helper (the session may use another login). Nothing hard-coded was found." };
}

// 4.3 workspace isolation: customer data must not sit in the workspace Claude Code is running in.
// Heuristic: customer-data-looking file names, plus PII in a sample of data files. Never prints values.
function workspaceIsolation(ctx: DoctorContext): Check {
  const base = { id: "workspace-isolation", policy: "4.3", title: "No customer data in this workspace" };
  const nameRe = /(?:customers?|clients?|patients?|users?|members?|employees?|subscribers?|prod(?:uction)?[-_]?(?:dump|data|export|backup)|pii|phi)[\w.-]*\.(?:csv|tsv|sql|json|jsonl|ndjson|xlsx?|parquet|dump|bak)$|\.(?:dump|bak|sqlite3?|db)$/i;
  const skip = new Set([".git", "node_modules", "dist", "build", ".next", "coverage", "venv", ".venv", "__pycache__", "target"]);
  const testy = /(?:^|\/)(?:tests?|__tests__|fixtures?|mocks?|examples?|samples?|testdata|docs?)(?:\/|$)/i;
  const named: string[] = [], pii = new Map<string, Set<string>>();
  let seen = 0;
  const walk = (dir: string, rel: string, depth: number) => {
    if (depth > 4 || seen > 3000) return;
    let entries; try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!skip.has(e.name)) walk(join(dir, e.name), r, depth + 1); continue; }
      if (!e.isFile() || testy.test(r)) continue;
      seen++;
      if (nameRe.test(e.name)) named.push(r);
      if (/\.(?:csv|tsv|sql|jsonl|ndjson|json)$/i.test(e.name) && pii.size < 10) {
        try {
          const full = join(dir, e.name); if (statSync(full).size > 2_000_000) continue;
          const kinds = new Set(detectSensitive(readFileSync(full, "utf8").slice(0, 200_000)).filter(f => ["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IBAN", "NATIONAL_ID", "PASSPORT", "MRN", "HEALTH_PLAN_ID", "MEDICAL_ID", "PHI"].includes(f.kind) && f.confidence >= 0.8).map(f => f.kind));
          if (kinds.size >= 2 && /\.(?:csv|tsv|sql|jsonl|ndjson)$/i.test(e.name) || kinds.size >= 3) pii.set(r, kinds);
        } catch { /* unreadable */ }
      }
    }
  };
  walk(ctx.cwd, "", 0);
  const flagged = [...new Set([...named, ...pii.keys()])];
  if (!flagged.length) return { ...base, status: "pass", detail: `Scanned ${seen} files; no customer-data-looking files found.` };
  const list = flagged.slice(0, 6).map(f => pii.has(f) ? `${f} (${[...pii.get(f)!].join(", ")})` : f).join(", ");
  return { ...base, status: pii.size ? "fail" : "warn", detail: `Possible customer data in the workspace: ${list}${flagged.length > 6 ? ", …" : ""}.`, fix: "Move it out of this directory, or scrub it, before using Claude Code here (policy 4.3 Workspace Isolation)." };
}

// 8.2: incidents must reach the security lead within four hours. Reads Beam's own records only.
function incidentsCheck(ctx: DoctorContext): Check {
  const base = { id: "incidents", policy: "8.2", title: "Incidents reported within 4 hours" };
  const open = listIncidents(ctx.dataDir).filter(i => i.status === "open");
  const overdue = open.filter(i => urgency(i) === "overdue");
  const label = (i: (typeof open)[number]) => `${i.id} (${i.type}, ${timeLeft(i)})`;
  if (overdue.length) return { ...base, status: "fail", detail: `Past the 4-hour deadline: ${overdue.map(label).join(", ")}.`, fix: "Send each to the security lead now (`beam incident show <id>`), then `beam incident report <id> --to <name>`. Policy 8.2 also treats a late report as a violation to log." };
  if (open.length) return { ...base, status: "warn", detail: `Not yet reported: ${open.map(label).join(", ")}.`, fix: "Review with `beam incident show <id>`, send it, then `beam incident report <id> --to <name>`." };
  return { ...base, status: "pass", detail: "No open incidents." };
}

const unverifiable = (): Check[] => [
  { id: "api-tier", policy: "5.6", title: "Commercial API tier", status: "skip", detail: "Cannot be verified from this machine.", fix: "Confirm in the Anthropic Console that the key belongs to a commercial/API account." },
  { id: "workstation", policy: "6.3", title: "Workstation baseline (disk encryption, patching, screen lock)", status: "skip", detail: "Out of scope for Beam; verify with your endpoint management.", fix: "FileVault/BitLocker on, auto-update on, screen lock <= 5 minutes." },
];

export async function runDoctor(ctx: DoctorContext = defaultContext()): Promise<Check[]> {
  const policy = await readPolicy().catch(() => null);
  const ignore = (policy?.rules.gitGateIgnore ?? []).flatMap(p => { try { return [new RegExp(p)]; } catch { return []; } });
  const checks: Array<Check | Check[] | Promise<Check | Check[]>> = [
    hooksInstalled(ctx), policyEnforcement(), vaultProtected(ctx), memoryDisabled(ctx), networkEnv(ctx), claudeClient(ctx),
    wrapperAvailable(ctx), repoChecks(ctx, ignore), extensionCheck(ctx), apiKeyStorage(ctx), workspaceIsolation(ctx), incidentsCheck(ctx), unverifiable(),
  ];
  const out: Check[] = [];
  for (const entry of checks) {
    try { const value = await entry; out.push(...(Array.isArray(value) ? value : [value])); }
    catch (error) { out.push({ id: "internal", policy: "-", title: "Doctor check", status: "warn", detail: `A check failed to run: ${error instanceof Error ? error.message : String(error)}` }); }
  }
  return out;
}

const ICON: Record<Status, string> = { pass: "✓", warn: "!", fail: "✗", skip: "-" };
export function formatDoctor(checks: Check[]): string {
  const lines = ["beam doctor: Claude Code Secure Usage Policy checks", ""];
  for (const c of checks) {
    lines.push(` ${ICON[c.status]} ${c.status.toUpperCase().padEnd(4)}  ${c.title}  (policy ${c.policy})`);
    lines.push(`          ${c.detail}`);
    if (c.fix && c.status !== "pass") lines.push(`          Fix: ${c.fix}`);
  }
  const n = (s: Status) => checks.filter(c => c.status === s).length;
  lines.push("", `${n("pass")} passed, ${n("warn")} warnings, ${n("fail")} failed, ${n("skip")} not checkable.`);
  return lines.join("\n");
}
export const doctorExitCode = (checks: Check[]) => checks.some(c => c.status === "fail") ? 1 : 0;
