import { basename } from "node:path";
import { heredocBlocks, shellActionCommands } from "./credential-egress.js";
import type { ActionContext } from "./action-context.js";

// "Does this command USE a secret, or just mention one?" Agents constantly edit, grep and list
// files whose text contains ".env", "credentials" or "process.env" -- writing code that reads
// config, checking .gitignore, searching for a variable name. None of that opens a secret file.
// The shapes that do are loading a dotenv file, reading/copying/printing a private path, or
// handing one to a program that can read it.

const PIPES_TO_INTERPRETER = /\|\s*(?:sudo\s+)?(?:(?:ba|z|fi|da)?sh|python[\d.]*|node|bun|ruby|perl|php)\b/;
const INTERPRETER_HEREDOC = /\b(?:python[23]?|node|bun|deno|ruby|perl|php|bash|sh|zsh|psql|mysql|sqlite3)\b[^<\n]*$/;

/** The text that is actually executed: heredoc bodies that are only data (written to a file with
 * cat/tee, or a git/gh message body) are removed; code fed to an interpreter stays. */
export function executedText(text: string): string {
  const blocks = heredocBlocks(text);
  if (!blocks.length) return text;
  let out = ""; let at = 0;
  for (const b of blocks) {
    const opener = b.header.slice(0, b.header.search(/<</)); // what the heredoc is fed to
    if ((INTERPRETER_HEREDOC.test(opener) && !/(?:^|[;&|]\s*)(?:cat|tee)\b[^;&|]*$/.test(opener)) || PIPES_TO_INTERPRETER.test(b.header.slice(b.header.search(/<</)))) continue;
    out += text.slice(at, b.start); at = b.end;
  }
  return out + text.slice(at);
}

export const PRIVATE_PATH = /(?:^|[/\\])\.env(?:[.\\/][\w.-]*)?$|(?:^|[/\\])\.env(?:\.[\w-]+)?(?![\w.])|\.ssh[/\\]|\.aws[/\\]credentials\b|id_(?:rsa|ed25519)|\.npmrc\b|\.netrc\b|kubeconfig|\.pgpass\b|credentials\.json|\.docker[/\\]config\.json|\.gnupg[/\\]/i;

/** Committed templates (.env.example, .env.sample, ...) hold placeholders, not secrets. */
const TEMPLATE_ENV = /\.env(?:\.[\w-]+)*\.(?:example|sample|template|dist|defaults?)$/i;
export const isTemplateEnvPath = (path: string) => TEMPLATE_ENV.test(path.trim());
export const isPrivatePath = (path: string) => PRIVATE_PATH.test(path) && !isTemplateEnvPath(path);

// Code that loads or reads a secret file's contents.
const CONTENT_LOAD = new RegExp([
  String.raw`\bload_dotenv\s*\(`, String.raw`\bdotenv_values\s*\(`, String.raw`\bdotenv\.config\s*\(`,
  String.raw`\b(?:from|import)\s+dotenv\b`, String.raw`require\(\s*['"]dotenv`,
  String.raw`\b(?:open|readFileSync|readFile|read_text|read_bytes|Path)\s*\([^)\n]{0,160}(?:\.env\b(?!\.(?:example|sample|template|dist|defaults?)\b)|\.aws[/\\]credentials|\.ssh[/\\]|id_(?:rsa|ed25519)|credentials\.json|\.netrc|\.pgpass)`,
  String.raw`(?:^|[;&|\s])(?:source|\.)\s+[^\s;&|]*\.env\b(?!\.(?:example|sample|template|dist|defaults?)\b)`, String.raw`\$\(\s*cat\s+[^)]*\.env\b(?!\.(?:example|sample|template|dist|defaults?)\b)`,
  String.raw`--env-file[=\s]+\S*\.env\b(?!\.(?:example|sample|template|dist|defaults?)\b)`,
].join("|"), "i");

// Commands that take a path but never open its contents.
const METADATA_ONLY = new Set(["ls","ll","la","stat","file","test","[","[[","find","pgrep","pkill","which","type","command","mkdir","touch","chmod","chown","wc","echo","printf","true","false","pwd","dirname","basename","realpath","readlink","cd","git-check-ignore"]);
const GIT_METADATA = new Set(["ls-files","check-ignore","status","rev-parse","ls-tree","add","rm","reset","restore","clean","log","branch","remote","config","stash","blame-ignore"]);

function metadataOnly(cmd: string, args: string[]): boolean {
  if (METADATA_ONLY.has(cmd)) return true;
  if (cmd === "git") return GIT_METADATA.has(args.find(a => !a.startsWith("-")) ?? "");
  if (cmd === "grep" || cmd === "rg") return args.some(a => /^-[a-zA-Z]*[lLcq][a-zA-Z]*$/.test(a) || a === "--files-with-matches" || a === "--count" || a === "--quiet");
  return false;
}

/** True when the command opens, loads, copies or feeds a secret file's contents to something. */
export function touchesSecretContent(text: string, context: ActionContext): boolean {
  if (context.actions.some(a => ["file-read","file-search","file-write"].includes(a.operation) && isPrivatePath(a.resolvedPath ?? a.target ?? ""))) return true;
  if (CONTENT_LOAD.test(executedText(text))) return true;
  for (const c of shellActionCommands(text)) {
    const tokens = c.tokens; let at = 0;
    while (/^[A-Za-z_]\w*=/.test(tokens[at]?.value ?? "")) at++;
    if (tokens[at]?.value === "sudo") at++;
    const cmd = basename(tokens[at]?.value ?? "").toLowerCase();
    const args = tokens.slice(at + 1).map(t => t.value);
    if (!cmd || !args.some(a => isPrivatePath(a))) continue;
    if (!metadataOnly(cmd, args)) return true;
  }
  return false;
}

/** For an apply_patch-style edit ("*** Begin Patch ... *** Update File: path"), the files it
 * touches, one per line. The patch body is code being written, not something that runs, so the
 * secret-access rules should judge the edit by its targets. Undefined for any other text. */
export function patchTargetText(text: string): string | undefined {
  if (!/^\s*\*\*\* Begin Patch\b/.test(text)) return undefined;
  return [...text.matchAll(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+?)\s*$|^\*\*\* Move to:\s*(.+?)\s*$/gm)].map(m => m[1] ?? m[2]).filter(path => !isTemplateEnvPath(path)).join("\n");
}

const SOURCE_PATH = /^[^\s'"]+\.(?:tsx?|jsx?|mjs|cjs|py|go|rs|rb|java|kt|swift|php|cs|cpp|c|h|vue|svelte|css|scss|html|md|mdx|json|ya?ml|toml|sql|sh)$/i;
/** True for a lone path to an ordinary source/doc file ("lib/account-password.ts"). The name of
 * such a file says nothing about credentials, so word matches like "password" don't count; only
 * actual secret-file paths do (see `credentials.access`). */
export const isSourceFilePath = (text: string) => SOURCE_PATH.test(text.trim()) && !PRIVATE_PATH.test(text.trim());

// A python/node heredoc that only reads a file, rewrites it and writes it back cannot run the
// command-looking strings it contains ("curl | bash", "rm -rf", "truncate text"): they are text
// being edited. A body that spawns processes, deletes, fetches, evals or opens a secret file is
// not treated that way.
const EDITS_FILE = /\.write_text\(|\.write\(|\bwriteFile(?:Sync)?\(|\bopen\([^)]*['"][wa]b?['"]/;
const DOES_THINGS = /\bsubprocess\b|\bPopen\b|\bos\.(?:system|popen|remove|unlink|rmdir|removedirs|exec\w*|spawn\w*)\b|\bshutil\b|\brmtree\b|\bunlink\b|\bexec\s*\(|\beval\s*\(|child_process|\bspawn(?:Sync)?\s*\(|\bexec(?:Sync|File)?\s*\(|\bfs\.(?:rm|rmdir|unlink)|\brmSync\b|\brequests\.|\burllib\b|\burlopen\b|\bfetch\s*\(|\bsocket\b|\bsystem\s*\(/;
// String literals removed, so words inside the file content being written ("subprocess",
// "requests.", "exec(") don't make a plain editing script look like it does things.
const STRINGS = /"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`/g;
export function withoutEditorScripts(text: string): string {
  const blocks = heredocBlocks(text);
  if (!blocks.length) return text;
  let out = ""; let at = 0;
  for (const b of blocks) {
    const opener = b.header.slice(0, b.header.search(/<</));
    const body = text.slice(b.start, b.end);
    if (!INTERPRETER_HEREDOC.test(opener) || /(?:^|[;&|]\s*)(?:cat|tee)\b[^;&|]*$/.test(opener)) continue;
    if (!EDITS_FILE.test(body) || DOES_THINGS.test(body.replace(STRINGS, '""')) || CONTENT_LOAD.test(body)) continue;
    out += text.slice(at, b.start); at = b.end;
  }
  return out + text.slice(at);
}

/** Files an agent writes that run later WITHOUT any further action it takes: shell startup files,
 * cron, systemd/launchd units, authorized_keys -- plus shell scripts, which we stay careful with. */
const STARTUP_OR_SCRIPT = /(?:^|\/)(?:\.(?:bash|zsh|z)?(?:rc|profile|env|login|logout)|\.bash_aliases|crontab|authorized_keys|[^/]*\.(?:sh|bash|zsh|command|ps1|bat|cmd|service|plist|timer))$|^\/etc\/|\/cron[^/]*\/|\/LaunchAgents\/|\/systemd\//i;
export const isStartupOrScriptPath = (path: string) => STARTUP_OR_SCRIPT.test(path.trim());

/** Heredoc bodies that are only data written to a file (cat/tee > f <<EOF) or a message body.
 * Nothing in them runs. Kept: bodies fed to an interpreter or piped into one, and bodies written to
 * a startup or script file. */
export function withoutDataHeredocs(text: string): string {
  const blocks = heredocBlocks(text);
  if (!blocks.length) return text;
  let out = ""; let at = 0;
  for (const b of blocks) {
    const marker = b.header.search(/<</);
    const opener = b.header.slice(0, marker), rest = b.header.slice(marker);
    if (INTERPRETER_HEREDOC.test(opener) && !/(?:^|[;&|]\s*)(?:cat|tee)\b[^;&|]*$/.test(opener)) continue;
    if (PIPES_TO_INTERPRETER.test(rest)) continue;
    const target = /(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?([^\s"'<>|;&]+)/.exec(b.header)?.[1];
    if (target && isStartupOrScriptPath(target)) continue;
    out += text.slice(at, b.start); at = b.end;
  }
  return out + text.slice(at);
}
