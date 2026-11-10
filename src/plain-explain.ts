import { basename } from "node:path";
import { shellActionCommands } from "./credential-egress.js";
import type { ActionContext } from "./action-context.js";
import { PRIVATE_PATH, isTemplateEnvPath, touchesSecretContent, executedText } from "./secret-use.js";
import { commandsOf, hostOf, hostsIn, outwardFor, usesSecrets } from "./outbound.js";

/**
 * Event-specific plain-language facts, built without any model: what the agent actually did, step
 * by step, and -- for secret-looking files -- whether anything opened their contents. The dashboard
 * combines this with its own per-rule wording ("why it matters", "what to do") to show a non-technical
 * reader a 4-8 line explanation. Only short, redacted strings are produced; nothing here is a
 * detection verdict, it just narrates the command the detector already looked at.
 */
export type PlainExplanation = {
  v: 1;
  /** Ordered, everyday-language steps (at most 6, each at most 140 chars). */
  steps: string[];
  /** For private files: were their contents opened, or only their names listed/mentioned? */
  opened?: "contents" | "names-only" | "none";
  /** Friendly names of sensitive things involved (at most 4). */
  touched?: string[];
  /** A hint for triage, not a verdict: routine, worth a check, or risky. */
  verdict: "routine" | "check" | "risky";
  /** One sentence tying this event to the rule: what the detector saw vs. what really happened. */
  nuance?: string;
  /** Hosts the command contacts (curl/wget, and URLs inside inline scripts), at most 4. */
  contacted?: string[];
  /** A request the command sends outward, and whether credentials are in play in the same command. */
  sent?: { kind: "post" | "upload" | "push" | "publish" | "deploy"; target?: string; withSecret: boolean };
};

const MAX_STEPS = 6;
const clip = (s: string, n = 140) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

// Pipe tails and plumbing: they shape output but are not an action worth narrating.
const PLUMBING = new Set(["cut", "wc", "sort", "uniq", "tr", "awk", "xargs", "tee", "cd", "echo", "printf", "true", "false", "export", "set", "unset", "sleep", "clear", "pwd", "[", "[[", "test", "read", "exit", "wait", "alias", "time", "nohup"]);

/** Last two path segments, no quotes -- the form used inside data fields. */
export function shortPath(path: string, safe: (s: string) => string): string {
  const clean = path.replace(/^["']|["']$/g, "");
  if (/[$`]/.test(clean)) return "a file chosen by the command";
  const parts = clean.replace(/\/+$/, "").split("/").filter(Boolean);
  return safe(parts.length > 2 ? parts.slice(-2).join("/") : parts.join("/") || clean);
}
/** Quoted friendly name for reading in a sentence. */
export const friendlyName = (path: string, safe: (s: string) => string): string => nice(path, safe);

function nice(path: string, safe: (s: string) => string): string {
  const clean = path.replace(/^["']|["']$/g, "");
  if (/[$`]/.test(clean)) return "a file chosen by the command";
  if (/[*?]/.test(clean)) return `files matching “${safe(clean.split("/").pop() ?? clean)}”`;
  const parts = clean.replace(/\/+$/, "").split("/").filter(Boolean);
  const tail = parts.length > 2 ? parts.slice(-2).join("/") : parts.join("/") || clean;
  return `“${safe(tail)}”`;
}
const list = (items: string[], max = 3) => (items.length > max ? `${items.slice(0, max).join(", ")} and ${items.length - max} more` : items.join(", "));
const GIT: Record<string, string> = {
  status: "checked which files changed in git", diff: "looked at code changes in git", log: "looked at the commit history",
  add: "staged files in git", commit: "saved a git commit", push: "pushed code to the shared repository", pull: "pulled the latest code",
  checkout: "switched git branches", branch: "looked at git branches", stash: "set changes aside in git", reset: "reset git state",
  clean: "removed untracked files with git", "ls-files": "asked git which files it tracks", "check-ignore": "asked git whether a file is ignored",
  rm: "removed files through git", mv: "moved files through git", merge: "merged branches", rebase: "rewrote branch history", fetch: "fetched updates",
};

function describe(cmd: string, args: string[], safe: (s: string) => string, command = ""): string | undefined {
  const files = args.filter(a => !a.startsWith("-") && !/^\d+(?:,\d+)?p?$/.test(a));
  if (/^(?:cat|head|tail|less|more|nl|bat|xxd|strings|od|sed)$/.test(cmd)) {
    // sed's first non-option argument is its script (1,40p), not a file.
    const target = cmd === "sed" ? args.filter(a => !a.startsWith("-")).slice(1) : files;
    if (!target.length) return undefined; // reading a pipe, not a file
    const range = cmd === "sed" ? args.join(" ").match(/-n\s+['"]?(\d+),(\d+)p/) : cmd === "head" || cmd === "tail" ? args.join(" ").match(/-n?\s*(\d+)\b/) : null;
    const how = range ? (range[2] ? `lines ${range[1]}–${range[2]} of ` : `${cmd === "head" ? "the first" : "the last"} ${range[1]} lines of `) : "";
    return `read ${how}${list(target.map(f => nice(f, safe)))}`;
  }
  if (/^(?:ls|ll|la|tree|stat|file)$/.test(cmd)) {
    if (!files.length) return "listed the files in the current folder";
    return files.length === 1 && /[*?]/.test(files[0]) ? `listed ${nice(files[0], safe)}` : `listed the files in ${list(files.map(f => nice(f, safe)))}`;
  }
  if (cmd === "find") return `searched for files${files[0] ? ` under ${nice(files[0], safe)}` : ""}`;
  if (/^(?:grep|egrep|rg|ag|ack)$/.test(cmd)) {
    const pattern = files[0], where = files.slice(1);
    const what = pattern && !/[|\\^$]{2,}/.test(pattern) ? ` for “${clip(safe(pattern.replace(/^["']|["']$/g, "")), 28)}”` : "";
    return where.length ? `searched ${list(where.map(f => nice(f, safe)))}${what}` : `filtered the output${what}`;
  }
  if (cmd === "git") return GIT[args.find(a => !a.startsWith("-")) ?? ""] ?? "ran a git command";
  if (/^(?:npm|pnpm|yarn|bun|bunx|npx)$/.test(cmd)) {
    const sub = args.find(a => !a.startsWith("-"));
    if (sub === "run" || (cmd === "bun" && sub === "run")) return `ran the project's “${safe(args[args.indexOf("run") + 1] ?? "script")}” command`;
    if (sub === "install" || sub === "i" || sub === "add") return "installed packages";
    if (cmd === "npx" || cmd === "bunx") return `ran the tool “${safe(sub ?? "")}” on demand`;
    return `ran ${cmd} ${safe(sub ?? "")}`.trim();
  }
  if (/^(?:python[\d.]*|node|deno|ruby|perl|php)$/.test(cmd)) {
    const language = /^python/.test(cmd) ? "Python" : ({ node: "Node", deno: "Deno", ruby: "Ruby", perl: "Perl", php: "PHP" } as Record<string, string>)[cmd]!;
    const at = args.findIndex(a => /^(?:-e|-p|-pe|--eval|--print|-c)$/.test(a));
    const contacts = (hosts: string[]) => (hosts.length ? ` that contacts ${hosts.length <= 3 ? hosts.join(", ").replace(/, ([^,]*)$/, " and $1") : list(hosts, 3)}` : "");
    if (at >= 0) return `ran an inline ${language} script${contacts(hostsIn(args[at + 1] ?? ""))}`; // the code is the argument, not a file
    if (args.some(a => a === "-")) return `ran a short ${language} script typed into the command${contacts(hostsIn(executedText(command)))}`;
    return files[0] ? `ran the script ${nice(files[0], safe)}` : `ran a short ${language} script`;
  }
  if (/^(?:curl|wget)$/.test(cmd)) {
    const url = args.find(a => /^https?:\/\//i.test(a.replace(/^["']|["']$/g, "")));
    const host = url ? url.replace(/^["']/, "").replace(/^https?:\/\//i, "").split(/[/?#"']/)[0] : undefined;
    return `contacted ${host ? safe(host) : "a web address"}${args.some(a => /^-[a-zA-Z]*[oO]$|^--output/.test(a)) ? " and saved the response" : ""}`;
  }
  if (cmd === "rm") return `deleted ${list(files.map(f => nice(f, safe))) || "files"}${args.some(a => /^-[a-z]*r/i.test(a)) ? " (including everything inside)" : ""}`;
  if (cmd === "mkdir") return `created the folder ${list(files.map(f => nice(f, safe)))}`;
  if (cmd === "cp") return `copied ${files.length > 1 ? nice(files[0], safe) : "files"}${files.length > 1 ? ` to ${nice(files[files.length - 1], safe)}` : ""}`;
  if (cmd === "mv") return `moved ${files.length > 1 ? nice(files[0], safe) : "files"}${files.length > 1 ? ` to ${nice(files[files.length - 1], safe)}` : ""}`;
  if (cmd === "touch") return `created the file ${list(files.map(f => nice(f, safe)))}`;
  if (cmd === "chmod" || cmd === "chown") return "changed who is allowed to use a file";
  if (/^(?:pkill|kill|killall|lsof|ps|pgrep)$/.test(cmd)) return "stopped or looked at a running program";
  if (/^(?:psql|mysql|sqlite3|mongosh|redis-cli)$/.test(cmd)) return "ran a database command";
  if (/^(?:docker|podman|kubectl|helm|terraform|aws|gcloud|az|vercel|railway|fly|gh|heroku)$/.test(cmd)) return `used the ${cmd} command-line tool`;
  if (/^(?:source|\.)$/.test(cmd)) return files[0] ? `loaded settings from ${nice(files[0], safe)}` : "loaded a settings file";
  if (cmd === "env" || cmd === "printenv") return args.some(a => !a.startsWith("-")) ? "looked up a named setting" : "listed all of the computer's hidden settings";
  if (/^(?:sed|awk)$/.test(cmd)) return undefined;
  return `ran “${safe(cmd)}”`;
}

/** Steps for a shell command, in order, with plumbing left out and repeats merged. */
export function narrateCommand(command: string, safe: (s: string) => string): { steps: string[]; admin: boolean } {
  const all: string[] = []; let admin = false;
  const heredocEditor = /<<-?\s*['"]?\w+['"]?/.test(command) && /\.write_text\(|\.write\(|writeFile(?:Sync)?\(|open\([^)]*['"][wa]b?['"]/.test(command);
  for (const c of shellActionCommands(command)) {
    const t = c.tokens; let at = 0;
    while (/^[A-Za-z_]\w*=/.test(t[at]?.value ?? "")) at++;
    if (t[at]?.value === "sudo") { admin = true; at++; }
    const cmd = basename(t[at]?.value ?? "").toLowerCase();
    if (!cmd) continue;
    // Redirections (`2>/dev/null`, `> out.log`) are plumbing, not things the command acted on -- except
    // that a redirect into a real file is worth saying ("wrote to ...").
    const raw = t.slice(at + 1).map(x => x.value); const args: string[] = []; let out: string | undefined;
    for (let i = 0; i < raw.length; i++) {
      if (/^(?:\d*>>?|&>>?|<)$/.test(raw[i])) { if (!raw[i].startsWith("<") && raw[i + 1] && raw[i + 1] !== "/dev/null") out = raw[i + 1]; i++; continue; }
      if (/^(?:\d*>>?|&>>?|<)\S/.test(raw[i])) { const target = raw[i].replace(/^(?:\d*>>?|&>>?)/, ""); if (!raw[i].startsWith("<") && target && target !== "/dev/null" && !target.startsWith("&")) out = target; continue; }
      if (/^\d*>&\d*$/.test(raw[i])) continue;
      args.push(raw[i]);
    }
    const plumbing = PLUMBING.has(cmd);
    if (plumbing && !(out && /^(?:echo|printf)$/.test(cmd))) continue;
    let text = plumbing ? undefined : describe(cmd, args, safe, command);
    if (out) text = text ? `${text}, saving the output to ${nice(out, safe)}` : `wrote to ${nice(out, safe)}`;
    if (!text) continue;
    if (all.includes(text)) continue;
    all.push(text);
  }
  if (heredocEditor && !all.some(s => /script/.test(s))) all.unshift("ran a short script that edits files");
  const steps = all.length > MAX_STEPS ? [...all.slice(0, MAX_STEPS - 1), `and ${all.length - (MAX_STEPS - 1)} more steps`] : all;
  return { steps: steps.map(s => clip(s)), admin };
}

const ACCESS_RULES = new Set(["credentials.environment", "credentials.access", "source.private_files"]);

/** Builds the event-specific explanation. Returns undefined when there is nothing useful to narrate. */
export function explainFinding(input: {
  ruleId: string; severity: string; command: string; context?: ActionContext; safe: (s: string) => string;
}): PlainExplanation | undefined {
  const { ruleId, severity, command, context, safe } = input;
  if (!command.trim()) return undefined;
  const narrated = narrateCommand(command, safe);
  const steps = narrated.steps;
  if (!steps.length) return undefined;

  const privateNames = new Set<string>();
  for (const a of context?.actions ?? []) {
    const p = a.resolvedPath ?? a.target ?? "";
    if (p && PRIVATE_PATH.test(p) && !isTemplateEnvPath(p)) privateNames.add(basename(p) || p);
  }
  for (const m of executedText(command).matchAll(/(?:^|[\s/"'=])(\.env(?:\.[\w-]+)?|\.npmrc|\.netrc|\.pgpass|id_(?:rsa|ed25519)|credentials\.json)(?![\w.])/g)) {
    if (!isTemplateEnvPath(m[1])) privateNames.add(m[1]);
  }
  const touched = [...privateNames].slice(0, 4).map(n => clip(safe(n), 60));

  let opened: PlainExplanation["opened"];
  let nuance: string | undefined;
  if (ACCESS_RULES.has(ruleId)) {
    const dump = context?.actions.some(a => a.operation === "environment-dump");
    const lookup = context?.actions.some(a => a.operation === "environment-lookup");
    if (touched.length) {
      opened = context && touchesSecretContent(command, context) ? "contents" : "names-only";
      nuance = opened === "contents"
        ? `It opened ${list(touched)}, so its contents may have been shown to the agent.`
        : `${list(touched)} was only listed or mentioned; nothing opened its contents, so no secret was exposed.`;
    } else if (ruleId === "credentials.environment") {
      nuance = dump ? "It listed every hidden setting at once, which can include passwords and keys."
        : lookup ? "It looked up a single named setting, not the whole set."
        : "The detector saw the word “env”, but the command did not list the computer's settings.";
      opened = dump || lookup ? "contents" : "none";
    } else {
      opened = "none";
      nuance = "The command only mentions a credential-related word; it did not open a secret file.";
    }
  }

  // What the command reaches out to, and whether it sends something using credentials.
  const cmds = commandsOf(command);
  const contacted = [...new Set([...(context?.actions ?? []).filter(a => a.operation === "network-request").map(a => hostOf(a.target)).filter((h): h is string => !!h), ...hostsIn(executedText(command))])].slice(0, 4);
  const outward = outwardFor(command, cmds, context, safe);
  const sent = outward ? { kind: outward.kind, ...(outward.target ? { target: outward.target } : {}), withSecret: usesSecrets(command, cmds, context) } : undefined;

  let verdict: PlainExplanation["verdict"] = "check";
  if (severity === "critical" || opened === "contents" || (!ACCESS_RULES.has(ruleId) && severity === "high" && narrated.admin)) verdict = "risky";
  else if (ACCESS_RULES.has(ruleId) && (opened === "none" || opened === "names-only")) verdict = "routine";
  else if (severity === "low" || severity === "info") verdict = "routine";

  if (sent?.withSecret && verdict === "routine") verdict = "check";
  return { v: 1, steps, ...(opened ? { opened } : {}), ...(touched.length ? { touched } : {}), verdict, ...(nuance ? { nuance: clip(nuance, 220) } : {}), ...(contacted.length ? { contacted } : {}), ...(sent ? { sent } : {}) };
}
