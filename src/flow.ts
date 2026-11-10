import { basename } from "node:path";
import { shellActionCommands } from "./credential-egress.js";
import type { ActionContext } from "./action-context.js";
import { narrateCommand, friendlyName, shortPath } from "./plain-explain.js";
import { PRIVATE_PATH, isTemplateEnvPath, touchesSecretContent, patchTargetText } from "./secret-use.js";
import { detectSensitive } from "./data-detectors.js";

/**
 * One small, redacted record per event that lets the dashboard draw the chain of steps in a session:
 * what each step did in plain words, what it touched, whether it sent anything outward, and what
 * came of it. Built deterministically from the event (no model, no network). Strings are short,
 * paths are trimmed to their last two segments, and no file or command output is ever included --
 * only counts of secret-looking values found in the output.
 *
 * Every field is optional beyond `v`/`label`/`kind`, and older CLI versions send none of it: the
 * dashboard falls back to the event's own summary for those, so nothing depends on this existing.
 */
export type FlowKind = "prompt" | "read" | "write" | "search" | "run" | "web" | "mcp" | "delete" | "git" | "other";
export type FlowOutward = { kind: "push" | "upload" | "post" | "publish" | "deploy"; target?: string };
export type FlowInfo = {
  v: 1;
  label: string;
  kind: FlowKind;
  effects?: { read?: string[]; wrote?: string[]; deleted?: string[]; hosts?: string[]; ran?: string[]; staged?: string[] };
  /** A private file's contents were opened by this step. */
  sensitive?: true;
  outward?: FlowOutward;
  /** Only with `outward`: does the same command reference a secret (a private file, a credential variable)? */
  carriesSensitive?: "yes" | "no-sign";
  outcome?: "ok" | "failed" | "denied" | "asked";
  /** From the tool's output, post-run only: how many secret-looking values appeared (never the values). */
  exposure?: { secrets: number; kinds?: string[] };
  toolUseId?: string;
  turn?: number;
};

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
const list = (items: (string | undefined)[], max = 6) => [...new Set(items.filter((x): x is string => !!x))].slice(0, max).map(x => clip(x, 70));
const hostOf = (url: string | undefined): string | undefined => {
  if (!url) return undefined;
  try { return new URL(/^[a-z]+:\/\//i.test(url) ? url : `https://${url}`).hostname.toLowerCase() || undefined; } catch { return undefined; }
};
const MCP_WRITE = /(?:create|update|delete|write|send|post|put|patch|execute|run|publish|deploy|remove|save|insert|add|grant|revoke|assign)/i;
const SECRET_KINDS = new Set(["SECRET", "API_KEY", "PASSWORD", "PRIVATE_KEY"]);
const CREDENTIAL_VAR = /\$\{?[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)*_(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)S?\}?/;

type Cmd = { cmd: string; args: string[] };
function commandsOf(command: string): Cmd[] {
  const out: Cmd[] = [];
  for (const c of shellActionCommands(command)) {
    const t = c.tokens; let at = 0;
    while (/^[A-Za-z_]\w*=/.test(t[at]?.value ?? "")) at++;
    if (t[at]?.value === "sudo") at++;
    const cmd = basename(t[at]?.value ?? "").toLowerCase();
    if (cmd) out.push({ cmd, args: t.slice(at + 1).map(x => x.value) });
  }
  return out;
}

const isPrivate = (p: string) => PRIVATE_PATH.test(p) && !isTemplateEnvPath(p);

/** What this command sends outward, if anything (a push, an upload, a POST, a publish, a deploy). */
function outwardOf(cmds: Cmd[], ctx: ActionContext | undefined, safe: (s: string) => string): FlowOutward | undefined {
  for (const { cmd, args } of cmds) {
    const sub = args.find(a => !a.startsWith("-"));
    if (cmd === "git" && sub === "push") return { kind: "push", target: ctx?.repository?.remote?.path ?? ctx?.repository?.name };
    if (/^(?:docker|podman)$/.test(cmd) && sub === "push") { const ref = args.filter(a => !a.startsWith("-"))[1]; return { kind: "push", target: ref ? clip(safe(ref.split(":")[0]), 70) : undefined }; }
    if (/^(?:npm|pnpm|yarn|bun)$/.test(cmd) && sub === "publish") return { kind: "publish", target: "package registry" };
    if (/^(?:twine|cargo|gem)$/.test(cmd) && /^(?:upload|publish|push)$/.test(sub ?? "")) return { kind: "publish", target: cmd };
    if (/^(?:vercel|netlify|railway|fly|flyctl|heroku|wrangler|firebase)$/.test(cmd) && (/^(?:deploy|up|publish|push|release)$/.test(sub ?? "") || args.includes("--prod"))) return { kind: "deploy", target: cmd };
    if (cmd === "gh" && /^(?:pr|gist|issue|release|repo)$/.test(sub ?? "") && /^(?:create|comment|edit|upload|merge)$/.test(args.filter(a => !a.startsWith("-"))[1] ?? "")) return { kind: "post", target: ctx?.repository?.remote?.path ?? "GitHub" };
    if (cmd === "aws" && sub === "s3") { const dest = args.find(a => /^s3:\/\//.test(a)); if (dest && /^(?:cp|sync|mv)$/.test(args.filter(a => !a.startsWith("-"))[1] ?? "")) return { kind: "upload", target: clip(safe(dest), 70) }; }
    if (/^(?:scp|rsync|sftp)$/.test(cmd)) { const remote = args.find(a => /^[^/\s-][^/\s]*@?[^/\s]*:/.test(a) && !a.startsWith("-")); if (remote) return { kind: "upload", target: clip(safe(remote.split(":")[0].replace(/^.*@/, "")), 70) }; }
    if (/^(?:curl|wget)$/.test(cmd)) {
      const url = args.find(a => /^https?:\/\//i.test(a.replace(/^["']|["']$/g, "")))?.replace(/^["']|["']$/g, "");
      const sends = args.some(a => /^(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-data|--post-file)$/.test(a) || /^-d.+/.test(a))
        || args.some((a, i) => /^(?:-X|--request)$/.test(a) && /^(?:POST|PUT|PATCH)$/i.test(args[i + 1] ?? ""));
      if (sends) return { kind: args.some(a => /^(?:-T|--upload-file|-F|--form)$/.test(a)) ? "upload" : "post", target: hostOf(url) };
    }
  }
  return undefined;
}

function referencesSecret(cmds: Cmd[], command: string): boolean {
  if (cmds.some(({ args }) => args.some(a => isPrivate(a.replace(/^@/, "")) || /@[^\s]*\.env\b/.test(a)))) return true;
  if (CREDENTIAL_VAR.test(command)) return true;
  // `git add .env && git push`: anything private staged earlier in the same command.
  return cmds.some(({ cmd, args }) => cmd === "git" && args[0] === "add" && args.slice(1).some(a => isPrivate(a)));
}

function exposureOf(toolResponse: unknown): FlowInfo["exposure"] | undefined {
  if (toolResponse === undefined || toolResponse === null) return undefined;
  let text: string;
  try { text = typeof toolResponse === "string" ? toolResponse : JSON.stringify(toolResponse); } catch { return undefined; }
  if (!text) return undefined;
  const found = detectSensitive(text.slice(0, 200_000)).filter(f => SECRET_KINDS.has(f.kind));
  const kinds = [...new Set(found.map(f => f.kind))].slice(0, 4);
  return { secrets: Math.min(found.length, 999), ...(kinds.length ? { kinds } : {}) };
}

export type FlowInput = {
  type: string; tool: string; command: string; path: string; url: string;
  phase?: string; policyAction?: string; promptTopic?: string;
  toolResponse?: unknown; toolUseId?: string; turn?: number;
  mcp?: { server: string; tool?: string }; context?: ActionContext;
  safe: (s: string) => string;
};

/** Builds the flow record for one event. Never throws. */
export function buildFlow(i: FlowInput): FlowInfo | undefined {
  try {
    const safe = i.safe;
    let label = "", kind: FlowKind = "other";
    let effects: NonNullable<FlowInfo["effects"]> = {};
    let sensitive: true | undefined, outward: FlowOutward | undefined, carries: FlowInfo["carriesSensitive"];

    if (i.type === "prompt.submit") { kind = "prompt"; label = i.promptTopic ? `You: “${clip(safe(i.promptTopic), 60)}”` : "You sent a message"; }
    else if (/^session\.start/.test(i.type)) label = "Session started";
    else if (/^session\.end/.test(i.type)) label = "Session ended";
    else if (/^message/.test(i.type)) label = "The agent replied";
    else if (i.type === "command.exec" && i.command) {
      const cmds = commandsOf(i.command);
      const narrated = narrateCommand(i.command, safe);
      const steps = narrated.steps;
      label = steps.length ? (steps.length === 1 ? steps[0] : `${steps[0]}, +${steps.length - 1} more`) : "ran a command";
      const actions = i.context?.actions ?? [];
      effects = {
        read: list(actions.filter(a => (a.operation === "file-read" || a.operation === "file-search" || a.operation === "source-search") && a.target && a.target !== "standard input").map(a => shortPath(a.target!, safe))),
        wrote: list(actions.filter(a => a.operation === "file-write").map(a => a.target && shortPath(a.target, safe))),
        deleted: list(actions.filter(a => a.operation === "delete").map(a => a.target && shortPath(a.target, safe))),
        hosts: list(actions.filter(a => a.operation === "network-request").map(a => hostOf(a.target))),
        ran: list(cmds.map(c => c.cmd).filter(c => !/^(?:cd|echo|printf|true|false|export|set|sleep|cut|wc|sort|uniq|tr|head|tail|xargs|tee)$/.test(c)), 5),
        staged: list(cmds.filter(c => c.cmd === "git" && c.args[0] === "add").flatMap(c => c.args.slice(1).filter(a => !a.startsWith("-")).map(a => (a === "." ? "everything" : shortPath(a, safe))))),
      };
      kind = actions.some(a => a.operation === "delete") ? "delete"
        : cmds.some(c => c.cmd === "git") ? "git"
        : actions.some(a => a.operation === "file-write") ? "write"
        : actions.some(a => a.operation === "network-request") ? "web"
        : actions.some(a => a.operation === "file-search" || a.operation === "source-search") ? "search"
        : actions.some(a => a.operation === "file-read") ? "read"
        : "run";
      outward = outwardOf(cmds, i.context, safe);
      if (outward) carries = referencesSecret(cmds, i.command) ? "yes" : "no-sign";
      const privateTouched = actions.some(a => isPrivate(a.resolvedPath ?? a.target ?? "")) || cmds.some(c => c.args.some(a => isPrivate(a)));
      if (privateTouched && i.context && touchesSecretContent(i.command, i.context)) sensitive = true;
    } else if (i.type === "file.read") { kind = "read"; label = i.path ? `read ${friendlyName(i.path, safe)}` : "read a file"; effects = { read: i.path ? list([shortPath(i.path, safe)]) : [] }; if (i.path && isPrivate(i.path)) sensitive = true; }
    else if (i.type === "file.write") {
      kind = "write";
      const patch = patchTargetText(i.command);
      const files = patch !== undefined ? patch.split("\n").filter(Boolean) : i.path ? [i.path] : [];
      label = files.length > 1 ? `edited ${files.length} files, starting with ${friendlyName(files[0], safe)}` : `edited ${files[0] ? friendlyName(files[0], safe) : "a file"}`;
      effects = { wrote: list(files.map(f => shortPath(f, safe))) };
    } else if (/^(?:browser\.navigate|web\.search)$/.test(i.type) || /^(?:WebFetch|WebSearch)$/i.test(i.tool)) {
      kind = "web"; const host = hostOf(i.url);
      label = host ? `looked at ${safe(host)}` : "searched the web"; if (host) effects = { hosts: [host] };
    } else if (i.mcp) {
      kind = "mcp"; label = `used ${safe(i.mcp.server)}${i.mcp.tool ? `: ${safe(i.mcp.tool)}` : ""}`;
      if (MCP_WRITE.test(i.mcp.tool ?? "")) { outward = { kind: "post", target: clip(safe(i.mcp.server), 70) }; carries = "no-sign"; }
    } else if (i.tool) label = `used ${safe(i.tool)}`;
    else return undefined;

    const outcome: FlowInfo["outcome"] =
      i.policyAction === "deny" ? "denied" : i.policyAction === "ask" ? "asked"
      : i.phase === "failed hook" ? "failed" : i.phase === "completed hook" ? "ok" : undefined;
    const exposure = exposureOf(i.toolResponse);
    const compact = Object.fromEntries(Object.entries(effects).filter(([, v]) => v && v.length)) as FlowInfo["effects"];
    return {
      v: 1, label: clip(label, 90), kind,
      ...(compact && Object.keys(compact).length ? { effects: compact } : {}),
      ...(sensitive ? { sensitive } : {}),
      ...(outward ? { outward, ...(carries ? { carriesSensitive: carries } : {}) } : {}),
      ...(outcome ? { outcome } : {}),
      ...(exposure ? { exposure } : {}),
      ...(i.toolUseId ? { toolUseId: clip(i.toolUseId, 80) } : {}),
      ...(i.turn ? { turn: i.turn } : {}),
    };
  } catch { return undefined; }
}
