import { basename } from "node:path";
import { shellActionCommands } from "./credential-egress.js";
import type { ActionContext } from "./action-context.js";
import { PRIVATE_PATH, isTemplateEnvPath, touchesSecretContent, executedText } from "./secret-use.js";

/**
 * What a command sends outside the machine, and whether it does so with credentials. Shared by the
 * per-event flow record (flow.ts) and the plain-language narration (plain-explain.ts) so they can
 * never disagree. Deterministic and offline: it only reads the command text.
 */
export type FlowOutward = { kind: "push" | "upload" | "post" | "publish" | "deploy"; target?: string };
const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
export const hostOf = (url: string | undefined): string | undefined => {
  if (!url) return undefined;
  try { return new URL(/^[a-z]+:\/\//i.test(url) ? url : `https://${url}`).hostname.toLowerCase() || undefined; } catch { return undefined; }
};

const CREDENTIAL_VAR = /\$\{?[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)*_(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)S?\}?/;

export type Cmd = { cmd: string; args: string[] };
export function commandsOf(command: string): Cmd[] {
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

export const isPrivate = (p: string) => PRIVATE_PATH.test(p) && !isTemplateEnvPath(p);

/** What this command sends outward, if anything (a push, an upload, a POST, a publish, a deploy). */
export function outwardOf(cmds: Cmd[], ctx: ActionContext | undefined, safe: (s: string) => string): FlowOutward | undefined {
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

export function referencesSecret(cmds: Cmd[], command: string): boolean {
  if (cmds.some(({ args }) => args.some(a => isPrivate(a.replace(/^@/, "")) || /@[^\s]*\.env\b/.test(a)))) return true;
  if (CREDENTIAL_VAR.test(command)) return true;
  // `git add .env && git push`: anything private staged earlier in the same command.
  return cmds.some(({ cmd, args }) => cmd === "git" && args[0] === "add" && args.slice(1).some(a => isPrivate(a)));
}


// ---- hosts named anywhere in the command, including inside inline scripts ------------------------
const URL_HOST = /\bhttps?:\/\/([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::\d+)?/g;
/** Distinct host names from URLs in the text (at most `max`). */
export function hostsIn(text: string, max = 4): string[] {
  const seen = new Set<string>();
  for (const m of text.matchAll(URL_HOST)) { seen.add(m[1]!.toLowerCase()); if (seen.size >= max) break; }
  return [...seen];
}

// ---- requests that inline code sends (curl/wget are handled by outwardOf above) ------------------
const INLINE_SENDS: RegExp[] = [
  /\bfetch\s*\(\s*([`"'])(https?:\/\/[^`"']+)\1[^;]{0,600}?\bmethod\s*:\s*["'](?:POST|PUT|PATCH)["']/i,
  /\b(?:requests|httpx)\.(?:post|put|patch)\s*\(\s*([`"'])(https?:\/\/[^`"']+)\1/i,
  /\baxios\.(?:post|put|patch)\s*\(\s*([`"'])(https?:\/\/[^`"']+)\1/i,
  /\burlopen\s*\(\s*(?:urllib\.request\.)?Request\s*\(\s*([`"'])(https?:\/\/[^`"']+)\1[^)]{0,300}?\bdata\s*=/i,
];
/** A POST/PUT/PATCH that a Node or Python script in the command sends. */
export function inlineOutward(text: string): FlowOutward | undefined {
  for (const re of INLINE_SENDS) {
    const m = re.exec(text);
    if (m) { const target = hostOf(m[2]); return { kind: "post", ...(target ? { target } : {}) }; }
  }
  return undefined;
}
/** Everything the command sends outward: shell tools first, then requests made by inline code. */
export function outwardFor(command: string, cmds: Cmd[], ctx: ActionContext | undefined, safe: (s: string) => string): FlowOutward | undefined {
  return outwardOf(cmds, ctx, safe) ?? inlineOutward(executedText(command));
}

// ---- does the command use credentials? -----------------------------------------------------------
const CODE_CREDENTIAL_ENV = /\bprocess\.env(?:\.|\[\s*['"])[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)|\bos\.environ(?:\.get)?\s*[\[(]\s*['"][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)|\bgetenv\s*\(\s*['"][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)/;
/**
 * True when the command loads a private settings file (`set -a; . .env`, `source .env`, `load_dotenv`),
 * references a credential variable, or reads a credential-named variable in inline code. This is
 * "credentials are in play", not proof that a given value was sent.
 */
export function usesSecrets(command: string, cmds: Cmd[], ctx: ActionContext | undefined): boolean {
  if (referencesSecret(cmds, command)) return true;
  if (ctx && touchesSecretContent(command, ctx)) return true;
  return CODE_CREDENTIAL_ENV.test(executedText(command));
}
