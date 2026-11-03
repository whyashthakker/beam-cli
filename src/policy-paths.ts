import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyActionContext } from "./action-context.js";
import { shellActionCommands } from "./credential-egress.js";

export type PolicyPathTarget = { path: string; eventType: string };
type Request = { path?: string; cwd?: string; command: string; tool: string; eventType?: string; input?: Record<string, unknown> };
const PATH_KEYS = /^(?:file_path|filePath|file_paths|filePaths|absolute_path|absolutePath|relative_path|relativePath|path|paths|files|filename|fileName|file|target_file|targetPath|directory|directory_path|directories|directoryPath|dir|folder|folders|target|source|destination|root_path|rootPath|search_path|searchPath|uri)$/;
const CODE_KEYS = /^(?:code|script|expression|patch|patchText|patch_text|diff)$/;

/** Resolve aliases without opening file contents, including a missing leaf below a symlink. */
export function canonicalPolicyPath(value: string, cwd?: string): string | undefined {
  if (!value || value.includes("\0")) return undefined;
  if (value.startsWith("file://")) {
    try { value = fileURLToPath(value); } catch { return undefined; }
  }
  if (value === "~" || value.startsWith("~/")) value = homedir() + value.slice(1);
  if (!isAbsolute(value) && !cwd) return undefined;
  const absolute = resolve(cwd || "/", value);
  const suffix: string[] = [];
  let parent = absolute;
  for (;;) {
    try { return resolve(realpathSync(parent), ...suffix); } catch { /* look for an existing ancestor */ }
    const next = dirname(parent);
    if (next === parent) return absolute;
    suffix.unshift(basename(parent));
    parent = next;
  }
}

/** Canonicalize the static part of a policy pattern; preserve its glob suffix. */
export function canonicalPolicyPattern(pattern: string, cwd?: string): string | undefined {
  const wildcard = pattern.search(/[*?]/);
  if (wildcard < 0) return canonicalPolicyPath(pattern, cwd);
  const slash = pattern.lastIndexOf("/", wildcard);
  if (slash < 0) return undefined;
  const root = canonicalPolicyPath(pattern.slice(0, slash) || "/", cwd);
  return root === undefined ? undefined : `${root === "/" ? "" : root}/${pattern.slice(slash + 1)}`;
}

/** Targets visible in hook arguments or static shell syntax, shared by every agent adapter.
 * This is a preflight check, not an OS sandbox for arbitrary programs. */
export function policyPathTargets(request: Request): PolicyPathTarget[] {
  const targets: PolicyPathTarget[] = [];
  const seen = new Set<string>();
  const cwd = request.cwd;
  const add = (path: unknown, eventType = request.eventType || "file.read", working = cwd) => {
    if (typeof path !== "string" || !path || path.length > 16384 || /^https?:\/\//i.test(path)) return;
    const key = `${eventType}\0${working}\0${path}`;
    if (!seen.has(key)) { seen.add(key); targets.push({ path: canonicalPolicyPath(path, working) ?? path, eventType }); }
  };
  const readType = /^(?:command.exec|tool.call|directory.read|file.search)$/.test(request.eventType ?? "") ? "file.read" : request.eventType;
  add(request.path, readType);
  const walk = (value: unknown, depth: number, pathField = false) => {
    if (depth > 12) return;
    if (typeof value === "string") { if (pathField) add(value, readType); return; }
    if (Array.isArray(value)) { for (const entry of value) walk(entry, depth + 1, pathField); return; }
    if (value && typeof value === "object") {
      for (const [key, entry] of Object.entries(value)) {
        if (CODE_KEYS.test(key) && typeof entry === "string") literals(entry);
        walk(entry, depth + 1, PATH_KEYS.test(key));
      }
    }
  };
  // Literal file paths in scripts/patches can be checked even for unfamiliar tools.
  const literals = (code: string, working = cwd) => {
    for (const match of code.matchAll(/["'`]([^"'`\n]+)["'`]/g)) {
      if (/^(?:\/|\.\.?\/|~\/|file:\/\/)/.test(match[1])) add(match[1], "file.read", working);
    }
    for (const match of code.matchAll(/^\*\*\* (?:Update|Add|Delete) File:\s*(.+)$/gm)) add(match[1].trim(), "file.write", working);
    for (const match of code.matchAll(/(?:\bopen|\breadFile(?:Sync)?|\bPath)\s*\(\s*["']([^"'\n]+)["']/g)) add(match[1], "file.read", working);
  };
  walk(request.input, 0);
  if (!request.command) return targets;

  const classified = classifyActionContext(request.tool, request.input ?? {}, cwd ?? "", request.command, (s) => s, false);
  for (const action of classified.actions) {
    const type = ({ "file-read": "file.read", "file-search": "file.read", "source-search": "file.read", "file-write": "file.write", delete: "file.write" } as Record<string, string>)[action.operation];
    if (type && action.target !== "standard input") add(action.resolvedPath ?? action.target, type);
  }
  let working = cwd;
  for (const command of shellActionCommands(request.command)) {
    const tokens = command.tokens.map((token) => token.value);
    let index = 0;
    while (/^[A-Za-z_]\w*=/.test(tokens[index] ?? "") || /^(?:sudo|command|exec|env)$/.test(tokens[index] ?? "")) index++;
    const executable = basename(tokens[index] ?? "").toLowerCase();
    const args = tokens.slice(index + 1);
    if (executable === "cd") { working = canonicalPolicyPath(args[0] ?? "~", working); continue; }
    // Check explicit path arguments conservatively, including interpreter script files,
    // upload sources and input redirection, without disabling the shell tool itself.
    for (const argument of args) {
      const path = argument.replace(/^\d*[<>]+/, "");
      if (/^(?:\/|\.\.?\/|~\/|file:\/\/)/.test(path)) add(path, "file.read", working);
      else if (working && !path.startsWith("-") && existsSync(resolve(working, path))) add(path, "file.read", working);
    }
    if (/^(?:ls|find|grep|rg|cat|head|tail|sed|awk|wc|cp|scp|tar|zip|python[23]?|node|bun|ruby|perl|bash|sh|zsh)$/.test(executable)) {
      literals(args.join(" "), working);
      if (/^(?:ls|find|rg|grep)$/.test(executable)) add(working, "file.read", working);
      // Relative filenames without a ./ prefix, including shell input redirection.
      for (let i = 0; i < args.length; i++) {
        if (args[i] === "<") add(args[i + 1], "file.read", working);
        if (/^(?:cat|head|tail|wc|cp|scp)$/.test(executable) && !args[i].startsWith("-") && !/^\d+$/.test(args[i])) add(args[i], "file.read", working);
      }
    }
  }
  return targets;
}
