import { shellActionCommands } from "./credential-egress.js";
// Deliberately lexical: an explicit, narrow test/scratch path can lower the
// severity, but does not establish ownership or inspect symlinks on the host.
export function isScopedTemporaryCleanup(text: string, depth=0, accept: (path: string) => boolean = isTemporaryTestPath): boolean {
  if(depth>4)return false;
  // `S=/literal/path; rm -rf $S/x` -- resolve plain literal assignments made earlier in the text.
  const vars=new Map<string,string>();
  for(const m of text.matchAll(/(?:^|[;&\n]\s*)(?:export\s+)?([A-Za-z_]\w*)=([^\s;&|$`"'()*?{}\[\]]+)(?=\s*(?:[;&\n]|$))/g))vars.set(m[1],m[2]);
  const commands=shellActionCommands(text);
  if(commands.length===1){const tokens=commands[0].tokens;
    if(tokens.length===3 && /(?:^|\/)(?:bash|sh|zsh)$/.test(tokens[0].value) && /^-[a-z]*c[a-z]*$/.test(tokens[1].value) && /^['"]/.test(tokens[2].raw))return isScopedTemporaryCleanup(tokens[2].value,depth+1,accept);
  }
  let found = false;
  for (const segment of text.split(/[;&|\n]/)) {
    if (!/\brm\b/.test(segment)) continue;
    // Wrappers, substitutions and unfamiliar syntax keep the default severity.
    const command = /^(?:\/(?:usr\/)?bin\/)?rm\s+(.+)$/.exec(segment.trim());
    if (!command) return false;
    // Redirections to /dev/null (`2>/dev/null`, `2>&1`) are not paths; any other redirect is kept and blocks the scoped reading.
    const raw = command[1].replace(/\s+\d*>&\d+/g, "").replace(/\s+(?:\d*>>?|&>)\s*\/dev\/null\b/g, "").replace(/\$\{?([A-Za-z_]\w*)\}?/g,(m,n:string)=>vars.get(n)??m);
    if (/[$`*?{}()[\]<>\\]/.test(raw)) return false;
    const tokens = raw.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
    let recursive = false, force = false, options = true;
    const paths: string[] = [];
    for (const token of tokens) {
      const value = token.replace(/^(['"])(.*)\1$/, "$2");
      if (options && value === "--") { options = false; continue; }
      if (options && value.startsWith("-")) {
        if (value === "--recursive") recursive = true;
        else if (value === "--force") force = true;
        else if (/^-[rfv]+$/.test(value)) { recursive ||= value.includes("r"); force ||= value.includes("f"); }
        else return false;
      } else paths.push(value);
    }
    if (!paths.length || !paths.every(accept)) return false;
    // Ordinary rm in a mixed cleanup must be scoped too, but this rule's trigger
    // is still recursive + force. Never create a finding for a plain file delete.
    found ||= recursive && force;
  }
  return found;
}

function isTemporaryTestPath(path: string): boolean {
  const match = /^\/(?:tmp|private\/tmp|var\/tmp)\/([^/]+)(?:\/([A-Za-z0-9._/-]+))?\/?$/.exec(path);
  if (!match) return false;
  const parts = path.split("/");
  if (parts.some(p => p === "." || p === "..") || /\/\//.test(path)) return false;
  if (!/^[A-Za-z0-9._-]+$/.test(match[1])) return false;
  // A name is a confidence signal, not permission: keep an alert at MEDIUM.
  if (!/(?:^|[-_.])(?:test|tests|tmp|temp|scratch|verify|download|downloads|cache|build|output|artifacts|probe|preview|draft|demo)(?:$|[-_.])/i.test(match[1])) return false;
  return !/(?:^|[/._-])(?:credentials?|secrets?|backups?|production|prod|\.env)(?:$|[/._-])/i.test(path);
}

// The agent harness's own per-session scratch folder, and caches a build recreates on demand.
// Deleting these loses nothing that wasn't generated, so they are LOW rather than a destructive alert.
const AGENT_SCRATCH = /^\/(?:private\/)?tmp\/claude-\d+\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/scratchpad(?:\/[A-Za-z0-9._/-]*)?\/?$/;
const REGENERABLE = /^(?:\.\/)?(?:[A-Za-z0-9._-]+\/)*(?:\.next(?:\/[A-Za-z0-9._/-]*)?|__pycache__|node_modules(?:\/[A-Za-z0-9._@/-]*)?|\.turbo|\.cache|\.pytest_cache|\.mypy_cache|\.parcel-cache|\.vite|\.nyc_output|dist|build|coverage|\.svelte-kit|\.nuxt|\.output)\/?$/;
// Per-user caches (uv, npm, pip, Library/Caches) are rebuilt on demand.
const USER_CACHE = /^~\/(?:\.cache|Library\/Caches)\/[A-Za-z0-9._@/-]+\/?$/;
function isLowRiskPath(path: string): boolean {
  if (path.split("/").some(p => p === "..") || /\/\//.test(path)) return false;
  return AGENT_SCRATCH.test(path) || USER_CACHE.test(path) || (!path.startsWith("/") && !path.startsWith("~") && REGENERABLE.test(path));
}
export function isLowRiskCleanup(text: string): boolean {
  return isScopedTemporaryCleanup(text, 0, isLowRiskPath);
}

// Paths this same command creates (mkdir, cat > f, tee, cp/mv destination, touch): deleting what
// you just made is cleaning up after yourself, not destroying existing work.
const norm = (p: string) => p.replace(/^["']|["']$/g, "").replace(/^\.\//, "").replace(/\/+$/, "");
function createdPaths(text: string): string[] {
  const made: string[] = [];
  for (const segment of text.split(/[;&|\n]/)) {
    const w = segment.trim().split(/\s+/);
    const head = w[0];
    const args = w.slice(1).filter(a => !a.startsWith("-"));
    if (head === "mkdir" || head === "touch") made.push(...args.map(norm));
    else if ((head === "cp" || head === "mv") && args.length >= 2) made.push(norm(args[args.length - 1]));
    const redirect = /(?:^|\s)(?:tee\s+(?:-a\s+)?|>>?\s*)["']?([^\s"'<>|;&]+)/.exec(segment);
    if (redirect) made.push(norm(redirect[1]));
  }
  return made.filter(Boolean);
}
const madeHere = (path: string, made: string[]) => { const p = norm(path); return made.some(m => p === m || m.startsWith(p + "/") || p.startsWith(m + "/")); };

// MEDIUM: contained to the project -- a relative path two or more levels deep, or anything this
// same command created. Top-level names (rm -rf src), absolute paths, ~ and .. stay HIGH.
const SENSITIVE = /(?:^|[/._-])(?:credentials?|secrets?|backups?|production|prod|\.env|\.ssh|\.aws)(?:$|[/._-])/i;
function isProjectScopedPath(path: string): boolean {
  if (path.split("/").some(p => p === ".." || p === ".") || /\/\//.test(path) || SENSITIVE.test(path)) return false;
  if (path.startsWith("/") || path.startsWith("~") || /[$`*?{}()[\]<>\\]/.test(path)) return false;
  return norm(path).split("/").filter(Boolean).length >= 2;
}
export function isProjectScopedCleanup(text: string): boolean {
  const made = createdPaths(text);
  return isScopedTemporaryCleanup(text, 0, p => isProjectScopedPath(p) || (!SENSITIVE.test(p) && !p.startsWith("/") && !p.startsWith("~") && !p.includes("..") && madeHere(p, made)));
}
/** `find DIR -type l -delete` removes only symlinks. */
export function isSymlinkOnlyDelete(text: string): boolean {
  const deletes = text.split(/[;&|\n]/).filter(seg => /-delete\b/.test(seg));
  return deletes.length > 0 && deletes.every(seg => /\bfind\b[^\n]*-type\s+l\b[^\n]*-delete\b/.test(seg)) && !/\brm\b/.test(text);
}
