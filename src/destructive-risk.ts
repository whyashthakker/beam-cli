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
    const raw = command[1].replace(/\$\{?([A-Za-z_]\w*)\}?/g,(m,n:string)=>vars.get(n)??m);
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
  if (!/(?:^|[-_.])(?:test|tests|tmp|temp|scratch|verify)(?:$|[-_.])/i.test(match[1])) return false;
  return !/(?:^|[/._-])(?:credentials?|secrets?|backups?|production|prod|\.env)(?:$|[/._-])/i.test(path);
}

// The agent harness's own per-session scratch folder, and caches a build recreates on demand.
// Deleting these loses nothing that wasn't generated, so they are LOW rather than a destructive alert.
const AGENT_SCRATCH = /^\/(?:private\/)?tmp\/claude-\d+\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/scratchpad(?:\/[A-Za-z0-9._/-]*)?\/?$/;
const REGENERABLE = /^(?:\.\/)?(?:[A-Za-z0-9._-]+\/)*(?:\.next(?:\/(?:dev|cache))?|__pycache__|node_modules\/\.cache|\.turbo|\.cache|\.pytest_cache|\.mypy_cache|\.parcel-cache|\.vite|\.nyc_output)\/?$/;
function isLowRiskPath(path: string): boolean {
  if (path.split("/").some(p => p === "..") || /\/\//.test(path)) return false;
  return AGENT_SCRATCH.test(path) || (!path.startsWith("/") && !path.startsWith("~") && REGENERABLE.test(path));
}
export function isLowRiskCleanup(text: string): boolean {
  return isScopedTemporaryCleanup(text, 0, isLowRiskPath);
}
