import { shellActionCommands } from "./credential-egress.js";
// Deliberately lexical: an explicit, narrow test/scratch path can lower the
// severity, but does not establish ownership or inspect symlinks on the host.
export function isScopedTemporaryCleanup(text: string, depth=0): boolean {
  if(depth>4)return false;
  const commands=shellActionCommands(text);
  if(commands.length===1){const tokens=commands[0].tokens;
    if(tokens.length===3 && /(?:^|\/)(?:bash|sh|zsh)$/.test(tokens[0].value) && /^-[a-z]*c[a-z]*$/.test(tokens[1].value) && /^['"]/.test(tokens[2].raw))return isScopedTemporaryCleanup(tokens[2].value,depth+1);
  }
  let found = false;
  for (const segment of text.split(/[;&|\n]/)) {
    if (!/\brm\b/.test(segment)) continue;
    // Wrappers, substitutions and unfamiliar syntax keep the default severity.
    const command = /^(?:\/(?:usr\/)?bin\/)?rm\s+(.+)$/.exec(segment.trim());
    if (!command) return false;
    const raw = command[1];
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
    if (!paths.length || !paths.every(isTemporaryTestPath)) return false;
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
