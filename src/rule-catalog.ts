// The built-in detection rules: pure data and regular expressions, with no Node.js built-ins, so
// the same catalog backs agent hooks (core.ts) and the in-app SDK (sdk.ts), which can run in
// edge runtimes.
export type Severity = "critical" | "high" | "medium" | "info";

export type RuleCategory = "exec" | "exfil" | "impact" | "integrity" | "persistence" | "privilege" | "recon" | "secrets" | "source_control" | "custom";
export type Rule = { id: string; title: string; severity: Severity; category: RuleCategory; explanation: string; match: (s: string) => boolean };

const secret = /(?:\.env(?:\b|[./])|\.ssh[\\/]|id_rsa|id_ed25519|\.aws[\\/]credentials|(?:api[_-]?key|access[_-]?token|password|secret)\b)/i;
const egress = /(?:https?:\/\/|\bcurl\b|\bwget\b|\bupload\b|\bwebhook\b|\bsend\b|\bexfiltrat\w*)/i;

// Linear checks for "something | sh". As regexes (/curl[^\n]*\|\s*sh/) they backtrack
// quadratically or worse on long hostile lines, and these rules also run on attacker-written
// text inside customer apps (App monitoring). Each line's pipes are split once and scanned in order.
const SHELL_AFTER_PIPE = /^\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b/i;
function pipesIntoShell(s: string, newArmer: () => (segment: string) => boolean): boolean {
  for (const line of s.split("\n")) {
    if (!line.includes("|")) continue;
    const arms = newArmer();
    let armed = false;
    for (const [i, segment] of line.split("|").entries()) {
      if (i > 0 && armed && SHELL_AFTER_PIPE.test(segment)) return true;
      armed = arms(segment) || armed;
    }
  }
  return false;
}
const downloads = () => (segment: string) => /\b(?:curl|wget)\b/i.test(segment);
// base64, then a decode flag after it (in the same segment or a later one).
const decodes = () => {
  let base64 = false;
  return (segment: string) => {
    const at = base64 ? 0 : segment.search(/\bbase64\b/i);
    if (at < 0) return false;
    base64 = true;
    return /(?:^|\s)(?:-\w*d\w*|--decode)\b/i.test(segment.slice(at));
  };
};

export const builtinRules: Rule[] = [
  { id: "destructive.delete", title: "Destructive operation", severity: "high", category: "impact", explanation: "Review the target and backups before allowing a recursive delete or destructive data operation.", match: s => /\brm\s+[^\n]{0,1000}?(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive)|\b(?:drop\s+(?:table|database)|truncate\s+(?:table\s+)?\w+)|\bRemove-Item\b[^\n]{0,1000}?(?:-Recurse|-Force)|\bgit\s+(?:reset\s+--hard|clean\s+-[^\n]{0,1000}?f)/i.test(s) },
  { id: "destructive.production", title: "Production change", severity: "high", category: "impact", explanation: "This action targets a production environment. Confirm the scope and rollback plan before proceeding.", match: s => /\b(?:production|prod)\b/i.test(s) && /\b(?:deploy|delete|drop|truncate|migrate|apply|destroy|restart|rollback|scale)\b/i.test(s) },
  { id: "credentials.environment", title: "Environment variable access", severity: "high", category: "secrets", explanation: "The action reads exported environment variables that may contain credentials or private configuration.", match: s => /\b(?:printenv|env|export\s+-p|process\.env|os\.environ|System\.getenv)\b|\$\{?[A-Z][A-Z0-9_]*\}?/i.test(s) },
  { id: "credentials.access", title: "Sensitive credential reference", severity: "medium", category: "secrets", explanation: "This action or instruction references a credential location. Confirm the agent needs access.", match: s => secret.test(s) },
  { id: "source.private_files", title: "Private source or configuration access", severity: "high", category: "secrets", explanation: "This action accesses a private credential or configuration file. Confirm that the agent needs the contents.", match: s => /(?:\.env(?:\.[\w.-]+)?|\.ssh[\\/]|\.aws[\\/]credentials|id_(?:rsa|ed25519)|\.npmrc|\.netrc|kubeconfig|private.?key)/i.test(s) },
  { id: "mcp.write", title: "MCP write operation", severity: "high", category: "impact", explanation: "The MCP tool appears to modify data or send an external side effect. Require approval before allowing it.", match: s => /\bmcp(?:__|:)[^\s]*(?:create|update|delete|write|send|post|put|patch|execute|run|publish|deploy|remove)\b/i.test(s) },
  { id: "credentials.egress", title: "Possible credential exposure", severity: "critical", category: "exfil", explanation: "Credential references and outbound delivery appear together. Inspect the destination and data before running this.", match: s => secret.test(s) && egress.test(s) },
  { id: "execution.remote", title: "Remote code execution pattern", severity: "high", category: "exec", explanation: "Downloaded content is piped directly into a shell without review.", match: s => pipesIntoShell(s, downloads) },
  { id: "execution.obfuscated", title: "Encoded execution", severity: "high", category: "exec", explanation: "Encoded content is decoded for execution. Review the decoded payload separately; Beam never executes it.", match: s => pipesIntoShell(s, decodes) || /\b(?:powershell|pwsh)\b[^\n]{0,500}?\s-(?:enc|encodedcommand)\b/i.test(s) },
  { id: "recon.network_sweep", title: "Network sweep", severity: "medium", category: "recon", explanation: "A scanner targets a network range. Verify scope and authorization before the agent probes other systems (ATT&CK T1046).", match: s => /\b(?:nmap|masscan|rustscan)\b/i.test(s) && /(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}|(?:\d{1,3}\.){3}\d{1,3}-\d{1,3}/.test(s) },
  { id: "privilege.elevation", title: "Elevated privileges", severity: "medium", category: "privilege", explanation: "The action requests elevated privileges or broad write permissions.", match: s => /\bsudo\s|\bchmod\s+(?:-R\s+)?777\b/i.test(s) },
  { id: "network.metadata", title: "Cloud metadata access", severity: "high", category: "secrets", explanation: "Cloud metadata endpoints can expose temporary instance credentials.", match: s => /169\.254\.169\.254|metadata\.google\.internal/i.test(s) },
  { id: "persistence.config", title: "Security-sensitive configuration", severity: "high", category: "persistence", explanation: "A persistence or agent configuration target is referenced. Check the intended change and trust boundary.", match: s => /authorized_keys|\bcrontab\b|LaunchAgents[\\/]|ANTHROPIC_BASE_URL/i.test(s) },
  { id: "network.reverse-shell", title: "Reverse shell pattern", severity: "critical", category: "exec", explanation: "This pattern can connect a command shell to another machine.", match: s => /\/dev\/tcp\/|\bnc\b[^\n]{0,300}?\s-e\s|socket[\s\S]{0,200}?subprocess/i.test(s) },
  { id: "instructions.override", title: "Instruction override attempt", severity: "high", category: "integrity", explanation: "Instructions attempt to override existing safeguards or conceal activity from the user.", match: s => /ignore\s+(?:all\s+)?(?:previous|prior|system|safety)\s+(?:instructions|rules|prompts)|(?:do not|don't|never)\s+(?:tell|inform|notify)\s+(?:the\s+)?user|disable\s+(?:security|safety|logging|audit)/i.test(s) },
  { id: "source_control.history_rewrite", title: "Git history rewrite", severity: "medium", category: "source_control", explanation: "Force-pushing or rewriting shared history can silently discard other people's commits. Confirm the branch isn't shared before proceeding.", match: s => /\bgit\s+push\s+[^\n]{0,1000}?(?:--force(?:-with-lease)?|-f\b)|\bgit\s+filter-(?:branch|repo)\b/i.test(s) },
  { id: "integrity.tls_bypass", title: "Certificate or signature verification disabled", severity: "medium", category: "integrity", explanation: "Disabling TLS/certificate verification removes protection against a tampered or impersonated destination.", match: s => /\bcurl\b[^\n]{0,1000}?(?:-k\b|--insecure)|\bwget\b[^\n]{0,1000}?--no-check-certificate|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|\bgit\b[^\n]{0,1000}?-c\s+http\.sslVerify=false/i.test(s) },
];

/** Built-in rules by id, for callers (like `beam monitor`) that reuse a subset of the catalog. */
export function builtinRulesById(ids: string[]): Rule[] {
  return ids.map(id => builtinRules.find(r => r.id === id)).filter((r): r is Rule => Boolean(r));
}
