// The built-in detection rules: pure data and regular expressions, with no Node.js built-ins, so
// the same catalog backs agent hooks (core.ts) and the in-app SDK (sdk.ts), which can run in
// edge runtimes.
import { promptAttack } from "./prompt-attacks.js";
import { isScopedTemporaryCleanup } from "./destructive-risk.js";
import { patternMatch, anyMatch, allMatch, functionalMatch, type Matcher, type MatchSpan } from "./rule-matches.js";
import { credentialExposureSpans, possibleCredentialExposure } from "./credential-egress.js";

export type Severity = "critical" | "high" | "medium" | "info";

export type RuleCategory = "exec" | "exfil" | "impact" | "integrity" | "persistence" | "privilege" | "recon" | "secrets" | "source_control" | "custom";
export type Rule = { id: string; title: string; severity: Severity; category: RuleCategory; explanation: string; match: Matcher; severityFor?: (s: string) => Severity };

const secret = /(?:\.env(?:\b|[./])|\.ssh[\\/]|id_rsa|id_ed25519|\.aws[\\/]credentials|\.pgpass\b|\.docker[\\/]config\.json|\.gnupg[\\/]|credentials\.json|(?:api[_-]?key|access[_-]?token|password|secret)\b)/i;
// Linear checks for "something | sh" or "something | <interpreter>". As regexes
// (/curl[^\n]*\|\s*sh/) they backtrack quadratically or worse on long hostile lines, and these
// rules also run on attacker-written text inside customer apps (App monitoring). Each line's
// pipes are split once and scanned in order.
const EXEC_AFTER_PIPE = /^\s*(?:sudo\s+)?(?:(?:ba|z|fi)?sh|python3?|node|ruby|perl|pwsh|powershell)\b/i;
function pipesIntoShell(s: string, newArmer: () => (segment: string) => boolean): boolean {
  for (const line of s.split("\n")) {
    if (!line.includes("|")) continue;
    const arms = newArmer();
    let armed = false;
    for (const [i, segment] of line.split("|").entries()) {
      if (i > 0 && armed && EXEC_AFTER_PIPE.test(segment)) return true;
      armed = arms(segment) || armed;
    }
  }
  return false;
}
function pipelineMatcher(newArmer: () => (segment: string) => boolean): Matcher {
  return functionalMatch(text => pipesIntoShell(text, newArmer), text => {
    const spans: MatchSpan[] = []; let offset = 0;
    for (const line of text.split("\n")) {
      const arms = newArmer(); let armedAt: number | undefined; let cursor = 0;
      for (const segment of line.split("|")) {
        const executed = EXEC_AFTER_PIPE.exec(segment);
        if (armedAt !== undefined && executed) { spans.push({start: offset + armedAt, end: offset + cursor + executed[0].length, label: "Pipeline into an interpreter"}); break; }
        if (arms(segment)) armedAt = cursor;
        else armedAt = undefined;
        cursor += segment.length + 1;
      }
      offset += line.length + 1;
    }
    return spans;
  });
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

// "rm" with recursive-force intent, however the flags are written: combined (-rf, -fr), split
// (-r -f), long-form (--recursive --force), or mixed (-r --force). A single regex over the whole
// command missed the split-flag case entirely (an easy, common bypass), so each command segment
// (split on ; && || | and newlines, the points a shell actually starts a new command) is checked
// for "rm" plus both an r-flag and an f-flag anywhere in that segment, in any order.
const CMD_SPLIT = /[;&|\n]|&&|\|\|/;
function recursiveDeleteSpans(s: string): MatchSpan[] {
  const spans: MatchSpan[] = [];
  let offset = 0;
  for (const segment of s.split(CMD_SPLIT)) {
    const start = offset; offset += segment.length + 1;
    if (!/\brm\b/i.test(segment)) continue;
    const hasR = /(?:^|\s)-[a-z]*r[a-z]*(?:\s|$)/i.test(segment) || /--recursive\b/i.test(segment);
    const hasF = /(?:^|\s)-[a-z]*f[a-z]*(?:\s|$)/i.test(segment) || /--force\b/i.test(segment);
    if (hasR && hasF) { const at = segment.search(/\brm\b/i); spans.push({ start: start + at, end: start + segment.trimEnd().length, label: "Recursive forced deletion" }); }
  }
  return spans;
}
function rmRecursiveForce(s: string): boolean { return recursiveDeleteSpans(s).length > 0; }

// Download-then-execute split across a command chain instead of a pipe: `curl -o x.sh ... && chmod
// +x x.sh && ./x.sh`. One segment fetches, a later segment (joined by && or ;) runs what it fetched.
const DOWNLOAD_THEN_EXEC = /\b(?:curl|wget)\b[^\n]{0,300}?(?:\s-[oO]\s|--output\b)[^\n]{0,300}?(?:&&|;)[^\n]{0,300}?(?:chmod\s+\+x|\.\/\S|(?:ba|z)?sh\b|python3?\b|node\b)/i;
// PowerShell's `IEX (New-Object Net.WebClient).DownloadString(...)` / `iwr ... | iex`, the
// single most common Windows download-and-run one-liner; and a Python process that fetches and
// executes in the same call instead of piping to a shell.
const POWERSHELL_DOWNLOAD_EXEC = /\bdownloadstring\s*\(|\b(?:iex|invoke-expression)\b[^\n]{0,300}?(?:iwr|invoke-webrequest|downloadstring)\b|\b(?:iwr|invoke-webrequest)\b[^\n]{0,300}?\|\s*(?:iex|invoke-expression)\b/i;
const PYTHON_FETCH_EXEC = /\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:urllib\.request\.urlopen|urlopen|requests\.get|urlretrieve)\b/i;

// Disk, partition and filesystem-level wipes: destroy an entire volume rather than files inside
// it, and are unrecoverable even with the deleted file still referenced elsewhere.
const DISK_WIPE = /\bdd\b[^\n]{0,300}?\bof=\/dev\/(?:[sh]d|nvme|disk)\w*|\bmkfs\b|\bmke2fs\b|\bwipefs\b|\bblkdiscard\b|\b(?:fdisk|gdisk|sgdisk|parted)\b|\bdiskutil\s+(?:eraseDisk|eraseVolume|reformat)\b|\bdiskpart\b[\s\S]{0,200}?\bclean\b|\bClear-Disk\b[^\n]{0,300}?-RemoveData|\bRemove-Partition\b|\bcipher\s+\/w:|\bformat\s+[a-z]:\s*\/y\b/i;
// The classic bash fork bomb and close variants (whitespace and function-name tolerant).
const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;
// Dropping an entire datastore instead of rows in it: Redis/Mongo have no SQL DROP/TRUNCATE syntax.
const DATASTORE_WIPE = /\bFLUSHALL\b|\bFLUSHDB\b|db\.dropDatabase\s*\(\)/i;

const otherDestructiveMatcher = anyMatch(patternMatch(/\bfind\b[^\n]{0,300}?-delete\b|\brsync\b[^\n]{0,300}?--delete\b|\bshred\b[^\n]{0,100}?-\w*u|\bshutil\.rmtree\s*\(|(?:\bfs\.)?\brm(?:dir)?Sync\s*\([^\n]{0,200}?recursive\s*:\s*true|\brd\s+\/s\s+\/q\b|\bRemove-Item\b[^\n]{0,1000}?(?:-Recurse|-Force)|\b(?:drop\s+(?:table|database)|truncate\s+(?:table\s+)?\w+)|\bgit\s+(?:reset\s+--hard|clean\s+-[^\n]{0,1000}?f)/i), patternMatch(DATASTORE_WIPE));
function otherDestructiveOperation(s: string): boolean { return otherDestructiveMatcher(s); }

// A vault/secret-manager reference (op://, Azure Key Vault, HashiCorp Vault, Infisical, Doppler,
// a GitHub Actions secrets expression, or a generic broker placeholder) typed literally into a
// live command instead of being resolved by its own CLI/platform first. An agent can't resolve
// one of these into the real value itself (that's the point of the convention -- the real value
// never reaches it), so seeing the raw reference token in a command about to run means either the
// command is about to fail with it unresolved, or -- worse -- the agent is about to "fix" that by
// asking for the real value and inlining it instead. Either way, a human/CI process starting the
// real service (with its own resolver already wired up) is what should happen next, not the agent
// improvising. Mirrors the CREDENTIAL_REFERENCE check in data-detectors.ts.
const UNRESOLVED_REFERENCE = /\bop:\/\/|@Microsoft\.KeyVault\(|\bvault:[\w/-]|\binfisical:\/\/|\bdoppler:\/\/|\$\{\{\s*secrets\.|__[A-Z][A-Z0-9_]*_REF_[\w-]+__/i;

export const builtinRules: Rule[] = [
  { id: "destructive.delete", title: "Destructive operation", severity: "high", category: "impact", explanation: "Recursive deletion or a destructive data operation. Scoped temporary test cleanup is MEDIUM; broad or uncertain targets remain HIGH. Review the target before allowing it.", match: anyMatch(functionalMatch(rmRecursiveForce, recursiveDeleteSpans), otherDestructiveMatcher), severityFor: s => !otherDestructiveOperation(s) && isScopedTemporaryCleanup(s) ? "medium" : "high" },
  { id: "destructive.disk_wipe", title: "Disk or partition wipe", severity: "critical", category: "impact", explanation: "This targets an entire disk, partition or filesystem rather than individual files, and is unrecoverable. Confirm this is an authorized, intentional wipe.", match: patternMatch(DISK_WIPE) },
  { id: "destructive.fork_bomb", title: "Fork bomb", severity: "critical", category: "impact", explanation: "This pattern spawns processes exponentially and can make the machine unresponsive.", match: patternMatch(FORK_BOMB) },
  { id: "destructive.audit_trail", title: "Audit trail or recovery point erased", severity: "critical", category: "integrity", explanation: "This clears shadow copies, event logs or shell history. It is also the standard precursor to covering up a destructive or malicious action; confirm the reason before allowing it.", match: patternMatch(/\bvssadmin\b[^\n]{0,100}?delete\s+shadows|\bwevtutil\b[^\n]{0,50}?\bcl\b|\bClear-EventLog\b|\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTSIZE\s*=\s*0\b|\bbcdedit\b[^\n]{0,50}?\/deletevalue/i) },
  { id: "destructive.orchestration", title: "Destroys infrastructure or a deployed workload", severity: "high", category: "impact", explanation: "This tears down a namespace, persistent volume, release, or an entire infrastructure stack. Confirm the environment and that nothing else depends on it.", match: patternMatch(/\bkubectl\s+delete\s+(?:namespace|pvc|persistentvolumeclaim)\b|\bhelm\s+uninstall\b|\bterraform\s+(?:destroy|apply\s+[^\n]{0,100}?-destroy)\b|\bdocker\s+system\s+prune\s+-a[^\n]{0,50}?--volumes|\bdocker\s+rm\s+-f\s+\$\(\s*docker\s+ps\s+-aq\s*\)/i) },
  { id: "destructive.cloud_resource", title: "Deletes a cloud resource", severity: "high", category: "impact", explanation: "This permanently removes a cloud resource (instance, database, bucket, or repository). Confirm this isn't a production or shared resource before allowing it.", match: patternMatch(/\baws\s+(?:ec2\s+terminate-instances|rds\s+delete-db-instance|s3\s+rb\b[^\n]{0,100}?--force)\b|\bgcloud\s+(?:compute\s+instances|sql\s+instances)\s+delete\b|\baz\s+(?:vm|group)\s+delete\b|\bgh\s+repo\s+delete\b|\bvercel\s+remove\b[^\n]{0,50}?--yes|\bnetlify\s+sites:delete\b/i) },
  { id: "destructive.account", title: "Deletes a system account", severity: "high", category: "impact", explanation: "This removes a user or group account, which can include its home directory and files. Confirm the account is no longer needed.", match: patternMatch(/\buserdel\s+-r\b|\bgroupdel\b|\bRemove-LocalUser\b|\bnet\s+user\s+\S+\s+\/delete\b|\bdscl\s+\.\s+-delete\s+\/Users\//i) },
  { id: "integrity.protection_disabled", title: "OS security control disabled", severity: "critical", category: "integrity", explanation: "This turns off a platform security control (System Integrity Protection, Gatekeeper, execution policy, or System Restore), which weakens the machine's security posture beyond this one action.", match: patternMatch(/\bcsrutil\s+disable\b|\bspctl\s+--master-disable\b|\bsecurity\s+delete-keychain\b|\bSet-ExecutionPolicy\s+Unrestricted\b|\bDisable-WindowsOptionalFeature\b|\bDisable-ComputerRestore\b/i) },
  { id: "network.firewall_disabled", title: "Firewall rules flushed or disabled", severity: "high", category: "integrity", explanation: "This removes or disables firewall protection on the host. Confirm the host doesn't need it, or that replacement rules are applied immediately.", match: patternMatch(/\biptables\s+-F\b|\bufw\s+(?:--force\s+reset|disable)\b|\bnetsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off\b/i) },
  { id: "destructive.production", title: "Production change", severity: "high", category: "impact", explanation: "This action targets a production environment. Confirm the scope and rollback plan before proceeding.", match: allMatch(patternMatch(/\b(?:production|prod|prd)\b/i), patternMatch(/\b(?:deploy|delete|drop|truncate|migrate|apply|destroy|restart|rollback|scale)\b/i)) },
  // Dumping the *whole* environment (every var, name and value) is the risky shape: that's what
  // can hand over credentials the agent was never told about. Referencing one named variable
  // ($PORT, $NODE_ENV, ${DATABASE_URL}) is how every normal dev workflow reads its own config and
  // used to trip this rule on every touch -- real alert fatigue, and the reason this rule got
  // called out as noisy. That case now only shows up (at "info", logged but not an approval gate)
  // in credentials.environment_ref below, and only for the few var-name shapes anyone would
  // actually call a credential; everyday vars like $PORT or $NODE_ENV don't get flagged anywhere.
  { id: "credentials.environment", title: "Environment variable access", severity: "high", category: "secrets", explanation: "The action reads every exported environment variable at once (not one named variable), which can expose credentials the agent was never told about.", match: patternMatch(/\b(?:printenv|env|export\s+-p|process\.env|os\.environ|System\.getenv|declare\s+-x|Get-ChildItem\s+env:)\b|\/proc\/self\/environ\b|(?:^|[;&|]\s*)set(?:\s*$|\s+-o\b)/i) },
  { id: "credentials.environment_ref", title: "Named credential variable referenced", severity: "info", category: "secrets", explanation: "A single environment variable whose name looks like a credential (KEY/SECRET/TOKEN/PASSWORD/CREDENTIAL) is referenced by name. Logged for visibility; this alone isn't a reason to block the ordinary case of an app reading its own configured secret.", match: patternMatch(/\$\{?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)S?\}?\b/) },
  { id: "credentials.access", title: "Sensitive credential reference", severity: "medium", category: "secrets", explanation: "This action or instruction references a credential location. Confirm the agent needs access.", match: patternMatch(secret) },
  { id: "source.private_files", title: "Private source or configuration access", severity: "high", category: "secrets", explanation: "This action accesses a private credential or configuration file. Confirm that the agent needs the contents.", match: patternMatch(/(?:\.env(?:\.[\w.-]+)?|\.ssh[\\/]|\.aws[\\/]credentials|id_(?:rsa|ed25519)|\.npmrc|\.netrc|kubeconfig|private.?key|\.pgpass\b|\.docker[\\/]config\.json|\.gnupg[\\/]|credentials\.json)/i) },
  { id: "mcp.write", title: "MCP write operation", severity: "high", category: "impact", explanation: "The MCP tool appears to modify data or send an external side effect. Require approval before allowing it.", match: patternMatch(/\bmcp(?:__|:)[^\s]*(?:create|update|delete|write|send|post|put|patch|execute|run|publish|deploy|remove|save|insert|add|grant|revoke|assign)\b/i) },
  { id: "credentials.egress", title: "Possible credential exposure", severity: "critical", category: "exfil", explanation: "A transfer command carries a sensitive payload, or sensitive output feeds an outbound command. This is a possible exposure, not proof of delivery; check the destination and authorization.", match: functionalMatch(possibleCredentialExposure, credentialExposureSpans) },
  { id: "secrets.unresolved_reference_launch", title: "Vault reference used directly instead of resolved", severity: "medium", category: "secrets", explanation: "This command includes a secret-manager reference (op://, Azure Key Vault, Vault, Infisical, Doppler, a GitHub Actions secrets expression, or a broker placeholder) typed in literally rather than resolved by its own CLI or platform. The agent cannot resolve it into the real value -- have a human or CI process start the real service instead, with its existing resolver already wired up.", match: patternMatch(UNRESOLVED_REFERENCE) },
  { id: "execution.remote", title: "Remote code execution pattern", severity: "high", category: "exec", explanation: "Downloaded content is fetched and run without review: piped into a shell or interpreter, fetched and executed in one step, or downloaded and run as separate chained commands.", match: anyMatch(anyMatch(anyMatch(pipelineMatcher(downloads), patternMatch(DOWNLOAD_THEN_EXEC)), patternMatch(POWERSHELL_DOWNLOAD_EXEC)), patternMatch(PYTHON_FETCH_EXEC)) },
  { id: "execution.obfuscated", title: "Encoded execution", severity: "high", category: "exec", explanation: "Encoded content is decoded for execution. Review the decoded payload separately; Beam never executes it.", match: anyMatch(pipelineMatcher(decodes), patternMatch(/\b(?:powershell|pwsh)\b[^\n]{0,500}?\s-(?:enc|encodedcommand)\b/i)) },
  { id: "recon.network_sweep", title: "Network sweep", severity: "medium", category: "recon", explanation: "A scanner targets a network range. Verify scope and authorization before the agent probes other systems (ATT&CK T1046).", match: allMatch(patternMatch(/\b(?:nmap|masscan|rustscan)\b/i), patternMatch(/(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}|(?:\d{1,3}\.){3}\d{1,3}-\d{1,3}/)) },
  { id: "privilege.elevation", title: "Elevated privileges", severity: "medium", category: "privilege", explanation: "The action requests elevated privileges or broad write permissions.", match: patternMatch(/\bsudo\s|\bdoas\s|(?:^|[\s;&|`(])su\s+(?:-\s*\w*|root)\b|\bpkexec\b|\brunas\s+\/user:|\bchmod\s+(?:-R\s+)?(?:777\b|[ugoa]*\+s\b|[2467][0-7]{3}\b)/i) },
  { id: "network.metadata", title: "Cloud metadata access", severity: "high", category: "secrets", explanation: "Cloud metadata endpoints can expose temporary instance credentials.", match: patternMatch(/169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/i) },
  { id: "persistence.config", title: "Security-sensitive configuration", severity: "high", category: "persistence", explanation: "A persistence or agent configuration target is referenced. Check the intended change and trust boundary.", match: patternMatch(/authorized_keys|\bcrontab\b|LaunchAgents[\\/]|ANTHROPIC_BASE_URL/i) },
  { id: "network.reverse-shell", title: "Reverse shell pattern", severity: "critical", category: "exec", explanation: "This pattern can connect a command shell to another machine.", match: patternMatch(/\/dev\/tcp\/|\bnc\b[^\n]{0,300}?\s-e\s|socket[\s\S]{0,200}?subprocess|\bNew-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\b|\bsocat\b[^\n]{0,300}?\bexec[:=]|\bsocket\([^\n]{0,150}?getprotobyname\(["']tcp["']\)[\s\S]{0,200}?\bconnect\(/i) },
  { id: "instructions.override", title: "Instruction override attempt", severity: "high", category: "integrity", explanation: "Instructions attempt to override existing safeguards or conceal activity from the user. Checked against the same folded view used for prompt-injection monitoring (Unicode/width normalization and base64 decoding), not a literal-text match, so stylized or encoded phrasing is caught too.", match: functionalMatch(promptAttack.override) },
  { id: "source_control.history_rewrite", title: "Git history rewrite", severity: "medium", category: "source_control", explanation: "Force-pushing or rewriting shared history can silently discard other people's commits. Confirm the branch isn't shared before proceeding.", match: patternMatch(/\bgit\s+push\s+[^\n]{0,1000}?(?:--force(?:-with-lease)?|-f\b)|\bgit\s+filter-(?:branch|repo)\b/i) },
  { id: "integrity.tls_bypass", title: "Certificate or signature verification disabled", severity: "medium", category: "integrity", explanation: "Disabling TLS/certificate verification removes protection against a tampered or impersonated destination.", match: patternMatch(/\bcurl\b[^\n]{0,1000}?(?:-k\b|--insecure)|\bwget\b[^\n]{0,1000}?--no-check-certificate|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|\bgit\b[^\n]{0,1000}?-c\s+http\.sslVerify=false|\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b/i) },
];

/** Built-in rules by id, for callers (like `beam monitor`) that reuse a subset of the catalog. */
export function builtinRulesById(ids: string[]): Rule[] {
  return ids.map(id => builtinRules.find(r => r.id === id)).filter((r): r is Rule => Boolean(r));
}
