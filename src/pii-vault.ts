// Local vault for sensitive values the model must never see. The governance chain:
//   prompt   -> real value stored here, prompt blocked, user resends with a placeholder ([SSN_001])
//   pre-tool -> placeholder in a shell command is swapped for the real value just before it runs
//   post-tool-> any vaulted value in the output is masked back to its placeholder
//   stop     -> a summary of which commands ran with vaulted values
// The model only ever holds placeholders. Real values live AES-256-GCM encrypted in
// <beam data dir>/vault.json (mode 0600), keyed per session and pruned after 24h.
//
// Key storage: a 32-byte random key in <data dir>/vault.key (mode 0600), or BEAM_VAULT_KEY
// (64 hex chars) when set. A key file beside the ciphertext stops casual disclosure (backups,
// accidental sharing of vault.json, grep) but NOT an attacker who can read both files as this user;
// a Keychain/KMS-backed key is the stronger option and is not implemented here.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getDataDirectory } from "./config.js";
import { detectSensitive, type CustomDetector, type DataFinding } from "./data-detectors.js";
import { redactWithSessionEntities } from "./entity-redaction.js";
import { withFileLock } from "./file-lock.js";

interface VaultValue { kind: string; enc: string }
interface LedgerEntry { at: string; tool: string; command: string; ids: string[]; toolUseId?: string; output?: string }
interface SessionVault { updatedAt: string; values: Record<string, VaultValue>; ledger: LedgerEntry[]; reported: number; events?: string[]; reportedEvents?: number }
type VaultFile = Record<string, SessionVault>;

const TTL_MS = 24 * 60 * 60 * 1000;
const PLACEHOLDER = /\[([A-Z_]+_\d{3})\]/g;

const vaultPath = (home: string) => join(home, "vault.json");

async function loadKey(home: string): Promise<Buffer> {
  const fromEnv = process.env.BEAM_VAULT_KEY;
  if (fromEnv && /^[0-9a-f]{64}$/i.test(fromEnv)) return Buffer.from(fromEnv, "hex");
  const keyPath = join(home, "vault.key");
  try {
    const existing = Buffer.from((await readFile(keyPath, "utf8")).trim(), "hex");
    if (existing.length === 32) return existing;
  } catch { /* create below */ }
  const key = randomBytes(32);
  await mkdir(dirname(keyPath), { recursive: true, mode: 0o700 });
  await writeFile(keyPath, `${key.toString("hex")}\n`, { mode: 0o600, flag: "wx" }).catch(async () => {
    // Lost a creation race with a concurrent hook process -- use the key that won.
    const winner = Buffer.from((await readFile(keyPath, "utf8")).trim(), "hex");
    if (winner.length !== 32) throw new Error("Beam vault key file is corrupt.");
    key.set(winner);
  });
  await chmod(keyPath, 0o600).catch(() => {});
  return key;
}

function encrypt(key: Buffer, plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), ct].map(b => b.toString("base64")).join(".");
}
function decrypt(key: Buffer, enc: string): string | null {
  try {
    const [iv, tag, ct] = enc.split(".").map(p => Buffer.from(p, "base64"));
    const decipher = createDecipheriv("aes-256-gcm", key, iv!);
    decipher.setAuthTag(tag!);
    return Buffer.concat([decipher.update(ct!), decipher.final()]).toString("utf8");
  } catch { return null; }
}

async function read(home: string): Promise<VaultFile> {
  try { return JSON.parse(await readFile(vaultPath(home), "utf8")) as VaultFile; } catch { return {}; }
}
async function write(file: VaultFile, home: string): Promise<void> {
  await mkdir(dirname(vaultPath(home)), { recursive: true, mode: 0o700 });
  await writeFile(vaultPath(home), `${JSON.stringify(file)}\n`, { mode: 0o600 });
  await chmod(vaultPath(home), 0o600).catch(() => {});
}
async function mutate<T>(home: string, fn: (file: VaultFile, now: string) => T): Promise<T> {
  return withFileLock(vaultPath(home), async () => {
    const file = await read(home);
    const now = new Date().toISOString();
    const cutoff = Date.now() - TTL_MS;
    for (const [id, s] of Object.entries(file)) if (Date.parse(s.updatedAt) < cutoff) delete file[id];
    const result = fn(file, now);
    await write(file, home);
    return result;
  });
}
const session = (file: VaultFile, id: string, now: string): SessionVault => (file[id] ??= { updatedAt: now, values: {}, ledger: [], reported: 0 });

/**
 * Redacts `text` with session-numbered placeholders (same ids entity-redaction assigns) AND stores
 * each real value encrypted so a later command can use the placeholder.
 */
export async function redactAndVault(text: string, sessionId: string, custom: CustomDetector[] = [], home = getDataDirectory(), onlyBlockingKinds = false): Promise<{ text: string; findings: DataFinding[] }> {
  const redacted = await redactWithSessionEntities(text, sessionId, custom, home);
  if (!redacted.findings.length || !sessionId) return redacted;
  const key = await loadKey(home);
  // Tool output is full of phone-shaped numbers (timestamps, ids). Redact them all, but only vault the
  // high-confidence kinds -- storing the rest adds sensitive-looking data to disk for no benefit.
  const found = redacted.findings.filter(f => !onlyBlockingKinds || BLOCKING_KINDS.has(f.kind) || f.kind === "CUSTOM").map(f => ({ id: f.replacement.slice(1, -1), kind: f.kind, value: text.slice(f.start, f.end) }));
  if (!found.length) return redacted;
  await mutate(home, (file, now) => {
    const s = session(file, sessionId, now); s.updatedAt = now;
    for (const { id, kind, value } of found) if (!s.values[id]) s.values[id] = { kind, enc: encrypt(key, value) };
  });
  return redacted;
}

/** Replaces this session's placeholders in `text` with the real values. Unknown ids are left alone. */
export async function resolvePlaceholders(text: string, sessionId: string, home = getDataDirectory()): Promise<{ text: string; ids: string[] }> {
  if (!sessionId || !PLACEHOLDER.test(text)) { PLACEHOLDER.lastIndex = 0; return { text, ids: [] }; }
  PLACEHOLDER.lastIndex = 0;
  const s = (await read(home))[sessionId];
  if (!s) return { text, ids: [] };
  const key = await loadKey(home);
  const ids: string[] = [];
  const out = text.replace(PLACEHOLDER, (match, id: string) => {
    const entry = s.values[id];
    const value = entry ? decrypt(key, entry.enc) : null;
    if (value === null) return match;
    if (!ids.includes(id)) ids.push(id);
    return value;
  });
  return { text: out, ids };
}

// A command can echo a value back transformed; mask the common encodings too. This is a mitigation,
// not a guarantee -- a command that splits, reverses or encrypts the value will not be caught.
function variants(value: string): string[] {
  const b64 = Buffer.from(value).toString("base64");
  return [...new Set([value, b64, b64.replace(/=+$/, ""), Buffer.from(value).toString("hex"), encodeURIComponent(value), value.replace(/[\s-]/g, "")])].filter(v => v.length >= 4);
}

/** Masks every vaulted value (and common encodings of it) in `text` back to its placeholder. */
export async function maskVaulted(text: string, sessionId: string, home = getDataDirectory()): Promise<{ text: string; ids: string[] }> {
  if (!sessionId || !text) return { text, ids: [] };
  const s = (await read(home))[sessionId];
  if (!s || !Object.keys(s.values).length) return { text, ids: [] };
  const key = await loadKey(home);
  const ids: string[] = [];
  let out = text;
  // Longest values first so a value containing another is masked whole.
  // Only high-confidence kinds are masked back from output; low-confidence ones (phone, email, address) are
  // redacted by the detectors with their own placeholders, and masking by stored value would re-flag every
  // later occurrence of a lookalike string (e.g. values an older build vaulted from timestamps).
  const entries = Object.entries(s.values).filter(([, v]) => BLOCKING_KINDS.has(v.kind) || v.kind === "CUSTOM").map(([id, v]) => ({ id, value: decrypt(key, v.enc) })).filter((e): e is { id: string; value: string } => !!e.value).sort((a, b) => b.value.length - a.value.length);
  for (const { id, value } of entries) {
    for (const variant of variants(value)) {
      if (out.includes(variant)) { out = out.split(variant).join(`[${id}]`); if (!ids.includes(id)) ids.push(id); }
    }
  }
  return { text: out, ids };
}

export async function recordSubstitution(sessionId: string, entry: { tool: string; command: string; ids: string[]; toolUseId?: string }, home = getDataDirectory()): Promise<void> {
  if (!sessionId) return;
  await mutate(home, (file, now) => { const s = session(file, sessionId, now); s.updatedAt = now; s.ledger.push({ at: now, ...entry }); });
}

/** Attaches the (already masked) output of a tool call to its ledger entry, for the end-of-turn summary. */
export async function attachLedgerOutput(sessionId: string, toolUseId: string, maskedOutput: string, home = getDataDirectory()): Promise<void> {
  if (!sessionId || !toolUseId) return;
  await mutate(home, (file) => {
    const entry = [...(file[sessionId]?.ledger ?? [])].reverse().find(e => e.toolUseId === toolUseId);
    if (entry) entry.output = maskedOutput.slice(0, 300);
  });
}

/** A one-line, secret-free note about something Beam did this turn (prompt rewritten, output masked ...). */
export async function recordEvent(sessionId: string, text: string, home = getDataDirectory()): Promise<void> {
  if (!sessionId) return;
  await mutate(home, (file, now) => { const s = session(file, sessionId, now); s.updatedAt = now; (s.events ??= []).push(text.slice(0, 300)); });
}

/** Everything Beam did since the last end-of-turn report; marks it reported. */
export async function takeTurnSummary(sessionId: string, home = getDataDirectory()): Promise<{ events: string[]; commands: LedgerEntry[] }> {
  if (!sessionId) return { events: [], commands: [] };
  return mutate(home, (file) => {
    const s = file[sessionId];
    if (!s) return { events: [], commands: [] };
    const events = (s.events ?? []).slice(s.reportedEvents ?? 0);
    const commands = s.ledger.slice(s.reported);
    s.reportedEvents = (s.events ?? []).length; s.reported = s.ledger.length;
    return { events, commands };
  });
}

/** Commands run with vaulted values since the last report; marks them reported. */
export async function takeUnreportedLedger(sessionId: string, home = getDataDirectory()): Promise<LedgerEntry[]> {
  if (!sessionId) return [];
  return mutate(home, (file) => {
    const s = file[sessionId];
    if (!s) return [];
    const fresh = s.ledger.slice(s.reported);
    s.reported = s.ledger.length;
    return fresh;
  });
}

/** Findings worth blocking a prompt over (high-confidence identity, financial and credential data). */
const BLOCKING_KINDS = new Set(["SSN", "CREDIT_CARD", "IBAN", "NATIONAL_ID", "PASSPORT", "DRIVER_LICENSE", "DOB", "SECRET", "API_KEY", "PASSWORD", "PRIVATE_KEY"]);
export function promptFindings(text: string, custom: CustomDetector[] = []): { blocking: DataFinding[]; advisory: DataFinding[] } {
  const all = detectSensitive(text, custom);
  return { blocking: all.filter(f => BLOCKING_KINDS.has(f.kind) || f.kind === "CUSTOM"), advisory: all.filter(f => !BLOCKING_KINDS.has(f.kind) && f.kind !== "CUSTOM") };
}

// A shell command that sends data over the network, so substituting a real value into it is a
// direct exfiltration path for anything the agent was talked into running.
const NETWORK_EGRESS = /\b(?:curl|wget|nc|ncat|netcat|socat|telnet|scp|sftp|ftp|rsync|ssh|dig|nslookup|ping)\b|https?:\/\/|\/dev\/(?:tcp|udp)\//i;
export function commandSendsOverNetwork(command: string): boolean { return NETWORK_EGRESS.test(command); }

/**
 * The vault scope for this process. Under `beam claude` every hook inherits BEAM_WRAPPER_ID, so the
 * wrapper (which can't know Claude's session id) and the hooks share one scope, and placeholders
 * survive /clear and resume. Otherwise the scope is the agent's session id.
 */
export function vaultScope(sessionId: string, env: NodeJS.ProcessEnv = process.env): string {
  return env.BEAM_WRAPPER_ID ? `wrapper:${env.BEAM_WRAPPER_ID}` : sessionId;
}
