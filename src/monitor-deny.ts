// `beam monitor --deny-file`: the pauses in force as a web server deny list, so a server that
// only has its logs watched can still refuse a paused sender. beam monitor reads logs after the
// fact and can't answer requests itself; the web server in front of the app can. The list is
// rewritten as pauses start and end, and an optional reload command (`nginx -s reload`) runs
// after each change.
//
//   nginx   deny 203.0.113.9;   (include it in a server or location block)
//   plain   203.0.113.9         (one per line: HAProxy `-f`, ipset restore scripts, anything else)
//
// Pauses scoped to sign-in or LLM routes go to their own files (--auth-deny-file, --llm-deny-file),
// to include only in those locations. User pauses (user:<id>) can't be expressed as addresses and
// are left to the SDK. Files are replaced atomically, so the server never reads half a list.
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { open, rename, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Pause, PauseScope } from "./monitor-pause.js";

export type DenyFormat = "nginx" | "plain";
export const DENY_FORMATS: DenyFormat[] = ["nginx", "plain"];

export interface DenyListSettings {
  /** Pauses on the whole app. */
  denyFile: string | null;
  /** Pauses on sign-in routes only (password guessing). */
  authDenyFile: string | null;
  /** Pauses on LLM routes only (model abuse). */
  llmDenyFile: string | null;
  format: DenyFormat;
  /** Run after a list changes, e.g. "nginx -s reload". Through the shell, with a 30-second limit. */
  reload: string | null;
}

const RELOAD_TIMEOUT_MS = 30_000;
const RELOAD_EVERY_MS = 5_000;
// What a reason may show in a comment: no newlines, nothing a config parser could read as syntax.
const safe = (text: string) => text.replace(/[^\w .:/()@+-]/g, "").slice(0, 120);

/** One scope's list, sorted so an unchanged set writes an identical file. */
export function renderDenyList(pauses: Pause[], scope: PauseScope, format: DenyFormat, now = Date.now()): string {
  const entries = pauses
    .filter(p => p.scope === scope && !p.dryRun && p.until > now && !p.target.startsWith("user:"))
    .sort((a, b) => a.target.localeCompare(b.target));
  const where = scope === "all" ? "the whole app" : scope === "auth" ? "sign-in routes" : "LLM routes";
  const header = [
    `# Written by beam monitor: addresses AgentBeam paused from ${where}. Rewritten as pauses start and end; don't edit.`,
    `# ${entries.length} paused.`,
  ];
  if (format === "plain") return `${[...header, ...entries.map(p => p.target)].join("\n")}\n`;
  return `${[...header, ...entries.map(p => `deny ${p.target};  # until ${new Date(p.until).toISOString().slice(0, 16)}Z: ${safe(p.reason)}`)].join("\n")}\n`;
}

/** Keeps the deny files in step with the pauses, reloading the web server after a change. */
export class DenyListWriter {
  private written = new Map<string, string>();
  private reloadTimer: NodeJS.Timeout | undefined;
  private lastReload = 0;
  private inflight: Promise<void> | null = null;
  private pendingReload = false;

  constructor(private readonly settings: DenyListSettings, private readonly log: (message: string) => void) {}

  get enabled(): boolean { return Boolean(this.settings.denyFile || this.settings.authDenyFile || this.settings.llmDenyFile); }

  private files(): [PauseScope, string][] {
    return ([["all", this.settings.denyFile], ["auth", this.settings.authDenyFile], ["llm", this.settings.llmDenyFile]] as [PauseScope, string | null][])
      .filter((f): f is [PauseScope, string] => Boolean(f[1]));
  }

  /** Writes each list that changed; returns whether any did. Errors are logged, never thrown. */
  async update(pauses: Pause[]): Promise<boolean> {
    let changed = false;
    for (const [scope, path] of this.files()) {
      const text = renderDenyList(pauses, scope, this.settings.format);
      const body = text.split("\n").filter(l => !l.startsWith("#")).join("\n");
      if (this.written.get(path) === body) continue;
      try {
        await writeAtomically(path, text);
        this.written.set(path, body);
        changed = true;
      } catch (error) {
        this.log(`Couldn't write ${path}: ${(error as Error).message}. Pauses for ${scope === "all" ? "the whole app" : `${scope} routes`} aren't enforced until it can be.`);
      }
    }
    if (changed) this.scheduleReload();
    return changed;
  }

  /** Empties every list (on shutdown: pauses shouldn't outlive the process that keeps them current). */
  async clear(): Promise<void> {
    await this.update([]);
    // Now rather than after the debounce (the process is exiting), once any reload in flight is done.
    await this.inflight;
    if (this.reloadTimer) { clearTimeout(this.reloadTimer); this.reloadTimer = undefined; }
    await this.reload();
  }

  private scheduleReload(): void {
    if (!this.settings.reload) return;
    this.pendingReload = true;
    if (this.reloadTimer) return;
    const wait = Math.max(0, this.lastReload + RELOAD_EVERY_MS - Date.now());
    this.reloadTimer = setTimeout(() => { this.reloadTimer = undefined; void this.reload(); }, wait);
    this.reloadTimer.unref?.();
  }

  private reload(): Promise<void> {
    const command = this.settings.reload;
    if (!command || this.inflight || !this.pendingReload) return this.inflight ?? Promise.resolve();
    this.pendingReload = false;
    this.lastReload = Date.now();
    this.inflight = run(command).then(({ code, output }) => {
      if (code !== 0) this.log(`The reload command (${command}) failed with exit code ${code}${output ? `: ${output}` : ""}. The deny list is written; the web server may still be using the old one.`);
    }).finally(() => {
      this.inflight = null;
      if (this.pendingReload) this.scheduleReload();
    });
    return this.inflight;
  }
}

async function writeAtomically(path: string, text: string): Promise<void> {
  const tmp = join(dirname(path), `.${randomUUID()}.beam-deny.tmp`);
  try {
    const file = await open(tmp, "wx", 0o644);
    try { await file.writeFile(text); } finally { await file.close(); }
    await rename(tmp, path);
  } finally {
    await rm(tmp, { force: true });
  }
}

function run(command: string): Promise<{ code: number; output: string }> {
  return new Promise(resolve => {
    let output = "";
    const child = spawn(command, { shell: true, stdio: ["ignore", "pipe", "pipe"] });
    const keep = (chunk: Buffer) => { output = (output + chunk.toString("utf8")).slice(-400); };
    child.stdout?.on("data", keep);
    child.stderr?.on("data", keep);
    const timer = setTimeout(() => child.kill("SIGKILL"), RELOAD_TIMEOUT_MS);
    child.on("error", error => { clearTimeout(timer); resolve({ code: -1, output: error.message }); });
    child.on("close", code => { clearTimeout(timer); resolve({ code: code ?? -1, output: output.trim().replace(/\s+/g, " ") }); });
  });
}
