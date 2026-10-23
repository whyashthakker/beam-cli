// Background auto-update, the way Claude Code does it: at most once a day an interactive `beam`
// command starts a detached check against the npm registry and, when a newer release exists,
// installs it in the background. The command you ran never waits. The next command says the
// update is in, and what to restart.
//
// It never runs where it could slow down or surprise anything: agent hooks and `beam run` (they
// sit in the agent's tool path), long-running `beam monitor` / `beam start` / MCP processes, CI,
// non-interactive shells, or source checkouts. It never asks for sudo: if the global install
// isn't writable it falls back to telling you to run `beam update`. Administrators can turn it
// off with BEAM_DISABLE_AUTOUPDATE=1 (for example through MDM) or `beam update --auto off`.
import { spawn } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getBeamHome } from "./config.js";

const PACKAGE = "@agent-beam/beam";
const LATEST_URL = "https://registry.npmjs.org/@agent-beam%2fbeam/latest";
const CHECK_EVERY_MS = 24 * 60 * 60 * 1000;
const INSTALL_STALE_MS = 15 * 60 * 1000;
export const WORKER_COMMAND = "__auto-update";

// Commands that are in an agent's tool path, run unattended, or manage updates themselves.
const SKIP_COMMANDS = new Set(["hook", "run", "mcp", "start", "monitor", "update", "uninstall", "import", WORKER_COMMAND]);

export interface UpdateState {
  autoUpdate?: boolean;
  checkedAt?: string;
  latest?: string;
  installing?: { version: string; pid: number; startedAt: string };
  installed?: { version: string; from: string; at: string };
  failed?: { version: string; at: string; reason: string };
  noticeShownAt?: string;
}

export const updateStatePath = () => join(getBeamHome(), "update-state.json");

export async function readUpdateState(path = updateStatePath()): Promise<UpdateState> {
  try { return JSON.parse(await readFile(path, "utf8")) as UpdateState; } catch { return {}; }
}

export async function writeUpdateState(state: UpdateState, path = updateStatePath()): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  await rename(tmp, path);
}

/** >0 when `a` is newer. Numeric major.minor.patch; prerelease suffixes are ignored. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.-]/).map(n => Number(n) || 0);
  const pb = b.split(/[.-]/).map(n => Number(n) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

export type InstallKind = "npm" | "binary" | "source";
/** npm package (global or local install), a standalone pkg binary, or a source checkout (dev). */
export function installKind(modulePath = fileURLToPath(import.meta.url)): InstallKind {
  if ((process as { pkg?: unknown }).pkg) return "binary";
  return /[\\/]node_modules[\\/]@agent-beam[\\/]beam[\\/]/.test(modulePath) ? "npm" : "source";
}

export function autoUpdateAllowed(
  command: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
  interactive = Boolean(process.stdout.isTTY && process.stderr.isTTY),
): boolean {
  if (/^(1|true|yes)$/i.test(env.BEAM_DISABLE_AUTOUPDATE ?? "")) return false;
  if (env.CI || env.BEAM_AUTO_UPDATE_WORKER) return false;
  if (!interactive) return false;
  return !SKIP_COMMANDS.has(command ?? "");
}

const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };

export interface TickDeps {
  now?: number;
  kind?: InstallKind;
  statePath?: string;
  startWorker?: () => void;
  fetchLatest?: () => Promise<string | null>;
}

/**
 * Runs on every eligible command: returns a one-line notice to print (or null), and starts the
 * background worker when a check is due. Never throws and never waits on the network for npm
 * installs; binaries do a short direct check because they can't install themselves.
 */
export async function autoUpdateTick(current: string, deps: TickDeps = {}): Promise<string | null> {
  try {
    const now = deps.now ?? Date.now();
    const kind = deps.kind ?? installKind();
    if (kind === "source") return null;
    const statePath = deps.statePath ?? updateStatePath();
    const state = await readUpdateState(statePath);
    if (state.autoUpdate === false) return null;

    // The background install finished and this process is the new version: say so, once.
    if (state.installed && state.installed.version === current && !state.noticeShownAt) {
      await writeUpdateState({ ...state, noticeShownAt: new Date(now).toISOString() }, statePath);
      return `✔ Beam updated to v${current} (from v${state.installed.from}). If Beam's background service is running, restart it to use the new version: beam service stop && beam service start`;
    }

    const due = !state.checkedAt || now - Date.parse(state.checkedAt) >= CHECK_EVERY_MS;
    const installing = state.installing && alive(state.installing.pid) && now - Date.parse(state.installing.startedAt) < INSTALL_STALE_MS;

    if (kind === "binary") {
      if (!due) return null;
      const latest = await (deps.fetchLatest ?? fetchLatest)();
      await writeUpdateState({ ...state, checkedAt: new Date(now).toISOString(), latest: latest ?? state.latest }, statePath);
      return latest && compareVersions(latest, current) > 0
        ? `Beam v${latest} is available (you have v${current}). Download it with: curl -fsSL https://agentbeam.com/install.sh | bash`
        : null;
    }

    // An install that needed privileges we won't take: point to the explicit command, once a day.
    if (state.failed && compareVersions(state.failed.version, current) > 0 && due) {
      await writeUpdateState({ ...state, checkedAt: new Date(now).toISOString() }, statePath);
      return `Beam v${state.failed.version} is available (you have v${current}). Run 'beam update' to install it.`;
    }

    if (due && !installing) {
      await writeUpdateState({ ...state, checkedAt: new Date(now).toISOString() }, statePath);
      (deps.startWorker ?? startWorker)();
    }
    return null;
  } catch {
    return null;
  }
}

async function fetchLatest(): Promise<string | null> {
  try {
    const response = await fetch(LATEST_URL, { signal: AbortSignal.timeout(3000), headers: { Accept: "application/json" } });
    if (!response.ok) return null;
    const { version } = (await response.json()) as { version?: unknown };
    return typeof version === "string" && /^\d+\.\d+\.\d+/.test(version) ? version : null;
  } catch {
    return null;
  }
}

function startWorker(): void {
  const cli = process.argv[1];
  if (!cli) return;
  const child = spawn(process.execPath, [cli, WORKER_COMMAND], {
    detached: true,
    stdio: "ignore",
    env: { ...process.env, BEAM_AUTO_UPDATE_WORKER: "1" },
  });
  child.unref();
}

export interface WorkerDeps {
  current: string;
  statePath?: string;
  fetchLatest?: () => Promise<string | null>;
  install?: (version: string) => Promise<void>;
}

/** The detached process: check, then install without prompting or escalating. */
export async function runAutoUpdateWorker(deps: WorkerDeps): Promise<void> {
  const statePath = deps.statePath ?? updateStatePath();
  const latest = await (deps.fetchLatest ?? fetchLatest)();
  const state = await readUpdateState(statePath);
  if (!latest || compareVersions(latest, deps.current) <= 0) {
    await writeUpdateState({ ...state, latest: latest ?? state.latest, installing: undefined }, statePath);
    return;
  }
  await writeUpdateState({ ...state, latest, installing: { version: latest, pid: process.pid, startedAt: new Date().toISOString() } }, statePath);
  try {
    await (deps.install ?? npmInstall)(latest);
    const after = await readUpdateState(statePath);
    await writeUpdateState({ ...after, installing: undefined, failed: undefined, noticeShownAt: undefined,
      installed: { version: latest, from: deps.current, at: new Date().toISOString() } }, statePath);
  } catch (error) {
    const after = await readUpdateState(statePath);
    await writeUpdateState({ ...after, installing: undefined,
      failed: { version: latest, at: new Date().toISOString(), reason: (error instanceof Error ? error.message : String(error)).slice(0, 300) } }, statePath);
  }
}

function npmInstall(version: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("npm", ["install", "-g", `${PACKAGE}@${version}`, "--no-audit", "--no-fund", "--loglevel=error"], {
      stdio: "ignore",
      shell: process.platform === "win32",
    });
    const timer = setTimeout(() => { child.kill(); reject(new Error("npm install timed out")); }, 5 * 60 * 1000);
    child.on("error", error => { clearTimeout(timer); reject(error); });
    child.on("exit", code => { clearTimeout(timer); code === 0 ? resolve() : reject(new Error(`npm install exited with ${code}`)); });
  });
}
