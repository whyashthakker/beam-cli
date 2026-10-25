// Settings for `beam monitor`, so a plain `beam monitor` in a systemd unit or a container needs no
// flags. Layered like git or npm config, lowest to highest:
//
//   managed   /etc/beam/monitor.json (macOS /Library/Application Support/Beam, Windows %ProgramData%\Beam):
//             set by IT through MDM or config management. It can lock settings, which nothing
//             below can then change.
//   user      ~/.beam/monitor.json (or $BEAM_HOME), 0600. The only file that may store a key.
//   project   beam.monitor.json in the directory beam monitor starts in (or --config <file>):
//             committed with the app, so keys are refused there.
//   environment variables, then command-line flags.
//
// Each top-level setting (files, app, maxCpuPercent, llm, pause) comes whole from the highest layer
// that sets it, so a project can't half-override a managed LLM setup. Pausing (deny lists and the
// command that reloads the web server) can't come from a project file: it runs a command. `beam monitor configure` shows
// where every effective value came from.
//
// It's created the first time a monitor command runs after an upgrade, carrying over older
// BEAM_LLM_* settings. It never copies a key's value from the environment, only the name of the
// variable that holds it. A key stored with `beam monitor configure --key-stdin` lives here, so
// the file is written 0600, like Beam's other config files.
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, rename, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { getBeamHome } from "./config.js";
import { DENY_FORMATS, type DenyFormat, type DenyListSettings } from "./monitor-deny.js";

export interface MonitorLlmSettings {
  /** beam (Beam's model, set in the dashboard), or a provider: openai, anthropic, gemini, ... */
  provider: string;
  model: string | null;
  baseUrl: string | null;
  /** The variable that holds the key where beam monitor runs. Default: the provider's usual one. */
  apiKeyEnv: string | null;
  /** A key stored with --key-stdin. Prefer apiKeyEnv: keys belong in a secret store. */
  apiKey?: string;
}
export interface MonitorFileConfig {
  version: 1;
  /** Log files `beam monitor` follows when started without --file, --stdin or --app. */
  files: string[];
  /** App directory whose lockfiles are checked at start and daily. */
  app: string | null;
  /** The most of one CPU core detection may use, in percent; past it, lines are skipped until the next minute. */
  maxCpuPercent: number;
  llm: MonitorLlmSettings;
  /** Where paused addresses are written for the web server, and how to reload it (monitor-deny.ts). */
  pause: DenyListSettings;
}

export const monitorConfigPath = () => join(getBeamHome(), "monitor.json");
export const DEFAULT_MONITOR_CONFIG: MonitorFileConfig = {
  version: 1, files: [], app: null, maxCpuPercent: 25, llm: { provider: "beam", model: null, baseUrl: null, apiKeyEnv: null },
  pause: { denyFile: null, authDenyFile: null, llmDenyFile: null, format: "nginx", reload: null },
};

const invalid = (why: string) => new Error(`${monitorConfigPath()} is invalid (${why}). Fix it, or run 'beam monitor configure' to rewrite it.`);
const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const optionalString = (v: unknown, max: number) => v === null || v === undefined || (typeof v === "string" && v.length <= max);

export function validateMonitorConfig(value: unknown): MonitorFileConfig {
  if (!isRecord(value) || value.version !== 1) throw invalid("unsupported version");
  const llm = isRecord(value.llm) ? value.llm : {};
  if (!Array.isArray(value.files ?? []) || !(value.files as unknown[] ?? []).every(f => typeof f === "string" && f.length <= 4096)) throw invalid("files must be a list of paths");
  if (!optionalString(value.app, 4096)) throw invalid("app must be a path");
  const cpu = value.maxCpuPercent ?? 25;
  if (typeof cpu !== "number" || !(cpu >= 1 && cpu <= 100)) throw invalid("maxCpuPercent must be a number from 1 to 100");
  if (typeof (llm.provider ?? "beam") !== "string" || !/^[a-z]{2,20}$/.test(String(llm.provider ?? "beam"))) throw invalid("llm.provider must be a provider name");
  if (!optionalString(llm.model, 120) || (typeof llm.model === "string" && !/^[\w.:/@-]+$/.test(llm.model))) throw invalid("llm.model must be a model name");
  if (!optionalString(llm.baseUrl, 2000)) throw invalid("llm.baseUrl must be a URL");
  if (!optionalString(llm.apiKeyEnv, 100) || (typeof llm.apiKeyEnv === "string" && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(llm.apiKeyEnv))) throw invalid("llm.apiKeyEnv must be a variable name");
  if (llm.apiKey !== undefined && (typeof llm.apiKey !== "string" || !llm.apiKey.trim() || /\s/.test(llm.apiKey) || llm.apiKey.length > 4096)) throw invalid("llm.apiKey must be a single key");
  const pause = isRecord(value.pause) ? value.pause : {};
  if (value.pause !== undefined && value.pause !== null && !isRecord(value.pause)) throw invalid("pause must be an object");
  for (const field of ["denyFile", "authDenyFile", "llmDenyFile"] as const)
    if (!optionalString(pause[field], 4096) || pause[field] === "") throw invalid(`pause.${field} must be a path`);
  if (pause.format !== undefined && !DENY_FORMATS.includes(pause.format as DenyFormat)) throw invalid(`pause.format must be ${DENY_FORMATS.join(" or ")}`);
  if (!optionalString(pause.reload, 1000) || pause.reload === "") throw invalid("pause.reload must be a command");
  return {
    version: 1,
    files: [...((value.files as string[] | undefined) ?? [])],
    app: (value.app as string | null | undefined) ?? null,
    maxCpuPercent: cpu,
    llm: {
      provider: String(llm.provider ?? "beam"),
      model: (llm.model as string | null | undefined) ?? null,
      baseUrl: (llm.baseUrl as string | null | undefined) ?? null,
      apiKeyEnv: (llm.apiKeyEnv as string | null | undefined) ?? null,
      ...(typeof llm.apiKey === "string" ? { apiKey: llm.apiKey } : {}),
    },
    pause: {
      denyFile: (pause.denyFile as string | null | undefined) ?? null,
      authDenyFile: (pause.authDenyFile as string | null | undefined) ?? null,
      llmDenyFile: (pause.llmDenyFile as string | null | undefined) ?? null,
      format: (pause.format as DenyFormat | undefined) ?? "nginx",
      reload: (pause.reload as string | null | undefined) ?? null,
    },
  };
}

/** The file's settings, or null when there's no file yet. Throws when it exists but is invalid. */
export async function readMonitorConfig(): Promise<MonitorFileConfig | null> {
  let file;
  try {
    file = await open(monitorConfigPath(), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw invalid("it can't be read");
  }
  try {
    const stats = await file.stat();
    if (!stats.isFile() || stats.size > 64 * 1024) throw invalid("not a small regular file");
    let parsed: unknown;
    try { parsed = JSON.parse(await file.readFile("utf8")); } catch { throw invalid("not valid JSON"); }
    return validateMonitorConfig(parsed);
  } finally {
    await file.close();
  }
}

export async function writeMonitorConfig(config: MonitorFileConfig): Promise<void> {
  const safe = validateMonitorConfig(config);
  await mkdir(getBeamHome(), { recursive: true, mode: 0o700 });
  const tmp = `${monitorConfigPath()}.${randomUUID()}.tmp`;
  try {
    const file = await open(tmp, "wx", 0o600);
    try { await file.writeFile(`${JSON.stringify(safe, null, 2)}\n`); } finally { await file.close(); }
    await rename(tmp, monitorConfigPath());
  } finally {
    await rm(tmp, { force: true });
  }
}

/** What an upgrade carries over from older BEAM_LLM_* settings: names and endpoints, never a key. */
export function migratedFromEnv(env: NodeJS.ProcessEnv): MonitorFileConfig {
  const baseUrl = env.BEAM_LLM_BASE_URL?.trim() || null;
  const model = env.BEAM_LLM_MODEL?.trim() || null;
  const hasKey = Boolean(env.BEAM_LLM_API_KEY?.trim());
  const provider = env.BEAM_LLM_PROVIDER?.trim().toLowerCase()
    || (baseUrl && !/^https:\/\/api\.openai\.com\/v1\/?$/.test(baseUrl) ? "custom" : baseUrl || model || hasKey ? "openai" : "beam");
  return { ...DEFAULT_MONITOR_CONFIG, llm: { provider, model, baseUrl, apiKeyEnv: hasKey ? "BEAM_LLM_API_KEY" : null } };
}

/**
 * The file's settings, creating the file first if this is the first monitor command since an
 * upgrade. A home directory that can't be written (a locked-down service user) isn't an error:
 * the defaults apply and nothing is created.
 */
export async function ensureMonitorConfig(env: NodeJS.ProcessEnv = process.env): Promise<{ config: MonitorFileConfig; created: boolean }> {
  const existing = await readMonitorConfig();
  if (existing) return { config: existing, created: false };
  const config = migratedFromEnv(env);
  try {
    await writeMonitorConfig(config);
    return { config, created: true };
  } catch {
    return { config, created: false };
  }
}

/** The settings for display: a stored key is shown as present, never printed. */
export function describeMonitorConfig(config: MonitorFileConfig): Record<string, unknown> {
  const { apiKey, ...llm } = config.llm;
  return { ...config, llm: { ...llm, ...(apiKey ? { apiKey: "(stored)" } : {}) } };
}

export type Layer = "default" | "managed" | "user" | "project";
export type SettingKey = "files" | "app" | "maxCpuPercent" | "llm" | "pause";
const SETTING_KEYS: SettingKey[] = ["files", "app", "maxCpuPercent", "llm", "pause"];
export type PartialSettings = Partial<Pick<MonitorFileConfig, SettingKey>>;

export function managedConfigPath(env: NodeJS.ProcessEnv = process.env): string {
  if (env.BEAM_MANAGED_CONFIG) return resolve(env.BEAM_MANAGED_CONFIG);
  if (process.platform === "darwin") return "/Library/Application Support/Beam/monitor.json";
  if (process.platform === "win32") return join(env.ProgramData || "C:\\ProgramData", "Beam", "monitor.json");
  return "/etc/beam/monitor.json";
}
export const PROJECT_CONFIG_FILE = "beam.monitor.json";

/**
 * A managed or project file: any subset of the settings. Keys are refused in both (they're shared
 * files); `locked` is only meaningful, and only allowed, in the managed file.
 */
export function validateLayer(value: unknown, kind: "managed" | "project", path: string): { settings: PartialSettings; locked: SettingKey[] } {
  const bad = (why: string) => new Error(`${path} is invalid (${why}).`);
  if (!isRecord(value) || (value.version !== undefined && value.version !== 1)) throw bad("unsupported version");
  if (isRecord(value.llm) && value.llm.apiKey !== undefined)
    throw bad("keys don't belong in a shared file: name the variable that holds it with llm.apiKeyEnv");
  if (kind === "project" && value.pause !== undefined)
    throw bad("pause runs a reload command on this server, so it can't come from a project file: set it with 'beam monitor configure' or in the managed config");
  const locked = value.locked ?? [];
  if (!Array.isArray(locked) || !locked.every(k => SETTING_KEYS.includes(k as SettingKey))) throw bad(`locked must list settings: ${SETTING_KEYS.join(", ")}`);
  if (kind === "project" && locked.length) throw bad("only the managed config can lock settings");
  // Reuse the full validation for field types, then keep only what this file set.
  const full = validateMonitorConfig({ ...value, version: 1, ...(isRecord(value.llm) ? {} : { llm: undefined }) });
  const settings: PartialSettings = {};
  for (const key of SETTING_KEYS) if (value[key] !== undefined) (settings as Record<string, unknown>)[key] = full[key];
  return { settings, locked: locked as SettingKey[] };
}

async function readJsonFile(path: string): Promise<unknown | null> {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error(`${path} can't be read.`);
  }
  try {
    const stats = await file.stat();
    if (!stats.isFile() || stats.size > 64 * 1024) throw new Error(`${path} is invalid (not a small regular file).`);
    try { return JSON.parse(await file.readFile("utf8")); } catch { throw new Error(`${path} is invalid (not valid JSON).`); }
  } finally {
    await file.close();
  }
}

export interface ResolvedSettings {
  settings: MonitorFileConfig;
  origins: Record<SettingKey, Layer>;
  /** Locked by the managed file: flags and environment variables don't change these either. */
  locked: Set<SettingKey>;
  sources: { layer: Exclude<Layer, "default">; path: string; status: "used" | "not found" | string }[];
  /** True when this run created the user file (the first monitor command after an upgrade). */
  created: boolean;
  /** Warnings worth showing, e.g. a stored key in a file other users can read. */
  warnings: string[];
}

/** The effective file settings across the managed, user and project layers. Throws on an invalid file. */
export async function resolveMonitorSettings(options: { cwd?: string; configPath?: string; env?: NodeJS.ProcessEnv } = {}): Promise<ResolvedSettings> {
  const env = options.env ?? process.env;
  const settings: MonitorFileConfig = { ...DEFAULT_MONITOR_CONFIG, llm: { ...DEFAULT_MONITOR_CONFIG.llm } };
  const origins = Object.fromEntries(SETTING_KEYS.map(k => [k, "default"])) as Record<SettingKey, Layer>;
  const locked = new Set<SettingKey>();
  const sources: ResolvedSettings["sources"] = [];
  const warnings: string[] = [];
  const apply = (layer: Exclude<Layer, "default">, part: PartialSettings) => {
    for (const key of SETTING_KEYS) {
      if (part[key] === undefined || locked.has(key)) continue;
      (settings as unknown as Record<string, unknown>)[key] = part[key];
      origins[key] = layer;
    }
  };

  const managedPath = managedConfigPath(env);
  const managed = await readJsonFile(managedPath);
  if (managed === null) sources.push({ layer: "managed", path: managedPath, status: "not found" });
  else {
    const layer = validateLayer(managed, "managed", managedPath);
    apply("managed", layer.settings);
    for (const key of layer.locked) if (layer.settings[key] !== undefined) locked.add(key);
    sources.push({ layer: "managed", path: managedPath, status: "used" });
  }

  const { config: user, created } = await ensureMonitorConfig(env);
  const userSet: PartialSettings = {};
  for (const key of SETTING_KEYS) if (JSON.stringify(user[key]) !== JSON.stringify(DEFAULT_MONITOR_CONFIG[key])) (userSet as Record<string, unknown>)[key] = user[key];
  apply("user", userSet);
  sources.push({ layer: "user", path: monitorConfigPath(), status: created ? "used (created now)" : "used" });
  if (user.llm.apiKey && process.platform !== "win32") {
    try {
      const { stat } = await import("node:fs/promises");
      if (((await stat(monitorConfigPath())).mode & 0o077) !== 0) warnings.push(`${monitorConfigPath()} stores a key but other users can read it. Run: chmod 600 ${monitorConfigPath()}`);
    } catch { /* not created */ }
  }

  const projectPath = options.configPath ? resolve(options.configPath) : join(options.cwd ?? process.cwd(), PROJECT_CONFIG_FILE);
  const project = await readJsonFile(projectPath);
  if (project === null) {
    if (options.configPath) throw new Error(`${projectPath} doesn't exist.`);
    sources.push({ layer: "project", path: projectPath, status: "not found" });
  } else {
    apply("project", validateLayer(project, "project", projectPath).settings);
    sources.push({ layer: "project", path: projectPath, status: "used" });
  }
  for (const key of locked) if (origins[key] !== "managed") origins[key] = "managed";
  return { settings, origins, locked, sources, created, warnings };
}
