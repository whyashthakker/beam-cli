// ~/.beam/monitor.json (or $BEAM_HOME/monitor.json): settings for `beam monitor`, so a plain
// `beam monitor` in a systemd unit or a container needs no flags. Command-line flags win over
// environment variables, which win over this file.
//
// It's created the first time a monitor command runs after an upgrade, carrying over older
// BEAM_LLM_* settings. It never copies a key's value from the environment, only the name of the
// variable that holds it. A key stored with `beam monitor configure --key-stdin` lives here, so
// the file is written 0600, like Beam's other config files.
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { getBeamHome } from "./config.js";

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
}

export const monitorConfigPath = () => join(getBeamHome(), "monitor.json");
export const DEFAULT_MONITOR_CONFIG: MonitorFileConfig = {
  version: 1, files: [], app: null, maxCpuPercent: 25, llm: { provider: "beam", model: null, baseUrl: null, apiKeyEnv: null },
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
