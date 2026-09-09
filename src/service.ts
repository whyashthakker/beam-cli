import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { getDataDirectory } from "./config.js";

export const run = promisify(execFile);

const LABEL = "ai.beam.collector";

// os.platform() does not track process.platform overrides in tests; process.platform does.
function osPlatform(): string { return process.platform; }

function cliEntryPath(): string {
  // dist/service.js sits next to dist/cli.js after build.
  return join(dirname(fileURLToPath(import.meta.url)), "cli.js");
}

function logDirectory(): string {
  return join(getDataDirectory(), "logs");
}

export interface ServiceOptions { port?: number; home?: string }
export interface ServiceInfo { platform: string; managed: boolean; configPath: string; running?: boolean; raw?: string }

// --- macOS: launchd user agent ---

export function macPlistPath(home = homedir()): string {
  return join(home, "Library", "LaunchAgents", `${LABEL}.plist`);
}

export function macPlist(port: number, dataDir: string): string {
  const exec = process.execPath;
  const cli = cliEntryPath();
  const escape = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${escape(exec)}</string>
    <string>${escape(cli)}</string>
    <string>serve</string>
    <string>--port</string>
    <string>${port}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>BEAM_DATA_DIR</key><string>${escape(dataDir)}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>${escape(join(dataDir, "logs", "collector.log"))}</string>
  <key>StandardErrorPath</key><string>${escape(join(dataDir, "logs", "collector.err.log"))}</string>
</dict>
</plist>
`;
}

async function macInstall(options: ServiceOptions): Promise<ServiceInfo> {
  const path = macPlistPath(options.home);
  const dataDir = getDataDirectory();
  await mkdir(join(dataDir, "logs"), { recursive: true });
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, macPlist(options.port ?? 4319, dataDir));
  await run("launchctl", ["load", "-w", path]).catch(() => {});
  return { platform: "darwin", managed: true, configPath: path };
}

async function macUninstall(home?: string): Promise<void> {
  const path = macPlistPath(home);
  await run("launchctl", ["unload", "-w", path]).catch(() => {});
  await rm(path, { force: true });
}

async function macStart(home?: string): Promise<void> { await run("launchctl", ["load", "-w", macPlistPath(home)]); }
async function macStop(home?: string): Promise<void> { await run("launchctl", ["unload", "-w", macPlistPath(home)]); }

async function macStatus(home?: string): Promise<ServiceInfo> {
  const { stdout } = await run("launchctl", ["list"]).catch(() => ({ stdout: "" }));
  const line = stdout.split("\n").find(l => l.includes(LABEL));
  return { platform: "darwin", managed: Boolean(line), configPath: macPlistPath(home), running: Boolean(line), raw: line };
}

// --- Linux: systemd user service ---

export function systemdUnitPath(home = homedir()): string {
  return join(home, ".config", "systemd", "user", "beam.service");
}

export function systemdUnit(port: number, dataDir: string): string {
  const exec = process.execPath;
  const cli = cliEntryPath();
  return `[Unit]
Description=Beam collector

[Service]
ExecStart=${exec} ${cli} serve --port ${port}
Environment=BEAM_DATA_DIR=${dataDir}
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
`;
}

async function systemdInstall(options: ServiceOptions): Promise<ServiceInfo> {
  const path = systemdUnitPath(options.home);
  const dataDir = getDataDirectory();
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, systemdUnit(options.port ?? 4319, dataDir));
  await run("systemctl", ["--user", "daemon-reload"]);
  await run("systemctl", ["--user", "enable", "--now", "beam.service"]);
  return { platform: "linux", managed: true, configPath: path };
}

async function systemdUninstall(home?: string): Promise<void> {
  await run("systemctl", ["--user", "disable", "--now", "beam.service"]).catch(() => {});
  await rm(systemdUnitPath(home), { force: true });
  await run("systemctl", ["--user", "daemon-reload"]).catch(() => {});
}

async function systemdStart(): Promise<void> { await run("systemctl", ["--user", "start", "beam.service"]); }
async function systemdStop(): Promise<void> { await run("systemctl", ["--user", "stop", "beam.service"]); }

async function systemdStatus(home?: string): Promise<ServiceInfo> {
  const { stdout } = await run("systemctl", ["--user", "is-active", "beam.service"]).catch(e => ({ stdout: (e as { stdout?: string }).stdout ?? "inactive" }));
  const running = stdout.trim() === "active";
  return { platform: "linux", managed: running, configPath: systemdUnitPath(home), running, raw: stdout.trim() };
}

// --- dispatch ---

function unsupported(): never {
  throw new Error(`'beam service' is not supported on ${osPlatform()} yet. Run 'beam serve' directly instead.`);
}

export async function installService(options: ServiceOptions = {}): Promise<ServiceInfo> {
  if (osPlatform() === "darwin") return macInstall(options);
  if (osPlatform() === "linux") return systemdInstall(options);
  return unsupported();
}

export async function uninstallService(home?: string): Promise<void> {
  if (osPlatform() === "darwin") return macUninstall(home);
  if (osPlatform() === "linux") return systemdUninstall(home);
  return unsupported();
}

export async function startService(home?: string): Promise<void> {
  if (osPlatform() === "darwin") return macStart(home);
  if (osPlatform() === "linux") return systemdStart();
  return unsupported();
}

export async function stopService(home?: string): Promise<void> {
  if (osPlatform() === "darwin") return macStop(home);
  if (osPlatform() === "linux") return systemdStop();
  return unsupported();
}

export async function serviceStatus(home?: string): Promise<ServiceInfo> {
  if (osPlatform() === "darwin") return macStatus(home);
  if (osPlatform() === "linux") return systemdStatus(home);
  return unsupported();
}

export async function serviceLogPaths(): Promise<{ out: string; err?: string }> {
  const dir = logDirectory();
  if (osPlatform() === "darwin") return { out: join(dir, "collector.log"), err: join(dir, "collector.err.log") };
  return { out: "journalctl --user -u beam.service -f" };
}

export async function readServiceConfig(home?: string): Promise<string | null> {
  const path = osPlatform() === "darwin" ? macPlistPath(home) : systemdUnitPath(home);
  try { return await readFile(path, "utf8"); } catch { return null; }
}
