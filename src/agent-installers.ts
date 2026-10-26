import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getBeamHome } from "./config.js";

// Agents whose hook contract is not a JSON file beam can merge into: Hermes Agent reads shell
// hooks from a YAML config, OpenClaw only runs typed hooks registered by a plugin. Each installer
// has the same three operations install.ts uses for the JSON agents.

export interface HookTarget { nodePath: string; cliPath: string; agentId: string }
export interface CustomInstallResult { path: string; alreadyInstalled: boolean; note?: string }
export interface CustomUninstallResult { path: string; removed: boolean; note?: string }
export interface CustomInstaller {
  install(home: string, target: HookTarget): Promise<CustomInstallResult>;
  uninstall(home: string): Promise<CustomUninstallResult>;
  isInstalled(home: string): Promise<boolean>;
}

// ---- Hermes Agent: ~/.hermes/config.yaml `hooks:` block ------------------------------------
// Shape verified against hermes-agent.nousresearch.com/docs/user-guide/features/hooks: each event
// under `hooks:` maps to a list of { matcher?, command, timeout?, fail_closed? } entries; the
// script gets hook_event_name/tool_name/tool_input/session_id/cwd on stdin and blocks with
// {"decision":"block","reason"} or exit code 2. The file is edited as text, between marker
// comments, so the user's comments, ordering and other settings are left exactly as they were.

const HERMES_BEGIN = "# beam:begin (managed by 'beam agent install hermes')";
const HERMES_END = "# beam:end";
const HERMES_NOTE = "Hermes asks you to approve the new hook the first time it runs (saved in ~/.hermes/shell-hooks-allowlist.json). In the gateway, cron or CI it stays inactive until you approve it, start Hermes with --accept-hooks, or set HERMES_ACCEPT_HOOKS=1. Restart Hermes to load it.";

// Hermes runs a hook command through shlex.split with shell=False, so quote each path with single
// quotes (no expansion), then emit the whole command as a YAML double-quoted scalar.
function shq(value: string): string { return `'${value.replace(/'/g, `'\\''`)}'`; }
function hermesCommand(t: HookTarget): string { return `${shq(t.nodePath)} ${shq(t.cliPath)} hook ${t.agentId}`; }

export function hermesStripBeam(text: string): string {
  const out: string[] = [];
  let skipping = false;
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!skipping && trimmed.startsWith("# beam:begin")) {
      skipping = true;
      if (!line.startsWith(" ") && out.length && out[out.length - 1] === "") out.pop(); // the blank line we added before a top-level block
      continue;
    }
    if (skipping) { if (trimmed === HERMES_END) skipping = false; continue; }
    out.push(line);
  }
  return out.join("\n");
}

export function hermesHasBeam(text: string): boolean {
  return text.split("\n").some(line => line.trim().startsWith("# beam:begin"));
}

function manualSnippet(command: string): string {
  return `hooks:\n  pre_tool_call:\n    - command: ${JSON.stringify(command)}\n      timeout: 30`;
}

export function hermesAddBeam(text: string, command: string): string {
  const base = hermesStripBeam(text);
  const entry = [`pre_tool_call:`, `  - command: ${JSON.stringify(command)}`, `    timeout: 30`];
  const lines = base.split("\n");
  const hooksIndex = lines.findIndex(line => /^hooks:/.test(line));
  if (hooksIndex === -1) {
    const block = [HERMES_BEGIN, "hooks:", ...entry.map(l => `  ${l}`), HERMES_END];
    const prefix = base.trim() === "" ? "" : `${base.replace(/\n+$/, "")}\n\n`;
    return `${prefix}${block.join("\n")}\n`;
  }
  if (!/^hooks:\s*(#.*)?$/.test(lines[hooksIndex])) {
    throw new Error(`~/.hermes/config.yaml has an inline 'hooks:' value; add Beam's hook by hand:\n${manualSnippet(command)}`);
  }
  if (lines.some(line => /^\s+pre_tool_call:/.test(line))) {
    throw new Error(`~/.hermes/config.yaml already has a pre_tool_call hook list; add this entry to it by hand:\n  - command: ${JSON.stringify(command)}\n    timeout: 30`);
  }
  lines.splice(hooksIndex + 1, 0, `  ${HERMES_BEGIN}`, ...entry.map(l => `  ${l}`), `  ${HERMES_END}`);
  return lines.join("\n");
}

function hermesPath(home: string): string { return join(home, ".hermes", "config.yaml"); }

const hermes: CustomInstaller = {
  async install(home, target) {
    const path = hermesPath(home);
    const raw = await readFile(path, "utf8").catch(() => "");
    const next = hermesAddBeam(raw, hermesCommand(target));
    const alreadyInstalled = raw !== "" && next === raw;
    if (!alreadyInstalled) { await mkdir(dirname(path), { recursive: true }); await writeFile(path, next); }
    return { path, alreadyInstalled, note: alreadyInstalled ? undefined : HERMES_NOTE };
  },
  async uninstall(home) {
    const path = hermesPath(home);
    const raw = await readFile(path, "utf8").catch(() => "");
    if (!hermesHasBeam(raw)) return { path, removed: false };
    await writeFile(path, hermesStripBeam(raw).replace(/\n{3,}/g, "\n\n"));
    return { path, removed: true };
  },
  async isInstalled(home) {
    const raw = await readFile(hermesPath(home), "utf8").catch(() => "");
    return hermesHasBeam(raw) && raw.includes(" hook hermes");
  },
};

// ---- OpenClaw: a plugin that registers a before_tool_call hook ------------------------------
// OpenClaw has no hook config file. docs.openclaw.ai/plugins/hooks says typed hooks are registered
// in plugin code with api.on("before_tool_call", handler), and that a plugin is installed with
// `openclaw plugins install --link <dir>` then `openclaw plugins enable <id>`. The event fields
// and return shape ({ block, blockReason }) come from the hooks page and published plugins; the
// page does not print them as a reference, so the plugin reads each field defensively.

const OPENCLAW_ID = "beam";
const OPENCLAW_MARKER = "// beam-managed: generated by 'beam agent install openclaw'";

function openclawDir(): string { return join(getBeamHome(), "openclaw-plugin"); }

function openclawIndex(t: HookTarget): string {
  return `${OPENCLAW_MARKER}
import { spawnSync } from "node:child_process";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const NODE = ${JSON.stringify(t.nodePath)};
const CLI = ${JSON.stringify(t.cliPath)};

export default definePluginEntry({
  id: ${JSON.stringify(OPENCLAW_ID)},
  name: "Beam",
  description: "Reports OpenClaw tool calls to the local Beam collector and applies workspace policy.",
  register(api: any) {
    api.on("before_tool_call", async (event: any, ctx: any) => {
      const payload = {
        hook_event_name: "before_tool_call",
        tool_name: event?.toolName ?? event?.name,
        tool_input: event?.params ?? event?.args ?? {},
        tool_use_id: event?.toolCallId,
        session_id: ctx?.sessionKey ?? ctx?.sessionId,
        cwd: ctx?.workspaceDir ?? process.cwd(),
        source_agent: "openclaw",
        source_type: "hook",
      };
      const result = spawnSync(NODE, [CLI, "hook", "openclaw"], { input: JSON.stringify(payload), encoding: "utf8", timeout: 5000 });
      let response: any = {};
      try { response = JSON.parse(result.stdout || "{}"); } catch { /* fail closed below */ }
      // OpenClaw's hook runner fails open on a thrown error, so a failure here returns a block instead.
      if (result.error || result.status !== 0 || response.decision === "deny") {
        return { block: true, blockReason: response.reason || "Beam denied this tool call." };
      }
    });
  },
});
`;
}

const OPENCLAW_MANIFEST = `${JSON.stringify({
  id: OPENCLAW_ID,
  name: "Beam",
  activation: { onStartup: true },
  configSchema: { type: "object", additionalProperties: false },
}, null, 2)}\n`;

const OPENCLAW_PACKAGE = `${JSON.stringify({ name: "beam-openclaw-plugin", private: true, type: "module", openclaw: { extensions: ["./index.ts"] } }, null, 2)}\n`;

function runOpenclaw(args: string[]): { ok: boolean; reason?: string } {
  try {
    execFileSync(process.env.BEAM_OPENCLAW_BIN || "openclaw", args, { stdio: "ignore", timeout: 60_000 });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: (e as NodeJS.ErrnoException).code === "ENOENT" ? "the openclaw command was not found on PATH" : "the openclaw command failed" };
  }
}

const openclaw: CustomInstaller = {
  async install(home, target) {
    void home;
    const dir = openclawDir();
    const index = openclawIndex(target);
    const existing = await readFile(join(dir, "index.ts"), "utf8").catch(() => "");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "openclaw.plugin.json"), OPENCLAW_MANIFEST, { mode: 0o600 });
    await writeFile(join(dir, "package.json"), OPENCLAW_PACKAGE, { mode: 0o600 });
    await writeFile(join(dir, "index.ts"), index, { mode: 0o600 });
    const linked = runOpenclaw(["plugins", "install", "--link", dir, "--force"]);
    const enabled = linked.ok ? runOpenclaw(["plugins", "enable", OPENCLAW_ID]) : linked;
    const manual = `openclaw plugins install --link ${dir} --force && openclaw plugins enable ${OPENCLAW_ID}`;
    const note = enabled.ok
      ? "Restart the OpenClaw gateway to load the plugin, then check it with 'openclaw plugins list'."
      : `Plugin written, but not registered (${enabled.reason}). Run: ${manual}`;
    return { path: dir, alreadyInstalled: existing === index && enabled.ok, note };
  },
  async uninstall() {
    const dir = openclawDir();
    const existing = await readFile(join(dir, "index.ts"), "utf8").catch(() => "");
    if (!existing.startsWith(OPENCLAW_MARKER)) return { path: dir, removed: false };
    await rm(dir, { recursive: true, force: true });
    return { path: dir, removed: true, note: `Also remove the '${OPENCLAW_ID}' plugin from OpenClaw ('openclaw plugins --help' lists the command), or it will warn about a missing path.` };
  },
  async isInstalled() {
    const existing = await readFile(join(openclawDir(), "index.ts"), "utf8").catch(() => "");
    return existing.startsWith(OPENCLAW_MARKER);
  },
};

export const CUSTOM_INSTALLERS: Record<string, CustomInstaller> = { hermes, openclaw };
