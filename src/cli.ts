#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { Command } from "commander";
import { startServer } from "./serve.js";
import { captureHook, extractPreview, extractSave, importEvents, readToken, reloadRemoteRules, scanFile } from "./client.js";
import { supportsExtraction } from "./extract.js";
import { AGENTS } from "./agents.js";
import { installAllDetectedHooks, installHook, uninstallAllHooks, uninstallHook } from "./install.js";
import { configuredPort, installService, serviceLogPaths, serviceStatus, startService, stopService, uninstallService } from "./service.js";
import { waitForCollectorUp } from "./collector-health.js";
import { getBeamHome, getCollectorUrl, getDataDirectory, getIdentityPath } from "./config.js";
import { clearIdentity, readIdentity } from "./enroll.js";
import { startConnect } from "./connect.js";
import { runSetup, promptYesNo } from "./setup.js";
import { installEnterprisePackage } from "./enterprise-install.js";
import { fetchAccount, revokeDevice } from "./account.js";
import { syncPolicy } from "./forward.js";
import { openBrowser } from "./open-browser.js";
import { ruleCatalog } from "./core.js";
import { loadCustomRules } from "./custom-rules.js";
import { sequenceRuleCatalog } from "./sequences.js";
import { printBanner } from "./banner.js";
import { runWithSudoFallback } from "./elevate.js";
import { renderColumns, withSpinner } from "./prompts.js";
import { cyan, green } from "./color.js";
import { runAgent } from "./run.js";
import { AGENT_BINARIES, installShims, listShims, pathExportLine, shimDir, uninstallShims } from "./shims.js";
import { runMcpProxy } from "./mcp-proxy.js";
import { registerJevCommands } from "./jev-cli.js";
import { addTrustedPath, readTrustedPaths, removeTrustedPath, trustedPathsFile } from "./trusted-paths.js";
import { blockedTargetsFile, readBlockedTargets, removeBlockedTarget } from "./blocked-targets.js";
import { checkForUpdate, installUpdate } from "./update.js";
import { recordExpectedHooks, reportControlEvent } from "./tamper.js";

// Lets 'BEAM_API_URL=... beam connect' style overrides live in a .env file instead of the
// shell profile. Checked in cwd first (handy when developing from the repo), then in
// ~/.beam so overrides still apply when 'beam' is run globally from any directory.
for (const envPath of [path.join(process.cwd(), ".env"), path.join(getBeamHome(), ".env")]) {
  try {
    process.loadEnvFile(envPath);
  } catch {
    // no .env file at this location -- fine, env vars set another way still apply
  }
}

// The banner is a nice hello for a bare 'beam', 'beam --help', or 'beam setup', but printing the
// full ASCII art before every single subcommand (agent list, service status, ...) is just noise
// -- especially once several 'beam' calls run back-to-back from a script.
const argv = process.argv.slice(2);
const wantsBanner = argv.length === 0 || argv[0] === "help" || argv[0] === "setup" || argv.includes("--help") || argv.includes("-h");
if (wantsBanner) printBanner();

// Handled before Commander ever sees argv: the wrapped agent (claude, codex, etc.) has its own
// flags (e.g. `--dangerously-skip-permissions`), which Commander's own option parser would try
// to interpret as beam's own options if `run` were a normal Commander subcommand. Everything
// after `run` is passed through untouched.
if (process.argv[2] === "run") {
  const [command, ...rest] = process.argv.slice(3);
  await runAgent(command, rest);
}

const packageJson = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const program = new Command()
  .name("beam")
  .description("Local observation and heuristic risk scanning for AI agent activity")
  .version(packageJson.version);

registerJevCommands(program);

program.command("setup")
  .description("One-shot onboarding: wire beam's hook into every detected agent, connect this device, and optionally start the background service")
  .action(runSetup);

program.command("start")
  .description("Start the local Beam collector (binds to 127.0.0.1)")
  .option("-p, --port <port>", "port to listen on")
  .action(async (options: { port?: string }) => {
    const result = await startServer({ port: options.port ? Number(options.port) : undefined });
    const rulesNote = result.customRules.loaded ? `\nCustom rules loaded: ${result.customRules.loaded} from ${result.customRules.path}` : "";
    for (const message of result.customRules.errors) console.error(`✖ ${message}`);
    const policyNote = result.policySync ? "\nPolicy sync: on (every 60s)" : "\nPolicy sync: off (device not enrolled — run 'beam setup')";
    const newlyInstalled = result.agentInstalls.filter(r => r.status === "installed");
    const installNote = newlyInstalled.length
      ? `\nAgent hooks installed: ${newlyInstalled.map(r => r.name).join(", ")}`
      : "";
    for (const r of result.agentInstalls) {
      if (r.status === "error") console.error(`✖ Could not wire beam's hook into ${r.name}: ${r.error}`);
    }
    console.log(`Beam collector running.\nMode: observe only\nLocal storage: ${result.directory}${rulesNote}${policyNote}${installNote}\nRun 'beam agent list' to see every detected agent's capture status.\nRun 'beam token' for the pairing token.`);
  });

// Shared gate for every command that reduces or removes beam's visibility on this device
// (stopping/uninstalling the service, detaching an agent's hook, or logging out entirely). On an
// enrolled device these are exactly the actions an employee could otherwise use to go dark to
// their org's dashboard without anyone knowing -- see tamper.ts. So each one prints what will
// actually happen and, when enrolled, that the org admin will be notified this device did it,
// then requires an explicit "Yes" (or --yes, for scripted/CI use) before doing anything. There is
// no path to run the underlying action without either declining here or accepting the notice: the
// action and the report are the same decision, not two.
async function confirmControlAction(message: string, identity: Awaited<ReturnType<typeof readIdentity>>, yes?: boolean): Promise<boolean> {
  console.log(
    identity
      ? `${message}\nYour organization admin will be notified that this device (${identity.hostname}) did this.`
      : message
  );
  if (yes) return true;
  return promptYesNo("\nProceed?", false);
}

const service = program.command("service").description("Run the collector as a background service (launchd on macOS, systemd --user on Linux)");

service.command("install")
  .description("Install and start the collector as a background service that survives reboots")
  .option("-p, --port <port>", "port to listen on")
  .action(async (options: { port?: string }) => {
    const result = await installService({ port: options.port ? Number(options.port) : undefined });
    const up = await waitForCollectorUp(result.port ?? 4319);
    if (up) {
      console.log(`✔ Installed and started the beam service (${result.platform})\n  config: ${result.configPath}`);
    } else {
      console.log(`✖ Installed the beam service (${result.platform}), but it isn't responding on port ${result.port ?? 4319} yet.\n  config: ${result.configPath}\n  Check the logs: beam service logs`);
      process.exitCode = 1;
    }
  });

service.command("uninstall")
  .description("Stop and remove the background service")
  .option("--yes", "skip the confirmation prompt")
  .action(async (options: { yes?: boolean }) => {
    const identity = await readIdentity();
    const proceed = await confirmControlAction(
      "This will stop and remove beam's background service. It will no longer observe or policy-enforce AI agent activity on this device.",
      identity, options.yes
    );
    if (!proceed) { console.log("Cancelled."); return; }
    if (identity) await reportControlEvent("service-uninstall", `Beam service removed on ${identity.hostname}`, "This device ran 'beam service uninstall'. Beam's background collector will no longer start automatically -- it is not observing or policy-enforcing until 'beam service install' runs again.");
    await uninstallService();
    console.log("✔ Removed the beam service.");
  });

service.command("start")
  .description("Start the installed background service")
  .action(async () => {
    await startService();
    const port = await configuredPort();
    const up = await waitForCollectorUp(port);
    if (up) console.log("✔ Started.");
    else { console.log(`✖ Told to start, but the collector isn't responding on port ${port} yet.\n  Check the logs: beam service logs`); process.exitCode = 1; }
  });
service.command("stop")
  .description("Stop the installed background service")
  .option("--yes", "skip the confirmation prompt")
  .action(async (options: { yes?: boolean }) => {
    const identity = await readIdentity();
    const proceed = await confirmControlAction(
      "This will stop beam's background service. It will not observe or policy-enforce AI agent activity on this device until it's started again.",
      identity, options.yes
    );
    if (!proceed) { console.log("Cancelled."); return; }
    if (identity) await reportControlEvent("service-stop", `Beam service stopped on ${identity.hostname}`, "This device ran 'beam service stop'. Beam's background collector is not running -- it is not observing or policy-enforcing until it's started again.");
    await stopService();
    console.log("✔ Stopped.");
  });

service.command("status")
  .description("Show whether the background service is installed and running")
  .action(async () => {
    const result = await serviceStatus();
    console.log(`platform: ${result.platform}\ninstalled: ${result.managed}\nrunning: ${result.running ?? "unknown"}\nconfig: ${result.configPath}`);
  });

service.command("logs")
  .description("Print the background service's log file paths (or the command to follow them)")
  .action(async () => {
    const paths = await serviceLogPaths();
    console.log(paths.err ? `stdout: ${paths.out}\nstderr: ${paths.err}` : paths.out);
  });

program.command("studio")
  .description("Open the local activity dashboard in your browser")
  .action(async () => {
    const origin = getCollectorUrl().origin;
    let token: string;
    try { token = await readToken(); }
    catch (e) { throw new Error(`${(e as Error).message} 'beam studio' needs the collector running first.`); }
    try { await fetch(`${origin}/health`, { signal: AbortSignal.timeout(2000) }); }
    catch { throw new Error("Cannot reach the collector. Run 'beam start' or 'beam service install' first."); }
    openBrowser(`${origin}/?token=${encodeURIComponent(token)}`);
    console.log("Opening beam studio in your browser…");
  });

program.command("whoami")
  .description("Show this device's enrollment, if any")
  .action(async () => {
    const identity = await readIdentity();
    if (!identity) throw new Error("This device is not enrolled. Run 'beam setup'.");
    console.log(`device: ${identity.deviceId}\norg:    ${identity.orgId}\napi:    ${identity.apiBase}\nhost:   ${identity.hostname} (${identity.os})\nsince:  ${identity.enrolledAt}`);
  });

program.command("account")
  .description("Show the signed-in user and workspace this device is connected to")
  .action(async () => {
    const identity = await readIdentity();
    if (!identity) throw new Error("This device is not enrolled. Run 'beam setup'.");
    const account = await fetchAccount(identity);
    console.log(
      `user:   ${account.user.email}${account.user.name ? ` (${account.user.name})` : ""}\n` +
      `org:    ${account.org.name} (${account.org.slug})\n` +
      `device: ${account.device.hostname} (${account.device.os}) · ${account.device.status.toLowerCase()}\n` +
      `since:  ${account.device.enrolled_at}`
    );
  });

program.command("logout")
  .description("Disconnect this device from your Beam workspace and remove local credentials")
  .option("--yes", "skip the confirmation prompt")
  .action(async (options: { yes?: boolean }) => {
    const identity = await readIdentity();
    if (!identity) {
      console.log("This device is not enrolled -- nothing to do.");
      return;
    }
    const proceed = await confirmControlAction(
      "This will disconnect this device from your Beam workspace. It will stop reporting activity until it's re-enrolled.",
      identity, options.yes
    );
    if (!proceed) { console.log("Cancelled."); return; }
    // Sent while identity.json still exists, so it authenticates -- and before revokeDevice()
    // below, so it's an authenticated "I chose to log out" record rather than something an admin
    // has to infer from the device simply going quiet (see tamper.ts).
    await reportControlEvent("logout", `Beam logged out on ${identity.hostname}`, `This device was logged out via 'beam logout'. It is no longer enrolled and will stop reporting until re-enrolled.`);
    try {
      await revokeDevice(identity);
    } catch (e) {
      console.error(`✖ Could not reach ${identity.apiBase} to revoke this device: ${(e as Error).message}`);
      console.error("  Clearing local credentials anyway.");
    }
    await clearIdentity();
    console.log(`✔ Logged out. Removed ${getIdentityPath()}.`);
  });

program.command("uninstall")
  .description("Completely remove beam from this device: stop the service, strip its hooks from every AI agent, delete local data, revoke this device, and uninstall the beam command itself")
  .option("--yes", "skip the confirmation prompt")
  .option("--keep-package", "leave the globally installed beam (and beam-enterprise) npm package in place")
  .action(async (options: { yes?: boolean; keepPackage?: boolean }) => {
    const beamHome = getBeamHome();
    const dataDir = getDataDirectory();
    const identityBeforeUninstall = await readIdentity();

    const proceed = await confirmControlAction(
      "This will remove:\n" +
      "  - the beam background service (if installed)\n" +
      "  - beam's hooks from every AI agent config it was wired into\n" +
      `  - ${beamHome} (identity, cached policy, event logs, custom rules)\n` +
      "  - this device's registration with your Beam workspace" +
      (options.keepPackage ? "" : "\n  - the globally installed beam (and beam-enterprise, if present) npm package"),
      identityBeforeUninstall, options.yes
    );
    if (!proceed) { console.log("Cancelled."); return; }

    // Sent first, before anything below touches identity.json, the service, or hooks -- so the
    // workspace has an authenticated "this was a deliberate 'beam uninstall'" record even if a
    // later step in this command fails partway through. See tamper.ts: this is what distinguishes
    // an authorized removal from the silent kind checkForTampering() is built to catch.
    if (identityBeforeUninstall) {
      await reportControlEvent("uninstall", `Beam uninstalled on ${identityBeforeUninstall.hostname}`, "This device ran 'beam uninstall'. Its background service, agent hooks, and local data are being removed, and its registration is being revoked.");
    }

    try {
      await uninstallService();
      console.log("✔ Removed the background service.");
    } catch (e) {
      console.log(`— Skipped background service (${(e as Error).message}).`);
    }

    // Wrapped like uninstallService() above: one agent's hook config being unreadable (invalid
    // JSON, a permission error) must not abort the rest of 'beam uninstall' -- in particular it
    // must not skip revokeDevice() below, or the device is wiped locally but the dashboard shows
    // it as connected forever with nothing left running here to ever tell it otherwise.
    try {
      const hookResults = await uninstallAllHooks();
      const removedHooks = hookResults.filter(r => r.removed);
      if (removedHooks.length) {
        for (const r of removedHooks) console.log(`✔ Removed beam's hook from ${r.agent}\n  → ${r.path}`);
      } else {
        console.log("— No installed agent hooks found.");
      }
    } catch (e) {
      console.log(`— Could not remove every agent hook (${(e as Error).message}).`);
    }

    const identity = await readIdentity();
    if (identity) {
      try {
        await revokeDevice(identity);
        console.log("✔ Revoked this device with your Beam workspace.");
      } catch (e) {
        console.log(`— Could not reach ${identity.apiBase} to revoke this device: ${(e as Error).message}`);
      }
    }

    await fs.promises.rm(dataDir, { recursive: true, force: true });
    await fs.promises.rm(beamHome, { recursive: true, force: true });
    console.log(`✔ Removed ${beamHome}.`);

    if (!options.keepPackage) {
      try {
        await runWithSudoFallback("npm", ["uninstall", "-g", "beam-enterprise"]);
        console.log("✔ Uninstalled beam-enterprise.");
      } catch {
        // Not installed, or already gone -- fine either way.
      }
      // Uninstall beam itself last -- this deletes the very script currently running. That's
      // safe: npm just unlinks the file, and the process (already loaded into memory) keeps
      // running to completion and prints its final message below.
      try {
        await runWithSudoFallback("npm", ["uninstall", "-g", "@agent-beam/beam"]);
        console.log("✔ Uninstalled the beam npm package.");
      } catch (e) {
        console.log(`— Could not uninstall the beam npm package automatically: ${(e as Error).message}\n  Run manually: npm uninstall -g @agent-beam/beam`);
      }
    }

    console.log("\n✔ Beam has been removed from this device.");
  });

program.command("sync")
  .description("Pull the latest policy from your Beam workspace into ~/.beam/data/policy.json")
  .action(async () => {
    const result = await syncPolicy();
    if (result.status === "not-enrolled") throw new Error("This device is not enrolled. Run 'beam setup'.");
    if (result.status === "unreachable") throw new Error("Could not reach the Beam workspace. Check the network or 'beam whoami'.");
    console.log(result.status === "updated" ? `✔ Policy v${result.version} synced → ${result.path}` : "✔ Policy already up to date.");
  });

program.command("update")
  .description("Update the globally installed beam CLI to the latest published version")
  .option("--check", "only check for an update, don't install it")
  .action(async (options: { check?: boolean }) => {
    let check: Awaited<ReturnType<typeof checkForUpdate>>;
    try {
      check = await checkForUpdate(packageJson.version);
    } catch (e) {
      throw new Error(`Could not check for updates: ${(e as Error).message}`);
    }
    if (check.upToDate) { console.log(`✔ beam is up to date (v${check.current}).`); return; }
    console.log(`A new version is available: v${check.current} → v${check.latest}`);
    if (options.check) return;
    try {
      await installUpdate(check.latest);
      console.log(`✔ Updated to v${check.latest}. Restart any running beam service to pick it up: 'beam service stop && beam service start'.`);
    } catch (e) {
      throw new Error(`Could not install the update automatically: ${(e as Error).message}\n  Run manually: npm install -g @agent-beam/beam@${check.latest}`);
    }
  });

const shims = program.command("shims").description("Make agent CLIs (claude, codex, ...) sandboxed automatically, without typing 'beam run'");

shims.command("install")
  .description("Install PATH shims for the given agents (default: all known agents found on this machine)")
  .argument("[agents...]", `Agent ids: ${Object.keys(AGENT_BINARIES).join(", ")}`)
  .action((agents: string[]) => {
    const results = installShims(agents.length ? agents : undefined);
    for (const r of results) {
      console.log(r.status === "installed" ? `✔ ${r.binary} (${r.agentId}) — shimmed` : `— ${r.binary} (${r.agentId}) — not found on PATH, skipped`);
    }
    if (results.some(r => r.status === "installed")) {
      console.log(`\nAdd this to your shell rc (~/.zshrc), then restart your shell:\n  ${pathExportLine()}`);
      console.log(`\nOnce that's in your PATH, typing e.g. 'claude' or 'codex' runs it through beam's sandbox automatically.`);
    }
  });

shims.command("list")
  .description("Show which shims are currently installed")
  .action(() => {
    const installed = listShims();
    console.log(installed.length ? installed.join("\n") : `No shims installed. Run 'beam shims install' first.\nShim directory: ${shimDir()}`);
  });

shims.command("uninstall")
  .description("Remove all installed shims")
  .action(() => { uninstallShims(); console.log("✔ Removed all shims. (Remove the PATH line from your shell rc manually if you added it.)"); });

program.command("token")
  .description("Print the Beam collector pairing token")
  .action(async () => console.log(await readToken()));

program.command("connect")
  .description("Pair this device with your Beam dashboard by signing in through the browser")
  .action(async () => {
    const existing = await readIdentity();
    if (existing) console.error(`Replacing the existing enrollment (device ${existing.deviceId}).`);

    const session = await startConnect();
    console.log(`Connect Beam CLI to Agentbeam:\n${cyan(session.url)}\n`);
    openBrowser(session.url);

    const identity = await withSpinner("Waiting for you to finish in the browser", () => session.poll());
    console.log(
      `${green("✔")} Connected device ${identity.deviceId}\n` +
      `  org:      ${identity.orgId}\n` +
      `  api:      ${identity.apiBase}\n` +
      `  identity: ${getIdentityPath()} (0600)`
    );

    const enterprise = await withSpinner("Checking for beam-enterprise", () => installEnterprisePackage(identity));
    if (enterprise.status === "installed") console.log(`${green("✔")} beam-enterprise installed (OS-level monitoring enabled).`);
    else if (enterprise.status === "error") console.error(`✖ Could not install beam-enterprise: ${enterprise.message}`);
    // "not-entitled": org isn't on the enterprise plan -- nothing to print, this is the normal case.

    console.log(cyan("\nNext: beam agent install-all && beam start"));
  });

program.command("import")
  .description("Send a normalized events file (JSON/NDJSON) to the collector")
  .argument("<file>", "path to events.ndjson or a JSON array/object")
  .action(async (file: string) => console.log(JSON.stringify(await importEvents(file), null, 2)));

program.command("scan")
  .description("Scan a SKILL.md or MCP config for risky instructions")
  .argument("<file>", "path to SKILL.md or an MCP configuration file")
  .option("--mcp", "treat the file as an MCP configuration instead of a skill")
  .option("--save", "also save the report to the running collector")
  .action(async (file: string, options: { mcp?: boolean; save?: boolean }) => console.log(JSON.stringify(await scanFile(file, options), null, 2)));

const mcp = program.command("mcp").description("Run and protect local MCP integrations");
mcp.command("proxy")
  .description("Run an MCP server through Beam response filtering")
  .argument("<command>", "MCP server command, for example npx")
  .argument("[args...]", "arguments passed to the MCP server")
  .action(async (command: string, args: string[]) => { process.exitCode = await runMcpProxy(command, args ?? []); });

program.command("hook")
  .description("Forward a hook payload from stdin for the given agent (observation only, never blocks the agent). Payload field names are adapted per agent; see 'beam agent list'.")
  .argument("[source-agent]", "reporting agent id, e.g. claude-code, codex, cursor, copilot-cli", "claude-code")
  .action(async (sourceAgent: string) => captureHook(sourceAgent));

const agent = program.command("agent").description("Discover and configure supported AI agents");

agent.command("list")
  .alias("ls")
  .description("List supported agents and their hook payload verification status")
  .action(() => {
    const rows = AGENTS.map(a => [
      a.id,
      a.name,
      a.hookConfigPath ? "installable" : "config wiring not built yet",
      a.verifiedPayload ? "payload verified" : "payload best-effort",
    ]);
    console.log(renderColumns(["id", "name", "status", "payload"], rows));
  });

agent.command("install")
  .description("Wire beam's hook into an agent's own hook config file, without disturbing existing hooks")
  .argument("<agent>", "agent id, e.g. claude-code, codex, cursor, copilot-cli")
  .action(async (agentId: string) => {
    const result = await installHook(agentId);
    await recordExpectedHooks();
    console.log(result.alreadyInstalled ? `✔ Already installed for ${result.agent}\n  → ${result.path}` : `✔ Installed beam hook for ${result.agent}\n  → ${result.path}`);
  });

agent.command("uninstall")
  .description("Detach beam's hook from a single agent's own hook config, leaving everything else installed")
  .argument("<agent>", "agent id, e.g. claude-code, codex, cursor, copilot-cli")
  .option("--yes", "skip the confirmation prompt")
  .action(async (agentId: string, options: { yes?: boolean }) => {
    const identity = await readIdentity();
    const proceed = await confirmControlAction(
      `This will detach beam's hook from ${agentId}. Its activity will no longer be observed or policy-enforced by beam.`,
      identity, options.yes
    );
    if (!proceed) { console.log("Cancelled."); return; }
    if (identity) await reportControlEvent(`agent-uninstall-${agentId}`, `Beam hook detached from ${agentId} on ${identity.hostname}`, `This device ran 'beam agent uninstall ${agentId}'. ${agentId} is no longer being observed or policy-enforced by beam.`);
    const result = await uninstallHook(agentId);
    await recordExpectedHooks();
    console.log(result.removed ? `✔ Detached beam's hook from ${result.agent}\n  → ${result.path}` : `— No beam hook found for ${result.agent}.`);
  });

agent.command("extract")
  .description("Forensic extraction: read an agent's existing session/transcript files directly, no hook or live capture required")
  .argument("<agent>", `agent id (currently: claude-code, codex)`)
  .option("--save", "import extracted records into the running collector instead of just previewing them")
  .option("--limit <n>", "cap how many events the offline preview prints", "200")
  .action(async (agentId: string, options: { save?: boolean; limit?: string }) => {
    if (!supportsExtraction(agentId)) throw new Error(`Forensic extraction isn't built for '${agentId}' yet. Supported: claude-code, codex.`);
    if (options.save) {
      const result = await extractSave(agentId);
      console.log(`Found ${result.found} historical action${result.found === 1 ? "" : "s"} in ${agentId}'s session files.\n✔ Imported: ${result.accepted}\n— Already had: ${result.duplicates}\n— Skipped (unsupported record type): ${result.skipped}`);
    } else {
      const result = await extractPreview(agentId, Number(options.limit) || 200);
      console.log(JSON.stringify(result.events, null, 2));
      console.log(`\n${result.found} historical action${result.found === 1 ? "" : "s"} found (showing ${result.previewed}). This was NOT sent to the collector -- rerun with --save to import.`);
    }
  });

agent.command("install-all")
  .description("Detect which agents are actually installed on this machine and wire beam's hook into all of them")
  .action(async () => {
    const results = await installAllDetectedHooks();
    await recordExpectedHooks();
    for (const r of results) {
      if (r.status === "installed") console.log(`✔ Installed for ${r.name}\n  → ${r.path}`);
      else if (r.status === "already-installed") console.log(`✔ Already installed for ${r.name}`);
      else if (r.status === "not-supported") console.log(`— ${r.name} detected, but hook install isn't built for it yet`);
      else if (r.status === "error") console.log(`✖ ${r.name}: ${r.error}`);
      // "not-detected" agents are omitted entirely to keep this output about what's actually on this machine.
    }
    const acted = results.filter(r => r.status === "installed" || r.status === "already-installed");
    if (!acted.length) console.log("No supported agents detected on this machine. Run 'beam agent list' to see what's supported.");
    if (acted.length && !(await readIdentity())) console.log(cyan("\nTip: run 'beam connect' to link this device to your dashboard and see this activity."));
  });

const rule = program.command("rule").description("Inspect the active detection rule catalog");

rule.command("list")
  .alias("ls")
  .description("List every active rule (built-in, custom, and cross-event sequence rules) grouped by category")
  .action(async () => {
    const customResult = await loadCustomRules();
    const catalog = ruleCatalog();
    const byCategory = new Map<string, typeof catalog>();
    for (const r of catalog) {
      const list = byCategory.get(r.category);
      if (list) list.push(r); else byCategory.set(r.category, [r]);
    }
    for (const [category, entries] of [...byCategory.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      console.log(`\n${category}`);
      for (const r of entries) console.log(`  ${r.id}\t${r.severity}\t${r.title}`);
    }
    console.log(`\nsequence (cross-event, evaluated per session)`);
    for (const r of sequenceRuleCatalog) console.log(`  ${r.id}\t${r.severity}\t${r.title} (${r.steps.length} steps)`);
    const customCount = catalog.filter(r => r.category === "custom").length;
    console.log(`\n${catalog.length} single-event rule${catalog.length === 1 ? "" : "s"} (${customCount} custom), ${sequenceRuleCatalog.length} sequence rule${sequenceRuleCatalog.length === 1 ? "" : "s"}.`);
    if (customResult.errors.length) { console.log(`\nCustom rule file issues (${customResult.path}):`); for (const e of customResult.errors) console.log(`  ✖ ${e}`); }
  });

rule.command("reload")
  .description("Reload ~/.beam/rules.json into the running collector, without restarting it")
  .action(async () => {
    const result = await reloadRemoteRules();
    console.log(`Loaded ${result.loaded} custom rule${result.loaded === 1 ? "" : "s"} from ${result.path}.`);
    for (const e of result.errors) console.log(`✖ ${e}`);
  });

const trust = program.command("trust").description("Manage the global allowlist of outside-workspace paths Beam won't ask about again (advisory/enforce mode only)");

trust.command("add <path>")
  .description("Pre-approve a path or directory (or a glob containing '*') so Beam stops asking about it")
  .action(async (path: string) => {
    await addTrustedPath(path);
    console.log(`✔ Trusted: ${path}`);
  });

trust.command("remove <path>")
  .alias("rm")
  .description("Remove a path from the trusted allowlist")
  .action(async (path: string) => {
    await removeTrustedPath(path);
    console.log(`✔ Untrusted: ${path}`);
  });

trust.command("list")
  .alias("ls")
  .description("List all trusted outside-workspace paths")
  .action(async () => {
    const paths = await readTrustedPaths();
    if (!paths.length) { console.log(`No trusted paths (${trustedPathsFile()}).`); return; }
    for (const p of paths) console.log(p);
  });

const block = program.command("block").description("Audit or undo entries added by the 'Block always' choice on a warn prompt");

block.command("remove <target>")
  .alias("rm")
  .description("Remove a target from the blocked list")
  .action(async (target: string) => {
    await removeBlockedTarget(target);
    console.log(`✔ Unblocked: ${target}`);
  });

block.command("list")
  .alias("ls")
  .description("List all blocked targets")
  .action(async () => {
    const targets = await readBlockedTargets();
    if (!targets.length) { console.log(`No blocked targets (${blockedTargetsFile()}).`); return; }
    for (const t of targets) console.log(t);
  });

try {
  await program.parseAsync();
} catch (error: unknown) {
  console.error(`\n✖ ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
