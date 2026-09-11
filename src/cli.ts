#!/usr/bin/env node
import fs from "node:fs";
import { Command } from "commander";
import { startServer } from "./serve.js";
import { captureHook, extractPreview, extractSave, importEvents, readToken, reloadRemoteRules, scanFile } from "./client.js";
import { supportsExtraction } from "./extract.js";
import { AGENTS } from "./agents.js";
import { installAllDetectedHooks, installHook } from "./install.js";
import { installService, serviceLogPaths, serviceStatus, startService, stopService, uninstallService } from "./service.js";
import { getCollectorUrl, getIdentityPath } from "./config.js";
import { clearIdentity, enrollDevice, readIdentity } from "./enroll.js";
import { startConnect } from "./connect.js";
import { runSetup } from "./setup.js";
import { installEnterprisePackage } from "./enterprise-install.js";
import { fetchAccount, revokeDevice } from "./account.js";
import { syncPolicy } from "./forward.js";
import { openBrowser } from "./open-browser.js";
import { ruleCatalog } from "./core.js";
import { loadCustomRules } from "./custom-rules.js";
import { sequenceRuleCatalog } from "./sequences.js";
import { printBanner } from "./banner.js";

printBanner();

const packageJson = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const program = new Command()
  .name("beam")
  .description("Local observation and heuristic risk scanning for AI agent activity")
  .version(packageJson.version);

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
    const policyNote = result.policySync ? "\nPolicy sync: on (every 60s)" : "\nPolicy sync: off (device not enrolled — run 'beam enroll')";
    const newlyInstalled = result.agentInstalls.filter(r => r.status === "installed");
    const installNote = newlyInstalled.length
      ? `\nAgent hooks installed: ${newlyInstalled.map(r => r.name).join(", ")}`
      : "";
    for (const r of result.agentInstalls) {
      if (r.status === "error") console.error(`✖ Could not wire beam's hook into ${r.name}: ${r.error}`);
    }
    console.log(`Beam collector running.\nMode: observe only\nLocal storage: ${result.directory}${rulesNote}${policyNote}${installNote}\nRun 'beam agent list' to see every detected agent's capture status.\nRun 'beam token' for the pairing token.`);
  });

const service = program.command("service").description("Run the collector as a background service (launchd on macOS, systemd --user on Linux)");

service.command("install")
  .description("Install and start the collector as a background service that survives reboots")
  .option("-p, --port <port>", "port to listen on")
  .action(async (options: { port?: string }) => {
    const result = await installService({ port: options.port ? Number(options.port) : undefined });
    console.log(`✔ Installed and started the beam service (${result.platform})\n  config: ${result.configPath}`);
  });

service.command("uninstall")
  .description("Stop and remove the background service")
  .action(async () => { await uninstallService(); console.log("✔ Removed the beam service."); });

service.command("start").description("Start the installed background service").action(async () => { await startService(); console.log("✔ Started."); });
service.command("stop").description("Stop the installed background service").action(async () => { await stopService(); console.log("✔ Stopped."); });

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

program.command("enroll")
  .description("Enroll this device with your Beam workspace using a code from your manager")
  .requiredOption("--code <code>", "enrollment code, e.g. BEAM-XXXX-XXXX-XXXX")
  .option("--url <url>", "Beam API base URL (default $BEAM_API_URL or https://app.agentbeam.com)")
  .action(async (options: { code: string; url?: string }) => {
    const existing = await readIdentity();
    if (existing) console.error(`Replacing the existing enrollment (device ${existing.deviceId}).`);
    const identity = await enrollDevice(options);
    console.log(
      `✔ Enrolled device ${identity.deviceId}\n` +
      `  org:      ${identity.orgId}\n` +
      `  api:      ${identity.apiBase}\n` +
      `  identity: ${getIdentityPath()} (0600)\n\n` +
      `Next: beam agent install-all && beam start`
    );
  });

program.command("whoami")
  .description("Show this device's enrollment, if any")
  .action(async () => {
    const identity = await readIdentity();
    if (!identity) throw new Error("This device is not enrolled. Run 'beam enroll --code <code>'.");
    console.log(`device: ${identity.deviceId}\norg:    ${identity.orgId}\napi:    ${identity.apiBase}\nhost:   ${identity.hostname} (${identity.os})\nsince:  ${identity.enrolledAt}`);
  });

program.command("account")
  .description("Show the signed-in user and workspace this device is connected to")
  .action(async () => {
    const identity = await readIdentity();
    if (!identity) throw new Error("This device is not enrolled. Run 'beam connect' or 'beam enroll --code <code>'.");
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
  .action(async () => {
    const identity = await readIdentity();
    if (!identity) {
      console.log("This device is not enrolled -- nothing to do.");
      return;
    }
    try {
      await revokeDevice(identity);
    } catch (e) {
      console.error(`✖ Could not reach ${identity.apiBase} to revoke this device: ${(e as Error).message}`);
      console.error("  Clearing local credentials anyway.");
    }
    await clearIdentity();
    console.log(`✔ Logged out. Removed ${getIdentityPath()}.`);
  });

program.command("sync")
  .description("Pull the latest policy from your Beam workspace into ~/.beam/data/policy.json")
  .action(async () => {
    const result = await syncPolicy();
    if (result.status === "not-enrolled") throw new Error("This device is not enrolled. Run 'beam enroll --code <code>'.");
    if (result.status === "unreachable") throw new Error("Could not reach the Beam workspace. Check the network or 'beam whoami'.");
    console.log(result.status === "updated" ? `✔ Policy v${result.version} synced → ${result.path}` : "✔ Policy already up to date.");
  });

program.command("token")
  .description("Print the Beam collector pairing token")
  .action(async () => console.log(await readToken()));

program.command("connect")
  .description("Pair this device with your Beam dashboard by signing in through the browser")
  .action(async () => {
    const existing = await readIdentity();
    if (existing) console.error(`Replacing the existing enrollment (device ${existing.deviceId}).`);

    const session = await startConnect();
    console.log(`Connect Beam CLI to Agentbeam:\n${session.url}`);
    openBrowser(session.url);
    console.log("\nWaiting for you to finish in the browser…");

    const identity = await session.poll();
    console.log(
      `✔ Connected device ${identity.deviceId}\n` +
      `  org:      ${identity.orgId}\n` +
      `  api:      ${identity.apiBase}\n` +
      `  identity: ${getIdentityPath()} (0600)`
    );

    const enterprise = await installEnterprisePackage(identity);
    if (enterprise.status === "installed") console.log("✔ beam-enterprise installed (OS-level monitoring enabled).");
    else if (enterprise.status === "error") console.error(`✖ Could not install beam-enterprise: ${enterprise.message}`);
    // "not-entitled": org isn't on the enterprise plan -- nothing to print, this is the normal case.

    console.log("\nNext: beam agent install-all && beam start");
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

program.command("hook")
  .description("Forward a hook payload from stdin for the given agent (observation only, never blocks the agent). Payload field names are adapted per agent; see 'beam agent list'.")
  .argument("[source-agent]", "reporting agent id, e.g. claude-code, codex, cursor, copilot-cli", "claude-code")
  .action(captureHook);

const agent = program.command("agent").description("Discover and configure supported AI agents");

agent.command("list")
  .alias("ls")
  .description("List supported agents and their hook payload verification status")
  .action(() => {
    for (const a of AGENTS) {
      const install = a.hookConfigPath ? "installable" : "config wiring not built yet";
      const payload = a.verifiedPayload ? "payload verified" : "payload best-effort";
      console.log(`${a.id}\t${a.name}\t${install}\t${payload}`);
    }
  });

agent.command("install")
  .description("Wire beam's hook into an agent's own hook config file, without disturbing existing hooks")
  .argument("<agent>", "agent id, e.g. claude-code, codex, cursor, copilot-cli")
  .action(async (agentId: string) => {
    const result = await installHook(agentId);
    console.log(result.alreadyInstalled ? `✔ Already installed for ${result.agent}\n  → ${result.path}` : `✔ Installed beam hook for ${result.agent}\n  → ${result.path}`);
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
    for (const r of results) {
      if (r.status === "installed") console.log(`✔ Installed for ${r.name}\n  → ${r.path}`);
      else if (r.status === "already-installed") console.log(`✔ Already installed for ${r.name}`);
      else if (r.status === "not-supported") console.log(`— ${r.name} detected, but hook install isn't built for it yet`);
      else if (r.status === "error") console.log(`✖ ${r.name}: ${r.error}`);
      // "not-detected" agents are omitted entirely to keep this output about what's actually on this machine.
    }
    const acted = results.filter(r => r.status === "installed" || r.status === "already-installed");
    if (!acted.length) console.log("No supported agents detected on this machine. Run 'beam agent list' to see what's supported.");
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

program.parseAsync().catch((error: unknown) => {
  console.error(`\n✖ ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
