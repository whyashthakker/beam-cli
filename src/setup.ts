import { detectAgents, installHook } from "./install.js";
import { readIdentity } from "./enroll.js";
import { startConnect } from "./connect.js";
import { installEnterprisePackage } from "./enterprise-install.js";
import { installService } from "./service.js";
import { openBrowser } from "./open-browser.js";
import { checkbox, confirm, renderTable, withSpinner } from "./prompts.js";
import { showFirstRunWelcome } from "./owl.js";
import { cyan, dim, green, indigoOut, red } from "./color.js";
import { syncPolicy } from "./forward.js";
import { AGENT_BINARIES } from "./shims.js";
import { installMcpProxies } from "./mcp-config.js";
import { forwardMcpInventory } from "./forward.js";

const TOTAL_STEPS = 5;
function step(n: number, title: string): void {
  console.log(`\n${indigoOut(`Step ${n}/${TOTAL_STEPS}`)}  ${title}`);
}

function ok(message: string): void {
  console.log(`  ${green("✔")} ${message}`);
}

function skip(message: string): void {
  console.log(`  ${dim(`— ${message}`)}`);
}

function fail(message: string): void {
  console.log(`  ${red("✖")} ${message}`);
}

// Kept as promptYesNo (rather than renaming every call site to `confirm`) since `beam uninstall`
// also imports it by this name for its own "Proceed?" prompt.
export const promptYesNo = confirm;

// Colors a summary-table status value by what it means, so the table communicates state at a
// glance instead of reading as one flat block of text.
function statusValue(value: string): string {
  if (value.startsWith("failed")) return red(value);
  if (value === "none" || value === "not connected" || value === "not started" || value === "skipped") return dim(value);
  return green(value);
}

// One-shot onboarding for a machine that already has `beam` installed: wires beam's hook into
// whichever detected agents the user picks, connects the device if it isn't already, and
// optionally starts the background service. Any step that genuinely needs root (currently just
// installing the beam-enterprise package into global node_modules) transparently falls back to
// sudo via runWithSudoFallback -- service install never does, since it must write into the
// invoking user's own home directory, not root's.
export async function runSetup(): Promise<void> {
  // Owl says hello, but only the first time this machine is ever set up.
  await showFirstRunWelcome();
  console.log(indigoOut("Setting up Beam") + dim(" — 4 quick steps"));

  const agentRows: string[] = [];
  let dashboardStatus = "not connected";
  let serviceStatus = "not started";
  let policyStatus = "not enrolled";

  // --- Step 1: detect agents, then let the user choose which ones get the hook ---
  step(1, "Detecting AI agents on this machine");
  const detected = await detectAgents();
  const installable = detected.filter(a => a.hookConfigPath && a.mergeHookConfig);
  const unsupported = detected.filter(a => !a.hookConfigPath || !a.mergeHookConfig);

  if (!detected.length) {
    skip("No supported agents detected on this machine.");
  } else {
    for (const a of unsupported) skip(`${a.name}: hook install isn't built for it yet`);
  }

  if (installable.length) {
    const picked = await checkbox(
      `  Found ${installable.length} agent${installable.length === 1 ? "" : "s"} — pick which get beam's hook:`,
      installable.map(a => ({ label: a.name, checked: true }))
    );
    const toInstall = picked.map(i => installable[i]);
    for (const agent of toInstall) {
      try {
        const result = await withSpinner(`Installing hook for ${agent.name}`, () => installHook(agent.id));
        agentRows.push(`${agent.name}${result.alreadyInstalled ? " (already installed)" : ""}`);
      } catch (e) {
        agentRows.push(`${agent.name} — failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    const skipped = installable.filter(a => !toInstall.includes(a));
    for (const a of skipped) skip(`Skipped ${a.name} (run 'beam agent install ${a.id}' later if you change your mind)`);
  }

  // Shims are never installed automatically -- writing into PATH resolution is a bigger footprint
  // than a hook install, and this session has no way to also edit the user's shell rc for them.
  // Just point at the exact command for whichever detected agents shims actually support.
  const shimmable = detected.filter(a => AGENT_BINARIES[a.id]);
  if (shimmable.length) {
    console.log(`\n  Tip: to sandbox ${shimmable.map(a => a.name).join(", ")} automatically (no need to type 'beam run'), run:`);
    console.log(`    beam shims install ${shimmable.map(a => a.id).join(" ")}`);
  }

  const mcpResults = await installMcpProxies();
  const mcpInventory = mcpResults.flatMap(result => result.servers);
  const mcpWrapped = mcpResults.reduce((total, result) => total + result.wrapped, 0);
  const mcpErrors = mcpResults.filter(result => result.error);
  if (mcpWrapped) ok(`Protected ${mcpWrapped} MCP server${mcpWrapped === 1 ? "" : "s"} with the local response proxy.`);
  if (mcpInventory.length) ok(`Detected MCP servers: ${mcpInventory.map(server => server.name).join(", ")}`);
  for (const result of mcpErrors) fail(`Could not update MCP config ${result.path}: ${result.error}`);

  // --- Step 2: connect this device to the dashboard (dashboard-v1, or BEAM_DASHBOARD_URL) ---
  step(2, "Connecting to your Beam dashboard");
  let identity = await readIdentity();
  let shouldConnect = !identity;
  if (identity) {
    ok(`Already connected as device ${identity.deviceId}.`);
    dashboardStatus = `connected (${identity.deviceId})`;
    shouldConnect = await promptYesNo("  Reconnect or link to a different workspace?", false);
  } else {
    shouldConnect = await promptYesNo("  Connect this device to your Beam dashboard now?");
  }

  if (shouldConnect) {
    // Mirrors 'beam connect': always opens the browser and overwrites any existing identity,
    // so re-running setup can also be used to re-pair or switch workspaces.
    const session = await startConnect();
    openBrowser(session.url);
    console.log(`  ${dim("Didn't open? Visit:")} ${cyan(session.url)}`);
    identity = await withSpinner("Waiting for you to finish in the browser", () => session.poll());
    ok(`Connected device ${identity.deviceId} (org ${identity.orgId})`);
    dashboardStatus = `connected (${identity.deviceId})`;

    const enterprise = await withSpinner("Checking for beam-enterprise", () => installEnterprisePackage(identity!));
    if (enterprise.status === "installed") ok("beam-enterprise installed (OS-level monitoring enabled).");
    else if (enterprise.status === "error") fail(`Could not install beam-enterprise: ${enterprise.message}`);
    // "not-entitled": org isn't on the enterprise plan -- nothing to print, this is the normal case.
  } else if (!identity) {
    skip("Skipped. Run 'beam connect' whenever you're ready.");
  }
  // --- Step 3: fetch this device's effective policy (org + any user-level override), if enrolled ---
  // A device can be enrolled from a previous `beam setup`/`beam enroll` run without this run ever
  // reaching Step 2's connect branch above -- so this always runs off whatever `identity` ended up
  // being, not just the freshly-connected path.
  step(3, "Fetching your org's policy");
  if (identity) {
    const result = await withSpinner("Syncing policy", () => syncPolicy());
    if (result.status === "updated") { console.log(`  ✔ Policy v${result.version} synced (org + any user override, merged).`); policyStatus = `synced (v${result.version})`; }
    else if (result.status === "unchanged") { console.log("  ✔ Already up to date."); policyStatus = "up to date"; }
    else if (result.status === "unreachable") { console.error("  ✖ Could not reach the Beam workspace — will retry automatically once the service is running."); policyStatus = "unreachable (will retry)"; }
  } else {
    console.log("  Skipped — device isn't connected to a dashboard yet.");
  }
  if (identity && mcpInventory.length) {
    const sent = await withSpinner("Sending MCP inventory", () => forwardMcpInventory(mcpInventory));
    if (sent) ok(`Sent ${mcpInventory.length} MCP server${mcpInventory.length === 1 ? "" : "s"} to the dashboard.`);
    else fail("Could not send MCP inventory; local MCP protection remains active and it will be retried on the next setup.");
  }

  // --- Step 4: background collector service ---
  step(4, "Starting the background collector");
  const shouldStart = await promptYesNo("  Start the beam background service now (survives reboot/logout)?");
  if (shouldStart) {
    try {
      const result = await withSpinner("Installing and starting the beam service", () => installService());
      serviceStatus = `running (${result.platform})`;
    } catch (err) {
      serviceStatus = `failed: ${(err as Error).message}`;
    }
  } else {
    skip("Skipped. Run 'beam service install' (background) or 'beam start' (foreground) whenever you want it running.");
    serviceStatus = "skipped";
  }

  // --- Step 5: summary ---
  step(5, "Done");
  console.log();
  const agentSummary = agentRows.length
    ? `${agentRows.length} installed (${agentRows.join(", ")})`
    : "none";
  const agentSummaryColor = agentRows.some(r => r.includes("failed")) ? red : statusValue;
  console.log(renderTable([
    { label: "Agent hooks", value: agentSummaryColor(agentSummary) },
    { label: "Dashboard", value: statusValue(dashboardStatus) },
    { label: "Policy", value: statusValue(policyStatus) },
    { label: "Service", value: statusValue(serviceStatus) },
  ]));
  console.log(`\n${dim("Useful next commands:")}`);
  console.log(`  ${cyan("beam studio")}          open the activity dashboard`);
  console.log(`  ${cyan("beam service status")}  check whether the collector is running`);
  console.log(`  ${cyan("beam agent list")}      check hook status per agent`);
  if (shimmable.length) console.log(`  ${cyan(`beam shims install ${shimmable.map(a => a.id).join(" ")}`)}   sandbox ${shimmable.map(a => a.name).join(", ")} automatically`);
}
