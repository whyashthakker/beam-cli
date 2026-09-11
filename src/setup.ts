import { createInterface } from "node:readline/promises";
import { detectAgents, installHook } from "./install.js";
import { readIdentity } from "./enroll.js";
import { startConnect } from "./connect.js";
import { installEnterprisePackage } from "./enterprise-install.js";
import { installService } from "./service.js";
import { openBrowser } from "./open-browser.js";
import { getIdentityPath } from "./config.js";
import { checkbox, renderTable, withSpinner } from "./prompts.js";

const TOTAL_STEPS = 4;
function step(n: number, title: string): void {
  console.log(`\nStep ${n}/${TOTAL_STEPS}: ${title}`);
}

async function promptYesNo(question: string, defaultYes = true): Promise<boolean> {
  const suffix = defaultYes ? "[Y/n]" : "[y/N]";
  if (!process.stdin.isTTY) {
    console.log(`${question} ${suffix} (non-interactive shell, defaulting to ${defaultYes ? "yes" : "no"})`);
    return defaultYes;
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`${question} ${suffix} `)).trim().toLowerCase();
    if (!answer) return defaultYes;
    return answer.startsWith("y");
  } finally {
    rl.close();
  }
}

// One-shot onboarding for a machine that already has `beam` installed: wires beam's hook into
// whichever detected agents the user picks, connects the device if it isn't already, and
// optionally starts the background service. Any step that genuinely needs root (currently just
// installing the beam-enterprise package into global node_modules) transparently falls back to
// sudo via runWithSudoFallback -- service install never does, since it must write into the
// invoking user's own home directory, not root's.
export async function runSetup(): Promise<void> {
  console.log("Setting up Beam — 4 quick steps.");

  const agentRows: string[] = [];
  let dashboardStatus = "not connected";
  let serviceStatus = "not started";

  // --- Step 1: detect agents, then let the user choose which ones get the hook ---
  step(1, "Detecting AI agents on this machine");
  const detected = await detectAgents();
  const installable = detected.filter(a => a.hookConfigPath && a.mergeHookConfig);
  const unsupported = detected.filter(a => !a.hookConfigPath || !a.mergeHookConfig);

  if (!detected.length) {
    console.log("  No supported agents detected on this machine.");
  } else {
    for (const a of unsupported) console.log(`  — ${a.name}: hook install isn't built for it yet`);
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
    for (const a of skipped) console.log(`  — Skipped ${a.name} (run 'beam agent install ${a.id}' later if you change your mind)`);
  }

  // --- Step 2: connect this device to the dashboard (dashboard-v1, or BEAM_DASHBOARD_URL) ---
  step(2, "Connecting to your Beam dashboard");
  let identity = await readIdentity();
  if (identity) {
    console.log(`  Already connected (device ${identity.deviceId}).`);
    dashboardStatus = `connected (${identity.deviceId})`;
  } else {
    const shouldConnect = await promptYesNo("  Connect this device to your Beam dashboard now?");
    if (shouldConnect) {
      const session = await startConnect();
      console.log(`  Open this to finish pairing:\n  ${session.url}`);
      openBrowser(session.url);
      identity = await withSpinner("Waiting for you to finish in the browser", () => session.poll());
      console.log(
        `    org:      ${identity.orgId}\n` +
        `    api:      ${identity.apiBase}\n` +
        `    identity: ${getIdentityPath()} (0600)`
      );
      dashboardStatus = `connected (${identity.deviceId})`;

      const enterprise = await withSpinner("Checking for beam-enterprise", () => installEnterprisePackage(identity!));
      if (enterprise.status === "installed") console.log("  beam-enterprise installed (OS-level monitoring enabled).");
      else if (enterprise.status === "error") console.error(`  Could not install beam-enterprise: ${enterprise.message}`);
      // "not-entitled": org isn't on the enterprise plan -- nothing to print, this is the normal case.
    } else {
      console.log("  Skipped. Run 'beam connect' whenever you're ready.");
    }
  }

  // --- Step 3: background collector service ---
  step(3, "Starting the background collector");
  const shouldStart = await promptYesNo("  Start the beam background service now (survives reboot/logout)?");
  if (shouldStart) {
    try {
      const result = await withSpinner("Installing and starting the beam service", () => installService());
      serviceStatus = `running (${result.platform})`;
    } catch (err) {
      serviceStatus = `failed: ${(err as Error).message}`;
    }
  } else {
    console.log("  Skipped. Run 'beam service install' (background) or 'beam start' (foreground) whenever you want it running.");
    serviceStatus = "skipped";
  }

  // --- Step 4: summary ---
  step(4, "Done");
  console.log();
  console.log(renderTable([
    { label: "Agent hooks", value: agentRows.length ? agentRows.join(", ") : "none" },
    { label: "Dashboard", value: dashboardStatus },
    { label: "Service", value: serviceStatus },
  ]));
  console.log("\nUseful next commands:");
  console.log("  beam studio          open the activity dashboard");
  console.log("  beam service status  check whether the collector is running");
  console.log("  beam agent list      check hook status per agent");
}
