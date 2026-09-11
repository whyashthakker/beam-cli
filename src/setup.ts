import { createInterface } from "node:readline/promises";
import { installAllDetectedHooks } from "./install.js";
import { readIdentity } from "./enroll.js";
import { startConnect } from "./connect.js";
import { installEnterprisePackage } from "./enterprise-install.js";
import { installService } from "./service.js";
import { openBrowser } from "./open-browser.js";
import { getIdentityPath } from "./config.js";

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
// every detected agent, connects the device if it isn't already, and optionally starts the
// background service. Any step that genuinely needs root (currently just installing the
// beam-enterprise package into global node_modules) transparently falls back to sudo via
// runWithSudoFallback -- service install never does, since it must write into the invoking
// user's own home directory, not root's.
export async function runSetup(): Promise<void> {
  console.log("Setting up Beam...\n");

  console.log("Detecting installed AI agents and wiring beam's hook into each one...");
  const hookResults = await installAllDetectedHooks();
  for (const r of hookResults) {
    if (r.status === "installed") console.log(`  ✔ Installed for ${r.name}`);
    else if (r.status === "already-installed") console.log(`  ✔ Already installed for ${r.name}`);
    else if (r.status === "not-supported") console.log(`  — ${r.name} detected, but hook install isn't built for it yet`);
    else if (r.status === "error") console.log(`  ✖ ${r.name}: ${r.error}`);
  }
  if (!hookResults.some(r => r.status === "installed" || r.status === "already-installed")) {
    console.log("  No supported agents detected on this machine.");
  }

  let identity = await readIdentity();
  if (identity) {
    console.log(`\n✔ Already connected (device ${identity.deviceId}).`);
  } else {
    const shouldConnect = await promptYesNo("\nConnect this device to your Beam workspace now?");
    if (shouldConnect) {
      const session = await startConnect();
      console.log(`\nConnect Beam CLI to Agentbeam:\n${session.url}`);
      openBrowser(session.url);
      console.log("Waiting for you to finish in the browser…");
      identity = await session.poll();
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
    } else {
      console.log("Skipped. Run 'beam connect' whenever you're ready.");
    }
  }

  const shouldStart = await promptYesNo("\nStart the beam background service now (survives reboot/logout)?");
  if (shouldStart) {
    try {
      const result = await installService();
      console.log(`✔ Installed and started the beam service (${result.platform})\n  config: ${result.configPath}`);
    } catch (err) {
      console.error(`✖ Could not start the beam service: ${(err as Error).message}`);
    }
  } else {
    console.log("Skipped. Run 'beam service install' (background) or 'beam start' (foreground) whenever you want it running.");
  }

  console.log("\nSetup complete. Run 'beam studio' to see activity, or 'beam agent list' to check hook status.");
}
