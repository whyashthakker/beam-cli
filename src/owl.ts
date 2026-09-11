import { mkdir, writeFile, access } from "node:fs/promises";
import path from "node:path";
import { getBeamHome } from "./config.js";

// Beam the owl, in 2-bit block art — the same little mascot that watches over
// your agents on agentbeam.com, drawn for a monospace terminal.
const OWL = String.raw`
     ▟▀▙  ▟▀▙
     █◉█  █◉█
     ▜▄▛▲▜▄▛
       ▔`;

const WELCOME = [
  "",
  "  Hi, I'm Beam. I'll keep an eye on what your AI agents do —",
  "  locally, on this machine. No agent activity leaves without you.",
  "",
];

// A once-ever marker in ~/.beam. Its presence means this machine has already
// been greeted, so the welcome only ever shows on the very first setup.
function welcomeMarkerPath(): string {
  return path.join(getBeamHome(), ".welcomed");
}

async function hasBeenWelcomed(): Promise<boolean> {
  try {
    await access(welcomeMarkerPath());
    return true;
  } catch {
    return false;
  }
}

/**
 * Print the owl and a short hello the first time `beam setup` runs on a
 * machine, then record that it happened. Any later setup runs stay quiet.
 * Never throws — a greeting is never worth failing onboarding over.
 */
export async function showFirstRunWelcome(): Promise<void> {
  try {
    if (await hasBeenWelcomed()) return;
    console.log(OWL);
    for (const line of WELCOME) console.log(line);
    await mkdir(getBeamHome(), { recursive: true });
    await writeFile(welcomeMarkerPath(), `${new Date().toISOString()}\n`, "utf8");
  } catch {
    // Ignore — if we can't write the marker, worst case the owl greets twice.
  }
}
