import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runWithSudoFallback } from "./elevate.js";

const run = promisify(execFile);
const PACKAGE = "@agent-beam/beam";

export interface UpdateCheck { current: string; latest: string; upToDate: boolean }

// Plain numeric semver compare (major.minor.patch, ignoring any prerelease suffix) -- good
// enough for comparing against npm's published "latest" dist-tag. Returns >0 when `a` is newer.
function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.-]/).map(n => Number(n) || 0);
  const pb = b.split(/[.-]/).map(n => Number(n) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

export async function checkForUpdate(current: string): Promise<UpdateCheck> {
  const { stdout } = await run("npm", ["view", PACKAGE, "version"], { timeout: 15_000 });
  const latest = stdout.trim();
  // Not just !==: a locally-run, unreleased build can be ahead of what's published -- that's
  // "up to date" too, not something to offer downgrading.
  return { current, latest, upToDate: compareVersions(latest, current) <= 0 };
}

// Installs the latest published version globally, falling back to sudo the same way
// enterprise-install.ts and 'beam uninstall' do when the global node_modules isn't
// user-writable (e.g. a system Node install).
export async function installUpdate(version: string): Promise<void> {
  await runWithSudoFallback("npm", ["install", "-g", `${PACKAGE}@${version}`], { timeout: 120_000 });
}
