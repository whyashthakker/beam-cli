import { readFileSync } from "node:fs";

let cached: string | undefined;
/** This install's version, from its own package.json. */
export function beamVersion(): string {
  if (cached) return cached;
  try { cached = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version; } catch { cached = "0.0.0"; }
  return cached;
}
/** Header the workspace reads to show which beam version each device runs. */
export const versionHeaders = (): Record<string, string> => ({ "X-Beam-Version": beamVersion() });
