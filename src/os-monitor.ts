// Enterprise plugin loader. OS-level observation of AI agent activity (watching `ps`/`lsof` for
// process starts/exits, independent of any agent's own hook cooperation) is NOT part of this
// open-source repo -- that detection logic (os-detect.ts, os-process.ts, os-network.ts, and the
// monitor loop itself) lives in the private `beam-enterprise` package.
//
// This file just tries to load that package at runtime. If it isn't installed -- the normal case
// for OSS users, since it's a private/paid npm package -- startOsMonitor() is a silent no-op:
// `beam start` works exactly the same without it, just without OS-level rows. See
// beam-enterprise/README.md for the plugin contract this depends on.
import { normalize, type Event } from "./core.js";

export interface OsMonitorHandle { stop: () => void }

interface EnterprisePlugin {
  startOsMonitor(sink: (records: Record<string, unknown>[]) => void | Promise<void>): Promise<OsMonitorHandle>;
}

// Not a string literal type on purpose: a literal specifier makes TypeScript try to resolve the
// module at compile time and fail typecheck for every OSS dev/CI run that (correctly) doesn't
// have this private package installed. Widening to `string` makes it a genuine runtime-only
// dynamic import.
const ENTERPRISE_PACKAGE: string = "beam-enterprise";

export async function startOsMonitor(sink: (events: Event[]) => void | Promise<void>): Promise<OsMonitorHandle> {
  let plugin: EnterprisePlugin;
  try {
    plugin = (await import(ENTERPRISE_PACKAGE)) as EnterprisePlugin;
  } catch {
    return { stop: () => {} };
  }
  return plugin.startOsMonitor(async records => { await sink(records.map(normalize)); });
}
