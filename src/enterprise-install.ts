import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Identity } from "./enroll.js";
import { runWithSudoFallback } from "./elevate.js";

export type EnterpriseInstallResult =
  | { status: "installed" }
  | { status: "not-entitled" } // org isn't on the enterprise plan -- not an error, just nothing to do
  | { status: "error"; message: string };

// Called right after 'beam connect' succeeds. Fetches a short-lived presigned S3 URL for the
// private beam-enterprise package (see apps/dashboard's /v1/enterprise/package), downloads the
// tarball ourselves, and installs it from a local temp path -- never from the URL directly, so
// the presigned URL (a bearer credential in itself) never appears in argv/ps output or any log.
export async function installEnterprisePackage(identity: Identity): Promise<EnterpriseInstallResult> {
  let response: Response;
  try {
    response = await fetch(`${identity.apiBase}/v1/enterprise/package`, {
      headers: { Authorization: `Bearer ${identity.deviceSecret}` },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return { status: "error", message: `Could not reach ${identity.apiBase}.` };
  }

  if (response.status === 403) return { status: "not-entitled" };
  if (!response.ok) return { status: "error", message: `Could not fetch beam-enterprise (${response.status}).` };

  const { url } = (await response.json()) as { url?: string };
  if (!url) return { status: "error", message: "Enterprise package response was missing a download URL." };

  const tmpDir = await mkdtemp(join(tmpdir(), "beam-enterprise-"));
  const tarballPath = join(tmpDir, "package.tgz");
  try {
    let download: Response;
    try {
      download = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    } catch {
      return { status: "error", message: "Could not download beam-enterprise (network error)." };
    }
    if (!download.ok) return { status: "error", message: `Could not download beam-enterprise (${download.status}).` };

    await writeFile(tarballPath, Buffer.from(await download.arrayBuffer()));

    // -g so it lands in the same global node_modules as a globally-installed `beam`, where
    // os-monitor.ts's bare `import("beam-enterprise")` can resolve it. --no-save: this is a
    // local tarball path, not something meaningful to persist in any package.json. Falls back
    // to sudo if the global node_modules isn't user-writable (e.g. a system Node install).
    await runWithSudoFallback("npm", ["install", "-g", "--no-save", tarballPath], { timeout: 120_000 });
    return { status: "installed" };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { status: "error", message: `beam-enterprise install failed: ${message}` };
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}
