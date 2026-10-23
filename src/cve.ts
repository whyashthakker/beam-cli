// `beam cve check`: read an app's lockfiles and ask the workspace which installed versions have
// known vulnerabilities. Exit codes suit CI: 0 clean (below --fail-on), 2 vulnerable, 1 error.
import { resolve } from "node:path";
import { readInstalledPackages } from "./lockfiles.js";
import { checkPackages, monitorAuth, type Vulnerability } from "./monitor-client.js";
import { cyan, dim, green, red } from "./color.js";

export const CVE_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type CveSeverity = (typeof CVE_SEVERITIES)[number];
const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
// Advisories without a rating are treated as medium rather than ignored.
export const severityRank = (severity: string) => RANK[severity] ?? 2;

export interface CveCheckOptions { json?: boolean; failOn?: CveSeverity; depth?: number }

export function formatVulnerability(v: Vulnerability): string {
  const label = v.severity.toUpperCase().padEnd(8);
  const fix = v.patched ? `fixed in ${v.patched}` : "no fixed version yet";
  const kev = v.kev ? red(" [actively exploited: CISA KEV]") : "";
  return [
    `${severityRank(v.severity) >= 3 ? red(label) : label} ${v.id}  ${v.name} ${v.version} (${v.ecosystem}), ${fix}${kev}`,
    `         ${v.title}`,
    dim(`         ${v.files.join(", ")} · ${v.url}`),
  ].join("\n");
}

export async function runCveCheck(dir: string, options: CveCheckOptions = {}, write: (line: string) => void = console.log): Promise<number> {
  const identity = await monitorAuth();
  if (!identity) throw new Error("Set BEAM_APP_TOKEN to the app's token from the dashboard's App monitoring page, or connect this machine with 'beam connect'.");
  const root = resolve(dir);
  const scan = await readInstalledPackages(root, options.depth);
  if (!scan.files.length) {
    if (options.json) write(JSON.stringify({ files: [], checked: 0, vulnerabilities: [] }));
    else write(`No lockfiles found under ${root}. Beam reads package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, requirements*.txt, poetry.lock, uv.lock, Pipfile.lock, go.mod, Cargo.lock, composer.lock, Gemfile.lock, packages.lock.json, gradle.lockfile, mix.lock, Package.resolved and GitHub workflow files.`);
    return 0;
  }
  if (!scan.packages.length) {
    if (options.json) write(JSON.stringify({ files: scan.files, checked: 0, vulnerabilities: [], errors: scan.errors }));
    else write(`Found ${scan.files.length} lockfile${scan.files.length === 1 ? "" : "s"} but no pinned versions to check.`);
    return 0;
  }
  const response = await checkPackages(identity, scan.packages);
  if (!response.ok) throw new Error(response.message);
  const { vulnerabilities, database, checked, remaining, resetAt } = response.result;
  const threshold = RANK[options.failOn ?? "low"]!;
  const failing = vulnerabilities.filter(v => severityRank(v.severity) >= threshold);

  if (options.json) {
    write(JSON.stringify({ files: scan.files, checked, vulnerabilities, database, errors: scan.errors, truncated: scan.truncated }, null, 2));
    return failing.length ? 2 : 0;
  }
  write(`Checked ${checked.toLocaleString("en-US")} package${checked === 1 ? "" : "s"} from ${scan.files.length} file${scan.files.length === 1 ? "" : "s"} against ${database.advisories.toLocaleString("en-US")} advisories.`);
  for (const error of scan.errors) write(dim(`  skipped ${error}`));
  if (scan.truncated) write(dim("  Stopped at 20,000 packages; check large monorepos one app at a time."));
  if (!vulnerabilities.length) {
    write(green("✔ No known vulnerabilities in the pinned versions."));
  } else {
    write("");
    for (const v of vulnerabilities) write(`${formatVulnerability(v)}\n`);
    const counts = CVE_SEVERITIES.map(s => [s, vulnerabilities.filter(v => (RANK[v.severity] ? v.severity : "medium") === s).length] as const)
      .filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(", ");
    write(`${failing.length ? red("✖") : "!"} ${vulnerabilities.length} known vulnerabilit${vulnerabilities.length === 1 ? "y" : "ies"} (${counts}).`);
  }
  write(dim(`${remaining.toLocaleString("en-US")} dependency checks left this month (resets ${resetAt.slice(0, 10)}).`));
  if (failing.length && options.failOn && options.failOn !== "low") write(cyan(`Failing because ${failing.length} ${failing.length === 1 ? "is" : "are"} ${options.failOn} or above.`));
  return failing.length ? 2 : 0;
}
