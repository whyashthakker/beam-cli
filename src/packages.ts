// `beam add package`: fetch a package and its whole dependency tree into a throwaway folder
// without running any of it, scan every package, check known vulnerabilities when this machine
// is connected, and only then install the exact version that was scanned.
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { risk, type Finding } from "./core.js";
import { checkPackages, monitorAuth, type Vulnerability } from "./monitor-client.js";
import { normalizePipName } from "./package-risk-rules.js";
import { findNpmPackages, isPackageBlocked, packageRiskScore, scanNpmPackage, scanPythonDist, type PackageEcosystem, type PackageScan } from "./package-scan.js";

const run = promisify(execFile);
const shell = process.platform === "win32";

// Registry names with an optional exact version, tag, caret, tilde or x-range. Git URLs, tarball
// URLs and paths are refused: they can't be pinned to what was scanned. Nothing here can start
// with "-", so a spec is never read as an option.
const NPM_SPEC = /^((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)(?:@([\w.^~*+-]+))?$/i;
const PIP_SPEC = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w,.-]+\])?(?:(==|~=|>=|<=|!=)([\w.*+!-]+))?$/;

export function parseSpec(spec: string, ecosystem: PackageEcosystem): { name: string; range?: string } {
  if (ecosystem === "npm") {
    const m = spec.match(NPM_SPEC);
    if (!m) throw new Error(`"${spec}" isn't an npm registry package (name or name@version). Git URLs, tarballs and paths can't be pinned to the scanned version.`);
    return { name: m[1]!, range: m[2] };
  }
  const m = spec.match(PIP_SPEC);
  if (!m) throw new Error(`"${spec}" isn't a PyPI requirement (name, name==1.2.3, name>=1.2). Quote it if your shell split it.`);
  return { name: m[1]!, range: m[2] ? `${m[2]}${m[3]}` : undefined };
}

export type AddPackageOptions = { pip?: boolean; dev?: boolean; global?: boolean; force?: boolean; scanOnly?: boolean; cve?: boolean; python?: string; cwd?: string };
export type AddPackageResult = {
  spec: string; ecosystem: PackageEcosystem; name: string; version: string;
  /** The requested package first, then its dependencies. */
  scans: PackageScan[];
  vulnerabilities: Vulnerability[];
  notes: string[];
  blocked: string[];
  install?: { command: string; args: string[] };
};

const pythonCommand = (options: AddPackageOptions) => options.python ?? (process.platform === "win32" ? "python" : "python3");

// First publish date, for the "brand-new package" signal. Best effort: a private registry or a
// slow network just means the check is skipped.
async function npmCreated(name: string): Promise<string | undefined> {
  try {
    const { stdout } = await run("npm", ["view", name, "time.created", "--json"], { timeout: 15_000, shell });
    const value = JSON.parse(stdout) as unknown;
    return typeof value === "string" ? value : undefined;
  } catch { return undefined; }
}
async function pypiJson(name: string, version?: string): Promise<{ releases?: Record<string, Array<{ upload_time_iso_8601?: string }>>; urls?: Array<{ packagetype: string; url: string; filename: string; digests: { sha256: string } }>; info?: { version: string } } | undefined> {
  try {
    const response = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}${version ? `/${encodeURIComponent(version)}` : ""}/json`, { signal: AbortSignal.timeout(15_000) });
    return response.ok ? (await response.json()) as Awaited<ReturnType<typeof pypiJson>> : undefined;
  } catch { return undefined; }
}
async function pypiCreated(name: string): Promise<string | undefined> {
  const uploads = Object.values((await pypiJson(name))?.releases ?? {}).flat().map(f => f.upload_time_iso_8601).filter((t): t is string => Boolean(t)).sort();
  return uploads[0];
}

// npm resolves the full tree into the staging folder. --ignore-scripts means no lifecycle script
// of any package runs; nothing is executed until the scan passes.
async function stageNpm(spec: string, name: string, staging: string): Promise<{ version: string; scans: PackageScan[] }> {
  await writeFile(join(staging, "package.json"), JSON.stringify({ name: "beam-package-scan", private: true }));
  try {
    await run("npm", ["install", spec, "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", "--loglevel=error"], { cwd: staging, timeout: 300_000, maxBuffer: 16 * 1024 * 1024, shell });
  } catch (e) {
    const stderr = (e as { stderr?: string }).stderr?.trim().split("\n").slice(-3).join("\n");
    throw new Error(`npm couldn't fetch ${spec}${stderr ? `:\n${stderr}` : "."}`);
  }
  const top = join(staging, "node_modules", ...name.split("/"));
  const createdAt = await npmCreated(name);
  const first = await scanNpmPackage(top, { direct: true, createdAt });
  const rest = [];
  for (const dir of await findNpmPackages(join(staging, "node_modules"))) if (dir !== top) rest.push(await scanNpmPackage(dir));
  return { version: first.version, scans: [first, ...rest] };
}

// Wheels only, so pip never builds anything: building a source distribution runs its setup.py,
// which is exactly the code under suspicion. When the package has no wheel, its sdist is
// downloaded straight from PyPI (hash-checked) and unpacked, not built.
async function stagePip(spec: string, name: string, range: string | undefined, staging: string, options: AddPackageOptions, notes: string[]): Promise<{ version: string; scans: PackageScan[] }> {
  const python = pythonCommand(options);
  const downloads = join(staging, "dl");
  await mkdir(downloads);
  let wheels: string[] = [];
  let pipError: string | undefined;
  try {
    await run(python, ["-m", "pip", "download", spec, "--only-binary=:all:", "--dest", downloads, "--quiet", "--disable-pip-version-check", "--no-input"], { timeout: 300_000, maxBuffer: 16 * 1024 * 1024 });
    wheels = (await readdir(downloads)).filter(f => f.endsWith(".whl"));
  } catch (e) {
    if ((e as { code?: string }).code === "ENOENT") throw new Error(`${python} wasn't found. Pass --python <path> to the interpreter you install into.`);
    pipError = (e as { stderr?: string }).stderr?.trim().split("\n").pop();
  }
  const createdAt = await pypiCreated(name);
  const scans: PackageScan[] = [];
  const wanted = normalizePipName(name);
  for (const wheel of wheels) {
    const out = join(staging, "unpacked", wheel);
    await mkdir(out, { recursive: true });
    // -I: isolated mode, so nothing in the staging folder or the environment is imported.
    await run(python, ["-I", "-m", "zipfile", "-e", join(downloads, wheel), out], { timeout: 120_000 });
    const isTop = normalizePipName(wheel.split("-")[0]!) === wanted;
    scans.push(await scanPythonDist(out, isTop ? { direct: true, createdAt } : {}));
  }
  scans.sort((a, b) => Number(normalizePipName(b.name) === wanted) - Number(normalizePipName(a.name) === wanted));
  if (scans[0] && normalizePipName(scans[0].name) === wanted) return { version: scans[0].version, scans };

  const exact = range?.startsWith("==") ? range.slice(2) : undefined;
  if (range && !exact) throw new Error(`${name} has no wheel for this Python, and its source distribution can only be fetched by exact version (${name}==x.y.z).`);
  const release = await pypiJson(name, exact);
  const sdist = release?.urls?.find(u => u.packagetype === "sdist");
  if (!release?.info || !sdist) throw new Error(`Couldn't find ${spec} on PyPI.`);
  const archive = join(downloads, sdist.filename.replace(/[^\w.-]/g, "_"));
  const response = await fetch(sdist.url, { signal: AbortSignal.timeout(120_000) });
  if (!response.ok) throw new Error(`PyPI responded with HTTP ${response.status} for ${sdist.filename}.`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (createHash("sha256").update(bytes).digest("hex") !== sdist.digests.sha256) throw new Error(`${sdist.filename} doesn't match the hash PyPI publishes for it; not scanning it.`);
  await writeFile(archive, bytes);
  const out = join(staging, "unpacked", "sdist");
  await mkdir(out, { recursive: true });
  if (/\.zip$/i.test(archive)) await run(python, ["-I", "-m", "zipfile", "-e", archive, out], { timeout: 120_000 });
  else await run("tar", ["-xzf", archive, "-C", out], { timeout: 120_000 });
  const [root] = await readdir(out);
  const scan = await scanPythonDist(root ? join(out, root) : out, { version: release.info.version, direct: true, createdAt });
  notes.push(`pip couldn't fetch wheels for ${spec} and all its dependencies${pipError ? ` (${pipError})` : ""}, so only ${name}'s source distribution was scanned. Its setup.py runs at install; its dependencies weren't checked.`);
  return { version: release.info.version, scans: [scan] };
}

// Known vulnerabilities from the workspace's database, for every scanned package. Only names and
// versions are sent. Skipped (with a note) when the machine isn't connected.
export async function attachVulnerabilities(scans: PackageScan[], notes: string[]): Promise<Vulnerability[]> {
  let identity;
  try { identity = await monitorAuth(); } catch (e) { notes.push(`Known-vulnerability check skipped: ${(e as Error).message}`); return []; }
  if (!identity) { notes.push("Known-vulnerability check skipped: run 'beam connect' (or set BEAM_APP_TOKEN) to also check CVEs."); return []; }
  const packages = scans.filter(s => s.version).map(s => ({ ecosystem: s.ecosystem, name: s.name, version: s.version, file: `${s.name}@${s.version}` }));
  if (!packages.length) return [];
  const response = await checkPackages(identity, packages);
  if (!response.ok) { notes.push(`Known-vulnerability check skipped: ${response.message}`); return []; }
  const vulns = response.result.vulnerabilities;
  const severity = (s: string): Finding["severity"] => (s === "critical" ? "critical" : s === "high" ? "high" : s === "low" ? "info" : "medium");
  for (const scan of scans) {
    const own = vulns.filter(v => v.ecosystem === scan.ecosystem && v.name === scan.name && v.version === scan.version);
    if (!own.length) continue;
    // Actively exploited (CISA KEV) counts as critical whatever its CVSS rating.
    scan.findings.unshift(...own.map(v => ({ id: `cve.${v.id}`, title: `Known vulnerability ${v.id}: ${v.title}`, severity: v.kev ? "critical" as const : severity(v.severity), explanation: v.patched ? `Fixed in ${v.patched}. ${v.url}` : `No fixed version yet. ${v.url}`, evidence: `${v.name} ${v.version} matches ${v.vulnerable}`, file: "(advisory)" })));
    Object.assign(scan, packageRiskScore(scan.findings), { risk: risk(scan.findings) });
  }
  return vulns;
}

function detectManager(cwd: string): "npm" | "pnpm" | "yarn" | "bun" {
  if (existsSync(join(cwd, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(cwd, "yarn.lock"))) return "yarn";
  if (existsSync(join(cwd, "bun.lock")) || existsSync(join(cwd, "bun.lockb"))) return "bun";
  return "npm";
}

/** The command that installs exactly the scanned version with the project's own package manager. */
export function installCommand(ecosystem: PackageEcosystem, name: string, version: string, options: AddPackageOptions = {}): { command: string; args: string[] } {
  if (ecosystem === "pip") return { command: pythonCommand(options), args: ["-m", "pip", "install", `${name}==${version}`, ...(options.global ? ["--user"] : [])] };
  const pinned = `${name}@${version}`;
  if (options.global) return { command: "npm", args: ["install", "-g", pinned] };
  const manager = detectManager(options.cwd ?? process.cwd());
  const dev = options.dev ? [{ npm: "--save-dev", pnpm: "-D", yarn: "--dev", bun: "--dev" }[manager]] : [];
  return { command: manager, args: [manager === "npm" ? "install" : "add", pinned, ...dev] };
}

export async function addPackage(spec: string, options: AddPackageOptions = {}): Promise<AddPackageResult> {
  const ecosystem: PackageEcosystem = options.pip ? "pip" : "npm";
  if (ecosystem === "pip" && options.dev) throw new Error("--dev applies to npm packages only.");
  const { name, range } = parseSpec(spec, ecosystem);
  const notes: string[] = [];
  const staging = await mkdtemp(join(tmpdir(), "beam-package-"));
  try {
    const { version, scans } = ecosystem === "npm" ? await stageNpm(spec, name, staging) : await stagePip(spec, name, range, staging, options, notes);
    // The version comes from the downloaded package's own metadata, and on Windows the install runs
    // through a shell: anything beyond a plain version string is refused.
    if (!/^[\w.+!-]+$/.test(version)) throw new Error(`${name} reports an invalid version "${version.slice(0, 40)}"; not installing it.`);
    const vulnerabilities = options.cve === false ? [] : await attachVulnerabilities(scans, notes);
    // Staging paths are gone once this returns; report where each package sits in the tree instead.
    for (const scan of scans) scan.dir = `${scan.name}@${scan.version}`;
    const blocked = scans.filter(isPackageBlocked).map(s => `${s.name}@${s.version}`);
    const result: AddPackageResult = { spec, ecosystem, name, version, scans, vulnerabilities, notes, blocked };
    if (!options.scanOnly && (!blocked.length || options.force)) result.install = installCommand(ecosystem, name, version, options);
    return result;
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

/** Runs the install step from addPackage, streaming the package manager's own output to stderr. */
export function runInstall(install: { command: string; args: string[] }, cwd = process.cwd()): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(install.command, install.args, { cwd, stdio: ["ignore", process.stderr, process.stderr], shell });
    child.on("error", reject);
    child.on("exit", code => (code === 0 ? resolve() : reject(new Error(`${install.command} ${install.args.join(" ")} exited with code ${code}.`))));
  });
}

