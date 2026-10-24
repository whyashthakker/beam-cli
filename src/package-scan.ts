import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, normalize, relative, sep } from "node:path";
import { risk, severityRank, type Finding, type Severity } from "./core.js";
import { isSignal, packageComboFindings, scanCode, typosquatOf } from "./package-risk-rules.js";

export type PackageEcosystem = "npm" | "pip";
export interface PackageScan {
  ecosystem: PackageEcosystem; name: string; version: string; dir: string; hash: string;
  score: number; level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; risk: Severity;
  findings: Array<Finding & { file: string }>; filesScanned: number; skipped: string[];
  /** npm lifecycle scripts that run on install (preinstall, install, postinstall). */
  installScripts: Record<string, string>;
}
export interface PackageMeta {
  ecosystem: PackageEcosystem; name: string; version: string;
  /** Typed by a person or agent (the package being added, a direct dependency): gets the typosquat check. */
  direct?: boolean;
  /** When the package's first version was published, if known. */
  createdAt?: string;
}

const CODE_EXT = /\.(?:js|cjs|mjs|jsx|ts|cts|mts|tsx|py|pyw|pth|sh|bash|zsh|ps1|bat|cmd)$/i;
const SHELL_EXT = /\.(?:sh|bash|zsh|ps1|bat|cmd)$/i;
const BINARY_EXT = /\.(?:node|exe|dll|so|dylib)$/i;
const SKIP_FILE = /\.d\.[cm]?ts$|\.map$/i;
const MAX_FILES = 2000;
const MAX_FILE_BYTES = 3 * 1024 * 1024;
const INSTALL_HOOKS = ["preinstall", "install", "postinstall"];
const NEW_PACKAGE_DAYS = 30;

// 0-100, like skillRiskScore. Each rule counts once per package. Critical findings and the
// malware-shaped pkg.* highs count in full; everything else (borrowed shell rules, CVEs below
// critical, mediums) is capped below the HIGH band, so a package full of ordinary noise can't
// look as bad as one with an actual malware shape.
const WEIGHT: Record<Severity, number> = { critical: 40, high: 20, medium: 8, info: 2 };
export function packageRiskScore(findings: Finding[]): { score: number; level: PackageScan["level"] } {
  const unique = [...new Map(findings.map(f => [f.id, f])).values()];
  const full = unique.filter(f => f.severity === "critical" || (f.severity === "high" && f.id.startsWith("pkg."))).reduce((s, f) => s + WEIGHT[f.severity], 0);
  const capped = Math.min(35, unique.filter(f => !(f.severity === "critical" || (f.severity === "high" && f.id.startsWith("pkg.")))).reduce((s, f) => s + WEIGHT[f.severity], 0));
  const score = Math.min(100, Math.round(full + capped));
  return { score, level: score >= 70 ? "CRITICAL" : score >= 40 ? "HIGH" : score >= 15 ? "MEDIUM" : "LOW" };
}

// Critical means a malware shape (or a critical known vulnerability): don't install without --force.
export const isPackageBlocked = (scan: PackageScan) => scan.findings.some(f => f.severity === "critical");

async function listFiles(root: string, dir = root, out: string[] = []): Promise<string[]> {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (out.length >= MAX_FILES) break;
    // Nested node_modules are separate packages, scanned on their own.
    if (entry.isSymbolicLink() || entry.name === "node_modules" || entry.name === ".git" || entry.name === "__pycache__") continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await listFiles(root, full, out);
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

// Files a lifecycle script runs: `node scripts/postinstall.js`, `node -e "require('./install')"`.
function installTargets(scripts: Record<string, string>, files: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const command of Object.values(scripts)) {
    const refs = [...command.matchAll(/\b(?:node|python3?|sh|bash)\s+(?:-\S+\s+)*["']?([\w./@-]+)/g), ...command.matchAll(/(?:require|import)\(\s*\\?["']([\w./@-]+)\\?["']\s*\)/g)].map(m => m[1]!);
    for (const ref of refs) {
      const rel = normalize(ref).replace(/^[.][\\/]/, "");
      const hit = [rel, `${rel}.js`, `${rel}.cjs`, `${rel}.mjs`, join(rel, "index.js")].find(c => files.has(c));
      if (hit) out.add(hit);
    }
  }
  return out;
}

const DEP_SOURCE = /^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|file:)|^[\w-]+\/[\w.-]+(?:#.*)?$/;

/** Scan a package's files. Never executes anything; `files` are absolute paths under `root`. */
export async function scanPackageFiles(root: string, files: string[], meta: PackageMeta): Promise<PackageScan> {
  const skipped: string[] = [];
  const hash = createHash("sha256");
  const perFile: Array<{ file: string; findings: Finding[] }> = [];
  const packageFindings: Array<Finding & { file: string }> = [];
  const rels = new Set(files.map(f => relative(root, f)));

  let installScripts: Record<string, string> = {};
  if (meta.ecosystem === "npm") {
    let manifest: { scripts?: Record<string, unknown>; dependencies?: Record<string, unknown>; optionalDependencies?: Record<string, unknown> } = {};
    try { manifest = JSON.parse(await readFile(join(root, "package.json"), "utf8")); } catch { /* scanned without a manifest */ }
    installScripts = Object.fromEntries(INSTALL_HOOKS.flatMap(h => (typeof manifest.scripts?.[h] === "string" ? [[h, manifest.scripts[h] as string]] : [])));
    for (const [hook, command] of Object.entries(installScripts)) {
      packageFindings.push({ id: "pkg.install_script", title: "Runs code when installed", severity: "medium", explanation: "npm runs this lifecycle script on every install. Many native and binary-downloading packages need one; it's also how most malicious npm packages get to run.", evidence: `${hook}: ${command}`.slice(0, 200), file: "package.json" });
      // The script line itself is install-time code: `curl ... | sh` written straight into it.
      perFile.push({ file: `package.json#scripts.${hook}`, findings: scanCode(command, { shell: true }) });
      if (/\b(?:curl|wget|Invoke-WebRequest|iwr)\b/.test(command)) packageFindings.push({ id: "pkg.install_fetch", title: "Install script downloads from the network", severity: "high", explanation: "The lifecycle script itself fetches something on install, outside npm's integrity checks.", evidence: `${hook}: ${command}`.slice(0, 200), file: "package.json" });
    }
    for (const [dep, source] of Object.entries({ ...manifest.dependencies, ...manifest.optionalDependencies })) {
      if (typeof source === "string" && DEP_SOURCE.test(source)) {
        packageFindings.push({ id: "pkg.dependency_source", title: "Dependency from outside the registry", severity: "medium", explanation: "A dependency comes from a git repository, URL or local path, so it isn't a reviewed, immutable registry version.", evidence: `${dep}: ${source}`.slice(0, 200), file: "package.json" });
        break;
      }
    }
  }
  const installTime = meta.ecosystem === "npm" ? installTargets(installScripts, rels) : new Set([...rels].filter(r => r === "setup.py"));

  const binaries: string[] = [];
  for (const path of files) {
    const rel = relative(root, path);
    if (BINARY_EXT.test(path)) { binaries.push(rel); continue; }
    if (!CODE_EXT.test(path) || SKIP_FILE.test(path)) continue;
    let content: string;
    try {
      if ((await stat(path)).size > MAX_FILE_BYTES) { skipped.push(`${rel} (over 3 MB)`); continue; }
      content = await readFile(path, "utf8");
    } catch { continue; }
    hash.update(`${rel}\0${content}\0`);
    const findings = scanCode(content, { shell: installTime.has(rel) || SHELL_EXT.test(path) });
    // A .pth file in site-packages is executed on every Python start when a line begins with "import".
    if (/\.pth$/i.test(path) && /^import\s/m.test(content)) {
      findings.push({ id: "pkg.pth_exec", title: "Runs code on every Python start", severity: "medium", explanation: "Lines starting with 'import' in a .pth file execute whenever any Python program starts, not just when this package is used.", evidence: content.split(/\r?\n/).find(l => /^import\s/.test(l))!.slice(0, 200), line: 1 });
    }
    perFile.push({ file: rel, findings });
  }
  if (binaries.length) packageFindings.push({ id: "pkg.native_binary", title: "Ships compiled binaries", severity: "info", explanation: "Compiled code can't be reviewed by reading it. Expected for native addons and tools like esbuild.", evidence: binaries.slice(0, 5).join(", ") + (binaries.length > 5 ? ` (+${binaries.length - 5} more)` : ""), file: binaries[0]! });

  if (meta.direct) {
    const lookalike = typosquatOf(meta.name, meta.ecosystem);
    if (lookalike) packageFindings.push({ id: "pkg.typosquat", title: `Name is one typo away from "${lookalike}"`, severity: "high", explanation: `Check you meant ${lookalike}. Typosquats copy a popular package's name with one character changed, and AI agents often install names that are close to real ones.`, evidence: `${meta.name} ≈ ${lookalike}`, file: "(name)" });
  }
  if (meta.createdAt && Date.now() - Date.parse(meta.createdAt) < NEW_PACKAGE_DAYS * 86_400_000) {
    packageFindings.push({ id: "pkg.new_package", title: "First published in the last 30 days", severity: "medium", explanation: "A new package has no track record yet. Malicious packages are usually caught and removed within days of publishing.", evidence: `first published ${meta.createdAt.slice(0, 10)}`, file: "(registry)" });
  }

  const ids = (f: { file: string; findings: Finding[] }) => new Set([...f.findings.map(x => x.id), ...(installTime.has(f.file) || f.file.startsWith("package.json#") ? ["install"] : [])]);
  const combos = packageComboFindings(perFile.map(f => ({ file: f.file, ids: ids(f) })), new Set(packageFindings.map(f => f.id)));
  const findings = [...packageFindings, ...perFile.flatMap(f => f.findings.filter(x => !isSignal(x.id)).map(x => ({ ...x, file: f.file }))), ...combos]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
  return { ecosystem: meta.ecosystem, name: meta.name, version: meta.version, dir: root, hash: hash.digest("hex"), ...packageRiskScore(findings), risk: risk(findings), findings, filesScanned: perFile.length, skipped, installScripts };
}

/** An npm package folder (has package.json). */
export async function scanNpmPackage(dir: string, meta: Partial<PackageMeta> = {}): Promise<PackageScan> {
  let manifest: { name?: string; version?: string } = {};
  try { manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8")); } catch { /* use the folder name */ }
  return scanPackageFiles(dir, await listFiles(dir), { ecosystem: "npm", name: manifest.name ?? basename(dir), version: manifest.version ?? "", ...meta });
}

// METADATA in a wheel's .dist-info, PKG-INFO in a sdist: `Name:` and `Version:` headers.
async function pythonMeta(file: string): Promise<{ name: string; version: string } | null> {
  try {
    const text = await readFile(file, "utf8");
    const name = text.match(/^Name:\s*(.+)$/m)?.[1]?.trim(), version = text.match(/^Version:\s*(.+)$/m)?.[1]?.trim();
    return name && version ? { name, version } : null;
  } catch { return null; }
}

/** An installed Python distribution: the files its .dist-info/RECORD lists, relative to site-packages. */
export async function scanDistInfo(sitePackages: string, distInfo: string, meta: Partial<PackageMeta> = {}): Promise<PackageScan | null> {
  const info = await pythonMeta(join(sitePackages, distInfo, "METADATA"));
  if (!info) return null;
  let record = "";
  try { record = await readFile(join(sitePackages, distInfo, "RECORD"), "utf8"); } catch { /* no RECORD: scan the metadata folder only */ }
  const files = [...new Set(record.split(/\r?\n/).map(l => l.split(",")[0]!.trim()).filter(Boolean))]
    // `../../bin/tool` entries point outside site-packages; .pyc is compiled from the .py we scan anyway.
    .filter(p => !p.startsWith("..") && !p.startsWith("/") && !/\.pyc$/.test(p))
    .slice(0, MAX_FILES)
    .map(p => join(sitePackages, p));
  let direct = false;
  try { await stat(join(sitePackages, distInfo, "REQUESTED")); direct = true; } catch { /* installed as a dependency */ }
  return scanPackageFiles(sitePackages, files, { ecosystem: "pip", ...info, direct, ...meta });
}

/** An unpacked wheel or sdist folder. */
export async function scanPythonDist(dir: string, meta: Partial<PackageMeta> = {}): Promise<PackageScan> {
  const files = await listFiles(dir);
  const metaFile = files.find(f => /\.dist-info[\\/]METADATA$/.test(f)) ?? files.find(f => relative(dir, f) === "PKG-INFO");
  const info = (metaFile && await pythonMeta(metaFile)) || { name: basename(dir), version: "" };
  return scanPackageFiles(dir, files, { ecosystem: "pip", ...info, ...meta });
}

// Every installed npm package folder under a node_modules tree, including scoped packages,
// nested node_modules and pnpm's .pnpm store. Symlinks are skipped: pnpm's top-level entries
// link into .pnpm, which is walked directly, so each copy is scanned once.
export async function findNpmPackages(nodeModules: string, out: string[] = []): Promise<string[]> {
  let entries;
  try { entries = await readdir(nodeModules, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name === ".bin" || entry.name === ".cache") continue;
    const full = join(nodeModules, entry.name);
    if (entry.name === ".pnpm") {
      for (const store of await readdir(full, { withFileTypes: true }).catch(() => [])) if (store.isDirectory()) await findNpmPackages(join(full, store.name, "node_modules"), out);
    } else if (entry.name.startsWith("@")) {
      for (const scoped of await readdir(full, { withFileTypes: true }).catch(() => [])) if (scoped.isDirectory()) await addNpmPackage(join(full, scoped.name), out);
    } else await addNpmPackage(full, out);
  }
  return out;
}
async function addNpmPackage(dir: string, out: string[]) {
  try { await stat(join(dir, "package.json")); } catch { return; }
  out.push(dir);
  await findNpmPackages(join(dir, "node_modules"), out);
}

/** site-packages folders of the virtualenvs in a project (.venv, venv, env), or `dir` itself. */
export async function findSitePackages(dir: string): Promise<string[]> {
  const out: string[] = [];
  const hasDistInfo = async (d: string) => (await readdir(d).catch(() => [] as string[])).some(n => n.endsWith(".dist-info"));
  if (await hasDistInfo(dir)) return [dir];
  for (const venv of [".venv", "venv", "env"]) {
    const windows = join(dir, venv, "Lib", "site-packages");
    if (await hasDistInfo(windows)) out.push(windows);
    for (const lib of await readdir(join(dir, venv, "lib")).catch(() => [] as string[])) {
      const site = join(dir, venv, "lib", lib, "site-packages");
      if (lib.startsWith("python") && await hasDistInfo(site)) out.push(site);
    }
  }
  return out;
}

export interface InstalledScan { scans: PackageScan[]; roots: string[] }

/** `beam packages scan`: everything installed under a project (node_modules and virtualenvs). */
export async function scanInstalledPackages(dir: string, onProgress?: (done: number, total: number) => void): Promise<InstalledScan> {
  const roots: string[] = [];
  // Direct dependencies get the typosquat check; they're what someone actually typed.
  let direct = new Set<string>();
  try {
    const manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8")) as Record<string, Record<string, unknown> | undefined>;
    direct = new Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].flatMap(k => Object.keys(manifest[k] ?? {})));
  } catch { /* not an npm project */ }

  const npmDirs = await findNpmPackages(join(dir, "node_modules"));
  if (npmDirs.length) roots.push(join(dir, "node_modules"));
  const sites = await findSitePackages(dir);
  roots.push(...sites);
  const pyDists = (await Promise.all(sites.map(async site => (await readdir(site)).filter(n => n.endsWith(".dist-info")).map(d => [site, d] as const)))).flat();

  const total = npmDirs.length + pyDists.length;
  const scans: PackageScan[] = [];
  for (const pkgDir of npmDirs) {
    // The installed name is the path after the last node_modules/ (one segment, or two when scoped).
    const name = pkgDir.split(`node_modules${sep}`).pop()!.split(sep).join("/");
    scans.push(await scanNpmPackage(pkgDir, { direct: direct.has(name) }));
    onProgress?.(scans.length, total);
  }
  for (const [site, distInfo] of pyDists) {
    const scan = await scanDistInfo(site, distInfo);
    if (scan) scans.push(scan);
    onProgress?.(scans.length, total);
  }
  return { scans, roots };
}
