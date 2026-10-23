// Reads exact dependency versions from an app's lockfiles for `beam cve check` and `beam monitor`.
// Only names and versions are extracted; no source code or file contents leave the machine.
// Manifests without pinned versions (package.json ranges, pom.xml properties) are skipped on
// purpose: a range can't be matched against an advisory honestly.
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, relative } from "node:path";

export type Ecosystem = "npm" | "pip" | "go" | "rust" | "maven" | "nuget" | "composer" | "rubygems" | "actions" | "erlang" | "swift";
export interface InstalledPackage { ecosystem: Ecosystem; name: string; version: string; file: string }

const MAX_FILE_BYTES = 20 * 1024 * 1024;
export const MAX_PACKAGES = 20_000;
const SKIP_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", "vendor", "venv", ".venv", "env", "__pycache__", ".tox", "dist", "build", "target", ".next", ".nuxt", ".turbo", ".cache", "coverage", "bower_components", ".gradle", ".idea"]);

type Parser = (text: string) => Omit<InstalledPackage, "file">[];

const pick = (ecosystem: Ecosystem, name: unknown, version: unknown) =>
  typeof name === "string" && typeof version === "string" && name && /\d/.test(version)
    ? [{ ecosystem, name, version: version.trim().replace(/^[=v]+(?=\d)/, "") }]
    : [];

function npmLock(text: string) {
  const lock = JSON.parse(text) as { packages?: Record<string, { version?: string; link?: boolean }>; dependencies?: Record<string, unknown> };
  if (lock.packages) {
    return Object.entries(lock.packages).flatMap(([path, meta]) => {
      // "" is the root project and "packages/x" style keys are workspace sources, not installs.
      const at = path.lastIndexOf("node_modules/");
      if (at < 0 || meta.link) return [];
      return pick("npm", path.slice(at + "node_modules/".length), meta.version);
    });
  }
  const out: Omit<InstalledPackage, "file">[] = [];
  const walk = (deps: Record<string, unknown> | undefined) => {
    for (const [name, meta] of Object.entries(deps ?? {})) {
      const m = meta as { version?: string; dependencies?: Record<string, unknown> };
      out.push(...pick("npm", name, m.version));
      walk(m.dependencies);
    }
  };
  walk(lock.dependencies);
  return out;
}

// Yarn v1 (`version "1.2.3"`) and Berry (`version: 1.2.3`). The header names the package.
function yarnLock(text: string) {
  const out: Omit<InstalledPackage, "file">[] = [];
  let name: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line && !/^\s/.test(line) && line.endsWith(":") && !line.startsWith("#")) {
      const spec = line.slice(0, -1).split(",")[0]!.trim().replace(/^"|"$/g, "");
      const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
      const range = spec.slice(at + 1);
      name = at > 0 && !/^(?:workspace|link|portal|file):/.test(range) ? spec.slice(0, at) : null;
      continue;
    }
    const m = name ? line.match(/^\s+version:?\s+"?([^"\s]+)"?\s*$/) : null;
    if (m && name) { out.push(...pick("npm", name, m[1])); name = null; }
  }
  return out;
}

// pnpm v5 `/name/1.2.3:`, v6 `/name@1.2.3:`, v9 `name@1.2.3:` (scoped names are quoted), with
// optional peer suffixes like `(react@18.2.0)`.
function pnpmLock(text: string) {
  const out: Omit<InstalledPackage, "file">[] = [];
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) { inPackages = /^(?:packages|snapshots):\s*$/.test(line); continue; }
    if (!inPackages) continue;
    const key = line.match(/^ {2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"(]+)[@/]([0-9][^\s'"():_]*)/);
    if (key) out.push(...pick("npm", key[1], key[2]));
  }
  return out;
}

// bun.lock is JSONC: `"packages": { "<key>": ["name@version", ...] }`.
function bunLock(text: string) {
  const json = JSON.parse(text.replace(/,(\s*[}\]])/g, "$1")) as { packages?: Record<string, unknown[]> };
  return Object.values(json.packages ?? {}).flatMap(entry => {
    const spec = Array.isArray(entry) ? entry[0] : undefined;
    if (typeof spec !== "string") return [];
    const at = spec.lastIndexOf("@");
    return at > 0 ? pick("npm", spec.slice(0, at), spec.slice(at + 1)) : [];
  });
}

function requirements(text: string) {
  return text.split(/\r?\n/).flatMap(line => {
    const m = line.replace(/\s+#.*$/, "").match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;,]*)/);
    return m ? pick("pip", m[1], m[2]) : [];
  });
}

// poetry.lock, uv.lock and Cargo.lock share the `[[package]]` name/version layout.
const tomlPackages = (ecosystem: Ecosystem): Parser => text => {
  const out: Omit<InstalledPackage, "file">[] = [];
  let current: { name?: string; version?: string } | null = null;
  const flush = () => { if (current) out.push(...pick(ecosystem, current.name, current.version)); };
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*\[\[package\]\]\s*$/.test(line)) { flush(); current = {}; continue; }
    if (/^\s*\[/.test(line)) { flush(); current = null; continue; }
    const m = current && line.match(/^\s*(name|version)\s*=\s*"([^"]+)"/);
    if (m && current) current[m[1] as "name" | "version"] = m[2];
  }
  flush();
  return out;
};

function pipfileLock(text: string) {
  const lock = JSON.parse(text) as Record<string, Record<string, { version?: string }>>;
  return ["default", "develop"].flatMap(section => Object.entries(lock[section] ?? {}).flatMap(([name, meta]) => pick("pip", name, meta?.version)));
}

function goMod(text: string) {
  const out: Omit<InstalledPackage, "file">[] = [];
  let block = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) { block = true; continue; }
    if (block && line === ")") { block = false; continue; }
    const m = block ? line.match(/^(\S+)\s+(v\d\S*)$/) : line.match(/^require\s+(\S+)\s+(v\d\S*)$/);
    if (m) out.push(...pick("go", m[1], m[2]!.replace(/\+incompatible$/, "")));
  }
  return out;
}

function composerLock(text: string) {
  const lock = JSON.parse(text) as { packages?: { name?: string; version?: string }[]; "packages-dev"?: { name?: string; version?: string }[] };
  return [...(lock.packages ?? []), ...(lock["packages-dev"] ?? [])].flatMap(p => pick("composer", p.name, p.version));
}

// Gemfile.lock specs: four-space `name (version)`; platform gems append `-x86_64-linux`.
function gemfileLock(text: string) {
  return text.split(/\r?\n/).flatMap(line => {
    const m = line.match(/^ {4}([A-Za-z0-9_.-]+) \(([0-9][^)\s]*)\)$/);
    return m ? pick("rubygems", m[1], m[2]!.split("-")[0]) : [];
  });
}

function nugetLock(text: string) {
  const lock = JSON.parse(text) as { dependencies?: Record<string, Record<string, { resolved?: string; type?: string }>> };
  return Object.values(lock.dependencies ?? {}).flatMap(framework =>
    Object.entries(framework).flatMap(([name, meta]) => (meta?.type === "Project" ? [] : pick("nuget", name, meta?.resolved))));
}

function gradleLock(text: string) {
  return text.split(/\r?\n/).flatMap(line => {
    const m = line.match(/^([^#:\s]+):([^:\s]+):([^=\s]+)=/);
    return m ? pick("maven", `${m[1]}:${m[2]}`, m[3]) : [];
  });
}

function mixLock(text: string) {
  return [...text.matchAll(/"([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)"/g)].flatMap(m => pick("erlang", m[1], m[2]));
}

function swiftResolved(text: string) {
  type Pin = { location?: string; repositoryURL?: string; state?: { version?: string } };
  const json = JSON.parse(text) as { pins?: Pin[]; object?: { pins?: Pin[] } };
  return (json.pins ?? json.object?.pins ?? []).flatMap(pin => {
    const url = pin.location ?? pin.repositoryURL;
    const name = url?.replace(/^https?:\/\//, "").replace(/^git@([^:]+):/, "$1/").replace(/\.git$/, "");
    return pick("swift", name, pin.state?.version);
  });
}

// `uses: owner/repo@v4.1.0` in workflow files. Branch and SHA refs can't be range-matched.
function workflow(text: string) {
  return [...text.matchAll(/^\s*-?\s*uses:\s*["']?([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:\/[^@\s"']*)?@(v?\d[\w.-]*)/gm)].flatMap(m => pick("actions", m[1], m[2]));
}

const PARSERS: Record<string, Parser> = {
  "package-lock.json": npmLock,
  "npm-shrinkwrap.json": npmLock,
  "yarn.lock": yarnLock,
  "pnpm-lock.yaml": pnpmLock,
  "bun.lock": bunLock,
  "poetry.lock": tomlPackages("pip"),
  "uv.lock": tomlPackages("pip"),
  "Pipfile.lock": pipfileLock,
  "Cargo.lock": tomlPackages("rust"),
  "go.mod": goMod,
  "composer.lock": composerLock,
  "Gemfile.lock": gemfileLock,
  "packages.lock.json": nugetLock,
  "gradle.lockfile": gradleLock,
  "mix.lock": mixLock,
  "Package.resolved": swiftResolved,
};

export function parserFor(path: string): Parser | undefined {
  const name = basename(path);
  if (PARSERS[name]) return PARSERS[name];
  if (/^requirements[\w.-]*\.txt$/i.test(name)) return requirements;
  if (/[\\/]\.github[\\/]workflows[\\/][^\\/]+\.ya?ml$/.test(path)) return workflow;
  return undefined;
}

export async function findLockfiles(root: string, maxDepth = 4): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string, depth: number) => {
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (depth < maxDepth && !SKIP_DIRS.has(entry.name)) await walk(path, depth + 1);
      } else if (entry.isFile() && parserFor(path)) found.push(path);
    }
  };
  await walk(root, 0);
  return found.sort();
}

export interface LockfileScan { packages: InstalledPackage[]; files: string[]; errors: string[]; truncated: boolean }

export async function readInstalledPackages(root: string, maxDepth = 4): Promise<LockfileScan> {
  const files = await findLockfiles(root, maxDepth);
  const seen = new Set<string>();
  const packages: InstalledPackage[] = [];
  const errors: string[] = [];
  let truncated = false;
  for (const path of files) {
    const file = relative(root, path) || basename(path);
    try {
      if ((await stat(path)).size > MAX_FILE_BYTES) { errors.push(`${file}: larger than 20 MB, skipped`); continue; }
      for (const pkg of parserFor(path)!(await readFile(path, "utf8"))) {
        const key = `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}\0${file}`;
        if (seen.has(key)) continue;
        if (packages.length >= MAX_PACKAGES) { truncated = true; break; }
        seen.add(key);
        packages.push({ ...pkg, file });
      }
    } catch (error) {
      errors.push(`${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return { packages, files: files.map(f => relative(root, f) || basename(f)), errors, truncated };
}
