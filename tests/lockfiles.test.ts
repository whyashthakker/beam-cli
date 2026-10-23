import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { readInstalledPackages } from "../src/lockfiles.js";
import { runCveCheck } from "../src/cve.js";

let dir: string;
const put = async (path: string, text: string) => {
  await mkdir(dirname(join(dir, path)), { recursive: true });
  await writeFile(join(dir, path), text);
};
const found = async () => (await readInstalledPackages(dir)).packages.map(p => `${p.ecosystem}:${p.name}@${p.version}`).sort();

beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "beam-locks-")); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe("lockfile readers", () => {
  it("reads npm, yarn (v1 and berry), pnpm and bun lockfiles", async () => {
    await put("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: {
      "": { name: "app" }, "packages/ui": { version: "0.0.1" }, "node_modules/left-pad": { version: "1.3.0" },
      "node_modules/a/node_modules/@scope/b": { version: "2.0.0" }, "node_modules/linked": { link: true },
    } }));
    await put("v1/yarn.lock", '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.24.0"\n  resolved "x"\n\nlodash@^4:\n  version "4.17.20"\n');
    await put("berry/yarn.lock", '__metadata:\n  version: 8\n\n"axios@npm:^1.6.0":\n  version: 1.6.0\n  resolution: "axios@npm:1.6.0"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n');
    await put("pnpm/pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  '@types/node@20.11.0':\n    resolution: {integrity: x}\n\n  next@14.1.0(react@18.2.0):\n    resolution: {integrity: y}\n\nsnapshots:\n\n  next@14.1.0(react@18.2.0):\n    dependencies: {}\n");
    await put("pnpm6/pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /express@4.18.2:\n    resolution: {integrity: z}\n");
    await put("bun/bun.lock", '{\n  "lockfileVersion": 1,\n  "packages": {\n    "zod": ["zod@3.22.4", "", {}, "sha512-x"],\n    "@hono/node-server": ["@hono/node-server@1.8.0", "", {}, "sha512-y"],\n  },\n}\n');
    expect(await found()).toEqual([
      "npm:@babel/core@7.24.0", "npm:@hono/node-server@1.8.0", "npm:@scope/b@2.0.0", "npm:@types/node@20.11.0", "npm:axios@1.6.0",
      "npm:express@4.18.2", "npm:left-pad@1.3.0", "npm:lodash@4.17.20", "npm:next@14.1.0", "npm:zod@3.22.4",
    ]);
  });
  it("reads Python, Go, Rust, PHP, Ruby, .NET, Gradle, Hex, Swift and GitHub Actions", async () => {
    await put("requirements.txt", "# pinned\nlitellm==1.83.8\nrequests[socks]==2.31.0 ; python_version>'3'\nflask>=2.0\n-r other.txt\n");
    await put("py/poetry.lock", '[[package]]\nname = "Django"\nversion = "4.2.1"\n\n[package.dependencies]\nasgiref = "*"\n\n[[package]]\nname = "asgiref"\nversion = "3.7.2"\n');
    await put("py/Pipfile.lock", JSON.stringify({ default: { jinja2: { version: "==3.1.2" } }, develop: {} }));
    await put("go/go.mod", "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/net v0.20.0\n\nrequire (\n\tgolang.org/x/crypto v0.17.0 // indirect\n\tgithub.com/old/thing v2.0.0+incompatible\n)\n");
    await put("rs/Cargo.lock", 'version = 3\n\n[[package]]\nname = "serde_json"\nversion = "1.0.100"\n');
    await put("php/composer.lock", JSON.stringify({ packages: [{ name: "laravel/framework", version: "v10.1.0" }], "packages-dev": [] }));
    await put("rb/Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.18.8-x86_64-linux)\n      racc (~> 1.4)\n    rails (7.1.0)\n");
    await put("net/packages.lock.json", JSON.stringify({ version: 1, dependencies: { "net8.0": { "Newtonsoft.Json": { type: "Direct", resolved: "13.0.1" }, App: { type: "Project" } } } }));
    await put("jvm/gradle.lockfile", "# lockfile\norg.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\nempty=\n");
    await put("ex/mix.lock", '%{\n  "plug": {:hex, :plug, "1.14.0", "abc", [:mix], [], "hexpm", "def"},\n}\n');
    await put("ios/Package.resolved", JSON.stringify({ pins: [{ identity: "x", location: "https://github.com/ionic-team/capacitor-swift-pm.git", state: { version: "6.1.0" } }] }));
    await put(".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4.1.0\n      - uses: tj-actions/changed-files@main\n      - uses: org/repo/sub@v1.2\n");
    expect(await found()).toEqual([
      "actions:actions/checkout@4.1.0", "actions:org/repo@1.2", "composer:laravel/framework@10.1.0", "erlang:plug@1.14.0",
      "go:github.com/old/thing@2.0.0", "go:golang.org/x/crypto@0.17.0", "go:golang.org/x/net@0.20.0",
      "maven:org.apache.logging.log4j:log4j-core@2.14.1", "nuget:Newtonsoft.Json@13.0.1",
      "pip:Django@4.2.1", "pip:asgiref@3.7.2", "pip:jinja2@3.1.2", "pip:litellm@1.83.8", "pip:requests@2.31.0",
      "rubygems:nokogiri@1.18.8", "rubygems:rails@7.1.0", "rust:serde_json@1.0.100", "swift:github.com/ionic-team/capacitor-swift-pm@6.1.0",
    ]);
  });
  it("skips dependency folders and reports unreadable files without failing", async () => {
    await put("node_modules/x/package-lock.json", JSON.stringify({ packages: { "node_modules/y": { version: "1.0.0" } } }));
    await put("package-lock.json", "{ not json");
    const scan = await readInstalledPackages(dir);
    expect(scan.packages).toEqual([]);
    expect(scan.files).toEqual(["package-lock.json"]);
    expect(scan.errors[0]).toMatch(/^package-lock\.json: /);
  });
});

describe("beam cve check", () => {
  const originalEnv = { ...process.env };
  const originalFetch = global.fetch;
  let sent: unknown;
  const vulnerability = (severity: string) => ({
    id: "CVE-2026-59823", slug: "cve-2026-59823", url: "https://agentbeam.com/cve/cve-2026-59823", title: "LiteLLM SSRF", severity, kev: false, epss: null,
    ecosystem: "pip", name: "litellm", version: "1.83.8", vulnerable: "<= 1.83.8", patched: "1.83.9", files: ["requirements.txt"],
  });
  let response: () => Response;
  beforeEach(async () => {
    process.env = { ...originalEnv, BEAM_HOME: dir, BEAM_DATA_DIR: join(dir, ".beam-data") };
    await put(".beam-data/identity.json", JSON.stringify({ deviceSecret: "s", apiBase: "https://workspace.test" }));
    await put("requirements.txt", "litellm==1.83.8\n");
    response = () => Response.json({ checked: 1, vulnerabilities: [vulnerability("medium")], database: { generatedAt: "x", advisories: 3656 }, remaining: 99, resetAt: "2026-11-01T00:00:00.000Z" });
    global.fetch = jest.fn(async (_url: string | URL | Request, init?: RequestInit) => { sent = JSON.parse(String(init?.body)); return response(); }) as typeof fetch;
  });
  afterEach(() => { process.env = { ...originalEnv }; global.fetch = originalFetch; });

  it("sends only names and versions, and exits 2 when a finding meets --fail-on", async () => {
    const out: string[] = [];
    expect(await runCveCheck(dir, {}, l => out.push(l))).toBe(2);
    expect(sent).toEqual({ packages: [{ ecosystem: "pip", name: "litellm", version: "1.83.8", file: "requirements.txt" }] });
    expect(out.join("\n")).toContain("CVE-2026-59823");
    expect(out.join("\n")).toContain("fixed in 1.83.9");
    expect(await runCveCheck(dir, { failOn: "high" }, () => {})).toBe(0);
  });
  it("needs a connected workspace with App monitoring on", async () => {
    response = () => Response.json({ error: "App monitoring is turned off for this workspace." }, { status: 403 });
    await expect(runCveCheck(dir, {}, () => {})).rejects.toThrow("turned off");
    await rm(join(dir, ".beam-data/identity.json"));
    await expect(runCveCheck(dir, {}, () => {})).rejects.toThrow("beam connect");
  });
});
