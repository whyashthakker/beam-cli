import { resolve } from "node:path";
import { homedir } from "node:os";
import { existsSync } from "node:fs";

export function parseArgs(argv: string[]): { roots: string[]; maxRepos: number; json?: string; html?: string; open: boolean; skipLive: boolean; policy?: string; online: boolean; maxDepth: number; maxFiles: number; wholePc: boolean; vscodeCdp?: string; uiAdapters?: string; extensionsOnly: boolean; launchVscode: boolean; extensionAgent: string; full: boolean } {
  const roots: string[] = [];
  let maxRepos = 500;
  let json: string | undefined;
  let html: string | undefined;
  let open = false;
  let skipLive = true, liveSpecified = false, full = false;
  let policy: string | undefined;
  let extensionsOnly = false, launchVscode = false;
  let extensionAgent = "all";
  let vscodeCdp: string | undefined, uiAdapters: string | undefined;
  let online = false, wholePc = false, maxDepth = 12, maxFiles = 20000;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--root" && argv[i + 1]) roots.push(resolve(argv[++i]));
    else if (["--max-repos", "--max-depth", "--max-files"].includes(arg ?? "")) {
      const value = Number(argv[++i]); if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${arg} requires a positive integer`);
      if (arg === "--max-repos") maxRepos = value; else if (arg === "--max-depth") maxDepth = value; else maxFiles = value;
    }
    else if (arg === "--launch-vscode") launchVscode = true;
    else if (arg === "--full") full = true;
    else if (arg === "--extensions-only") extensionsOnly = true;
    else if (arg === "--online") online = true;
    else if (arg === "--whole-pc") wholePc = true;
    else if (arg === "--json" && argv[i + 1]) json = resolve(argv[++i]);
    else if (arg === "--html") html = argv[i + 1] && !argv[i + 1].startsWith("--") ? resolve(argv[++i]) : resolve("beam-audit-report.html");
    else if (arg === "--open") open = true;
    else if (arg === "--policy" && argv[i + 1]) policy = resolve(argv[++i]);
    else if (arg === "--vscode-cdp" && argv[i + 1]) vscodeCdp = argv[++i];
    else if (arg === "--extension-agent" && argv[i + 1]) { extensionAgent = argv[++i]!; if (!["all", "claude", "codex"].includes(extensionAgent)) throw new Error("--extension-agent must be claude, codex, or all"); }
    else if (arg === "--ui-adapters" && argv[i + 1]) uiAdapters = resolve(argv[++i]);
    else if (arg === "--live") { skipLive = false; liveSpecified = true; }
    else if (arg === "--skip-live") { skipLive = true; liveSpecified = true; }
    else if (arg === "--help" || arg === "-h") {
      console.log("Usage: beam-audit [--full] [--root <dir> ...] [--max-repos <n>] [--json <file>] [--html [file]] [--open] [--skip-live] [--live] [--policy <file>] [--online] [--whole-pc] [--max-depth <n>] [--max-files <n>] [--vscode-cdp <loopback-url>] [--ui-adapters <file>] [--extensions-only] [--launch-vscode] [--extension-agent claude|codex|all]");
      process.exit(0);
    } else throw new Error(`Unknown or incomplete option: ${arg}`);
  }
  if (full) {
    if (extensionsOnly) throw new Error("--full cannot be combined with --extensions-only");
    wholePc = true;
    online = true;
    if (!liveSpecified) skipLive = false;
    if (!vscodeCdp) launchVscode = true;
    html ??= resolve("beam-audit-report.html");
    json ??= resolve("beam-audit-report.json");
  }
  if (wholePc) {
    roots.push(homedir());
    if (process.platform === "win32") roots.push(..."CDEFGHIJKLMNOPQRSTUVWXYZ".split("").map(d => `${d}:\\`).filter(existsSync));
    else roots.push("/");
  }
  if (roots.length === 0) roots.push(homedir());
  return { roots, maxRepos, json, html, open, skipLive, policy, online, maxDepth, maxFiles, wholePc, vscodeCdp, uiAdapters, extensionsOnly, launchVscode, extensionAgent, full };
}

