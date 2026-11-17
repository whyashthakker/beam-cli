// Policy 6.1 API Key Management: "must be stored exclusively in an OS-level environment variable or
// a recognised secrets manager... must never be hard-coded in source files, configuration files...".
// The repo content scan (repo-scan.ts) already catches literal keys in tracked files; this covers the
// two places that scan doesn't reach: shell startup files (not part of any repo) and Claude Code's
// own settings.json (global and per-repo), which is explicitly a "configuration file" under 6.1.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AuditContext, Check } from "../types.js";
import { readShellRcFiles } from "../shell-env.js";

const HARDCODED_KEY = /ANTHROPIC_(?:API_KEY|AUTH_TOKEN)\s*[:=]\s*["']?(sk-ant-[A-Za-z0-9_-]{10,}|[A-Za-z0-9_-]{20,})["']?/;

// `export ANTHROPIC_API_KEY=$(op read ...)` / `$(security find-generic-password ...)` resolves the
// value from a secrets manager at shell-start time -- the opposite of hardcoding it.
const SECRETS_MANAGER_REF = /\$\(|op:\/\/|vault read|security find-generic-password|pass show/;

export function apiKeyStorageCheck(ctx: AuditContext): Check {
  const hits: string[] = [];

  for (const { path, text } of readShellRcFiles(ctx.home)) {
    for (const line of text.split("\n")) {
      if (line.trim().startsWith("#") || SECRETS_MANAGER_REF.test(line)) continue;
      const m = HARDCODED_KEY.exec(line);
      if (m) hits.push(`${path}: ANTHROPIC_API_KEY set to a literal value`);
    }
  }

  const settingsFiles = [join(ctx.home, ".claude", "settings.json"), ...ctx.repos.flatMap(r => [join(r, ".claude", "settings.json"), join(r, ".claude", "settings.local.json")])];
  for (const file of settingsFiles) {
    if (!existsSync(file)) continue;
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (HARDCODED_KEY.test(text) && !SECRETS_MANAGER_REF.test(text)) hits.push(`${file}: contains a literal ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN value`);
  }

  return {
    id: "6.1-api-key-storage",
    policySection: "6.1 (API Key Management)",
    title: "Anthropic API key not hardcoded in shell startup files or settings.json",
    status: hits.length > 0 ? "fail" : "pass",
    detail: hits.length > 0
      ? `${hits.length} location(s) set ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN to a literal value instead of resolving it from a secrets manager.`
      : "No literal Anthropic API key found in shell startup files or Claude Code settings.json (global or per-repo).",
    evidence: [...new Set(hits)].slice(0, 50),
    fix: hits.length > 0 ? "Rotate the key, then replace the literal value with an OS keychain/secrets-manager lookup (e.g. `export ANTHROPIC_API_KEY=$(op read op://vault/item/field)`) or Claude Code's `apiKeyHelper` setting." : undefined,
  };
}
