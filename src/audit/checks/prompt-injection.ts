// Policy 7 Risk Mitigation: "Prompt Injection via Malicious Third-Party Code -- Malicious
// instructions embedded in third-party code or data manipulate Claude Code's behaviour." A
// self-contained heuristic (deliberately not importing beam-cli's own, more thorough detector --
// this package has zero dependency on the main product) over text an agent is likely to read:
// README/docs/CLAUDE.md/config files in each scanned repository.
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { spawnSync } from "node:child_process";
import type { AuditContext, Check } from "../types.js";

const TEXT_EXT = /\.(?:md|mdx|txt|rst|adoc|ya?ml)$|^CLAUDE\.md$|^README/i;
const MAX_FILE_BYTES = 500_000;

// Deliberately narrow: an instruction aimed at an AI reader, not ordinary prose that happens to
// contain the word "ignore" or "instructions". Requires the override phrase AND a target
// ("instructions", "system prompt", "rules", "guidelines", "prior directives", ...).
const OVERRIDE = /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|all|above|system)\b[^.\n]{0,20}\b(?:instructions?|prompts?|rules?|guidelines?|directives?)\b/i;
const FORGED_TURN = /^\s*(?:system|assistant)\s*:\s*\S/im; // a forged chat-turn label at line start
const JAILBREAK = /\bDAN\b.{0,20}\bmode\b|\bdo anything now\b|\bno (?:ethical|moral) (?:guidelines|restrictions)\b/i;

function trackedTextFiles(repo: string): string[] {
  const res = spawnSync("git", ["-C", repo, "ls-files"], { encoding: "utf8", timeout: 15_000 });
  if (res.status !== 0 || typeof res.stdout !== "string") return [];
  return res.stdout.split("\n").filter(f => f && TEXT_EXT.test(f));
}

export function promptInjectionScan(ctx: AuditContext): Check {
  const hits: string[] = [];
  for (const repo of ctx.repos) {
    for (const file of trackedTextFiles(repo)) {
      let text: string;
      try {
        const buf = readFileSync(join(repo, file));
        if (buf.byteLength > MAX_FILE_BYTES) continue;
        text = buf.toString("utf8");
      } catch {
        continue;
      }
      const shapes = [
        OVERRIDE.test(text) && "instruction override phrasing",
        FORGED_TURN.test(text) && "forged chat-turn label (system:/assistant: at line start)",
        JAILBREAK.test(text) && "jailbreak phrasing",
      ].filter(Boolean) as string[];
      if (shapes.length > 0) hits.push(`${relative(ctx.home, repo)}/${file}: ${shapes.join(", ")}`);
    }
  }
  return {
    id: "7-prompt-injection",
    policySection: "7 (Risk Mitigation - Prompt Injection)",
    title: "Instructions embedded in repository content aimed at an AI reader",
    status: hits.length > 0 ? "warn" : "pass",
    detail: hits.length > 0
      ? `${hits.length} file(s) contain text shaped like a prompt-injection attempt. This is a heuristic over README/docs/CLAUDE.md/config files -- it will also flag legitimate security documentation that discusses these patterns as examples, so each hit needs a human read, not an automatic block.`
      : "No prompt-injection-shaped content found in scanned README/docs/CLAUDE.md/config files.",
    evidence: hits.slice(0, 50),
    fix: hits.length > 0 ? "Review each listed file manually; per policy 7, AI-generated output influenced by third-party content must still go through human review before execution." : undefined,
  };
}
