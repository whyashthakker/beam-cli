import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { getDataDirectory } from "./config.js";

export type PolicyMode = "observe" | "advisory" | "enforce";

export interface PolicyRules {
  mode: PolicyMode;
  blockedTools: string[];
  blockedCommandPatterns: string[];
  disabledAgents: string[];
}

export interface PolicyBundle {
  version: number;
  rules: PolicyRules;
  notAfter: string | null;
}

const EMPTY: PolicyRules = { mode: "observe", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [] };

export function policyPath(): string {
  return join(getDataDirectory(), "policy.json");
}

export async function readPolicy(): Promise<PolicyBundle | null> {
  try {
    const parsed = JSON.parse(await readFile(policyPath(), "utf8")) as Partial<PolicyBundle>;
    if (!parsed.rules) return null;
    return {
      version: typeof parsed.version === "number" ? parsed.version : 0,
      notAfter: parsed.notAfter ?? null,
      rules: { ...EMPTY, ...parsed.rules },
    };
  } catch {
    return null;
  }
}

export type DecisionAction = "allow" | "warn" | "deny";
export interface Decision {
  action: DecisionAction;
  reason?: string;
  mode: PolicyMode;
  policyVersion: number;
}

export interface ActionContext {
  agent: string;
  tool: string;
  command: string;
}

// Evaluate a proposed action. No policy, observe mode, or an expired bundle => allow.
export function evaluate(bundle: PolicyBundle | null, ctx: ActionContext): Decision {
  if (!bundle) return { action: "allow", mode: "observe", policyVersion: 0 };

  const { rules, version } = bundle;
  const base = { mode: rules.mode, policyVersion: version };

  if (rules.mode === "observe") return { action: "allow", ...base };
  // Stale cached policy: fail open rather than trap the user offline.
  if (bundle.notAfter && Date.parse(bundle.notAfter) < Date.now()) return { action: "allow", ...base };

  const hit = (reason: string): Decision => ({
    action: rules.mode === "enforce" ? "deny" : "warn",
    reason,
    ...base,
  });

  if (rules.disabledAgents.some((a) => a.toLowerCase() === ctx.agent.toLowerCase())) {
    return hit(`${ctx.agent} is disabled for your account by workspace policy.`);
  }
  if (ctx.tool && rules.blockedTools.some((t) => t.toLowerCase() === ctx.tool.toLowerCase())) {
    return hit(`The ${ctx.tool} tool is blocked by workspace policy.`);
  }
  for (const pattern of rules.blockedCommandPatterns) {
    if (!ctx.command) break;
    try {
      if (new RegExp(pattern, "i").test(ctx.command)) {
        return hit(`This command matches a blocked pattern: /${pattern}/`);
      }
    } catch {
      /* ignore an unparseable pattern */
    }
  }
  return { action: "allow", ...base };
}
