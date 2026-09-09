import { describe, expect, it } from "@jest/globals";
import { evaluate, type PolicyBundle } from "../src/policy.js";

const bundle = (rules: Partial<PolicyBundle["rules"]>, notAfter: string | null = null): PolicyBundle => ({
  version: 1,
  notAfter,
  rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [], ...rules },
});

const ctx = { agent: "claude-code", tool: "Bash", command: "rm -rf /" };

describe("evaluate", () => {
  it("allows when there is no policy", () => {
    expect(evaluate(null, ctx).action).toBe("allow");
  });

  it("allows everything in observe mode", () => {
    expect(evaluate(bundle({ mode: "observe", blockedTools: ["Bash"] }), ctx).action).toBe("allow");
  });

  it("denies a blocked tool in enforce mode", () => {
    const d = evaluate(bundle({ blockedTools: ["Bash"] }), ctx);
    expect(d.action).toBe("deny");
    expect(d.reason).toMatch(/Bash/);
  });

  it("warns (not denies) a blocked tool in advisory mode", () => {
    expect(evaluate(bundle({ mode: "advisory", blockedTools: ["Bash"] }), ctx).action).toBe("warn");
  });

  it("denies a blocked command pattern", () => {
    const d = evaluate(bundle({ blockedCommandPatterns: ["\\brm\\b.*-[a-z]*f"] }), ctx);
    expect(d.action).toBe("deny");
  });

  it("denies a disabled agent regardless of tool", () => {
    expect(evaluate(bundle({ disabledAgents: ["claude-code"] }), ctx).action).toBe("deny");
  });

  it("fails open on an expired bundle", () => {
    const past = new Date(Date.now() - 1000).toISOString();
    expect(evaluate(bundle({ blockedTools: ["Bash"] }, past), ctx).action).toBe("allow");
  });

  it("ignores an unparseable command pattern", () => {
    expect(evaluate(bundle({ blockedCommandPatterns: ["("] }), ctx).action).toBe("allow");
  });
});
