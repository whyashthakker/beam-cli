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

  it("asks for approval for a blocked tool in advisory mode", () => {
    expect(evaluate(bundle({ mode: "advisory", blockedTools: ["Bash"] }), ctx).action).toBe("ask");
  });

  it("denies an MCP tool matched by a wildcard rule (Claude-style tool name)", () => {
    const d = evaluate(
      bundle({ rules: [{ id: "mcp.block.posthog.claude", tool: "mcp__posthog__*", action: "BLOCK", reason: "posthog MCP is blocked" }] }),
      { ...ctx, tool: "mcp__posthog__exec", command: "" },
    );
    expect(d.action).toBe("deny");
    expect(d.reason).toMatch(/posthog/);
  });

  it("denies an MCP tool matched by a wildcard rule (colon-style tool name)", () => {
    const d = evaluate(
      bundle({ rules: [{ id: "mcp.block.posthog", tool: "mcp:posthog:*", action: "BLOCK", reason: "posthog MCP is blocked" }] }),
      { ...ctx, tool: "mcp:posthog:exec", command: "" },
    );
    expect(d.action).toBe("deny");
  });

  it("does not block an unrelated MCP server's tools", () => {
    const d = evaluate(
      bundle({ rules: [{ id: "mcp.block.posthog.claude", tool: "mcp__posthog__*", action: "BLOCK", reason: "posthog MCP is blocked" }] }),
      { ...ctx, tool: "mcp__sanity__query_documents", command: "" },
    );
    expect(d.action).toBe("allow");
  });

  it("does not block plain agent tool-calling when only an MCP rule is set", () => {
    const d = evaluate(
      bundle({ rules: [{ id: "mcp.block.posthog.claude", tool: "mcp__posthog__*", action: "BLOCK", reason: "posthog MCP is blocked" }] }),
      { ...ctx, command: "ls" },
    );
    expect(d.action).toBe("allow");
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

  it("does not let an unparseable legacy pattern disable independent risk protection", () => {
    expect(evaluate(bundle({ blockedCommandPatterns: ["("] }), ctx).action).toBe("deny");
  });

  it("lets a specific destructive command block override broad allows", () => {
    const d = evaluate(bundle({ rules: [
      { id: "bash-allow", tool: "Bash", action: "ALLOW" },
      { id: "rm-allow", tool: "Bash", command: "rm", action: "ALLOW" },
      { id: "root-delete", tool: "Bash", command: "rm", args: ["-rf", "/"], action: "BLOCK", reason: "filesystem root deletion" },
    ] }), { ...ctx, args: ["-rf", "/"] });
    expect(d.action).toBe("deny");
    expect(d.rule).toBe("root-delete");
    expect(d.reason).toContain("filesystem root");
  });

  it("matches path rules and keeps less-specific paths available", () => {
    const policy = bundle({ rules: [
      { id: "src-allow", path: "./src/**", action: "ALLOW" },
      { id: "env-block", path: "**/.env*", action: "BLOCK" },
    ] });
    expect(evaluate(policy, { ...ctx, command: "cat", path: "./src/app.ts" }).action).toBe("allow");
    expect(evaluate(policy, { ...ctx, command: "cat", path: "./src/.env.local" }).action).toBe("deny");
  });

  it("supports role and agent-specific rules", () => {
    const policy = bundle({ rules: [
      { id: "marketing-no-shell", role: "marketing", tool: "Bash", action: "BLOCK" },
      { id: "codex-test", agent: "codex", command: "npm", args: ["test"], action: "ALLOW" },
    ] });
    expect(evaluate(policy, { ...ctx, role: "marketing" }).action).toBe("deny");
    expect(evaluate(policy, { ...ctx, agent: "codex", command: "npm test", args: ["test"] }).action).toBe("allow");
  });

  it("returns all supported policy actions with explainability", () => {
    for (const action of ["ALLOW", "ASK", "BLOCK", "REDACT", "AUDIT"] as const) {
      const d = evaluate(bundle({ rules: [{ id: action.toLowerCase(), action }] }), ctx);
      expect(d.rule).toBe(action.toLowerCase());
      expect(d.riskScore).toBeGreaterThan(0);
      expect(d.tool).toBe("Bash");
    }
  });

  it("returns ASK for an explicit ask rule", () => {
    const d = evaluate(bundle({ rules: [{ id: "protected-push", command: "git", args: ["push"], action: "ASK", reason: "Protected repository" }] }), { ...ctx, command: "git push", args: ["push"] });
    expect(d.action).toBe("ask");
    expect(d.reason).toBe("Protected repository");
  });

  it("returns REDACT for an explicit redaction rule", () => {
    const d = evaluate(bundle({ rules: [{ id: "external-data", tool: "WebFetch", action: "REDACT" }] }), { ...ctx, tool: "WebFetch", command: "send" });
    expect(d.action).toBe("redact");
  });

  it("carries a policy-defined single approval level", () => {
    const d = evaluate(bundle({ rules: [{ id: "prod-change", action: "ASK", environment: "production", approval: { level: "MANAGER" } }] }), { ...ctx, environment: "production" });
    expect(d.action).toBe("ask");
    expect(d.approval?.level).toBe("MANAGER");
  });

  it("matches a commandLine rule against the exact full command", () => {
    const d = evaluate(
      bundle({ rules: [{ id: "risk-123", commandLine: "rm -rf /tmp/build-cache", action: "ALLOW" }] }),
      { ...ctx, command: "rm -rf /tmp/build-cache" },
    );
    expect(d.action).toBe("allow");
    expect(d.rule).toBe("risk-123");
  });

  it("does not match a commandLine rule against a different full command sharing the same binary", () => {
    const d = evaluate(
      bundle({ rules: [{ id: "risk-123", commandLine: "rm -rf /tmp/build-cache", action: "ALLOW" }] }),
      { ...ctx, command: "rm -rf /" },
    );
    expect(d.action).toBe("deny");
  });

  it("does not let a commandLine rule interfere with an existing command (binary-name) rule", () => {
    const policy = bundle({ rules: [
      { id: "rm-allow", tool: "Bash", command: "rm", action: "ALLOW" },
      { id: "risk-123", tool: "Bash", commandLine: "rm -rf /tmp/build-cache", action: "BLOCK", reason: "flagged finding" },
    ] });
    expect(evaluate(policy, { ...ctx, command: "rm -rf /tmp/other" }).action).toBe("allow");
    const d = evaluate(policy, { ...ctx, command: "rm -rf /tmp/build-cache" });
    expect(d.action).toBe("deny");
    expect(d.rule).toBe("risk-123");
  });

  it("still denies a risk-panel commandLine BLOCK rule in advisory mode, instead of downgrading it to ask", () => {
    const d = evaluate(
      bundle({ mode: "advisory", rules: [{ id: "risk-123", tool: "Bash", commandLine: "rm -rf /tmp/build-cache", action: "BLOCK", reason: "flagged finding" }] }),
      { ...ctx, command: "rm -rf /tmp/build-cache" },
    );
    expect(d.action).toBe("deny");
    expect(d.rule).toBe("risk-123");
  });

  it("still asks for a legacy blocked tool in advisory mode (no pinned command, so mode still governs it)", () => {
    expect(evaluate(bundle({ mode: "advisory", blockedTools: ["Bash"] }), ctx).action).toBe("ask");
  });

});
