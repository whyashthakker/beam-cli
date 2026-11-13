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

  it("a legacy blocked tool still blocks in observe mode, but an unmatched tool stays allowed", () => {
    const d = evaluate(bundle({ mode: "observe", blockedTools: ["Bash"] }), ctx);
    expect(d.action).toBe("deny");
    expect(d.rule).toBe("legacy.tool.Bash");
    expect(evaluate(bundle({ mode: "observe", blockedTools: ["Write"] }), ctx).action).toBe("allow");
  });

  it("a legacy blocked command pattern still blocks in observe mode", () => {
    const d = evaluate(bundle({ mode: "observe", blockedCommandPatterns: ["rm\\s+-rf"] }), ctx);
    expect(d.action).toBe("deny");
    expect(d.rule).toBe("legacy.command.rm\\s+-rf");
  });

  it("an ordinary structured BLOCK rule still blocks in observe mode, but an ASK rule does not", () => {
    const blockRule = bundle({ mode: "observe", rules: [{ id: "block-rule", tool: "Bash", action: "BLOCK" }] });
    expect(evaluate(blockRule, ctx).action).toBe("deny");
    const askRule = bundle({ mode: "observe", rules: [{ id: "ask-rule", tool: "Bash", action: "ASK" }] });
    expect(evaluate(askRule, ctx).action).toBe("allow");
  });

  it("the implicit risk-score heuristic stays silent in observe mode even for a high-risk action", () => {
    expect(evaluate(bundle({ mode: "observe" }), { ...ctx, command: "rm -rf /" }).action).toBe("allow");
  });

  it("enforces only the selected mitigation while preserving observe mode for unrelated calls", () => {
    const commandRegex = String.raw`(?:^|[;&|]\s*)(?:(?:sudo|command)\s+)?(?:\/?[A-Za-z0-9_.-]+\/)*ping(?:\s+(?:--|-[A-Za-z][A-Za-z0-9-]*(?:=\d{1,6})?|\d{1,6}))*\s+['"]?google\.com\.?['"]?(?=$|[\s;&|])`;
    const policy = bundle({ mode: "observe", rules: [{ id: "mitigation-command", agent: "claude-code", commandRegex, enforce: true, action: "BLOCK" }] });
    for (const command of ["ping google.com", "ping google.com.", "ping -c 1 google.com", "ping -c1 google.com", "ping -n 1 google.com", "sudo ping -- google.com", "/sbin/ping google.com"])
      expect(evaluate(policy, { ...ctx, command }).action).toBe("deny");
    for (const command of ["ping example.com", "ping google.com.evil.test", "grep google.com README.md", "echo 'ping google.com'"])
      expect(evaluate(policy, { ...ctx, command }).action).toBe("allow");
    expect(evaluate(policy, { ...ctx, agent: "codex", command: "ping google.com" }).action).toBe("allow");
  });

  it("enforces an explicit agent suspension in observe mode without changing another agent", () => {
    const policy = bundle({ mode: "observe", rules: [{ id: "mitigation-suspend-claude", agent: "claude-code", enforce: true, action: "BLOCK" }] });
    expect(evaluate(policy, { ...ctx, tool: "Read", command: "" }).action).toBe("deny");
    expect(evaluate(policy, { ...ctx, agent: "codex", command: "rm -rf /" }).action).toBe("allow");
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

  it("a disabled agent is still denied in observe mode, but softened to ask in advisory", () => {
    expect(evaluate(bundle({ mode: "observe", disabledAgents: ["claude-code"] }), ctx).action).toBe("deny");
    expect(evaluate(bundle({ mode: "advisory", disabledAgents: ["claude-code"] }), ctx).action).toBe("ask");
    expect(evaluate(bundle({ mode: "observe", disabledAgents: ["claude-code"] }), { ...ctx, agent: "codex" }).action).toBe("allow");
  });

  it("does not let a more specific ALLOW rule bypass an agent suspension", () => {
    const policy = bundle({ disabledAgents: ["claude-code"], rules: [{ id: "previous-allow", agent: "claude-code", tool: "Bash", commandLine: "echo hello", action: "ALLOW" }] });
    const decision = evaluate(policy, { ...ctx, command: "echo hello" });
    expect(decision.action).toBe("deny");
    expect(decision.rule).toBe("legacy.disabled-agent");
    expect(evaluate(policy, { ...ctx, agent: "codex", command: "echo hello" }).action).toBe("allow");
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


describe("agent action type rules", () => {
  const policy = bundle({ rules: [{ id: "claude-search", agent: "claude-code", eventType: "file.search", action: "BLOCK" }] });
  it.each(["Grep", "Glob", "search_files"])("blocks Claude search through %s", (tool) => {
    expect(evaluate(policy, { agent: "claude-code", tool, command: "" }).action).toBe("deny");
  });
  it("allows another Claude action", () => {
    expect(evaluate(policy, { agent: "claude-code", tool: "Read", command: "" }).action).toBe("allow");
  });
  it("allows search by another agent", () => {
    expect(evaluate(policy, { agent: "codex", tool: "Grep", command: "" }).action).toBe("allow");
  });
  it("matches argument-dependent web search", () => {
    const web = bundle({ rules: [{ id: "search", eventType: "web.search", action: "BLOCK" }] });
    expect(evaluate(web, { agent: "codex", tool: "web.run", command: "", input: { search_query: [{ q: "example" }] } }).action).toBe("deny");
    expect(evaluate(web, { agent: "codex", tool: "web.run", command: "", input: { open: [{ ref_id: "https://example.com" }] } }).action).toBe("allow");
  });
  it("an explicit BLOCK rule still applies in observe mode; advisory softens it to ask", () => {
    const search = { agent: "claude-code", tool: "Grep", command: "" };
    expect(evaluate({ ...policy, rules: { ...policy.rules, mode: "observe" } }, search).action).toBe("deny");
    expect(evaluate({ ...policy, rules: { ...policy.rules, mode: "advisory" } }, search).action).toBe("ask");
    // Observe mode still allows an action the rule doesn't match.
    expect(evaluate({ ...policy, rules: { ...policy.rules, mode: "observe" } }, { agent: "claude-code", tool: "Read", command: "" }).action).toBe("allow");
  });
});

describe("repository review requirements", () => {
  it("requires command review even in observe mode", () => {
    const decision = evaluate(bundle({ mode: "observe", review: { commands: true } }), { ...ctx, command: "echo hello", eventType: "command.exec" });
    expect(decision.action).toBe("ask");
    expect(decision.mode).toBe("enforce");
  });
  it("does not turn an explicit deny into an approval", () => {
    expect(evaluate(bundle({ blockedTools: ["Bash"], review: { commands: true } }), { ...ctx, eventType: "command.exec" }).action).toBe("deny");
  });
  it("gates clean commits and permits reads", () => {
    const policy = bundle({ mode: "observe", review: { commits: true, edits: true } });
    expect(evaluate(policy, { ...ctx, command: "git commit -m reviewed" }).action).toBe("ask");
    expect(evaluate(policy, { ...ctx, tool: "Read", command: "", eventType: "file.read" }).action).toBe("allow");
  });
});
