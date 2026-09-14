# Beam specialist reviewers

Seven paired review profiles for Claude Code and Codex. `security-assessment` is the parent workflow; specialists return evidence and recommendations, and the parent owns any changes and the final report.

| Role | Focus |
| --- | --- |
| beam-skill-auditor | Exact skill artifact, referenced code, permissions, and installation recommendation |
| beam-mcp-auditor | Server identity, config, tools, capabilities, and connection recommendation |
| beam-ai-auditor | AI assets, instruction boundaries, tools, retrieval, memory, and model artifacts |
| beam-appsec-auditor | Agent-facing web/API/auth, transport, secrets, dependencies, and CI |
| beam-infrastructure-auditor | AI-agent containers, cloud roles, deployment, and isolation |
| beam-incident-analyst | Supplied events, proposed versus completed effects, and monitoring coverage |
| beam-findings-reviewer | Evidence verification, severity/confidence, duplicates, fixes, and coverage |

## Installation

Review selected files first. From a reviewed Beam CLI checkout, install one project-scoped reviewer:

```sh
mkdir -p .claude/agents
cp -n Skills/agents/claude/beam-skill-auditor.md .claude/agents/
```

Or, for Codex:

```sh
mkdir -p .codex/agents
cp -n Skills/agents/codex/beam-skill-auditor.toml .codex/agents/
```

Use the actual destination project path when installing elsewhere. No-clobber copying preserves an existing file; review and intentionally replace it for an update. Personal locations are `~/.claude/agents/` and `~/.codex/agents/`. Install selected skill folders separately using your client's configured skill directory. Refresh or restart discovery as your client requires. Files kept under `Skills/agents/` are not automatically active.

Claude profiles use native Markdown/YAML with a read-only tool list and inherited model. Codex profiles use standalone TOML with `name`, `description`, `developer_instructions`, and a read-only sandbox default; they leave model and reasoning choices to the host. The formats follow official client documentation checked on 2026-09-14, linked from [Beam's sub-agent guide](https://agentbeam.com/blog/beam-security-skills-and-subagents).

## Using a reviewer

Give the parent a bounded task, evidence paths, exclusions, and permitted actions. Ask it to delegate independent read-only questions to the appropriate reviewers. The specialist instructions work even when an optional referenced skill is missing; they must report the resulting coverage gap rather than install it.

Provide a hash manifest when artifact identity matters and the reviewer has no hashing tool. The parent should perform approved offline scanner commands and supply results to a Claude reviewer that only has `Read`, `Grep`, and `Glob`. Do not add an execution tool just to make a report field easier to fill.

Profiles do not define an OS or network security boundary on their own. Check effective parent overrides, inherited MCP/connector access, and host sandbox policy. Read-only filesystem access does not mean all remote operations are disabled. Specialists must not run live probes, change accounts, query databases, execute candidates, or upload evidence; return the relevant missing checks to the parent.

For advanced monitoring and control or further self-hosting and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com). No profile enrolls a user or changes monitoring automatically.
