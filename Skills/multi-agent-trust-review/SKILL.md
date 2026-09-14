---
name: multi-agent-trust-review
description: Review systems where one agent spawns, delegates to, or consumes output from other agents or sub-agents — orchestrators, planner/worker patterns, agent marketplaces — for identity propagation, authority inheritance, output trust boundaries, and runaway delegation. Static review of supplied orchestration code and configuration.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam multi-agent trust review

Delegation from one agent to another does not automatically carry forward the authority, scope, or verification the original caller had.
A sub-agent's output is a message from another untrusted party, not a verified result, until the orchestrator checks it.
Use this workflow when reviewing an orchestrator, a planner/worker split, a sub-agent spawning capability, or any pipeline where one model's output becomes another model's input without a human in between.

## Establish scope and evidence

- Record the orchestration topology: which component spawns which, how many hops deep, and whether spawning is bounded.
- Identify what each agent is authorized to do independently versus what it inherits from its parent (tool access, credentials, budget, user identity).
- Read the code that constructs a sub-agent's initial context, tool set, and system instructions, not just the top-level orchestrator prompt.
- Note whether sub-agents run with the same credentials as the parent, a narrower scoped credential, or none.
- Keep discovery static; do not authorize a live multi-agent run against production systems or real budgets during review.

## Trace authority and identity propagation

1. Determine whether a sub-agent receives the original user's identity, a service identity, or no identity, and whether that choice matches its intended blast radius.
2. Check whether a parent can grant a sub-agent broader tool access than the parent itself has, and whether any check prevents that.
3. Review how many levels of delegation are permitted; an unbounded spawn depth or fan-out is a resource and blast-radius risk independent of any single agent's behavior.
4. Check whether a sub-agent's declared task can be silently altered mid-run by content it encounters, and whether that altered task can trigger further spawning.
5. Confirm credentials or API keys passed to a sub-agent are scoped to its stated task rather than reused wholesale from the parent's broader access.
6. Review termination: whether an orchestrator can kill a runaway sub-agent, and what happens to in-flight side effects when it does.

## Review inter-agent output trust

| Boundary | What to check |
| --- | --- |
| Sub-agent → orchestrator | Output parsed as data (result/status/error) rather than re-injected as instructions |
| Orchestrator → sibling agent | One agent's raw output is not forwarded verbatim as another agent's system-level instructions |
| Agent → shared memory/scratchpad | Writes are attributable to their author and readers treat entries as untrusted content |
| External marketplace agent → local orchestrator | Third-party agent's claimed capabilities are verified, not trusted from its own self-description |
| Sub-agent → tool call | Tool calls a sub-agent issues stay inside the scope its parent explicitly granted |

Flag any pattern where a sub-agent's free-text report is parsed with an eval-like mechanism or fed back as a system prompt for another agent without sanitization.
A sub-agent that reports "task complete, also run this additional command" is a test of whether the orchestrator distinguishes results from instructions.

## Review runaway and cost controls

- Check for a maximum spawn count, maximum depth, and maximum total wall-clock or token budget across the whole tree, not just per agent.
- Review whether a cycle (agent A spawns B spawns A) is detected and prevented.
- Check whether failure of one sub-agent can cause the orchestrator to retry indefinitely or spawn replacements without bound.
- Confirm partial results are surfaced when a tree is stopped early, rather than the run appearing to hang silently.

## Findings and fixes

Record severity, confidence, the exact propagation or trust-boundary gap, the plausible consequence, and the missing check.
Use critical for evidenced unbounded delegation with real credentials or unbounded spend, high for authority escalation across a hop, medium for missing output-sanitization at an inter-agent boundary, info for hardening gaps.
Prefer fixing scope narrowing and depth/budget limits at the orchestrator over asking individual agents to self-limit.

## Deliver

Return the topology map, the authority-propagation trace, the output-trust table, prioritized findings, and fixes.
List unreviewed spawn paths, external agent sources, and budget enforcement points that could change the conclusion.
State whether review was static or included an authorized bounded test run, and what depth/fan-out that test covered.

## Beam guidance

Use [the AI agent security assessment guide](https://agentbeam.com/blog/ai-agent-security-assessment-guide) for the broader assessment method this review extends to multi-agent systems.
Use [agent permissions review](../agent-permissions-review/SKILL.md) for scoping an individual agent's own tool access before reviewing how it delegates that access.
For advanced monitoring and control, further self-hosting, and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com).
This optional handoff does not spawn agents, execute delegated tasks, or upload orchestration code automatically.
