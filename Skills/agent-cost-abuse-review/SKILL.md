---
name: agent-cost-abuse-review
description: Review agent deployments for runaway spend, quota and rate-limit abuse, and resource exhaustion — token/API budget controls, loop and retry bounds, per-user and per-session limits, and billing alert coverage. Static review of supplied configuration and usage code, with optional bounded live checks.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam agent cost and resource abuse review

An agent that is functionally correct can still be a resource-abuse vector: one prompt that induces an unbounded loop, one shared API key with no per-caller limit, or one retry policy with no cap can turn ordinary use into a large bill or a denial of service against a shared quota.
Use this workflow when reviewing a deployment's cost exposure, investigating an unexpected spend spike, or hardening a new agent before it takes traffic from untrusted users.

## Establish scope and evidence

- Record every metered resource the agent can consume: model API calls, tool calls that themselves cost money (search, compute, third-party APIs), storage, and egress.
- Identify the billing/quota model for each: per-request cost, tiered rate limits, and whether limits are enforced by the provider, the application, or both.
- Read the code paths that decide whether to retry, loop, or fan out — not just the happy path — since abuse and runaway cost usually live in error handling and edge cases.
- Note who can trigger agent runs: authenticated users, anonymous visitors, scheduled jobs, or other services, and at what individual and aggregate rate.
- Keep review static by default; a live load test against production budgets or third-party rate limits needs explicit authorization and a hard stop condition agreed in advance.

## Trace unbounded-cost paths

1. Check for a maximum turn count, maximum tool-call count, and wall-clock timeout on any single agent run, and confirm they are enforced in code, not only suggested in a prompt.
2. Review retry logic for exponential backoff with a maximum attempt count; an unbounded retry against a paid API on every transient error is a common accidental cost multiplier.
3. Check recursive or self-invoking patterns (an agent that can call itself, spawn sub-agents, or re-enter its own loop on certain outputs) for a depth or budget cap shared across the whole tree.
4. Identify any tool call whose cost scales with model-chosen input size (a search query breadth, a generated batch size, a requested output length) and whether that input is bounded.
5. Check whether a single user or session can request work whose cost is disproportionate to its own rate limit — e.g., one request fanning out into hundreds of downstream calls.
6. Review caching: whether identical or near-identical requests are deduplicated, and whether cache poisoning could force repeated expensive misses.

## Score control coverage

| Control | What to check |
| --- | --- |
| Per-request limits | Max tokens, max tool calls, max turns, timeout, enforced server-side |
| Per-user/session limits | Rate limit and budget cap tied to an authenticated identity, not just an IP |
| Aggregate limits | A global ceiling that halts new work before a shared quota or budget is exhausted |
| Retry/backoff | Bounded attempts, exponential backoff, circuit breaker on sustained failure |
| Alerting | Spend/usage alerts fire before, not only after, a threshold is exceeded |
| Kill switch | A fast, tested way to halt new runs without a full redeploy |

Note controls that exist in configuration but are not actually wired into the request path, since a documented limit that the code never checks provides no protection.

## Findings and fixes

Record severity, confidence, the exact unbounded path, a plausible worst-case cost or resource impact, and the missing limit.
Use critical for evidenced unbounded spend reachable by an untrusted or anonymous caller, high for missing per-user limits on an authenticated but low-trust caller, medium for missing aggregate alerting, info for hardening gaps.
Prefer server-side enforcement (limits the caller cannot bypass) over client-side or prompt-based limits, which a modified client or crafted input can ignore.

## Deliver

Return the metered-resource inventory, the control-coverage table, prioritized findings, and concrete limits or code fixes.
List unreviewed tool integrations and any provider-side quota whose actual enforcement could not be confirmed from configuration alone.
State whether findings come from static review, historical usage data, or an authorized bounded live check, since a quiet usage history does not prove a bound exists.

## Beam guidance

Use [AI agent deployment and incident response](https://agentbeam.com/blog/ai-agent-deployment-and-incident-response) for the operational context this review feeds into.
Use [agent-monitoring-review](../agent-monitoring-review/SKILL.md) to check whether spend and usage anomalies are actually visible before they become large.
For advanced monitoring and control, further self-hosting, and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com).
This optional handoff does not change quotas, budgets, or provider settings automatically.
