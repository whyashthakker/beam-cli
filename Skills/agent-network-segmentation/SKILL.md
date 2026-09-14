---
name: agent-network-segmentation
description: Review network reachability for an agent's execution environment — egress allow-lists, internal service and metadata-endpoint exposure, DNS resolution scope, and blast radius if the agent's own runtime is compromised or manipulated into acting as a pivot. Static review of supplied network configuration.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam agent network segmentation review

An agent's runtime often has broader network reachability than any single tool call needs, because it inherits the network posture of the environment it runs in rather than one scoped to its actual task.
That gap becomes the blast radius if the agent is manipulated into requesting something on an attacker's behalf, or if the runtime itself is compromised.
Use this workflow when reviewing where an agent's compute runs, what it can reach, and what could reach it in return.

## Establish scope and evidence

- Record the agent's execution environment: local process, container, VM, or serverless function, and its network placement (which VPC/subnet, which security groups or firewall rules).
- Identify what the agent's actual task requires reaching: specific external APIs, specific internal services, and nothing else by default.
- Read the network configuration directly (security groups, firewall rules, egress proxy allow-lists, container network policies) rather than relying on architecture diagrams that may be stale.
- Note whether the environment is shared with other workloads (multi-tenant compute, a shared VPC) and what isolation separates them.
- Keep review static; do not run active network scans against production infrastructure without explicit authorization and a defined blast-radius-limited target.

## Trace reachability

1. Determine egress scope: unrestricted outbound, a default-deny with an explicit allow-list, or unrestricted-but-logged. Default-deny with an allow-list is the target state for most agent runtimes.
2. Check reachability to the cloud metadata endpoint (`169.254.169.254` or equivalent) from the agent's runtime; this is a common path from a manipulated agent to credential theft when not blocked.
3. Check reachability to internal-only services (databases, internal APIs, admin panels) that the agent's task does not require, especially when the runtime shares a network with those services by default.
4. Review DNS resolution: whether the runtime can resolve arbitrary external domains (enabling exfiltration via DNS or a surprising new destination) or only pre-approved ones.
5. Check ingress: what can reach the agent's runtime directly, and whether that matches only the intended callers (an orchestrator, a specific API gateway) rather than a broad internal or public surface.
6. For multi-tenant or shared compute, confirm network policy actually isolates tenants at the layer enforced (not just addressed by convention, like unenforced subnet allocation).

## Score segmentation posture

| Surface | Target state |
| --- | --- |
| Outbound to the internet | Default-deny with an explicit, task-scoped allow-list |
| Cloud metadata endpoint | Blocked, or reachable only via a scoped, non-forwardable token mechanism |
| Internal services | Reachable only where the agent's task requires it, not the full internal network |
| DNS | Resolves only allow-listed domains where feasible |
| Inbound to the runtime | Restricted to the specific expected caller(s) |
| Tenant isolation (shared compute) | Enforced at the network layer, not just logical/application-layer separation |

Flag any control described as "the agent wouldn't do that" rather than a network-layer restriction; an agent influenced by injected content is exactly the case this posture needs to hold against.

## Review pivot and exfiltration blast radius

- Assess what a fully compromised agent process could reach and do on the network as currently configured, independent of the agent's intended behavior.
- Check whether outbound requests are logged with enough detail (destination, volume) to detect an anomalous new destination or a spike in data transferred.
- Review whether a single compromised agent instance could reach and affect other agent instances or their credentials over the network.

## Findings and fixes

Record severity, confidence, the exact reachable path, a plausible pivot or exfiltration scenario, and the segmentation fix (deny rule, allow-list entry removal, metadata-endpoint block).
Use critical for evidenced reachability to the metadata endpoint or sensitive internal services with no task justification, high for unrestricted egress from a runtime that processes untrusted content, medium for missing egress logging, info for hardening gaps.
Prefer fixing the network policy itself (default-deny plus allow-list) over relying on application-level checks that a compromised runtime could bypass entirely.

## Deliver

Return the reachability map, the segmentation-posture table, blast-radius notes, prioritized findings, and concrete network fixes.
List configuration that could not be directly inspected (managed-service defaults, provider-side rules) and mark conclusions there as lower confidence.
State whether findings come from configuration review alone or an authorized reachability test, since documented rules and effective behavior can diverge.

## Beam guidance

Use [container and sandbox security](../container-sandbox-security/SKILL.md) for the execution-isolation half of the runtime this network review surrounds.
Use [cloud agent security](../cloud-agent-security/SKILL.md) for the broader cloud-deployment context this segmentation review sits within.
For advanced monitoring and control, further self-hosting, and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com).
This optional handoff does not change network rules or run scans automatically.
