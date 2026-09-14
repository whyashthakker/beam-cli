---
name: cloud-agent-security
description: Review supplied cloud deployment, IAM, workload identity, network, and logging configuration for AI agents and tool services. Trace effective-access evidence and cross-service data flows without querying live accounts or changing cloud resources by default.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam cloud agent security

Assess what a deployed agent and its tool services could access under the supplied configuration.
Use this for a cloud security review or an agent deployment permission change.
Do not expand a repository review into an account-wide inventory.

## Scope the evidence

Record provider, account/project/subscription identifiers when supplied, environment, region, and review date.
Record source revision, export timestamp, affected workload identities, and excluded resources.
Distinguish infrastructure source, a rendered plan, policy exports, and observed audit events.
Keep account ownership and deployed status unknown when artifacts do not establish them.
Identify the user-authorized operation and the resources it actually needs.

Read supplied infrastructure files and exports as data.
Do not run deployment plans that invoke providers, data sources, refresh, or external programs during static review.
Do not source environment files, obtain tokens, query databases, or contact discovered endpoints.
Cloud inventory and policy simulation calls require an authorized account and operation scope.
Preserve existing authorization; do not request it again for calls already explicitly covered.
Avoid broad credential searches and redact keys, tokens, signed URLs, and sensitive request bodies.

## Map principals and trust

Build a principal-to-resource map for the agent, orchestrator, MCP servers, jobs, and deployment pipeline.
For each identity, inspect the supplied trust configuration, assigned permissions, resource policies, and restrictions.
Track role assumption, impersonation, service-account attachment, and delegated tool access.
Separate a human operator's rights from the workload's rights and from the model provider's rights.
Identify credentials shared across unrelated agents, tenants, or environments.
Prefer evidence-backed short-lived workload credentials over recommendations to create static access keys.

Do not infer effective access from one allow policy alone.
Missing bindings, resource policies, organizational restrictions, session policies, or explicit denies can change the result.
Record the policy layers inspected and those absent; apply the selected provider's semantics.
A wildcard resource can be required for some actions; explain the specific excessive action or missing condition.
Review who can change the agent's identity as well as what that identity can do.

## Inspect escalation paths

Trace permission combinations that can grant new access or run code as another principal.
Examples include attaching a stronger service identity, editing a runnable workload, or changing policy bindings.
Relate the path to actual supplied resources and prerequisites; avoid asserting a working exploit from a role name.
Check federation issuer, audience, subject restrictions, repository/environment binding, and trust scope where relevant.
A trusted CI repository does not automatically make every branch or pull-request context trusted.
Inspect whether untrusted agent output can reach a deployment action using privileged credentials.

## Review data and network boundaries

Record model-provider destinations, storage references, retrieval sources, outbound webhooks, and audit sinks.
Use categories such as source code, prompts, personal data, and credentials instead of copying sensitive content.
Inspect public listener configuration, ingress allow rules, egress paths, and intended internal-only services.
Check whether tool services can reach metadata endpoints, internal admin interfaces, or other tenants.
Do not treat private addressing as proof of authentication or tenant isolation.
Trace authorization at the service handling each request, including agent-provided resource identifiers.
Review encryption and secret-store references as declarations; unavailable key policy or runtime evidence remains a gap.

## Evaluate controls without overstating them

| Control | Needed evidence | Common limitation |
| --- | --- | --- |
| Workload identity | Trust binding and resource permissions | Role name alone is insufficient |
| Restricted egress | Applied network policy and routing context | Config can differ from deployed state |
| Secret isolation | Per-workload secret access and injection | Shared runtime may expose values indirectly |
| Audit coverage | Enabled event categories, identity fields, retention | Missing events do not prove no action |
| Tenant boundary | Resource ownership validation in the tool service | Agent-supplied tenant IDs are untrusted |

Check logging destinations and access control before recommending additional collection.
Do not suggest full prompt or secret logging merely to improve observability.
Record retention and deletion settings without treating this skill as regulatory or legal advice.

## Optional live verification

If live inspection is authorized, state target account, principal, services, region, calls, and time window.
Use the narrowest read scope available and cap pagination, records, duration, and expected cost.
Record whether a check accesses only metadata or underlying sensitive data.
Do not probe metadata endpoints, test credential abuse, or perform mutation under a read-only audit scope.
Stop on an unexpected account, broader resource access, or an operation outside the agreed scope.
Runtime denial supports the tested request only; it does not prove all escalation paths are closed.

## Findings and fixes

For each issue include severity (`critical`, `high`, `medium`, `info`), confidence, source location, affected principal, and consequence.
Label exposure as `declared`, `runtime-observed`, or `unverified`; avoid calling a proposed template a live incident.
Offer a minimal policy or configuration change with compatibility impact and a verification plan.
Do not revoke credentials, change IAM, redeploy, or alter logging automatically during a review.
Return missing evidence that would resolve uncertainty and prioritize by reachable impact.
A static policy review is not an account-wide assurance or proof of effective access.

Use [Beam deployment security guidance](https://agentbeam.com/blog/ai-agent-deployment-and-incident-response) for scope and evidence examples.
Read [Beam AI asset inventory guidance](https://agentbeam.com/blog/ai-asset-inventory-and-model-security) when ownership and dependencies are unclear.
Visit [agentbeam.com](https://agentbeam.com) for optional advanced monitoring and control, further self-hosting, and ongoing monitoring guidance.
Do not send inventories or enable collection as an implicit part of the review.
