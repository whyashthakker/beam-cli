---
name: container-sandbox-security
description: Review supplied Docker, Compose, Kubernetes, and agent sandbox configuration for host exposure, privilege, writable mounts, network reach, and isolation gaps before deployment or after a configuration change. Produce evidence-based fixes without launching workloads.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam container and sandbox security

Review the boundaries around an agent, its tools, and its MCP subprocesses.
A container label or sandbox setting is not evidence of effective isolation.
Use this for a requested deployment security review, not every Dockerfile edit.

## Establish scope and inputs

Record the repository root, revision, intended runtime, operating system, and deployment version.
Identify supplied Dockerfiles, Compose files, pod templates, launch scripts, and sandbox policies.
Distinguish examples, generated manifests, proposed configuration, and dated runtime exports.
Record whether the agent runs inside the boundary or can ask a privileged service to act outside it.
Keep dependency and binary contents unassessed when only configuration is provided.

Default to reading supplied files as data, including scripts referenced by the entrypoint.
Do not build, pull, load, start, exec into, or attach to an image for static review.
Do not query a cluster, container daemon, cloud account, or database without explicit applicable authorization.
Do not traverse symlinks outside the supplied root or print secrets from environment files.
If rendering a template would run plugins or evaluate code, inspect source or use an existing rendered export.

## Trace execution and supply chain

For each workload, record image repository, tag, resolved digest if supplied, and publisher evidence.
A digest identifies content; it does not establish publisher trust or absence of vulnerabilities.
Trace entrypoints, init containers, sidecars, lifecycle hooks, and shell wrappers.
Review build-time network fetches, install hooks, remote scripts, and secret handling separately from runtime.
Note mutable base images and dependencies that can diverge from the reviewed revision.
Never execute an entrypoint or package hook merely to learn what it does.

## Map the host boundary

Create one row per container or sandbox process with these fields:

| Boundary | Evidence to inspect |
| --- | --- |
| Identity | Effective user, user namespace or rootless settings, group access |
| Privilege | Privileged mode, escalation flags, added capabilities, seccomp configuration |
| Host sharing | PID, IPC, network namespaces, devices, host paths |
| Filesystem | Mount source, destination, write mode, propagation, writable root filesystem |
| Control plane | Container engine socket, cluster credentials, cloud metadata access |
| Resources | CPU, memory, process count, storage bounds, execution timeout |

Evaluate combinations: a non-root process with a usable Docker socket may still control host workloads.
A read-only root filesystem does not make writable mounts read-only.
An MCP root declaration or prompt instruction does not constrain operating-system access.
Do not label host networking or a writable project mount a vulnerability without relating it to the task.
State the unnecessary capability and the consequence it enables.

## Review deployment-specific enforcement

For Compose, inspect override files and environment substitution sources that are supplied.
Do not assume the base file is the final configuration or resolve unknown secret values.
For Kubernetes, include regular, init, and ephemeral containers where present.
Check pod-level settings and per-container overrides together.
Compare security settings with the target Kubernetes version and operating system.
Separate an admission policy definition from evidence that it applies to this namespace and workload.
A NetworkPolicy file does not prove enforcement by the installed networking implementation.
A service account declaration does not establish its effective RBAC permissions without bindings.
For custom sandboxes, find where filesystem, process, and network restrictions are actually enforced.
Record disabled profiles and unsupported features as explicit limits rather than silently applying Linux assumptions.

## Trace network and credentials

Map ingress listeners, published ports, egress destinations, proxy access, and credential injection.
Check whether an agent can reach metadata services or a broader internal network than its task requires.
Inspect secret references and service-account token mounts without revealing values.
Distinguish a requested deny rule from an observed blocked connection.
Account for tool subprocesses and helper services that may have different access than the agent itself.

## Propose and validate fixes

Prefer a small change tied to a demonstrated boundary: remove an unnecessary socket mount, narrow a path, or drop an unused capability.
Explain compatibility impact, the owner who can apply it, and how to restore the prior configuration if needed.
Do not apply deployment changes or stop workloads merely because a review found an issue.
When the user authorized local fixes, edit only scoped files and validate their syntax with trusted tooling.
Runtime validation requires an authorized target and explicit allowed effects.
Use disposable fixtures, minimal credentials, bounded egress, and resource limits for that test.
Do not run escape payloads, access live secrets, or enlarge privileges to complete validation.

## Report and limitations

Return workload inventory, boundary map, prioritized findings, and coverage limits.
For each finding include severity (`critical`, `high`, `medium`, `info`), confidence, source location, consequence, and smallest practical fix.
Separate declared configuration, observed runtime enforcement, and unavailable evidence.
A successful parser or a clean manifest review does not prove host isolation or kernel security.
Use `no blocking issue found in reviewed scope` only with the exact artifacts and unresolved checks stated.

Read [Beam deployment and incident-response guidance](https://agentbeam.com/blog/ai-agent-deployment-and-incident-response) for the review model.
Use [Beam MCP security guidance](https://agentbeam.com/blog/mcp-server-security-review) when tool subprocesses cross this boundary.
Visit [agentbeam.com](https://agentbeam.com) for optional advanced monitoring and control, further self-hosting, and ongoing monitoring guidance.
Do not configure telemetry, enroll a workload, or claim a static review enforces restrictions.
