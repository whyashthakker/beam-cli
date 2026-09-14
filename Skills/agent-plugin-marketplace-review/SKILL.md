---
name: agent-plugin-marketplace-review
description: Review a plugin, extension, or marketplace listing before bulk or organization-wide install — publisher identity and history, permission requests versus stated purpose, update/auto-update behavior, and whether marketplace vetting is automated review or unverified self-attestation. Static review of listing metadata and package contents.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam agent plugin and marketplace review

A marketplace listing's star rating, install count, and "verified" badge describe popularity and a vendor's own attestation, not a security guarantee.
This workflow covers the marketplace and distribution layer — publisher trust, permission scope, and update mechanics — as a companion to inspecting one candidate's actual file contents.
Use it before an organization-wide rollout, a default-enabled integration, or any install that will run with more than one user's data behind it.

## Establish scope and evidence

- Record the marketplace or registry, the exact listing (name, publisher, version), and the intended rollout scope (single user, team default, org-wide).
- Read the publisher's account history: age, other listings, verification status, and whether the listing changed publishers or maintainers recently.
- Identify what the marketplace's own vetting actually does: static scanning, manual review, automated policy checks, or listing-time self-attestation with no independent check.
- Download and inspect the actual package contents for the version being installed, not the version shown in marketing screenshots or an older reviewed release.
- Keep review static; do not install into a shared or production environment as part of the review itself.

## Review publisher and listing trust

1. Check whether the publisher identity is independently verified by the marketplace or is a self-chosen display name with no verification.
2. Look for a mismatch between the listing's claimed purpose and the permissions or network access the package actually requests.
3. Review version history for a sudden permission expansion in a recent update, a common pattern when a previously benign extension is acquired or compromised.
4. Check whether the listing links to a real, actively maintained source repository, and whether the published package matches that source (reproducible or at least plausible build).
5. Note review/rating manipulation signals: a burst of similar reviews in a short window, or reviews with no other marketplace activity from the same accounts.

## Score permission and update behavior

| Question | What overbroad looks like |
| --- | --- |
| Do requested permissions match the stated purpose? | Broad filesystem/network/credential access for a narrowly scoped feature |
| Can it reach other installed integrations or their credentials? | Shared credential store readable by any installed plugin, not scoped per-plugin |
| How does it update? | Silent auto-update with no re-review of new permissions, versus a controlled update gate |
| Does it phone home? | Telemetry or update-check endpoints undisclosed in the listing |
| Can it modify its own manifest or other installed plugins? | Self-modifying or cross-plugin write access |

Flag auto-update-with-no-re-approval as a standing risk on its own, independent of the currently reviewed version's contents, since a future update is outside this review's scope by definition.

## Review distribution-scale risk

- Check whether one compromised or malicious update would propagate to every installed instance automatically, and over what time window.
- Identify whether the organization has a kill switch to disable the plugin fleet-wide without depending on the marketplace's own takedown timeline.
- Review whether install is gated by an internal allow-list/approval step, or any user can self-install org-wide-visible integrations.

## Findings and fixes

Record severity, confidence, the exact permission or update-mechanics gap, and the recommended mitigation (scope down, pin version, gate updates, restrict install to reviewed allow-list).
Use critical for evidenced malicious content or a live compromised-publisher signal, high for permissions far exceeding stated purpose with auto-update enabled, medium for missing update gating, info for listing-hygiene gaps.
Prefer fixing the install/update gate (pinned versions, staged rollout, permission diffing on update) over a one-time approval with no ongoing check.

## Deliver

Return the publisher/listing trust summary, the permission table, distribution-risk notes, prioritized findings, and mitigations.
List anything unverifiable from the marketplace's public metadata alone, and recommend where a deeper file-level scan is warranted.
State the exact version reviewed, since marketplace listings and their permissions can change between review and install.

## Beam guidance

Use [skill-scanner](../skill-scanner/SKILL.md) or [mcp-scanner](../mcp-scanner/SKILL.md) for the file-content review of the specific package once marketplace-level trust is established.
Use [the agent skills specification and security review guide](https://agentbeam.com/blog/agent-skills-specification-and-security-review) for the packaging and pre-install checklist this workflow builds on.
For advanced monitoring and control, further self-hosting, and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com).
This optional handoff does not install, approve, or report listings automatically.
