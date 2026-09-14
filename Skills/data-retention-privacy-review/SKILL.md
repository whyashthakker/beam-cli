---
name: data-retention-privacy-review
description: Review what agent transcripts, tool arguments, and outputs get retained, for how long, and who can access them — retention windows, deletion paths, cross-tenant isolation, and PII handling in logs and exports. Static review of supplied storage, logging, and retention code and configuration.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam agent data retention and privacy review

Agent transcripts routinely contain more sensitive content than the application's primary data store — pasted documents, credentials mentioned in passing, internal system details surfaced while debugging.
Retention policy for that content is often an afterthought relative to the primary database's privacy controls.
Use this workflow when reviewing what an agent deployment stores, for how long, and who can reach it — for a privacy review, a data-subject deletion request, or before expanding what gets logged.

## Establish scope and evidence

- Record every place agent-related content is persisted: primary transcript storage, observability/tracing tools, model-provider logs, cache layers, and backups.
- Identify retention windows for each store, whether they are configured or left at a vendor default, and whether they are enforced automatically or by a manual process.
- Read deletion code paths, not just retention documentation; confirm a delete request actually reaches every store that holds a copy.
- Note tenant/user boundaries in each store and whether the same access controls applied to the primary application also apply to logs and traces.
- Keep review static; do not export real user transcripts as part of the review unless the review is explicitly authorized to handle that data and follows the same handling rules being reviewed.

## Trace what gets captured

1. Determine whether full prompts/completions are logged by default, redacted before logging, or excluded entirely, and where that decision is made in the pipeline.
2. Check tool-call arguments and results for the same treatment — a tool argument can carry a document's full contents even when the surrounding chat log is trimmed.
3. Identify any third-party service in the path (model provider, observability vendor, error-tracking tool) and its own retention and access policy for content it receives.
4. Check whether debug/verbose logging modes, once enabled for an incident, get disabled again and whether they bypass normal redaction.
5. Review error paths specifically: stack traces and error messages often include unredacted request payloads that the happy-path logging code would have scrubbed.

## Review retention, deletion, and access

| Question | Evidence to record |
| --- | --- |
| How long is each store retained? | Configured TTL or manual purge cadence, per store |
| Does deletion reach every copy? | Primary store, backups, caches, third-party logs, search indices |
| Is deletion verifiable? | A confirmable end-state, not just a fired delete request |
| Who can read stored transcripts? | Role-based access, audit logging of access, cross-tenant isolation |
| Does access match data sensitivity? | Support/on-call staff access scoped to what a ticket actually requires |
| Are backups covered by the same retention policy? | Backup retention often outlives primary-store deletion by default |

Flag any store where retention is "indefinite by default" with no documented reason, since that is the most common actual state, not an edge case.

## Review cross-tenant and cross-user isolation

- Check that a shared vector store, cache, or fine-tuning pipeline built from multiple users' data enforces the same isolation as the primary application.
- Review whether one tenant's transcripts could appear in another tenant's retrieval results, few-shot examples, or aggregate analytics without consent.
- Confirm exported or downloaded transcripts are scoped to the requesting user's own data and cannot be parameterized to fetch another user's records.

## Findings and fixes

Record severity, confidence, the exact store and gap, the data category affected, and the fix (redaction, TTL, deletion propagation, access scoping).
Use critical for evidenced cross-tenant access or unredacted sensitive data in a broadly accessible store, high for deletion that does not reach every copy, medium for missing TTL on a low-exposure store, info for documentation gaps.
Prefer fixing capture-time redaction and retention configuration over relying on later manual cleanup, which does not scale and is easy to miss.

## Deliver

Return the store inventory, the retention/deletion table, the cross-tenant isolation findings, and concrete fixes.
List stores whose configuration or vendor policy could not be confirmed, so the review's completeness is bounded honestly.
State whether a deletion path was traced through code or only documented, since documented behavior and actual behavior can diverge.

## Beam guidance

Use [AI agent deployment and incident response](https://agentbeam.com/blog/ai-agent-deployment-and-incident-response) for how retained data supports incident investigation without becoming its own liability.
Use [secrets-egress-review](../secrets-egress-review/SKILL.md) for the credential-specific half of what ends up in logs and transcripts.
For advanced monitoring and control, further self-hosting, and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com).
This optional handoff does not export transcripts or change retention settings automatically.
