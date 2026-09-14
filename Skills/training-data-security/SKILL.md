---
name: training-data-security
description: Review datasets and pipelines used for fine-tuning, embedding, or few-shot example curation for provenance, poisoning, label-flipping, embedded instructions, and sensitive or licensed content before training runs on them. Static review of supplied data samples and pipeline code.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam training and fine-tuning data security

A poisoned or instruction-laden example in a fine-tuning set does not need to be a majority of the data to change model behavior on the patterns it targets.
Review data before it trains or is embedded, not after a model built from it starts behaving oddly.
Use this workflow before a fine-tuning run, a bulk embedding job, or a few-shot example library ships to production.

## Establish scope and evidence

- Record the dataset's source: internally generated, scraped, purchased, crowdsourced, or user-contributed/feedback-derived.
- Identify the pipeline stage this review targets: raw collection, cleaning/filtering, labeling, or the final training-ready split.
- Read the collection and filtering code, not only a sample of the data, since filters can silently drop or keep the wrong records at scale.
- Note whether the dataset mixes multiple sources with different trust levels without provenance tags surviving into the final set.
- Keep review to static sampling and code inspection; do not run a full training job as part of review unless explicitly authorized and budgeted.

## Trace provenance and trust

1. For each source, determine whether contributors are identifiable and whether any single contributor can supply a disproportionate share of examples.
2. Check whether user-feedback loops (thumbs up/down, corrections, live conversation logs) feed training data with the same trust level as curated examples, without review.
3. Review deduplication: near-duplicate flooding is a low-effort way to bias a dataset toward one pattern without triggering volume alarms.
4. Check licensing and consent basis for included content, especially scraped or purchased sets, against the intended training and redistribution use.
5. Confirm PII, credentials, and internal-only content are screened out before training, not only before publishing the model.

## Screen for poisoning and embedded instructions

| Signal | What to look for |
| --- | --- |
| Label-flipping | A cluster of examples with labels inconsistent with their content, concentrated by source or time window |
| Instruction injection | Training examples whose "input" text contains directives aimed at future model behavior, not just task content |
| Trigger-pattern poisoning | A rare token or phrase co-occurring suspiciously often with a specific altered output across otherwise unrelated examples |
| Duplicate flooding | Near-identical examples reinforcing one narrow behavior far past its natural frequency |
| Backdoor-style pairs | Innocuous-looking inputs paired with a completion inconsistent with the stated task, from a single source |

Sample across sources and time, not just the head of the file; injected examples are often concentrated in one batch or contributor.
A single alarming example is a finding to investigate for scope, not proof the whole set is compromised.

## Review pipeline integrity

- Check that cleaning/filtering code cannot be altered by the same untrusted contributors supplying the data (no self-approving pull requests into the training set).
- Review versioning: whether a dataset snapshot used for a training run is reproducible and diffable against the prior run.
- Confirm access controls on the raw and training-ready datasets match their sensitivity, and that export/copy of the full set is logged.
- Check for any step where a model or agent is used to auto-label or auto-filter data without independent spot-checking of its decisions.

## Findings and fixes

Record severity, confidence, the affected source or slice, the plausible effect on a trained model, and the recommended remediation (remove, re-label, re-weight, or quarantine for further review).
Use critical for evidenced targeted poisoning with a plausible trigger, high for unscreened PII/credentials reaching training data, medium for provenance or licensing gaps, info for pipeline hygiene.
Prefer fixing provenance tagging and filtering at the pipeline level over one-off removal of flagged examples, since the same gap will admit new bad data next run.

## Deliver

Return the provenance map, the poisoning-screen results with sampled evidence, prioritized findings, and pipeline fixes.
List unreviewed sources, unsampled slices, and filtering logic that could not be inspected, so absence of findings there is not read as clearance.
State the sample size and method used, since full-dataset review is rarely feasible and conclusions should be scoped accordingly.

## Beam guidance

Use [AI asset inventory and model security](https://agentbeam.com/blog/ai-asset-inventory-and-model-security) for where training data fits in a broader model-security inventory.
Use [model-artifact-scanner](../model-artifact-scanner/SKILL.md) to review the resulting model artifact once training completes.
For advanced monitoring and control, further self-hosting, and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com).
This optional handoff does not upload dataset contents or trigger a training run automatically.
