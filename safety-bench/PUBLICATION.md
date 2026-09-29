# Publishing and growing WipeBench

**WipeBench is a benchmark by [AgentBeam](https://agentbeam.com), in collaboration
with [ExplainX.ai](https://explainx.ai).** Original code, documentation, and synthetic
scenarios are available under Apache-2.0.

## Canonical locations

- Source, issues, contributions, and versioned releases:
  [whyashthakker/WipeBench](https://github.com/whyashthakker/WipeBench).
- Overview, quickstart, scope, and frequently asked questions:
  [agentbeam.com/benchmarks/wipebench](https://agentbeam.com/benchmarks/wipebench).
- Local `safety-bench/` copies in Beam and Beam CLI are integration snapshots.
  Update them from this source; avoid independently maintained implementations.

A standalone repository makes the benchmark easy to clone, cite, and contribute
to without installing Beam. The AgentBeam page gives readers one discoverable
overview with direct links to the source and evidence.

## What to show

Lead with the question: **Can a coding agent finish the task without harmful
side effects?** Show the objective, the commands the agent chooses, and the
resulting effects. Report safety and task completion separately, with
**safe + complete** as the primary usefulness measure.

The quickstart needs no API key and runs scripted smoke checks. Keep every mock
demo labeled as scripted. The public alpha has harness-validation evidence;
real-agent comparisons require new live runs and reviewed results.

## Search and discovery

Use the descriptive title **WipeBench: AI Coding Agent Safety Benchmark** and
explain concrete topics naturally: harmful shell commands, destructive file
operations, secret leakage, prompt injection, Claude Code, and Codex evaluation.
These are audience-intent hypotheses, not measured search-volume claims.

The landing page includes a canonical URL, Open Graph and Twitter previews,
Dataset/SoftwareSourceCode metadata, crawlable coverage, and links to methodology
and the downloadable source. Include it in the sitemap and the site's navigation.
[Google's dataset guidance](https://developers.google.com/search/docs/appearance/structured-data/dataset)
describes discovery metadata; indexing and traffic are not guaranteed.

Use GitHub topics such as `ai-safety`, `ai-agents`, `benchmark`, `coding-agents`,
`prompt-injection`, `docker`, and `agent-security`. Keep the About description
specific and point its homepage at the canonical landing page. CITATION.cff
provides [GitHub citation metadata](https://docs.github.com/en/repositories/archiving-a-github-repository/referencing-and-citing-content).

## Before a model leaderboard

1. Independently review objectives, fixture quality, and scorers, including
   false positives, negation handling, and incomplete command capture.
2. Freeze the suite and reviewed Docker image digests; record all model/CLI flags.
3. Run real agents on the same full suite with repeated trials. Count errors and
   refusals. Publish denominators, category scores, and redacted command evidence.
4. Provide a held-out evaluation plan and a process to dispute or correct results.
   Public synthetic tasks cannot establish universal safety or incident rates.

## Launch and follow through

Start with the public alpha, a no-key quickstart, and an honest scripted example.
After real-agent review, share a short demo of recognizable failures and safe
alternatives with relevant developer and research communities. The owner can
post a Show HN and share through AgentBeam and ExplainX channels. No outreach is
sent automatically by the benchmark or its publication workflow.

Accept reproducible result submissions and distinct new failure mechanisms.
Measure source/quickstart clicks, voluntarily submitted run reports, release
downloads, external contributions, and citations. There is no benchmark CLI
telemetry, signup requirement, or promise of search rankings.
