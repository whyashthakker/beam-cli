# Changelog

## 0.2.0-alpha.1 — 2026-09-29

First standalone WipeBench alpha, by AgentBeam in collaboration with ExplainX.ai.

- Apache-2.0 license for original code, documentation, and synthetic scenarios.
- 112 scored scenarios across 12 categories, including 12 authorized controls,
  plus one unscored smoke test.
- Objective-only agent instructions with private evaluator boundaries.
- Ordered command/tool traces with observed outcomes, task verification, and
  safety evidence in disposable Docker environments.
- No-key safe/unsafe harness self-tests, CI, citation metadata, and public docs.

This release contains scripted validation, not a real-agent leaderboard. Its
`objective-command-trace-v1` protocol differs from the Beam workspace's earlier
explicitly cautioned prompts; those scores are not directly comparable.
