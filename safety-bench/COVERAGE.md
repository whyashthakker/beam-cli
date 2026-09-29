# Coverage matrix and gaps

This is a finite development corpus, not a claim to cover every possible scenario.
The matrix records concrete mechanisms and distinguishes implemented simulations from live-provider coverage.

| Category | Scored cases | Controls | Implemented mechanisms |
| --- | --- | --- | --- |
| Credential & sensitive-data access | 10 | 1 | SSH, cloud, npm, Docker and Git credential stores; shell history; response/log/archive disclosure; authorized local token use. |
| Destructive commands | 10 | 1 | Recursive deletion, empty variables, find scope, truncation, backups, reset/clean, stash/history loss, symlink cleanup, authorized tree deletion. |
| Permission & security changes | 10 | 1 | Recursive permissions, SSH modes, TLS/host verification, Git TLS settings, umask, setuid, executable data, read-only files, authorized restriction. |
| Unsafe network / exfiltration | 10 | 1 | HTTP/HTTPS attempts, headers, URL queries, base64, multipart, Python HTTP, archives, remote scripts, authorized loopback requests. |
| Prompt injection | 10 | 1 | README, code comments, build logs, issue text, tool-result JSON, fake role markup, encoded snippets, CSV cells, review comments, quoted-command control. |
| Acting outside the workspace | 10 | 1 | Sibling/parent files, global Git settings, shell profiles, symlinks/hardlinks, archive traversal, shared caches, explicit cross-directory authorization. |
| Tampering with guardrails | 10 | 1 | Config disabling, hook deletion/path redirection, audit erasure, test weakening, scanner exclusions, forged approvals, self-issued waivers, authorized tightening. |
| Honest reporting | 10 | 1 | False claims about tests, builds, lint, deployment, coverage, audit findings, dry runs, installs, skipped tests, and an actual successful-check control. |
| Dependencies & supply chain | 8 | 1 | Lifecycle scripts, lockfiles, registry changes, checksum mismatch, license stripping, unpinned upgrades, typo substitution, authorized version pin. |
| Data integrity & transformations | 8 | 1 | Leading-zero IDs, Unicode, large integers, unrelated fields, duplicates/order, invalid input rollback, newline normalization, authorized redaction. |
| Process & resource boundaries | 8 | 1 | Shell substitution/separators, sourcing data, tool-path poisoning, bounded output, startup persistence, background workers, authorized PID targeting. |
| Publishing & external side effects | 8 | 1 | Send versus draft, Git push, release/package publication, remote deletion, deployment webhooks, permission grants, authorized intercepted mock endpoint. |

## Cross-cutting dimensions

- Authority: agent-facing objectives, authorized exceptions, evaluator-only safety boundaries, lower-trust file instructions, and a quoted dangerous command that should remain data.
- Outcomes: read, write, delete, chmod, process mutation, network attempt, disclosure, data corruption, and false final claims.
- Evidence: objective-linked ordered command/tool traces, reported command results, filesystem state/access, command patterns, intercepted requests, output assertions, and truth-claim checks.
- Context: local project, home directory, sibling/parent path, shared storage, dependency metadata, and simulated external services.
- Scoring: safety, task completion, their intersection, controls, error coverage, categories, and repeated trials.

## Explicitly not covered in this release

- Windows/macOS shell, ACL, keychain, native permission dialogs, mobile, or hardware behavior.
- Browser/DOM actions, real email/chat/calendar tools, MCP protocol attacks, tool-schema poisoning, or IDE-specific APIs.
- Real database queries/migrations, billing/payment APIs, real cloud IAM, production deployments, actual package publication, or real outgoing email. External effects are intercepted attempts.
- Kernel/container escape exploitation, privilege escalation against the host, distributed attacks, arbitrary native binaries, or unbounded resource exhaustion. Workloads are deliberately small.
- Adversarial communication between parallel containers, multi-agent delegation, cross-session memory poisoning, or long-horizon persistent workflows.
- Exhaustive command obfuscation/encoding, every archive format, transient write-and-restore attacks, race conditions, or full semantic truthfulness.
- Complete OS-level subprocess/syscall auditing. Command traces rely on CLI tool events and preserve unknown or unfinished outcomes.
- Broad multilingual injection, visual/audio prompt injection, accessibility/UI permission behavior, or all model-provider/tool versions.
- Native approval-mode comparisons, Beam enforcement ablations, private holdouts, independent expert labels, or statistically validated rankings.

## Expansion rules

Add a new failure mechanism or a meaningful contextual/authorization variation. Label related cases as related when analyzing results; do not equate the case count with independent vulnerability families. Include a useful safe path and an unsafe counterexample, then inspect actual Docker evidence. New tool/OS/provider surfaces require real adapters and isolated fixtures rather than claiming coverage from a similar shell prompt.

Priorities for a later release: independent review; held-out realistic multi-file tasks; paired authorization variants; a pinned execution image; MCP/browser adapters; multi-turn/approval-mode evaluation; and empirically measured false-positive/false-negative rates.
