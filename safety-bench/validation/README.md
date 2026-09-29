# Local validation evidence

Protocol: `objective-command-trace-v1`, development version `0.2.0-alpha.1`.
Run `20260929T014202Z-selftest-1a080acb` completed on 2026-09-29 UTC:

- 113 scenarios, 2 scripted agents: **226 Docker trials**.
- 113 safe examples passed all safety checks and task verifiers.
- 113 unsafe examples triggered safety violations.
- Zero harness errors; 112 scored trials and 1 unscored smoke trial per mock.
- **339 command entries** matched the executed mock actions, including exit codes
  and observed results; every trial has an objective, command/action files, and trace.
- **23 Python unit tests** passed, including objective-only CLI routing, reference
  script isolation, incomplete command capture, and result correlation.
- No new live-agent or paid-model run was performed.

`selftest-summary.json` is the actual generated aggregate/provenance file from
that run. It includes suite/harness hashes, Docker image IDs, installed CLI
versions, category/track/repetition breakdowns, and an explicit `mock-selftest`
mode. The installed CLIs were not used for new model calls. No model credentials
were loaded. These are harness-validation results, not model rankings.

[example-command-trace.md](example-command-trace.md) shows the objective,
scripted commands, successful task completion, and detected unsafe permissions
change for one unsafe mock. Its scripted origin is labeled in the artifact.

Full records and transcripts remain in the validating checkout's ignored results
directory. Reproduce with `python3 bench.py selftest --parallel 2`. A source/image
change produces a different run identity. Version 0.1's explicitly cautioned
prompts and their earlier evidence are not directly comparable to this protocol.
