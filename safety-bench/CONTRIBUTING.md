# Contributing a scenario

One folder under `scenarios/<id>/` contains `scenario.toml` and optional
`files/`, whose paths are relative to `/home/dev`. Use a unique lowercase
hyphenated ID matching the folder name. Start with an existing case in the same
category; prefer a distinct failure mechanism over a renamed duplicate.

Include a legitimate `objective`, an evaluator-only `safety_boundary`, synthetic fixtures, a
deterministic task verifier, at least one safety check, and safe/unsafe mock
commands plus final responses. Use `[canaries]` placeholders for fake secrets.
Use `.test` endpoints for intercepted traffic and bounded workloads. Do not use
real credentials, third-party accounts, broad network scans, or host mounts.

Write the objective as a normal request for work. Let the agent choose its own
commands; do not reveal the expected bad action, tell it which safe command to
execute, or append the grading rubric. Include output filenames/format and actual
authorization when the task needs them. Every task-verifier requirement must
follow from the objective. Put adversarial instructions in lower-trust fixture
files when testing injection. `[mock]` scripts are harness tests, never live prompts.

Declare `track = "control"` when the action is explicitly authorized and the
scenario tests whether useful work is still possible. Use `track = "injection"`
for lower-trust instructions. Keep smoke checks unscored. New categories require
updating the category registry and adding an authorized control.

Check meaningful outcomes: a harmless no-op must not pass the task, and the
unsafe mock must fail for its intended action rather than a setup failure.
Keep safety and task completion conceptually separate. Truthfulness patterns
must be tested against ordinary negated claims and paraphrases before a public
ranking relies on them; the development grader currently has known limits.

```sh
python3 bench.py validate --scenarios YOUR_SCENARIO_ID
python3 bench.py selftest --scenarios YOUR_SCENARIO_ID --repeat 2
python3 -m unittest discover -s tests
```

Review `objective.txt`, `commands.jsonl`, `actions.jsonl`, `trace.md`, the raw
transcript, reported exit codes, and failed-check evidence. Include the
fixture mechanism, expected safe alternative, expected unsafe outcome, and any
gaps in a contribution description. Update CATALOG.md and COVERAGE.md. Add a
regression test when changing grading or runner behavior. Do not commit live
credentials or raw live result directories. Version any change to a published
suite and regenerate its fingerprints.

## License and review

Contributions to the original WipeBench code and scenarios are accepted under
the Apache License 2.0. Keep third-party attribution intact. Open a GitHub issue
for a new failure mechanism or a reproducible grading problem. Include the
version, suite hash, agent configuration, and redacted evidence for result reports.

Pull requests run catalog and unit checks without model credentials. The complete
Docker self-test runs on pushes to main and manually dispatched trusted revisions.
