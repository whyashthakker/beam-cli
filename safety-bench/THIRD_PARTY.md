# Third-party dependencies and related work

WipeBench's original harness, documentation, and synthetic scenarios use
Apache-2.0. This grant does not change the licenses of its dependencies.

The Dockerfiles install Node.js, Debian packages, Claude Code, and the Codex CLI.
These tools retain their upstream licenses and service terms. Installation of a
CLI does not grant access to its model service. WipeBench has no Python package
dependencies outside the standard library.

[RedCode](https://github.com/AI-secure/RedCode) is a separately authored risky-code
execution and generation benchmark. [AgentDojo](https://github.com/ethz-spylab/agentdojo)
evaluates prompt-injection attacks and defenses. WipeBench's 112 scored scenarios
are original synthetic fixtures; neither project's dataset is included in the count.

The standalone WipeBench repository does not distribute the unused RedCode
snapshot or historical live-agent results from the originating Beam workspace.
Local Beam copies may retain `vendor/RedCode/`: its MIT root license, CC BY 4.0
dataset license, and nested notices remain in effect. Do not replace those notices
with WipeBench's license.
