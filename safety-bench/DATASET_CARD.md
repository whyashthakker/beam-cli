# Dataset card

- **Name:** WipeBench — AI Coding Agent Safety Benchmark.
- **Version:** see VERSION; development release, not an independently validated ranking.
- **Maintainer:** Yash Thakker / [AgentBeam](https://agentbeam.com), in collaboration with [ExplainX.ai](https://explainx.ai).
- **Repository:** https://github.com/whyashthakker/WipeBench
- **Contents:** 112 scored synthetic scenarios and one smoke scenario. Twelve
  scored controls explicitly authorize a bounded action.
- **Format:** TOML objectives/private boundaries/checks/mock actions plus UTF-8 fixture files. Fixtures
  mirror the sandbox user's home. Setup scripts run inside Docker.
- **Language/environment:** predominantly English; Linux shell, Python, Node, Git,
  local text/JSON/CSV files, and intercepted HTTP/HTTPS attempts. One data case
  explicitly checks preservation of non-ASCII characters.
- **Origin:** original AI-assisted scenario authoring in this workspace. The
  existing RedCode reference snapshot is separate and contributes zero cases to
  the count. No claim that these are independently collected incidents.
- **Secrets/personal data:** synthetic canaries generated per trial, `.test`
  domains, and fictional fixture records. Live CLI credentials are runner inputs,
  never intended benchmark data. Raw live outputs still require publication review.
- **Intended use:** development, failure analysis, regression testing, transparent
  comparison of agent stacks under the documented protocol.
- **Out of scope:** certification, estimates of real-world incident frequency,
  claims of legal wrongdoing, conclusions about untested operating systems/tools,
  and scores for safety products that were not installed in the evaluation.
- **Biases:** manually chosen categories, editorial severity weights, related
  cases across surfaces, subjective interpretations of objectives, simple local tasks,
  English-heavy instructions, heuristic grading, public-set contamination.
- **Protocol:** `objective-command-trace-v1`. The agent receives only the objective
  and chooses its own actions. Evaluation boundaries and reference scripts are
  withheld. Command/tool traces and outcomes are recorded separately from scores.
- **Version comparability:** 0.2 changes agent-facing instructions from 0.1's
  explicit hazard warnings; the scores are not directly comparable.
- **Licensing:** Apache-2.0 for the original harness, documentation, and synthetic
  scenarios; see LICENSE and NOTICE. Third-party dependencies retain their own
  terms. The standalone release does not bundle the RedCode reference snapshot.
- **Human review:** independent scenario/scorer review and real-agent pilot runs
  remain required before a public leaderboard launch.

Run `python3 bench.py validate` for scenario identities, category counts, and
content hashes. See CATALOG.md for all cases and METHODOLOGY.md for scoring.
