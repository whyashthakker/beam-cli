# beam-audit

Free, standalone scanner for anyone who hasn't installed [beam](https://agentbeam.com) yet.
Checks whether anything on this machine already stops the data categories Claude Code should
never see (policy 4.2: production credentials, PII, PHI, customer data, trade secrets, network
topology) from reaching a prompt. Optional live tests collect observed behavior; missing output
is not evidence of a pre-transmission block.

## One combined scan and report

```sh
npm run audit -- --full --open
```

`--full` requests the workstation/repository/agent/MCP scan, filesystem-root discovery,
online advisory/provider/update evidence, Claude CLI live tests, and actual Claude/Codex
extension UI tests in a separate VS Code instance. One HTML and one JSON report are written
as `beam-audit-report.html` and `beam-audit-report.json`. Both the 11 audit categories and the
seven prohibited-data groups per extension appear in that report.

The command can consume agent credits and perform the external queries described below.
Open empty extension chats and handle authentication/initial setup in the isolated window
when prompted. Your working VS Code window is not restarted. Unavailable extension tests
are reported as untested, and workstation findings are still saved if VS Code cannot start.
Filesystem permission/depth/file/time limits remain explicit in the report.

`--launch-vscode` adds extension tests to the normal scan. Only `--extensions-only` excludes
the workstation and repository stages. Use `--full --skip-live` to skip Claude CLI calls while
keeping the extension UI tests. To attach to a prepared window instead of launching one,
use `--full --vscode-cdp http://127.0.0.1:9222`.

## Run

```
npx beam-audit
# or, scoped to specific folders:
npx beam-audit --root ~/Projects --root ~/Work
```

From inside this repo (before it's published), use the root `npm run audit` script -- but note
the `--` separator is required for any flag, or npm swallows it as its own unknown config option
and silently drops it:

```
npm run audit -- --root . --html report.html --open
```


No `beam` install, no signup. Live agent calls require `--live` and can consume account credits.
Agent live calls are disabled by default. GitHub and OS update queries require `--online`.

## What it checks

1. **Global + per-repo Claude Code config** — is there any `PreToolUse`/`UserPromptSubmit` hook at
   all, anywhere a repo's `.claude/settings.json` could override the global one with nothing?
2. **Every git repo found on the machine** — tracked/untracked credential files not gitignored,
   literal PII/PHI/financial-data patterns in tracked files, customer-data-shaped file names.
3. **Live round-trip test** — a synthetic (obviously fake) API key, SSN, email, and card number are
   sent through a real headless `claude -p` call; if the exact value comes back verbatim, nothing
   intercepted it before it left for Anthropic's API.
4. **VS Code extension + workspace-auto-include test** — confirms the official extension is
   installed and connected (via its own IDE socket files), then runs a live test for data that
   leaks purely because it's sitting in the working directory, never typed or pasted.

Real extension chat tests are separate from CLI tests. A CLI call in an IDE workspace is
labelled **Claude CLI in IDE workspace (not extension UI)**. Extension tests require an
explicit `--vscode-cdp` connection; see the setup below.

## Options

- `--root <dir>` (repeatable) — directories to search for git repos. Defaults to `$HOME`.
- `--max-repos <n>` — cap on repos discovered (default 500).
- `--json <file>` — also write raw findings as JSON.
- `--skip-live` — skip the two real API calls; config/file checks only.

Exit code is `1` if anything failed, `0` otherwise.

## Expanded workstation audit

The CLI includes known configuration discovery for Claude Code, Codex, Cursor, Gemini CLI,
and OpenCode; permissive setting signals; MCP/plugin declarations; endpoint overrides;
local history artifact discovery; effective Git hook inspection; and credential patterns
in the latest 100 commits across refs. Findings describe their inspection boundaries.
Configuration discovery is not proof of installation or effective runtime behavior.

Run with `--policy organization-policy.json` to enforce required check IDs and an agent
allowlist. Missing, skipped, and warning required controls fail policy evaluation.
External attestations remain warnings, even before expiry; the scanner does not certify them.

```json
{
  "version": 1,
  "requiredChecks": ["6.2-precommit-hook"],
  "allowedAgents": ["Claude Code", "Codex"],
  "evidence": {
    "incident-process": {
      "reference": "internal-security-review-123",
      "expires": "2027-01-01T00:00:00Z"
    }
  }
}
```

`--live` opts into real agent calls using synthetic data. These can consume account credits.
The default does not run live agent calls. GitHub visibility and OS update checks require `--online`. No discovered integration or Git hook is executed by the new checks.

### Requirements coverage and verification limits

| Policy section | Evidence collected or manual obligation |
| --- | --- |
| 2 Purpose, scope, governance | Roots and scope reported; renewal requires external approval evidence |
| 3 Approved tools/environment | Claude extension, known agent config, endpoint/TLS signals; version and extension approval need review |
| 4.1 Permitted data | Fixture/template exclusions; semantic classification remains manual |
| 4.2 Prohibited data | Credential, PII, PHI, customer filename, confidentiality, schema and topology heuristics; personal names unverified |
| 4.3 Code review | SAST declarations, workspace signals, optional live review tests; actual human review unverified |
| 5 Vendor assurances | Endpoint and memory signals; commercial tier, training, retention and certification require external evidence |
| 6.1 Keys | Repository and shell/settings credential checks; key ownership, sharing and rotation require evidence |
| 6.2 Repositories | Ignore exposure, hooks, visibility, bounded history; remote rules and full history unverified |
| 6.3 Workstation | Platform-dependent encryption, screen timeout, patch and EDR signals; skipped controls require verification |
| 6.4 Sessions | User behavior, remote-session MFA and physical access require external evidence |
| 6.5 Network | Endpoint/TLS signals; trusted network, VPN enforcement and API IP restrictions require evidence |
| 7 Risk mitigation | Injection heuristics, secrets, SAST; dependency provenance, incident monitoring and developer review require evidence |
| 8 Compliance | Manual process items plus policy evaluation; attestations do not establish technical compliance |
| 9 Sign-off | External signed approval required |

No claim of exhaustive whole-PC inspection is made: other users, inaccessible files, remote
machines, containers, ignored/deep folders, and unsupported agents may be outside discovery.
OSV advisory matching and GitHub classic default-branch protection inspection are available with `--online`. Account MFA/SSO, central log retention/tamper resistance, and provider rulesets still require external evidence.

Run regression checks with `node --import tsx --test packages/beam-audit/tests/scanner.test.ts`
from the repository root; typecheck with `npm run typecheck --workspace beam-audit`.

## Run the complete category audit locally

```sh
npm run build --workspace beam-audit
npm run audit -- --whole-pc --max-repos 2000 --max-depth 20 --max-files 50000 --html beam-audit-report.html --json beam-audit-report.json --open
```

On Windows PowerShell, run the same commands from the repository directory. `--whole-pc`
adds existing C–Z drive roots; on macOS/Linux it adds `/`. The current home is inspected first.
The scanner does not elevate privileges. It reports permission failures and discovery limits.
Whole-PC mode describes requested roots, not guaranteed exhaustive coverage.

Add `--online` for OSV package/version advisory queries, authenticated GitHub classic branch
protection and repository visibility, and OS update checks. This sends package names/versions
and GitHub repository identifiers; source, prompts, logs, and credential values are not sent
by these queries. Add `--live` separately for synthetic Claude tests. Other agents currently
receive configuration-based checks rather than live blocking tests.

Every HTML and JSON report includes all **11 categories**. A category being implemented is
separate from a device passing it. Unsupported or unavailable evidence remains NOT CHECKED.

| Category | Implemented evidence collection |
| --- | --- |
| Agent discovery/configuration | Home and repository JSON/JSONC/TOML locations for Claude, Codex, Cursor, Gemini, Copilot CLI, VS Code extensions and OpenCode |
| Permissions/bypasses | Parsed configuration bypass signals and optional Claude live review tests |
| Git/repository | Effective executable hooks, hook bypass environment, bounded history, optional GitHub classic protection and visibility |
| Workstation | macOS settings; Windows BitLocker, inactivity timeout, Defender, Remote Desktop; Linux root encryption topology, GNOME lock and EDR signals |
| Sensitive data | Existing repo detectors plus bounded non-repository text credential inspection |
| Organization policy | Required check IDs, approved agents, dated external evidence references |
| Coverage/evidence | Visited/excluded/inaccessible/depth-limited directories, capped scans, root scope, per-check evidence |
| Integrations/supply chain | MCP declarations including Codex TOML and VS Code JSONC, dependency lockfile presence, skill directory permissions |
| Network/destinations | TLS/endpoint signals; macOS application firewall, Windows firewall profiles and Linux UFW |
| Updates/vulnerabilities | OSV exact npm versions, supported npm agent release comparisons, Windows Update Agent, macOS update search, Linux APT cached updates |
| Logging/traceability | Bounded history sampling for timestamp/session/actor/tool/outcome fields, modification date span and POSIX permission signals |

Windows/Linux command results have fixture coverage; native verification must be performed
on those operating systems. Linux desktop/firewall/package-manager checks target GNOME,
UFW and APT, and are skipped or need review on other distributions. Local history presence
is not proof of complete, centrally retained or tamper-resistant audit logging.

Implementation references: [OSV batch queries](https://google.github.io/osv.dev/post-v1-querybatch/),
[GitHub classic branch protection](https://docs.github.com/en/rest/branches/branch-protection),
and [Windows Update Agent search](https://learn.microsoft.com/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search).

### Non-repository scan progress

This stage reports counters every two seconds and a completion summary. Overlapping roots
are deduplicated, including home plus `/`; the macOS duplicate `/System/Volumes` tree is
excluded. The stage uses a two-minute traversal budget, a 200,000-entry cap, the configured
file cap, depth 12, and a 256 KiB per-file limit. Reads are asynchronous with an abort signal.
Limits produce partial-coverage warnings in the report; they do not count as complete scans.
The time budget is checked between operations; an OS filesystem operation may take longer.

## Actual VS Code extension chat tests

This mode attaches to the running VS Code Chromium debugging endpoint and enters synthetic
fixtures into identified Claude/Codex extension webviews. It does not invoke either agent's CLI.
There are 15 test samples across all seven prohibited categories, including five credential
types and five PII types. Native extension selector compatibility depends on extension version.

1. Save work and fully quit VS Code. Starting a new window while it is already running may
   reuse an existing process without enabling the debugging port.
2. Start VS Code with `code --remote-debugging-port=9222`.
3. Confirm `curl http://127.0.0.1:9222/json/version` returns Chromium version JSON.
4. Open an empty Claude extension conversation and an empty Codex extension conversation.
   Keep both visible if possible. Existing conversations and nonempty drafts are rejected.
5. Run:

```sh
npm run audit -- --extensions-only --vscode-cdp http://127.0.0.1:9222 --html extension-tests.html --json extension-tests.json --open
```

This submits real prompts using your existing extension authentication and can consume credits.
It creates conversation history in the extensions; it does not delete that history or change
approval/sandbox settings. Samples are generated in code; production files are never used as
fixtures. Keep the debugging listener local and restart VS Code normally after testing.

The report distinguishes **VS Code · Claude extension** from **VS Code · Codex extension**.
Each sample reports one of:

- **Not blocked for this sample:** the assistant response echoes this run's unique marker and fixture.
- **Guardrail reports blocked:** a configured, dedicated guardrail UI event includes the same unique marker.
- **Inconclusive / not tested:** refused/omitted response, unavailable UI, changed selectors,
  unavailable debugging endpoint, timeout, or an existing conversation/draft.

A model refusal never proves that sensitive text was stopped before provider transmission.
Even a correlated guardrail UI event is UI evidence; independent egress verification requires
transport-side evidence. Policy 4.1 permits synthetic fixtures, so allowing a fake sample alone
does not demonstrate a violation for real sensitive data.

Default adapters target the installed Claude 2.1.317 and Codex 26.1111 UI structures; they are not guaranteed for other releases. If an extension reports selector mismatch, use `--ui-adapters file.json`
with a JSON array of adapters containing `agent` (Claude/Codex), `extensionId`
(anthropic.claude-code/openai.chatgpt), `composerSelector`, `submitSelector`, `assistantSelector`,
`userSelector`, and `emptyChatSelector`. Optional `pendingSelector` identifies an active turn.
Optional `blockedSelector` must identify a dedicated local guardrail event and include the test
ID; never point it at assistant text, user text, or a generic error notification. The runner
refuses ambiguous controls and never guesses which chat to submit to.

CDP attachment follows the [Playwright connectOverCDP interface](https://playwright.dev/docs/api/class-browsertype#browser-type-connect-over-cdp).

### Open a separate VS Code without restarting your working window

```sh
npm run audit -- --launch-vscode --html extension-tests.html --json extension-tests.json --open
```

This starts a new VS Code process with a temporary `--user-data-dir`, a synthetic workspace,
and its own loopback debugging port. It leaves the working VS Code process running. Existing
user settings are copied when available; authentication databases and conversations are not.
Installed extensions are loaded from the existing extension directory. Open empty Claude and
Codex chats in the new window when prompted. Workspace Trust and authentication prompts may
need attention; no global trust, permission or sandbox settings are disabled. The runner waits
up to 60 seconds per extension for a visible chat. Version-specific adapters may still require
calibration. Results from this isolated workspace do not certify your working project's controls.
Close the isolated window after testing; its temporary profile/history directory is printed in
the scan evidence and can then be removed manually.

Use `--extension-agent claude` or `--extension-agent codex` to limit the UI stage to one
extension. The default tests both. UI test IDs and correlated assistant-response hashes,
when observed, are included in the same JSON findings and evidence as workstation checks.

## Agent-specific controls in the combined scan

All normal scans (and `--full`) now inspect:

- Typed approval/bypass declarations, disabled hooks, broad tool grants, sandbox/network flags,
  selectable profiles and additional writable roots.
- File-derived Claude/Codex settings separately for user defaults and each discovered project.
  Supported scope-inapplicable settings are ignored during this candidate resolution. This is
  not an attestation of runtime flags, loaded cloud/MDM policy, trust or active session state.
- Supported managed policy files, their POSIX write permissions, and Codex managed approval/
  sandbox constraint declarations where accessible.
- Current-user running executable candidates and recognized bypass argument signals. Process
  names do not prove binary identity; macOS/Windows command-line parsing is ambiguous. Raw
  command lines, prompts and values are never copied into the report. Inspection is bounded
  to 32 candidates and a 10-second budget; wrappers/remote processes may be missed.
- Claude/Codex/Gemini credential cache metadata and POSIX access bits, or Windows broad-SID ACL
  signals. No token values are reported. Authentication metadata does not verify commercial API
  tier, SSO/MFA, account ownership, key rotation or vendor training/retention terms.
- Explicit memory generation/use settings and bounded first-level Claude/Codex memory content
  heuristics. Existing files do not prove memory is enabled. Inspection is capped at 500 files,
  256 KiB each, a 10-second budget, and the documented project/store limits.
- Installed extension manifest identities, versions, manifest hashes and policy approval.
  Recognized AI extension identities also feed agent discovery. A manifest is not proof of a
  genuine publisher, an active version, or the extension's actual data destinations.
- Claude/Gemini Markdown agent metadata, Codex role TOML references and definitions, supported
  root instruction/rule/skill files, and Claude plugin installation receipts. They are read
  as data, never executed or followed. Dynamic agents and unsupported stores remain unverified.
- MCP server/origin allowlists, auto-approval/trust declarations, npm exact-release arguments,
  absolute executable permission signals, inline-code launchers and literal secret environment
  fields. No server is started or connected; active authenticated connection state is unverified.

Configure organization controls in your policy file:

```json
{
  "version": 1,
  "requiredChecks": [],
  "allowedAgents": ["Claude Code", "Codex"],
  "agentControls": {
    "requireManualApproval": true,
    "requireSandbox": true,
    "forbidPersistentMemory": true,
    "requirePromptHooks": true,
    "requirePinnedMcpPackages": true,
    "allowedEndpointOrigins": ["https://api.anthropic.com", "https://api.openai.com"],
    "allowedMcpServers": [],
    "allowedPlugins": [],
    "allowedModels": ["your-approved-model-id"],
    "allowedExtensions": ["anthropic.claude-code", "openai.chatgpt"],
    "minimumExtensionVersions": {"anthropic.claude-code": "2.1.317"}
  }
}
```

Lists are explicit allowlists; empty lists deny all matching discovered declarations.
Omit a list when no organization baseline is available. Origin lists also apply to supported
MCP remote destinations, so include your approved MCP origins. Approval/model/sandbox checks
on individual files concern declarations, including inactive profiles; file-derived candidate
checks separately report supported precedence. Neither proves effective runtime enforcement.
`requirePromptHooks` is specifically a Claude `UserPromptSubmit` declaration requirement;
it is not a claim that every agent supports an equivalent hook mechanism.

Run `npm run audit -- --full --policy your-policy.json --open`. The supplied
`policies/requirements-agent-baseline.example.json` is a strict illustrative profile based on
the engagement document **plus additional sandbox/hook/MCP best practices**. It intentionally
retains the document's 30 September 2026 expiry, Windows family and Claude-only approval.
It is not a renewed authorization, exact Windows 10 edition verifier, or complete translation
of contractual obligations. A security owner must review the baseline and add approved tools,
extensions, endpoints and any renewal before using it as the organization's current policy.

### Live review evidence

When using the isolated launcher, the UI stage can additionally request one synthetic proof
file per available extension inside that temporary workspace. The scanner does not click
approval or run a model-provided command. A proof file records an observed edit; it does not
prove that a human did not interact, understand or review it. A dedicated version-specific
`approvalSelector` can observe a correlated approval request; without that evidence, a missing
proof file or refusal is inconclusive. These rows are grouped separately under policy 4.3.
An arbitrary `--vscode-cdp` attachment does not receive file-edit test requests because an
isolated synthetic target workspace has not been established.

Synthetic echo results are review findings, not automatic organization-policy failures:
policy 4.1 permits fictitious data. CLI proof tests and organization-required checks have
separate failure semantics. Missing CLI proof output no longer counts as a successful block.

Configuration references: [Claude settings precedence](https://code.claude.com/docs/en/settings),
[Codex configuration](https://developers.openai.com/codex/config-reference), and
[Gemini configuration](https://geminicli.com/docs/reference/configuration/).
