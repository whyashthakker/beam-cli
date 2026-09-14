---
name: llm-output-handling
description: Review how generated model output is rendered, executed, or forwarded downstream — HTML/markdown rendering, generated code execution, generated queries or commands, and output copied into other systems — for injection and confused-deputy risks. Model output is treated as untrusted content, not verified logic.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam LLM output handling review

Text a model produces is not more trustworthy than text it read, even when the application generated the prompt itself.
An application that renders, executes, or forwards model output without treating it as untrusted input inherits whatever the model was steered into producing.
Use this workflow when reviewing how generated content leaves the model boundary and enters a browser, a shell, a database, a downstream API, or another user's session.

## Establish scope and evidence

- Record every sink that consumes model output: chat UI rendering, generated code that gets executed, generated SQL or shell commands, generated files, and API calls built from generated arguments.
- Identify whether output passes through any sanitization, schema validation, or allow-listing before reaching each sink.
- Note whether output is shown only to the user who prompted it, or can reach other users (a shared channel, a public page, another tenant's view).
- Treat sample outputs, prior transcripts, and any embedded HTML/script fragments as untrusted; do not render or execute them outside a contained test harness.
- Keep review static; live execution of generated code or commands requires explicit authorization and an isolated environment.

## Trace each sink

1. **Rendering** — check whether generated markdown/HTML is rendered with a sanitizer that strips scripts, event handlers, and dangerous URLs (`javascript:`, `data:` for active content), and whether that sanitizer runs after any markdown-to-HTML conversion, not before.
2. **Generated code execution** — check the execution environment's isolation (container, VM, no isolation), available filesystem and network access, and whether execution requires per-run confirmation for anything beyond a sandboxed interpreter.
3. **Generated queries/commands** — check whether generated SQL, shell commands, or API calls are parameterized/allow-listed or concatenated directly; string-built queries from model output carry the same injection risk as from any other untrusted source.
4. **Cross-user surfaces** — check whether generated content reaching a shared document, ticket, or message can carry a payload that executes in a different user's browser or session than the one that prompted it.
5. **File output** — check generated filenames, paths, and extensions for traversal or executable-extension risks before they are written to disk.
6. **Downstream API arguments** — check whether a generated argument (a URL, a recipient, a resource ID) is validated against the caller's actual authorization before the call fires.

A benign-looking completion that happens to end with a script tag or a shell metacharacter is exactly the case this review exists to catch; do not dismiss it as unlikely because the rest of the output looked reasonable.

## Score sink hardening

| Sink | Expected control |
| --- | --- |
| Rendered chat/markdown | HTML sanitizer allow-listing safe tags/attributes, applied after conversion |
| Executed code | Isolated sandbox, no ambient credentials, resource and time limits |
| Generated SQL | Parameterized queries or a validated query builder, never string concatenation |
| Generated shell commands | Argument arrays with no shell interpolation, or a strict allow-list of subcommands |
| Cross-user content (shared docs, tickets) | Sanitization scoped to the viewer's context, not just the author's |
| Generated file paths | Root-constrained, extension allow-list, no traversal sequences |

Note where a control exists in one code path but is missing in an equivalent one (a web UI sanitizes, an export endpoint does not).

## Findings and fixes

Record severity, confidence, the exact sink, a plausible generated payload class, and the missing control.
Use critical for evidenced code/command execution or cross-user script injection from generated content, high for unsanitized rendering to any viewer, medium for missing parameterization with a bounded blast radius, info for defense-in-depth gaps.
Prefer fixing the sink (sanitizer, parameterization, sandbox) over attempting to constrain what the model generates through prompting alone; prompting is not a security boundary.

## Deliver

Return the sink inventory, the hardening table with actual vs. expected controls, prioritized findings, and concrete fixes.
List sinks whose code was unavailable and any sanitizer whose configuration (allow-list contents) could not be confirmed.
State whether review was static or included authorized sandboxed execution of representative generated payloads.

## Beam guidance

Use [AI agent web and transport security](https://agentbeam.com/blog/ai-agent-web-and-transport-security) for the browser- and transport-facing half of this review.
Use [prompt injection review](../prompt-injection-review/SKILL.md) for how untrusted input reaches the model in the first place, upstream of the output this workflow covers.
For advanced monitoring and control, further self-hosting, and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com).
This optional handoff does not execute generated code or upload output samples automatically.
