// Run with Bun and the companion collector checkout:
// bun scripts/verify-collector-contract.ts /path/to/beam/apps/collector
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { HOOK_CATALOG } from "../src/hook-catalog.ts";
import { adaptHookPayload } from "../src/hook-adapters.ts";
import { normalize } from "../src/core.ts";

const root = resolve(process.argv[2] ?? "../beam/apps/collector");
const { eventSchema } = await import(pathToFileURL(resolve(root, "src/event-schema.ts")).href);
const { eventCreateData } = await import(pathToFileURL(resolve(root, "src/event-record.ts")).href);
const tools = ["Bash", "Read", "Edit", "list_directory", "grep", "web_search", "web_fetch", "custom_tool"];
let cases = 0;
for (const spec of HOOK_CATALOG) for (const hook of spec.events) for (const tool of tools) {
  const wire = JSON.parse(JSON.stringify(normalize(adaptHookPayload(spec.id, {
    session_id: `session-${spec.id}`, tool_use_id: `call-${hook}-${tool}`, tool_name: tool,
    tool_input: { command: "printf hello", file_path: "/repo/a.ts", query: "api routing", url: "https://example.com", old_string: "before", new_string: "after" },
    tool_response: { content: "result" }, prompt: "Find the handler", assistant_text: "Updated the handler",
  }, hook))));
  const parsed = eventSchema.parse(wire);
  assert.deepEqual(parsed, wire, `Collector changed ${spec.id}/${hook}/${tool}`);
  const queued = JSON.parse(JSON.stringify({ ...parsed, orgId: "org", deviceId: "device", userId: "user", dedupeKey: parsed.id }));
  assert.deepEqual(eventCreateData(queued).raw, queued, `Persistence changed ${spec.id}/${hook}/${tool}`);
  cases++;
}
console.log(JSON.stringify({ agents: HOOK_CATALOG.length, nativeHooks: HOOK_CATALOG.reduce((sum, spec) => sum + spec.events.length, 0), toolKinds: tools.length, contractCases: cases, result: "passed" }));
