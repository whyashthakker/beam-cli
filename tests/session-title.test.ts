import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { notePrompt, sessionContextFor, titleFromPrompt } from "../src/session-title.js";
import { normalize } from "../src/core.js";
import { adaptHookPayload } from "../src/hook-adapters.js";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "beam-title-"));
  process.env.BEAM_DATA_DIR = join(dir, "data");
});
afterEach(async () => {
  delete process.env.BEAM_DATA_DIR;
  await rm(dir, { recursive: true, force: true });
});

describe("titleFromPrompt", () => {
  it("uses the first non-empty line, collapses whitespace and caps the length", () => {
    expect(titleFromPrompt("\n\n  fix   the login bug \nmore detail")).toBe("fix the login bug");
    const long = titleFromPrompt("x".repeat(300));
    expect(long.length).toBe(80);
    expect(long.endsWith("…")).toBe(true);
  });
  it("redacts secrets and drops injected wrapper tags", () => {
    expect(titleFromPrompt("deploy with API_KEY=abcdef123456")).not.toContain("abcdef123456");
    expect(titleFromPrompt("<timestamp>Monday</timestamp>\ndo we use fonts?")).toBe("do we use fonts?");
  });
});

describe("session title is set once", () => {
  it("keeps the first prompt's title when later prompts arrive", async () => {
    await notePrompt("s1", "fix the login bug");
    await notePrompt("s1", "now delete all the S3 buckets");
    expect((await sessionContextFor("cursor", "s1", { home: dir }))?.title).toBe("fix the login bug");
  });
  it("returns nothing for a session it has not seen", async () => {
    expect(await sessionContextFor("cursor", "unknown", { home: dir })).toBeNull();
  });
  it("upgrades once to Claude Code's own ai-title, then stays locked", async () => {
    await notePrompt("s2", "fix the login bug");
    const transcript = join(dir, "s2.jsonl");
    await writeFile(transcript, `{"type":"user"}\n{"type":"ai-title","aiTitle":"Login bug in auth middleware","sessionId":"s2"}\n`);
    expect((await sessionContextFor("claude-code", "s2", { home: dir, transcriptPath: transcript }))?.title).toBe("Login bug in auth middleware");
    await writeFile(transcript, `{"type":"ai-title","aiTitle":"Something else entirely","sessionId":"s2"}\n`);
    expect((await sessionContextFor("claude-code", "s2", { home: dir, transcriptPath: transcript }))?.title).toBe("Login bug in auth middleware");
  });
  it("upgrades to Codex's thread_name from the session index", async () => {
    await notePrompt("abc-123", "refresh button");
    await mkdir(join(dir, ".codex"), { recursive: true });
    await writeFile(join(dir, ".codex", "session_index.jsonl"), `{"id":"abc-123","thread_name":"Dashboard Refresh Button"}\n`);
    expect((await sessionContextFor("codex", "abc-123", { home: dir }))?.title).toBe("Dashboard Refresh Button");
  });
});

describe("turns and topic shift", () => {
  it("counts a turn per prompt and keeps the title while the topic moves on", async () => {
    await notePrompt("t1", "fix the login bug in the auth middleware", "/repo/app");
    await notePrompt("t1", "also fix the login redirect in the auth middleware", "/repo/app");
    let context = await sessionContextFor("cursor", "t1", { home: dir });
    expect(context).toMatchObject({ title: "fix the login bug in the auth middleware", turn: 2, shift: false });
    await notePrompt("t1", "delete the old production database backups from storage", "/repo/app");
    context = await sessionContextFor("cursor", "t1", { home: dir });
    expect(context).toMatchObject({ title: "fix the login bug in the auth middleware", turn: 3, topic: "delete the old production database backups from storage", shift: true });
  });
  it("ignores short follow-ups for the topic and flags a directory change", async () => {
    await notePrompt("t2", "refactor the billing invoice export", "/repo/a");
    await notePrompt("t2", "yes", "/repo/a");
    expect(await sessionContextFor("cursor", "t2", { home: dir })).toMatchObject({ turn: 2, topic: "refactor the billing invoice export", shift: false });
    await notePrompt("t2", "continue with the export", "/repo/b");
    expect((await sessionContextFor("cursor", "t2", { home: dir }))?.shift).toBe(true);
  });
});

describe("event and adapter wiring", () => {
  it("normalize carries the session title through", () => {
    const event = normalize({ tool_name: "Read", file_path: "a.ts", session_id: "s1", session_title: "fix the login bug" });
    expect(event.sessionTitle).toBe("fix the login bug");
    expect(normalize({ tool_name: "Read", file_path: "a.ts" }).sessionTitle).toBeUndefined();
    const turn = normalize({ tool_name: "Read", file_path: "a.ts", turn: 3, turn_topic: "delete backups", turn_shift: true }).turn;
    expect(turn).toEqual({ n: 3, topic: "delete backups", shift: true });
  });
  it("cursor's conversation_id becomes the session id", () => {
    expect(adaptHookPayload("cursor", { conversation_id: "conv-1", hook_event_name: "beforeSubmitPrompt", prompt: "hi" }).session_id).toBe("conv-1");
    expect(adaptHookPayload("cursor", { session_id: "s-9", conversation_id: "conv-1" }).session_id).toBe("s-9");
  });
  it("copilot userPromptSubmitted is recognised as a prompt event", () => {
    const data = adaptHookPayload("copilot-cli", { sessionId: "c1", prompt: "hello" });
    expect(data.hook_event_name).toBe("UserPromptSubmit");
    expect(adaptHookPayload("copilot-cli", { sessionId: "c1", toolName: "bash", toolArgs: "{}" }).hook_event_name).toBe("PreToolUse");
  });
});
