import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { InputGuard, type Inspect } from "../src/input-guard.js";
import { promptFindings, redactAndVault, resolvePlaceholders } from "../src/pii-vault.js";

const dirs: string[] = [];
let home: string;
beforeEach(async () => { home = await fs.mkdtemp(path.join(os.tmpdir(), "beam-guard-")); dirs.push(home); process.env.BEAM_DATA_DIR = home; });
afterEach(async () => { await Promise.all(dirs.splice(0).map(d => fs.rm(d, { recursive: true, force: true }))); });

const CARD = "4111 1111 1111 1111";
const inspect: Inspect = async (text) => {
  const found = promptFindings(text);
  if (!found.blocking.length) return null;
  return { replacement: (await redactAndVault(text, "wrapper:t", [], home)).text, summary: `${found.blocking.length}` };
};
const type = (guard: InputGuard, text: string) => guard.feed(Buffer.from(text));

describe("InputGuard", () => {
  it("forwards ordinary typing and Enter byte-for-byte", async () => {
    const guard = new InputGuard(inspect);
    expect(await type(guard, "refactor the parser")).toBe("refactor the parser");
    expect(await type(guard, "\r")).toBe("\r");
    expect(guard.rewrites).toBe(0);
  });

  it("on Enter, clears a typed line holding a card and retypes it with the placeholder", async () => {
    const guard = new InputGuard(inspect);
    expect(await type(guard, `my card is ${CARD}, run echo`)).toBe(`my card is ${CARD}, run echo`); // typing is echoed as usual
    const onEnter = await type(guard, "\r");
    expect(onEnter).toBe("\x15my card is [CREDIT_CARD_001], run echo\r");
    expect(onEnter).not.toContain("4111");
    expect(guard.rewrites).toBe(1);
    expect((await resolvePlaceholders("[CREDIT_CARD_001]", "wrapper:t", home)).text).toBe(CARD);
  });

  it("follows Backspace: a corrected line with no sensitive value is not rewritten", async () => {
    const guard = new InputGuard(inspect);
    await type(guard, "123-45-6789");
    await type(guard, "\x7f".repeat(11));
    await type(guard, "hello");
    expect(await type(guard, "\r")).toBe("\r");
  });

  it("rewrites a bracketed paste before any of it is forwarded, even when split across reads", async () => {
    const guard = new InputGuard(inspect);
    const a = await type(guard, `\x1b[200~my ssn is 123-`);
    const b = await type(guard, `45-6789 ok\x1b[201~`);
    expect(a).toBe("");
    expect(b).toBe("\x1b[200~my ssn is [SSN_001] ok\x1b[201~");
    expect(await type(guard, "\r")).toBe("\r"); // already placeholders: nothing to rewrite on Enter
    expect(guard.rewrites).toBe(1);
  });

  it("forwards a paste with nothing sensitive unchanged", async () => {
    const guard = new InputGuard(inspect);
    expect(await type(guard, "\x1b[200~just some text\x1b[201~")).toBe("\x1b[200~just some text\x1b[201~");
  });

  it("does not guess when the cursor moved: arrow keys mark the line uncertain and it is forwarded untouched", async () => {
    const guard = new InputGuard(inspect);
    await type(guard, `card ${CARD}`);
    expect(await type(guard, "\x1b[D")).toBe("\x1b[D"); // left arrow forwarded verbatim
    expect(await type(guard, "\r")).toBe("\r"); // not rewritten; the UserPromptSubmit hook is the backstop
    expect(guard.rewrites).toBe(0);
  });

  it("treats multi-line input (Alt+Enter) as uncertain", async () => {
    const guard = new InputGuard(inspect);
    await type(guard, `card ${CARD}`);
    await type(guard, "\x1b\r");
    expect(await type(guard, "\r")).toBe("\r");
  });

  it("passes terminal replies and other escape sequences through without treating them as typing", async () => {
    const guard = new InputGuard(inspect);
    expect(await type(guard, "\x1b[12;40R")).toBe("\x1b[12;40R"); // cursor position report
    expect(await type(guard, "\x1b]11;rgb:0000/0000/0000\x07")).toBe("\x1b]11;rgb:0000/0000/0000\x07"); // OSC reply
    expect(await type(guard, "ok")).toBe("ok");
    expect(await type(guard, "\r")).toBe("\r");
  });

  it("holds an escape sequence until it completes, and releases a lone Escape keypress on flush", async () => {
    const guard = new InputGuard(inspect);
    expect(await type(guard, "\x1b[1")).toBe(""); // split sequence is held, not leaked half-way
    expect(await type(guard, "A")).toBe("\x1b[1A");
    expect(await type(guard, "\x1b")).toBe("");
    expect(guard.hasPendingEscape).toBe(true);
    expect(guard.flushPendingEscape()).toBe("\x1b"); // Esc interrupts Claude Code, so it must not stay held
  });

  it("Ctrl-C and Ctrl-U reset the tracked line", async () => {
    const guard = new InputGuard(inspect);
    await type(guard, `card ${CARD}`);
    await type(guard, "\x03");
    expect(await type(guard, "ok\r")).toBe("ok\r");
  });

  it("handles multi-byte characters split across reads", async () => {
    const guard = new InputGuard(inspect);
    const bytes = Buffer.from("héllo");
    expect((await guard.feed(bytes.subarray(0, 2))) + (await guard.feed(bytes.subarray(2)))).toBe("héllo");
  });
});
