import { describe, expect, it } from "@jest/globals";
import { changedLines } from "../src/edit-stats.js";
import { normalize } from "../src/core.js";

describe("changedLines", () => {
  it("counts only the lines that actually changed in an Edit", () => {
    expect(changedLines({ old_string: "a\nb\nc\n", new_string: "a\nB\nc\nd\n" })).toEqual({ added: 2, removed: 1 });
  });
  it("sums a MultiEdit", () => {
    expect(changedLines({ edits: [{ old_string: "x", new_string: "y" }, { old_string: "", new_string: "1\n2" }] })).toEqual({ added: 3, removed: 1 });
  });
  it("counts a Write's content as added lines", () => {
    expect(changedLines({ content: "one\ntwo\nthree\n" })).toEqual({ added: 3, removed: 0 });
  });
  it("counts +/- lines in a patch, ignoring headers", () => {
    const patch = "*** Begin Patch\n*** Update File: a.ts\n@@\n-old\n+new\n+more\n*** End Patch";
    expect(changedLines(patch)).toEqual({ added: 2, removed: 1 });
    expect(changedLines({ command: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b" })).toEqual({ added: 1, removed: 1 });
  });
  it("says nothing when the input has no edit data", () => {
    expect(changedLines({ file_path: "a.ts" })).toBeUndefined();
    expect(changedLines("ls -la")).toBeUndefined();
  });
});

describe("normalize", () => {
  it("attaches line counts to file writes only, without the contents", () => {
    const write = normalize({ tool_name: "Edit", tool_input: { file_path: "a.ts", old_string: "a", new_string: "b\nc" } });
    expect(write.lines).toEqual({ added: 2, removed: 1 });
    expect(JSON.stringify(write)).not.toContain('"new_string"');
    expect(normalize({ tool_name: "Read", tool_input: { file_path: "a.ts" } }).lines).toBeUndefined();
  });
});
