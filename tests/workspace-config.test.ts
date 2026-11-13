import { describe, expect, it } from "@jest/globals";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ensureWorkspaceConfig } from "../src/workspace-config.js";

describe("automatic repository config", () => {
  it("creates at the root from a subdirectory and preserves existing settings", () => {
    const root = mkdtempSync(join(tmpdir(), "beam-config-"));
    try {
      mkdirSync(join(root, ".git"));
      mkdirSync(join(root, "src"));
      const file = ensureWorkspaceConfig(join(root, "src"))!;
      expect(file).toBe(join(root, ".beam", ".config"));
      expect(JSON.parse(readFileSync(file, "utf8"))).toEqual({ review: {} });
      writeFileSync(file, '{"review":{"commands":true}}');
      ensureWorkspaceConfig(root);
      expect(readFileSync(file, "utf8")).toBe('{"review":{"commands":true}}');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
  it("supports worktrees and creates nothing outside Git", () => {
    const root = mkdtempSync(join(tmpdir(), "beam-config-"));
    try {
      expect(ensureWorkspaceConfig(root)).toBeUndefined();
      expect(existsSync(join(root, ".beam"))).toBe(false);
      writeFileSync(join(root, ".git"), "gitdir: /unused/worktrees/example");
      expect(ensureWorkspaceConfig(root)).toBe(join(root, ".beam", ".config"));
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
