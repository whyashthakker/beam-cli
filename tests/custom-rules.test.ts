import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { loadCustomRules } from "../src/custom-rules.js";
import { detect, setCustomRules } from "../src/core.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  setCustomRules([]);
  await Promise.all(temporaryDirectories.splice(0).map(d => fs.rm(d, { recursive: true, force: true })));
});

async function tempHome(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-rules-"));
  temporaryDirectories.push(dir);
  return dir;
}

describe("loadCustomRules", () => {
  it("is a no-op (zero rules, zero errors) when the file doesn't exist", async () => {
    const home = await tempHome();
    const result = await loadCustomRules(home);
    expect(result).toEqual({ path: path.join(home, "rules.json"), loaded: 0, errors: [] });
    expect(detect("anything at all")).toEqual([]);
  });

  it("loads a well-formed rule and makes it available to detect()", async () => {
    const home = await tempHome();
    await fs.writeFile(path.join(home, "rules.json"), JSON.stringify([
      { id: "leaked_internal_host", pattern: "internal-only\\.corp", severity: "high", title: "Internal host referenced", explanation: "Should never leave the VPN.", category: "exfil" },
    ]));
    const result = await loadCustomRules(home);
    expect(result.loaded).toBe(1);
    expect(result.errors).toEqual([]);
    const findings = detect("curl https://internal-only.corp/secrets");
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ id: "custom.leaked_internal_host", title: "Internal host referenced", severity: "high" });
  });

  it("reports and skips entries with missing fields, invalid severity, or bad regex, without dropping the valid ones", async () => {
    const home = await tempHome();
    await fs.writeFile(path.join(home, "rules.json"), JSON.stringify([
      { id: "ok_rule", pattern: "danger", severity: "high" },
      { pattern: "no-id", severity: "high" },
      { id: "no_pattern", severity: "high" },
      { id: "bad_severity", pattern: "x", severity: "catastrophic" },
      { id: "bad_regex", pattern: "(unclosed", severity: "medium" },
    ]));
    const result = await loadCustomRules(home);
    expect(result.loaded).toBe(1);
    expect(result.errors).toHaveLength(4);
    expect(detect("danger zone").map(f => f.id)).toEqual(["custom.ok_rule"]);
  });

  it("skips a duplicate id (second occurrence) and reports it", async () => {
    const home = await tempHome();
    await fs.writeFile(path.join(home, "rules.json"), JSON.stringify([
      { id: "dup", pattern: "a", severity: "medium" },
      { id: "dup", pattern: "b", severity: "medium" },
    ]));
    const result = await loadCustomRules(home);
    expect(result.loaded).toBe(1);
    expect(result.errors.some(e => e.includes("duplicate"))).toBe(true);
  });

  it("reports a clear error and loads zero rules when the file isn't a JSON array", async () => {
    const home = await tempHome();
    await fs.writeFile(path.join(home, "rules.json"), JSON.stringify({ not: "an array" }));
    const result = await loadCustomRules(home);
    expect(result.loaded).toBe(0);
    expect(result.errors[0]).toContain("expected a JSON array");
  });

  it("reports a clear error and loads zero rules on invalid JSON, rather than throwing", async () => {
    const home = await tempHome();
    await fs.writeFile(path.join(home, "rules.json"), "{ not json");
    const result = await loadCustomRules(home);
    expect(result.loaded).toBe(0);
    expect(result.errors[0]).toContain("not valid JSON");
  });

  it("calling loadCustomRules again replaces the previous set rather than appending to it", async () => {
    const home = await tempHome();
    await fs.writeFile(path.join(home, "rules.json"), JSON.stringify([{ id: "first", pattern: "one", severity: "medium" }]));
    await loadCustomRules(home);
    await fs.writeFile(path.join(home, "rules.json"), JSON.stringify([{ id: "second", pattern: "two", severity: "medium" }]));
    const result = await loadCustomRules(home);
    expect(result.loaded).toBe(1);
    expect(detect("one")).toEqual([]);
    expect(detect("two").map(f => f.id)).toEqual(["custom.second"]);
  });
});
