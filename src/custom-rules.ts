import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { getBeamHome } from "./config.js";
import { setCustomRules, type Rule, type RuleCategory, type Severity } from "./core.js";

export interface CustomRuleLoadResult { path: string; loaded: number; errors: string[] }

const VALID_SEVERITIES: Severity[] = ["critical", "high", "medium", "info"];

export function customRulesPath(home = getBeamHome()): string { return join(home, "rules.json"); }

// Custom rules extend detection without editing beam's own source: a JSON array of
// { id, pattern, severity, title?, explanation?, category? } at ~/.beam/rules.json. A missing
// file is not an error (zero custom rules); a malformed entry is skipped with a reported reason,
// not a crash -- one bad rule must never take down detection for every other rule.
export async function loadCustomRules(home = getBeamHome()): Promise<CustomRuleLoadResult> {
  const path = customRulesPath(home);
  const errors: string[] = [];
  let raw: string;
  try { raw = await readFile(path, "utf8"); }
  catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") { setCustomRules([]); return { path, loaded: 0, errors: [] }; }
    throw e;
  }

  let parsed: unknown;
  try { parsed = JSON.parse(raw); }
  catch { setCustomRules([]); return { path, loaded: 0, errors: [`${path}: not valid JSON; no custom rules loaded.`] }; }

  if (!Array.isArray(parsed)) { setCustomRules([]); return { path, loaded: 0, errors: [`${path}: expected a JSON array of rule objects.`] }; }

  const rules: Rule[] = [];
  parsed.forEach((entry, i) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) { errors.push(`rule[${i}]: not an object, skipped.`); return; }
    const e = entry as Record<string, unknown>;
    if (typeof e.id !== "string" || !e.id.trim()) { errors.push(`rule[${i}]: missing "id", skipped.`); return; }
    if (typeof e.pattern !== "string" || !e.pattern) { errors.push(`rule[${i}] (${e.id}): missing "pattern", skipped.`); return; }
    if (typeof e.severity !== "string" || !VALID_SEVERITIES.includes(e.severity as Severity)) { errors.push(`rule[${i}] (${e.id}): "severity" must be one of ${VALID_SEVERITIES.join(", ")}, skipped.`); return; }
    let regex: RegExp;
    try { regex = new RegExp(e.pattern, "i"); }
    catch (err) { errors.push(`rule[${i}] (${e.id}): invalid regex pattern (${err instanceof Error ? err.message : String(err)}), skipped.`); return; }
    if (rules.some(r => r.id === `custom.${e.id}`)) { errors.push(`rule[${i}] (${e.id}): duplicate id, skipped.`); return; }
    rules.push({
      id: `custom.${e.id}`,
      title: typeof e.title === "string" && e.title ? e.title : e.id,
      severity: e.severity as Severity,
      category: (typeof e.category === "string" && e.category ? e.category : "custom") as RuleCategory,
      explanation: typeof e.explanation === "string" && e.explanation ? e.explanation : "User-defined rule.",
      match: (s: string) => regex.test(s),
    });
  });

  setCustomRules(rules);
  return { path, loaded: rules.length, errors };
}
