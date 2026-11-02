/** Positions use UTF-16 offsets in the original inspected input. Never ship the input itself here. */
export type MatchSpan = { start: number; end: number; label?: string };
export type Matcher = ((text: string) => boolean) & { spans?: (text: string) => MatchSpan[] };
const LIMIT = 8;
export function patternMatch(pattern: RegExp): Matcher {
  const match = ((text: string) => new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, "")).test(text)) as Matcher;
  match.spans = text => {
    const regex = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, "") + "g");
    const spans: MatchSpan[] = [];
    for (const found of text.matchAll(regex)) {
      if (found[0].length) spans.push({ start: found.index!, end: found.index! + found[0].length });
      if (spans.length >= LIMIT) break;
    }
    return spans;
  };
  return match;
}
export function anyMatch(...rules: Matcher[]): Matcher {
  const match = ((text: string) => rules.some(rule => rule(text))) as Matcher;
  match.spans = text => {
    const matched = rules.filter(rule => rule(text));
    const quota = Math.max(1, Math.floor(LIMIT / Math.max(1, matched.length)));
    return matched.flatMap(rule => (rule.spans?.(text) ?? []).slice(0, quota)).slice(0, LIMIT);
  };
  return match;
}
export function allMatch(...rules: Matcher[]): Matcher {
  const match = ((text: string) => rules.every(rule => rule(text))) as Matcher;
  match.spans = text => {
    if (!match(text)) return [];
    const quota = Math.max(1, Math.floor(LIMIT / rules.length));
    return rules.flatMap(rule => (rule.spans?.(text) ?? []).slice(0, quota)).slice(0, LIMIT);
  };
  return match;
}
export function functionalMatch(predicate: (text: string) => boolean, spans?: (text: string) => MatchSpan[]): Matcher {
  const match = ((text: string) => predicate(text)) as Matcher;
  if (spans) match.spans = text => predicate(text) ? spans(text).slice(0, LIMIT) : [];
  return match;
}
