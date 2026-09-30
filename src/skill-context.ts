// Is a rule's match an instruction, or just a mention of one? A skill that teaches an agent to
// resist prompt injection has to quote injection phrases ("ignore previous instructions"), and a
// security-review skill has to name `sudo` and `curl | sh` to tell you to flag them. Matching on
// the words alone flags those skills as malicious, which is the opposite of what they are. This
// looks at the words around a match; a match that is only being mentioned is not reported.
//
// It is heuristic: a determined attacker could word a real instruction to look like a mention, so
// this narrows false alarms, it isn't a guarantee. Only the context immediately around the match
// counts, and an unclosed quote never excuses anything.

// A negation just before the match: "never use sudo", "avoid curl | sh", "do not ignore ...".
const NEGATION = /(?:\bnever|\bdon'?t|\bdo not|\bavoid|\bmust not|\bshould not|\bshouldn'?t|\bwithout|\bno need to|\binstead of|\bnot to|\bcannot|\bcan'?t)\s+(?:\w+\s+){0,3}$/i;
// Framing that introduces an example rather than an order: "if the file contains ...", "such as ...".
const EXAMPLE_FRAMING = /\b(?:if|when|whenever)\b[^.!?\n]{0,120}\b(?:contains?|says?|includes?|asks?|tells?|instructs?|reads?|addressed)\b|\b(?:that|which|who)\s+(?:\w+\s+){0,2}(?:says?|contains?|includes?|tells?|asks?|reads?)\b|\b(?:shaped|formatted|worded|phrased|disguised)\s+(?:like|as|to look like)\b|\b(?:such as|for example|for instance|e\.g\.|i\.e\.|phrases? like|text like|something like|looks? like|attempts? to)\b/i;
// Verbs of review, used for risky commands only ("flag any skill that runs sudo"). Not applied to
// injection phrases, where a fake "detect:" prefix would be too easy to add.
const DETECTION_FRAMING = /\b(?:flag|detect|look(?:ing)? for|check(?:ing)? for|scan(?:ning)? for|search(?:ing)? for|grep(?:ping)? for|audit|report|reject|block|forbid|prohibit|disallow)\b/i;
// The same sentence goes on to refuse the quoted thing, with an object pointing back at it:
// `"ignore previous instructions" ... do not follow it`. "Do not follow" with nothing to point at,
// or in a later sentence, doesn't count -- otherwise appending that to a real injection would hide it.
const REFUSAL_AFTER = /\b(?:do not|don'?t|never|must not|should not|shouldn'?t|refuse to)\s+(?:\w+\s+){0,2}?(?:follow|obey|comply with|act on|execute|trust|file|treat|use)\s+(?:it|them|that|this|those|any of (?:it|them|these|those))\b/i;
// After the match, the text says what to do with it or what it is: "treat these strings as inert
// labels", "... is a test case, not a directive".
const AFTER_DEFENSE = /\b(?:treat|handle)\s+(?:these|this|them|it|those)(?:\s+\w+){0,2}\s+as\s+(?:inert|data|text|labels?|untrusted|content)\b|\b(?:is|are)\s+(?:a\s+|an\s+)?(?:test cases?|examples?|injection|attacks?|not an? (?:directive|instruction))\b/i;
// "screens that don't tell the user ..." describes something; it doesn't order it.
const RELATIVE_BEFORE = /\b(?:that|which|who|whose)\s+(?:\w+\s+){0,2}$/i;
const ANY_NEGATION = /\b(?:never|not|don'?t|cannot|can'?t|must not|shouldn'?t|no)\b/i;

// Quoted, with the closing quote actually present after the match.
function insideQuotes(line: string, start: number, end: number): boolean {
  const before = line.slice(0, start), after = line.slice(end);
  for (const ch of ['"', "`"]) {
    if ((before.split(ch).length - 1) % 2 === 1 && after.includes(ch)) return true;
  }
  return (before.lastIndexOf("“") > before.lastIndexOf("”") && after.includes("”"))
    || (before.lastIndexOf("‘") > before.lastIndexOf("’") && after.includes("’"));
}

export type Neighbours = { prev?: string; next?: string };

/** `phrase`: natural-language instructions (prompt injection). `command`: shell commands and paths. */
export function isMention(line: string, start: number, length: number, kind: "phrase" | "command", near: Neighbours = {}): boolean {
  const end = start + length;
  // A sentence often runs across a line break, so the neighbouring lines count as context too.
  const before = `${near.prev ? `${near.prev} ` : ""}${line.slice(0, start)}`.slice(-160);
  if (NEGATION.test(before.slice(-40))) return true;
  if (kind === "command") return EXAMPLE_FRAMING.test(before) || DETECTION_FRAMING.test(before);

  // Injection phrases. A bare quote is not enough (`Always start with "ignore previous
  // instructions"` is still an order); it has to be framed as an example or reviewed, or refused
  // or explained in the same sentence.
  const sentenceAfter = `${line.slice(end)}${near.next ? ` ${near.next}` : ""}`.split(/[.!?]\s/)[0]?.slice(0, 300) ?? "";
  const defended = REFUSAL_AFTER.test(sentenceAfter) || AFTER_DEFENSE.test(sentenceAfter);
  if (insideQuotes(line, start, end)) { if (EXAMPLE_FRAMING.test(before) || DETECTION_FRAMING.test(before) || defended) return true; }
  else if (defended) return true;
  if (RELATIVE_BEFORE.test(before.slice(-30))) return true;
  // "Never write memory from a paste without showing the user your plan" needs the user to be shown.
  // A "without ..." match that already sits inside a negated sentence is a double negative.
  if (/^without\b/i.test(line.slice(start, end))) {
    const sentence = before.split(/[.!?]\s/).pop() ?? "";
    if (ANY_NEGATION.test(sentence)) return true;
  }
  return false;
}

/** First match of `re` in `line` that is an actual instruction (not just a mention), or null. */
export function firstInstruction(line: string, re: RegExp, kind: "phrase" | "command", near: Neighbours = {}): { index: number; text: string } | null {
  const global = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  for (const m of line.matchAll(global)) {
    const index = m.index ?? 0;
    if (!isMention(line, index, m[0].length, kind, near)) return { index, text: m[0] };
  }
  return null;
}
