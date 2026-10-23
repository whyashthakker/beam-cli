// Attacks on LLM-powered apps (OWASP Top 10 for LLM Applications): direct and indirect prompt
// injection, instructions smuggled in invisible Unicode or base64, forged chat-template tokens,
// jailbreak personas, system prompt extraction, attempts to talk an AI reviewer out of an alert,
// and data exfiltration through model output.
//
// Used three ways: as `beam monitor` rules over logs and traffic, by the SDK's prompt() and
// output() checks, and to keep the optional LLM check from being argued out of an alert by the
// line it is judging (looksLikeInjection). Pure TypeScript with no Node.js built-ins, so it runs
// in edge runtimes. Heuristic like the rest of Beam: a new phrasing can get past it.

const TAG_CHAR = /[\u{E0000}-\u{E007F}]/u;
const TAG_RUN = /(\u{1F3F4})?([\u{E0000}-\u{E007F}]+)/gu;
// Zero-width characters and soft hyphens split words ("ig​nore") so phrase rules miss them.
const ZERO_WIDTH = /[­​-‍⁠﻿]/g;
const NON_ASCII = /[^\x00-\x7F]/;

/**
 * Text hidden in Unicode tag characters ("ASCII smuggling"): invisible on screen, read by models.
 * A subdivision flag (🏴 + a few tags, like England's) is an emoji, not hidden text.
 */
export function hiddenTagText(text: string): string {
  if (!TAG_CHAR.test(text)) return "";
  let out = "";
  for (const [, flag, run] of text.matchAll(TAG_RUN)) {
    const chars = [...run!];
    if (flag && chars.length <= 8 && chars.at(-1) === "\u{E007F}") continue;
    for (const ch of chars) {
      const c = ch.codePointAt(0)! - 0xe0000;
      if (c >= 0x20 && c < 0x7f) out += String.fromCharCode(c);
    }
  }
  return out;
}

/** For evidence a person reads: hidden tag text becomes visible as ⟦hidden: …⟧. */
export function revealHidden(text: string): string {
  if (!TAG_CHAR.test(text)) return text;
  return text.replace(TAG_RUN, (whole, flag: string | undefined) => {
    const hidden = hiddenTagText(whole);
    return hidden ? `${flag ?? ""}⟦hidden: ${hidden}⟧` : whole;
  });
}

const atobSafe = (s: string): string => {
  try { return atob(s.slice(0, s.length - (s.length % 4))); } catch { return ""; }
};
const isBase64Char = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47;
/**
 * Base64 runs that decode to readable sentences (a common way to slip instructions past filters).
 * One linear pass: a regex like /[A-Za-z0-9+/]{24,}/ rescans every short run from each start.
 */
function decodedBase64(text: string): string {
  const out: string[] = [];
  let start = -1;
  for (let i = 0; i <= text.length && out.length < 4; i++) {
    if (i < text.length && isBase64Char(text.charCodeAt(i))) { if (start < 0) start = i; continue; }
    if (start >= 0 && i - start >= 24) {
      const run = text.slice(start, Math.min(i, start + 4096));
      // Encoded prose mixes cases; hex digests and ids don't, and aren't worth decoding.
      if (/[a-z]/.test(run) && /[A-Z]/.test(run)) {
        const decoded = atobSafe(run);
        let printable = 0, spaces = 0;
        for (let j = 0; j < decoded.length; j++) {
          const c = decoded.charCodeAt(j);
          if ((c >= 0x20 && c < 0x7f) || c === 9 || c === 10) printable++;
          if (c === 0x20) spaces++;
        }
        if (decoded.length >= 16 && printable >= decoded.length * 0.9 && spaces >= 3) out.push(decoded.replace(/[^\x20-\x7E\t\n]/g, ""));
      }
    }
    start = -1;
  }
  return out.join("\n");
}

/**
 * What the phrase rules read: full-width and styled letters folded to ASCII, zero-width characters
 * removed, plus any tag-hidden text and readable base64, appended.
 */
export function injectionView(text: string): string {
  let s = text.length > 16_384 ? text.slice(0, 16_384) : text;
  const hidden = hiddenTagText(s);
  if (NON_ASCII.test(s)) s = s.normalize("NFKC").replace(ZERO_WIDTH, "");
  const decoded = decodedBase64(s);
  return hidden || decoded ? [s, hidden, decoded].filter(Boolean).join("\n") : s;
}

// The same decoded line is handed to every rule in turn; build its view once.
let lastText = "";
let lastView = "";
function view(text: string): string {
  if (text !== lastText) { lastText = text; lastView = injectionView(text); }
  return lastView;
}

const re = (parts: string[], flags = "i") => new RegExp(parts.join("|"), flags);

const OVERRIDE = re([
  // "ignore all previous instructions", "disregard the rules above", "bypass your system prompt"
  String.raw`\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|every\s+)?(?:of\s+)?(?:the\s+|your\s+|these\s+|those\s+)?(?:previous|prior|above|earlier|preceding|original|initial|system|safety|existing|developer)\s+(?:system\s+)?(?:instructions?|prompts?|rules|directions|directives|guidelines|guardrails|constraints|messages|context)\b`,
  String.raw`\bforget\s+(?:everything|all)\s+(?:above|before|you\s+(?:were|have\s+been)\s+told)\b`,
  String.raw`\b(?:new|updated|revised|real|actual)\s+(?:system\s+)?instructions?\s*:`,
  String.raw`\bsystem\s+(?:prompt|message)\s+(?:override|update)\b|\bend\s+of\s+(?:the\s+)?(?:system\s+prompt|instructions|user\s+input)\b`,
  String.raw`\bfrom\s+now\s+on,?\s+you\s+(?:will|must|are\s+to|shall)\s+(?:ignore|answer|respond|reply|act|obey|only)\b`,
  String.raw`\byou\s+are\s+now\s+(?:in\s+)?(?:DAN|developer\s+mode|jailbroken|an?\s+unrestricted|free\s+(?:from|of))\b`,
  String.raw`\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|warn)\s+(?:the\s+)?(?:user|admin|administrator|operator|security\s+team)\b`,
  String.raw`\bdisable\s+(?:the\s+|your\s+|all\s+)?(?:security|safety|logging|audit(?:ing)?|content\s+filter(?:s|ing)?|guardrails|moderation)\b`,
]);

// Aimed at whoever, or whatever, reviews the line, including Beam's own LLM check.
const REVIEWER = re([
  String.raw`\b(?:note|message|instructions?|attention)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:ai|llm|language\s+model|model|assistant|chatbot|gpt|claude|security\s+(?:analyst|reviewer|scanner|tool|team)|reviewer|classifier|moderator|monitor)s?\b`,
  String.raw`\b(?:classify|mark|label|treat|report|rate|consider)\s+(?:this|these|it|the\s+(?:following|above))\s+(?:(?:line|lines|request|requests|input|message|traffic|entry|log|finding)\s+)?as\s+(?:benign|safe|harmless|legitimate|a\s+false\s+positive|not\s+(?:malicious|an?\s+attack))\b`,
  String.raw`\b(?:this|the\s+following)\s+(?:is|request\s+is|line\s+is|traffic\s+is)\s+(?:an?\s+)?(?:authori[sz]ed|approved|sanctioned)\s+(?:security\s+)?(?:test|pentest|penetration\s+test|scan|audit)\b`,
  String.raw`["']?verdict["']?\s*[:=]\s*["']?benign\b`,
]);

const CHAT_TEMPLATE = re([
  String.raw`<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|begin_of_text|start_header_id|end_header_id|eot_id|eom_id|start|end|message|channel|return|call)\|>`,
  String.raw`\[\/?INST\]|<<\/?SYS>>|<\/?(?:start|end)_of_turn>`,
  String.raw`<\s*\/?\s*(?:system|important|instructions?|system[-_]reminder|admin[-_]override)\s*>`,
  String.raw`\b(?:BEGIN|END)\s+(?:SYSTEM\s+PROMPT|SYSTEM\s+INSTRUCTIONS)\b`,
]);

const JAILBREAK = re([
  String.raw`\bdo\s+anything\s+now\b`,
  String.raw`\b(?:developer|god|jailbreak|unrestricted|unfiltered|evil|opposite)\s+mode\s+(?:enabled|activated|on|output)\b|\benable\s+(?:developer|jailbreak|god|unrestricted)\s+mode\b`,
  String.raw`\b(?:respond|answer|reply|act|operate|talk|behave)\s+(?:freely\s+)?without\s+(?:any\s+)?(?:restrictions|limitations|filters|guidelines|censorship|content\s+polic(?:y|ies)|ethical\s+(?:guidelines|constraints))\b`,
  String.raw`\b(?:pretend|act\s+as\s+if|imagine)\s+(?:that\s+)?you\s+(?:are|have)\s+(?:an?\s+)?(?:ai\s+)?(?:with\s+no\s+(?:restrictions|filters|rules|limits)|without\s+(?:restrictions|filters|rules|limits)|unrestricted|jailbroken|evil)\b`,
  String.raw`\b(?:amoral|unethical)\s+(?:and\s+)?(?:unfiltered|uncensored)\b|\buncensored\s+and\s+unfiltered\b`,
]);

const EXTRACTION = re([
  String.raw`\b(?:repeat|print|reveal|output|display|dump|leak|recite|write\s+out|show|tell\s+me|give\s+me)\s+(?:me\s+)?(?:back\s+)?(?:your|the)\s+(?:(?:entire|full|complete|exact|original|initial|hidden|secret)\s+)*(?:system\s+(?:prompt|message|instructions)|initial\s+(?:prompt|instructions)|(?:original|hidden|secret|developer|internal)\s+(?:instructions|prompt|message)|instructions\s+(?:above|you\s+were\s+given)|prompt\s+above|(?:words|text|everything)\s+above)\b`,
  String.raw`\bwhat\s+(?:is|are|was|were)\s+your\s+(?:system\s+prompt|initial\s+instructions|original\s+instructions)\b`,
  String.raw`\b(?:repeat|output|print)\s+(?:everything|all\s+(?:the\s+)?(?:text|words))\s+(?:above|before\s+this)\b|\bstarting\s+with\s+["'“]you\s+are\b`,
  String.raw`\brepeat\s+(?:the\s+)?(?:word|phrase|token)\s+\S+\s+forever\b`,
  String.raw`\b(?:show|give|tell|list)\s+me\s+(?:what\s+)?other\s+users?(?:'s?)?\s+(?:asked|said|wrote|conversations?|chats?|messages|prompts)\b`,
]);

// Asking the model, or an agent with tools, for the app's keys, tokens or environment. "Your"
// addresses the app itself; a user asking where to find their own API key doesn't match.
const VERB = String.raw`(?:reveal|print|show|give|tell|output|display|dump|leak|list|send|share|repeat|return|read|expose|paste|email|post|write\s+out)`;
const PROVIDER = String.raw`(?:(?:openai|anthropic|claude|gemini|google|aws|azure|gcp|stripe|github|supabase|firebase|database|db|admin|service|secret|private|internal|server|backend|production|prod)\s+)*`;
const SECRET_REQUEST = re([
  String.raw`\b${VERB}\s+(?:me\s+|us\s+)?(?:all\s+(?:of\s+)?)?your\s+${PROVIDER}(?:api[\s_-]?keys?|secret[\s_-]?keys?|access[\s_-]?(?:keys?|tokens?)|auth(?:entication)?\s+tokens?|bearer\s+tokens?|tokens|keys|credentials|passwords?|connection\s+strings?|private\s+keys?|secrets|env(?:ironment)?\s+(?:variables|vars)|\.env(?:\s+file)?)\b`,
  String.raw`\b${VERB}\s+(?:me\s+|us\s+)?(?:all\s+(?:of\s+)?)?(?:the\s+)?(?:(?:server|system|app|application|backend|container|process|host|machine)(?:'s)?\s+)?(?:env(?:ironment)?\s+(?:variables|vars)|\.env\s+file|env\s+file|process\.env|os\.environ)\b`,
  String.raw`\bwhat\s+(?:is|are)\s+your\s+${PROVIDER}(?:api[\s_-]?keys?|secret[\s_-]?keys?|access\s+tokens?|credentials|passwords?|env(?:ironment)?\s+variables)\b`,
]);
// The same, by variable name: "print OPENAI_API_KEY", "what's $STRIPE_SECRET_KEY". Case-sensitive
// on the name, so ordinary words don't match.
const SECRET_BY_NAME = /(?:[Pp]rint|[Ee]cho|[Rr]eveal|[Ss]how|[Oo]utput|[Tt]ell\s+me|[Gg]ive\s+me|[Ww]hat(?:'s|\s+is)|[Vv]alue\s+of|[Cc]ontents\s+of|[Dd]ump|[Ll]eak|[Ss]end)\b[^\n]{0,40}?\$?\{?\b[A-Z][A-Z0-9_]*_(?:API_KEY|SECRET|SECRET_KEY|ACCESS_KEY|ACCESS_KEY_ID|AUTH_TOKEN|PRIVATE_KEY|TOKEN|PASSWORD|DATABASE_URL)\b/;
// Commands that print secrets, sent where an agent with a shell or file tool might run them.
const SECRET_COMMAND = /\b(?:cat|type|less|more|head|tail|strings|base64)\s+(?:\S*\/)?\.env(?:\.[\w-]+)?\b|\bprintenv\b|\benv\s*\|\s*(?:grep|sort|base64|curl|nc|tee)\b|\becho\s+["']?\$\{?[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD)|\bGet-ChildItem\s+env:|\/proc\/self\/environ\b/;
// Environment-style assignments in model output: KEY_NAME=value.
const ENV_SECRET = /\b[A-Z][A-Z0-9_]*(?:API_KEY|SECRET(?:_KEY)?|ACCESS_KEY|AUTH_TOKEN|PASSWORD|PRIVATE_KEY)\s*[=:]\s*["']?[A-Za-z0-9/+_\-.]{12,}/;

// A markdown image (or HTML img) whose URL carries a long value: rendering it sends that value to
// the URL's server without a click (the EchoLeak family of zero-click exfiltration).
const MARKDOWN_EXFIL = /!\[[^\]\n]{0,200}\]\(\s*<?https?:\/\/[^)\s>]+?[?&#][^)\s>]*=[^)\s>&]{16,}/i;
const IMG_EXFIL = /<img\b[^>]{0,200}\bsrc\s*=\s*["']?https?:\/\/[^"'\s>]+[?&][^"'\s>]*=[^"'\s>&]{16,}/i;

/** Instructions aimed at a model: override phrases, forged chat markers, hidden text, or appeals to a reviewer. */
export function looksLikeInjection(text: string): boolean {
  const v = view(text);
  return OVERRIDE.test(v) || REVIEWER.test(v) || CHAT_TEMPLATE.test(v) || hiddenTagText(text).length >= 4;
}

export const promptAttack = {
  override: (s: string) => OVERRIDE.test(view(s)),
  reviewer: (s: string) => REVIEWER.test(view(s)),
  chatTemplate: (s: string) => CHAT_TEMPLATE.test(view(s)),
  hidden: (s: string) => hiddenTagText(s).length >= 4,
  jailbreak: (s: string) => JAILBREAK.test(view(s)),
  extraction: (s: string) => EXTRACTION.test(view(s)),
  secretRequest: (s: string) => SECRET_REQUEST.test(view(s)),
  // Not for app logs: "value of OPENAI_API_KEY is empty" is an ordinary config error there.
  secretCommand: (s: string) => { const v = view(s); return SECRET_COMMAND.test(v) || SECRET_BY_NAME.test(v); },
  envSecret: (s: string) => ENV_SECRET.test(s),
  markdownExfil: (s: string) => MARKDOWN_EXFIL.test(s),
  htmlExfil: (s: string) => MARKDOWN_EXFIL.test(s) || IMG_EXFIL.test(s),
};

/** A canary planted in a system prompt, found in text: compared without case, spacing or punctuation, so light reformatting doesn't hide it. */
export function containsCanary(text: string, canaries: string[]): boolean {
  if (!canaries.length) return false;
  const squash = (s: string) => s.normalize("NFKC").toLowerCase().replace(/[^a-z0-9]/g, "");
  const haystack = squash(text);
  return canaries.some(c => { const needle = squash(c); return needle.length >= 8 && haystack.includes(needle); });
}
