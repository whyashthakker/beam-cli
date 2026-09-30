import { mkdir, readdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { getDataDirectory } from "./config.js";
import { redact } from "./core.js";

// A session's title is decided once, on the device, and never recomputed per event:
//   1. the first prompt of a session, trimmed and redacted, becomes the title straight away;
//   2. Claude Code / Codex write their own title a moment later -- if one shows up it replaces the
//      prompt title exactly once, then the title is locked.
// Everything here is plain string/file work -- no model call, so it never spends the user's tokens.
// Set BEAM_SESSION_TITLES=off to stop titles (and so any prompt text) leaving the machine.

const TITLE_MAX = 80;
const AGENT_TITLE_ATTEMPTS = 3;
const MAX_TRANSCRIPT_BYTES = 20_000_000;
const MAX_TRACKED_SESSIONS = 200;
const STATE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

type TitleEntry = {
  title: string; source: "prompt" | "agent"; attempts: number; ts: number;
  // Per-turn tracking: one turn per user prompt. `topic` is the latest substantive prompt.
  turn: number; topic: string; shift: boolean; cwd: string; recent: string[];
};
export type SessionContext = { title: string; titleSource: "prompt" | "agent"; turn: number; topic: string; shift: boolean };
type TitleState = Record<string, TitleEntry>;

export function sessionTitlesEnabled(): boolean {
  return !/^(off|0|false|no)$/i.test(process.env.BEAM_SESSION_TITLES ?? "");
}

/** First line of the prompt, secrets redacted, whitespace collapsed, capped at TITLE_MAX. */
export function titleFromPrompt(prompt: string): string {
  const firstLine = prompt
    .replace(/<[^>\n]+>[\s\S]*?<\/[^>\n]+>/g, " ") // injected wrappers like <timestamp>...</timestamp>
    .split(/\r?\n/)
    .map(line => line.trim())
    .find(line => line.length > 0) ?? "";
  const clean = redact(firstLine).replace(/\s+/g, " ").trim();
  return clean.length > TITLE_MAX ? `${clean.slice(0, TITLE_MAX - 1).trimEnd()}…` : clean;
}

function statePath(): string { return join(getDataDirectory(), "session-titles.json"); }

async function loadState(): Promise<TitleState> {
  try { return JSON.parse(await readFile(statePath(), "utf8")) as TitleState; }
  catch { return {}; }
}

async function saveState(state: TitleState): Promise<void> {
  try {
    const cutoff = Date.now() - STATE_TTL_MS;
    const kept = Object.entries(state)
      .filter(([, entry]) => entry.ts >= cutoff)
      .sort((a, b) => b[1].ts - a[1].ts)
      .slice(0, MAX_TRACKED_SESSIONS);
    const dir = getDataDirectory();
    await mkdir(dir, { recursive: true });
    const target = statePath();
    const temp = `${target}.${process.pid}.tmp`;
    await writeFile(temp, JSON.stringify(Object.fromEntries(kept)), { mode: 0o600 });
    await rename(temp, target);
  } catch { /* best-effort enrichment only */ }
}

// Claude Code appends {"type":"ai-title","aiTitle":"...","sessionId":"..."} to the session transcript.
async function claudeCodeTitle(home: string, sessionId: string, transcriptPath?: string): Promise<string> {
  const candidates: string[] = [];
  if (transcriptPath) candidates.push(transcriptPath);
  else {
    const projectsDir = join(home, ".claude", "projects");
    let dirs: string[] = [];
    try { dirs = await readdir(projectsDir); } catch { return ""; }
    for (const dir of dirs) candidates.push(join(projectsDir, dir, `${sessionId}.jsonl`));
  }
  for (const file of candidates) {
    try {
      if ((await stat(file)).size > MAX_TRANSCRIPT_BYTES) continue;
      const content = await readFile(file, "utf8");
      const at = content.lastIndexOf('"type":"ai-title"');
      if (at < 0) return "";
      const lineStart = content.lastIndexOf("\n", at) + 1;
      const lineEnd = content.indexOf("\n", at);
      const row = JSON.parse(content.slice(lineStart, lineEnd < 0 ? undefined : lineEnd)) as { aiTitle?: unknown };
      return typeof row.aiTitle === "string" ? row.aiTitle : "";
    } catch { continue; }
  }
  return "";
}

// Codex keeps {"id":"<session id>","thread_name":"..."} lines in ~/.codex/session_index.jsonl.
async function codexTitle(home: string, sessionId: string): Promise<string> {
  try {
    const lines = (await readFile(join(home, ".codex", "session_index.jsonl"), "utf8")).split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      if (!lines[i].includes(sessionId)) continue;
      const row = JSON.parse(lines[i]) as { id?: unknown; thread_name?: unknown };
      if (row.id === sessionId && typeof row.thread_name === "string") return row.thread_name;
    }
  } catch { /* no index yet */ }
  return "";
}

async function agentTitle(agent: string, home: string, sessionId: string, transcriptPath?: string): Promise<string> {
  const raw = agent === "claude-code" ? await claudeCodeTitle(home, sessionId, transcriptPath)
    : agent === "codex" ? await codexTitle(home, sessionId)
    : "";
  return raw ? titleFromPrompt(raw) : "";
}

const STOPWORDS = new Set(["the", "and", "for", "that", "this", "with", "from", "have", "what", "when", "where", "which", "into", "can", "you", "please", "also", "then", "them", "they", "just", "will", "would", "should", "could", "about", "there", "here", "yes", "not", "but", "are", "was", "how", "why", "now"]);
const RECENT_TOPICS = 3;
const MIN_TOPIC_WORDS = 3;
const SHIFT_OVERLAP = 0.15;

function words(text: string): string[] {
  return [...new Set(text.toLowerCase().match(/[a-z0-9_.\/-]{4,}/g)?.filter(w => !STOPWORDS.has(w)) ?? [])];
}

// Word overlap against the last few topics -- a cheap local check, no model. Short follow-ups
// ("yes", "continue", "run the tests") carry too little signal to move the topic or flag a shift.
function isTopicShift(topic: string, recent: string[]): boolean {
  const next = words(topic);
  if (next.length < MIN_TOPIC_WORDS - 1 || !recent.length) return false;
  const previous = new Set(recent.flatMap(words));
  if (!previous.size) return false;
  const shared = next.filter(w => previous.has(w)).length;
  return shared / Math.min(next.length, previous.size) < SHIFT_OVERLAP;
}

/**
 * Called for a prompt.submit event, before the prompt is stripped. The first prompt fixes the
 * session title (never changed by later prompts); every prompt starts a new turn and, when it is
 * substantive, becomes the "now working on" topic and is checked for a topic/directory shift.
 */
export async function notePrompt(sessionId: string, prompt: string, cwd = ""): Promise<void> {
  if (!sessionId || !prompt) return;
  const topic = titleFromPrompt(prompt);
  if (!topic) return;
  const state = await loadState();
  const entry = state[sessionId];
  if (!entry) {
    state[sessionId] = { title: topic, source: "prompt", attempts: 0, ts: Date.now(), turn: 1, topic, shift: false, cwd, recent: [topic] };
  } else {
    const substantive = words(topic).length >= MIN_TOPIC_WORDS - 1;
    const cwdChanged = Boolean(cwd && entry.cwd && cwd !== entry.cwd);
    entry.turn = (entry.turn ?? 1) + 1;
    entry.ts = Date.now();
    entry.shift = cwdChanged || (substantive && isTopicShift(topic, entry.recent ?? []));
    if (substantive) {
      entry.topic = topic;
      entry.recent = [...(entry.recent ?? []), topic].slice(-RECENT_TOPICS);
    }
    if (cwd) entry.cwd = cwd;
  }
  await saveState(state);
}

/**
 * The locked title plus the current turn for a session, or null if none is known yet. A prompt-derived title gets a few
 * chances (AGENT_TITLE_ATTEMPTS) to be replaced by the agent's own title; after that, or once an
 * agent title is in, the answer comes straight from the small local state file.
 */
export async function sessionContextFor(
  agent: string,
  sessionId: string,
  options: { home?: string; transcriptPath?: string } = {},
): Promise<SessionContext | null> {
  if (!sessionId) return null;
  const state = await loadState();
  const entry = state[sessionId];
  if (!entry) return null;
  if (entry.source === "prompt" && entry.attempts < AGENT_TITLE_ATTEMPTS) {
    const found = await agentTitle(agent, options.home ?? homedir(), sessionId, options.transcriptPath);
    entry.attempts += 1;
    if (found) { entry.title = found; entry.source = "agent"; }
    await saveState(state);
  }
  return { title: entry.title, titleSource: entry.source, turn: entry.turn ?? 1, topic: entry.topic ?? entry.title, shift: Boolean(entry.shift) };
}
