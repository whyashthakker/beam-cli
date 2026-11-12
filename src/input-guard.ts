// Keystroke-level preprocessing for `beam claude`. Sits between the terminal and Claude Code's
// pseudo-terminal and rewrites sensitive values in what you type or paste into vault placeholders
// BEFORE Claude Code receives the submitted prompt -- the one thing a UserPromptSubmit hook can't do.
//
// Bytes are forwarded verbatim except in two cases:
//   * a bracketed paste (ESC[200~ ... ESC[201~) is held until it ends, then forwarded either
//     unchanged or with sensitive values replaced;
//   * on Enter, if the typed line (tracked in a shadow buffer) holds a sensitive value, the line is
//     cleared (Ctrl-U) and retyped with placeholders before Enter is forwarded.
// Typing is best-effort: the shadow buffer follows printable characters, Backspace, Ctrl-U and
// Ctrl-C. Anything that moves the cursor or edits mid-line (arrows, Home/End, Ctrl-A/E/W/K,
// multi-line input) marks the line "uncertain", and Beam then forwards it untouched rather than guess
// -- the UserPromptSubmit hook still blocks it as the backstop.
import { StringDecoder } from "node:string_decoder";

export interface Rewrite { replacement: string; summary: string }
export type Inspect = (text: string) => Promise<Rewrite | null>;

const PASTE_START = "\x1b[200~";
const PASTE_END = "\x1b[201~";
const CLEAR_LINE = "\x15";
const PASTE_TIMEOUT_MS = 3000;

type State = "normal" | "esc" | "csi" | "osc" | "oscEsc" | "ss3" | "paste";

export class InputGuard {
  private state: State = "normal";
  private seq = "";
  private buffer = "";
  private uncertain = false;
  private multiline = false;
  private seqStartedAt = 0;
  private paste = "";
  private pasteStartedAt = 0;
  private readonly decoder = new StringDecoder("utf8");
  /** Number of prompts/pastes rewritten, for the wrapper's own status. */
  rewrites = 0;

  constructor(private readonly inspect: Inspect) {}

  private reset(): void { this.buffer = ""; this.uncertain = false; this.multiline = false; }

  /** Feed raw terminal bytes; resolves to the bytes to forward to Claude Code. Call sequentially. */
  async feed(chunk: Buffer | string): Promise<string> {
    const text = typeof chunk === "string" ? chunk : this.decoder.write(chunk);
    let out = "";
    for (const ch of text) out += await this.step(ch);
    return out;
  }

  /** A paste whose end marker never arrived: finish it so nothing stays held (and scanned either way). */
  async flushStalePaste(now = Date.now()): Promise<string> {
    if (this.state !== "paste" || now - this.pasteStartedAt < PASTE_TIMEOUT_MS) return "";
    return this.finishPaste();
  }

  private async finishPaste(): Promise<string> {
    const content = this.paste; this.paste = ""; this.state = "normal";
    const rewrite = await this.inspect(content);
    const body = rewrite ? rewrite.replacement : content;
    if (rewrite) this.rewrites++;
    if (/[\r\n]/.test(body)) this.multiline = true;
    this.buffer += body;
    return PASTE_START + body + PASTE_END;
  }

  private async step(ch: string): Promise<string> {
    switch (this.state) {
      case "paste": {
        this.paste += ch;
        if (this.paste.endsWith(PASTE_END)) { this.paste = this.paste.slice(0, -PASTE_END.length); return this.finishPaste(); }
        return "";
      }
      // Escape sequences are held until they complete so a paste-start marker is recognised before any
      // of it is forwarded. flushPendingEscape() releases a held lone Escape keypress.
      case "esc": {
        this.seq += ch;
        if (ch === "[") { this.state = "csi"; return ""; }
        if (ch === "]") { this.state = "osc"; return ""; }
        if (ch === "O") { this.state = "ss3"; return ""; }
        if (ch === "\r") this.multiline = true; // Alt/Shift+Enter inserts a newline
        return this.releaseSeq();
      }
      case "csi": {
        this.seq += ch;
        const code = ch.charCodeAt(0);
        if (code < 0x40 || code > 0x7e) return ""; // parameter / intermediate byte
        if (this.seq === PASTE_START) { this.seq = ""; this.state = "paste"; this.paste = ""; this.pasteStartedAt = Date.now(); return ""; }
        if (/[ABCDHF~]$/.test(this.seq)) this.uncertain = true; // arrows, Home/End, Delete/PgUp/PgDn
        return this.releaseSeq();
      }
      case "ss3": {
        this.seq += ch;
        if (/[ABCDHF]/.test(ch)) this.uncertain = true;
        return this.releaseSeq();
      }
      case "osc": {
        this.seq += ch;
        if (ch === "\x07") return this.releaseSeq();
        if (ch === "\x1b") this.state = "oscEsc";
        return "";
      }
      case "oscEsc": { this.seq += ch; return this.releaseSeq(); }
      default: return this.normal(ch);
    }
  }

  private releaseSeq(): string { const seq = this.seq; this.seq = ""; this.state = "normal"; return seq; }
  /** Release a held, incomplete escape sequence (a lone Escape keypress, or a sequence split across reads). */
  flushPendingEscape(): string {
    if (this.state === "normal" || this.state === "paste") return "";
    return this.releaseSeq();
  }
  get hasPendingEscape(): boolean { return this.state !== "normal" && this.state !== "paste"; }

  private async normal(ch: string): Promise<string> {
    if (ch === "\x1b") { this.state = "esc"; this.seq = ch; this.seqStartedAt = Date.now(); return ""; }
    if (ch === "\r") return this.enter();
    if (ch === "\n") { this.multiline = true; return ch; }
    if (ch === "\x7f" || ch === "\b") { this.buffer = [...this.buffer].slice(0, -1).join(""); return ch; }
    if (ch === "\x15" || ch === "\x03") { this.reset(); return ch; } // Ctrl-U / Ctrl-C clear the line
    if (ch === "\x01" || ch === "\x05" || ch === "\x0b" || ch === "\x17" || ch === "\x02" || ch === "\x06") { this.uncertain = true; return ch; }
    if (ch < " ") return ch; // other control characters don't change the line text
    this.buffer += ch;
    return ch;
  }

  private async enter(): Promise<string> {
    const line = this.buffer;
    const safe = !this.uncertain && !this.multiline && line.length > 0;
    this.reset();
    if (safe) {
      const rewrite = await this.inspect(line);
      if (rewrite) {
        this.rewrites++;
        // Clear what was typed into Claude Code's input box and retype it with placeholders.
        return CLEAR_LINE + rewrite.replacement + "\r";
      }
    }
    return "\r";
  }
}
