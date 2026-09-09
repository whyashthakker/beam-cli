import { describe, expect, it } from "@jest/globals";
import { studioPage } from "../src/studio.js";

function extractScript(html: string): string {
  const start = html.indexOf("<script>") + "<script>".length;
  const end = html.indexOf("</script>");
  if (start < 0 || end < 0) throw new Error("studio page has no inline <script> block");
  return html.slice(start, end);
}

describe("studio page", () => {
  it("serves a well-formed HTML document", () => {
    const html = studioPage();
    expect(html).toMatch(/^<!doctype html>/i);
    expect(html).toContain("<title>beam studio</title>");
  });

  it("has no stray escaped quotes from template-literal authoring mistakes", () => {
    expect(studioPage()).not.toMatch(/\\"/);
  });

  // The most important check: the embedded <script> must actually be valid JavaScript.
  // `new Function(...)` compiles (and thus syntax-checks) the source without executing it,
  // so this catches quote-escaping mistakes even though there's no DOM/browser in this test env.
  it("embeds syntactically valid JavaScript", () => {
    const script = extractScript(studioPage());
    expect(() => new Function(script)).not.toThrow();
  });
});

// Minimal fake DOM: no jsdom dependency, just enough for the studio script's actual code paths
// (connect/disconnect/token persistence) to run without throwing. Element lookups are lazy and
// generic -- any id/selector returns a reusable stub with style/value/innerHTML/addEventListener/
// classList, which is enough since this harness doesn't assert on rendered markup, only on
// localStorage + which handlers ran.
function fakeElement(): any {
  const listeners: Record<string, ((e: unknown) => void)[]> = {};
  return {
    style: {}, value: "", innerHTML: "", textContent: "",
    addEventListener(type: string, fn: (e: unknown) => void) { (listeners[type] ??= []).push(fn); },
    classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
    setAttribute() {}, getAttribute: () => null, click() { (listeners.click ?? []).forEach(fn => fn({})); },
  };
}

function fakeLocalStorage() {
  const store = new Map<string, string>();
  return {
    setItem: (k: string, v: string) => { store.set(k, v); },
    getItem: (k: string) => store.get(k) ?? null,
    removeItem: (k: string) => { store.delete(k); },
    _dump: () => Object.fromEntries(store),
  };
}

async function runStudioScript(opts: { search?: string; localStorage: ReturnType<typeof fakeLocalStorage>; fetchOk?: boolean }) {
  const script = extractScript(studioPage());
  const elements = new Map<string, ReturnType<typeof fakeElement>>();
  const document = {
    getElementById(id: string) { if (!elements.has(id)) elements.set(id, fakeElement()); return elements.get(id); },
    querySelectorAll: () => [],
  };
  const window = { location: { origin: "http://127.0.0.1:4319", search: opts.search ?? "", pathname: "/" } };
  const history = { replaceState() {} };
  const fetchCalls: string[] = [];
  const fetch = async (url: string) => {
    fetchCalls.push(url);
    if (opts.fetchOk === false) return { ok: false, json: async () => ({ error: "Pairing token is missing or incorrect." }) };
    return { ok: true, json: async () => ({ events: [], scans: [], reviews: {}, retention: 10000 }) };
  };
  // Stub timers so connect()'s setInterval(poll, 3000) never creates a real, uncleared timer --
  // otherwise every test leaves the Jest worker process alive indefinitely.
  const run = new Function("document", "window", "localStorage", "fetch", "history", "setInterval", "clearInterval", script);
  run(document, window, opts.localStorage, fetch, history, () => 0, () => {});
  // Let the fetch().then() microtask chain (connect's promise handling) resolve. The error path
  // has an extra .then() hop (res.json() before throwing), so flush more than the success path needs.
  for (let i = 0; i < 6; i++) await Promise.resolve();
  return { elements, fetchCalls };
}

describe("studio token persistence", () => {
  it("saves the token to localStorage after a successful connect via the URL param", async () => {
    var storage = fakeLocalStorage();
    await runStudioScript({ search: "?token=abc123", localStorage: storage });
    expect(storage._dump()).toEqual({ "beam-studio-token": "abc123" });
  });

  it("auto-reconnects from a previously stored token when no URL param is present", async () => {
    var storage = fakeLocalStorage();
    storage.setItem("beam-studio-token", "stored-token");
    const { fetchCalls } = await runStudioScript({ localStorage: storage });
    expect(fetchCalls.some(u => u.endsWith("/state"))).toBe(true);
    expect(storage.getItem("beam-studio-token")).toBe("stored-token");
  });

  it("clears the stored token when the collector rejects it (not just unreachable)", async () => {
    var storage = fakeLocalStorage();
    storage.setItem("beam-studio-token", "now-invalid");
    await runStudioScript({ localStorage: storage, fetchOk: false });
    expect(storage.getItem("beam-studio-token")).toBeNull();
  });

  it("does not touch localStorage when there is no token to connect with at all", async () => {
    var storage = fakeLocalStorage();
    await runStudioScript({ localStorage: storage });
    expect(storage._dump()).toEqual({});
  });
});
