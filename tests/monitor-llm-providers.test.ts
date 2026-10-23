import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { describeOwnLlm, detectedLlmKeys, judgeWithOwnLlm, ownLlmConfig } from "../src/monitor-llm.js";
import type { MonitorFinding } from "../src/monitor-client.js";

const finding = (id: string): MonitorFinding =>
  ({ id, ruleId: "web.sql_injection", title: "SQL injection attempt", severity: "high", source: "http", evidence: `GET /?id=${id} UNION SELECT 1`, count: 1, firstSeen: "2026-10-23T10:00:00Z" });
const checkIn = (system: string) => system.match(/"check": "(\w+)"/)?.[1];

describe("choosing your own LLM provider", () => {
  it("uses the key you already have, but only once you pick the provider", () => {
    const env = { OPENAI_API_KEY: "sk-mine", ANTHROPIC_API_KEY: "sk-ant-mine" };
    expect(ownLlmConfig(env)).toBeNull(); // a key in the environment alone changes nothing
    expect(detectedLlmKeys(env)).toEqual([{ provider: "openai", variable: "OPENAI_API_KEY" }, { provider: "anthropic", variable: "ANTHROPIC_API_KEY" }]);
    const openai = ownLlmConfig(env, "openai")!;
    expect(openai).toMatchObject({ provider: "openai", baseUrl: "https://api.openai.com/v1", model: "gpt-4.1-nano", apiKey: "sk-mine", keySource: "OPENAI_API_KEY" });
    expect(describeOwnLlm(openai)).toBe("your own OpenAI with your key from OPENAI_API_KEY: gpt-4.1-nano at api.openai.com");
    expect(describeOwnLlm(openai)).not.toContain("sk-mine");
    expect(ownLlmConfig({ ...env, BEAM_LLM_PROVIDER: "anthropic" })).toMatchObject({ provider: "anthropic", api: "anthropic", model: "claude-opus-5-5", keySource: "ANTHROPIC_API_KEY" });
    expect(ownLlmConfig({ ...env, BEAM_LLM_PROVIDER: "anthropic" }, "beam")).toBeNull(); // --llm beam wins
    expect(ownLlmConfig({ GROQ_API_KEY: "gsk", BEAM_LLM_MODEL: "openai/gpt-oss-120b" }, "groq")).toMatchObject({ model: "openai/gpt-oss-120b", baseUrl: "https://api.groq.com/openai/v1" });
    expect(ownLlmConfig({ OPENAI_API_KEY: "sk-mine", BEAM_LLM_API_KEY: "sk-other" }, "openai")).toMatchObject({ apiKey: "sk-other", keySource: "BEAM_LLM_API_KEY" });
  });
  it("explains what's missing instead of guessing", () => {
    expect(() => ownLlmConfig({}, "openai")).toThrow("set OPENAI_API_KEY");
    expect(() => ownLlmConfig({ GEMINI_API_KEY: "g" }, "gemini")).toThrow("Set BEAM_LLM_MODEL");
    expect(() => ownLlmConfig({}, "ollama")).toThrow("Set BEAM_LLM_MODEL");
    expect(ownLlmConfig({ BEAM_LLM_MODEL: "llama3.2" }, "ollama")).toMatchObject({ baseUrl: "http://localhost:11434/v1", apiKey: undefined });
    expect(() => ownLlmConfig({}, "custom")).toThrow("BEAM_LLM_BASE_URL");
    expect(() => ownLlmConfig({}, "chatgpt")).toThrow('Unknown LLM provider "chatgpt"');
    expect(ownLlmConfig({}, "anthropic")).toMatchObject({ keySource: "your Anthropic credentials", apiKey: undefined });
  });
  it("won't send a key over plain HTTP to a public host", () => {
    const custom = (url: string, extra = {}) => ownLlmConfig({ BEAM_LLM_BASE_URL: url, BEAM_LLM_MODEL: "m", BEAM_LLM_API_KEY: "k", ...extra }, "custom");
    expect(() => custom("http://llm.example.com/v1")).toThrow("plain HTTP");
    expect(custom("http://llm.example.com/v1", { BEAM_LLM_ALLOW_HTTP: "1" })).toMatchObject({ baseUrl: "http://llm.example.com/v1" });
    for (const url of ["http://localhost:4000/v1", "http://litellm:4000/v1", "http://10.0.3.7/v1", "http://gateway.internal/v1"])
      expect(custom(url)).toMatchObject({ baseUrl: url });
  });
});

describe("LLM checks per provider", () => {
  const originalFetch = global.fetch;
  afterEach(() => { global.fetch = originalFetch; });

  it("calls Anthropic's Messages API with structured output and no sampling parameters", async () => {
    const calls: { url: string; headers: Headers; body: Record<string, unknown> }[] = [];
    let reply: (check: string) => Response = check => Response.json({
      id: "msg_1", type: "message", role: "assistant", model: "claude-opus-5-5", stop_reason: "end_turn", stop_sequence: null,
      content: [{ type: "text", text: JSON.stringify({ check, results: [{ i: 0, verdict: "malicious", reason: "UNION-based injection" }, { i: 1, verdict: "benign", reason: "test" }] }) }],
      usage: { input_tokens: 10, output_tokens: 10 },
    });
    global.fetch = jest.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      calls.push({ url: String(input), headers: new Headers(init?.headers), body });
      return reply(checkIn(String(body.system))!);
    }) as typeof fetch;
    const config = ownLlmConfig({ ANTHROPIC_API_KEY: "sk-ant-test" }, "anthropic")!;
    const batch = [finding("a"), finding("b")];
    expect(await judgeWithOwnLlm(batch, "strict", config)).toBe(2);
    expect(calls[0]!.url).toMatch(/^https:\/\/api\.anthropic\.com\/v1\/messages/);
    expect(`${calls[0]!.headers.get("x-api-key")} ${calls[0]!.headers.get("authorization")}`).toContain("sk-ant-test");
    expect(calls[0]!.headers.get("anthropic-beta")).toContain("server-side-fallback-2026-07-01");
    expect(calls[0]!.body).toMatchObject({ model: "claude-opus-5-5", fallbacks: "default", output_config: { effort: "low", format: { type: "json_schema" } } });
    expect(calls[0]!.body).not.toHaveProperty("temperature");
    expect(batch.map(f => f.llm?.verdict)).toEqual(["malicious", "benign"]);

    reply = () => Response.json({ id: "msg_2", type: "message", role: "assistant", model: "claude-opus-5-5", stop_reason: "refusal", stop_sequence: null, content: [], usage: { input_tokens: 1, output_tokens: 0 } });
    const refused = [finding("c")];
    await judgeWithOwnLlm(refused, "strict", config);
    expect(refused[0]!.llm).toMatchObject({ verdict: "declined" });
    reply = () => Response.json({ type: "error", error: { type: "authentication_error", message: "invalid x-api-key" } }, { status: 401 });
    const rejected = [finding("d")];
    await judgeWithOwnLlm(rejected, "strict", config);
    expect(rejected[0]!.llm).toMatchObject({ verdict: "error", reason: "Anthropic rejected the API key." });
  });
  it("skips JSON mode where an endpoint rejects it, and still reads a fenced answer", async () => {
    let sent: Record<string, unknown> = {};
    global.fetch = jest.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      sent = JSON.parse(String(init?.body)) as Record<string, unknown>;
      const check = checkIn(String((sent.messages as { content: string }[])[0]!.content));
      return Response.json({ choices: [{ message: { content: "```json\n" + JSON.stringify({ check, results: [{ i: 0, verdict: "suspicious", reason: "r" }] }) + "\n```" } }] });
    }) as typeof fetch;
    const config = ownLlmConfig({ GEMINI_API_KEY: "g", BEAM_LLM_MODEL: "gemini-flash" }, "gemini")!;
    const batch = [finding("e")];
    await judgeWithOwnLlm(batch, "strict", config);
    expect(sent).not.toHaveProperty("response_format");
    expect(batch[0]!.llm?.verdict).toBe("suspicious");
  });
});
