import type { Command } from "commander";
import { jevState, readJevInput } from "./jev.js";
import { DEFAULT_JUDGE_CONFIG, judgeAction, judgeConfigPath, judgeRequest, readJudgeConfig, writeJudgeConfig, type JudgeConfig } from "./judge.js";

const OPENAI = "https://api.openai.com/v1";

export function registerJudgeCommands(program: Command): void {
  const judge = program.command("judge").description("Opt-in second opinion on agent actions from any LLM or decision service you choose (sends redacted action data to it)");
  judge.command("configure")
    .description("Enable checks with a general LLM (OpenAI-compatible) or your own decision service; store a key from stdin or use BEAM_JUDGE_API_KEY")
    .option("--provider <provider>", "llm (any OpenAI-compatible model) or http (a decision service)", "llm")
    .option("--url <url>", `llm: base URL ending in /v1 (default ${OPENAI}); http: the decision endpoint`)
    .option("--model <model>", "model name for --provider llm (default gpt-4.1-nano on OpenAI)")
    .option("--mode <mode>", "observe or enforce", "observe")
    .option("--timeout-ms <ms>", "how long a hook waits for a verdict, 500-15000", "3000")
    .option("--key-stdin", "read and store the API key from piped stdin (never pass keys as arguments)")
    .action(async (options: { provider: string; url?: string; model?: string; mode: string; timeoutMs: string; keyStdin?: boolean }) => {
      if (options.provider !== "llm" && options.provider !== "http") throw new Error("--provider must be llm or http.");
      if (options.provider === "http" && !options.url) throw new Error("--provider http needs --url, your decision endpoint.");
      const url = (options.url ?? OPENAI).replace(/\/+$/, "");
      const model = options.provider === "llm" ? options.model ?? (url === OPENAI ? DEFAULT_JUDGE_CONFIG.model : undefined) : undefined;
      if (options.provider === "llm" && !model) throw new Error("Set --model to the model name your endpoint serves.");
      let apiKey: string | undefined;
      if (options.keyStdin) {
        if (process.stdin.isTTY) throw new Error("Pipe your key from a secret manager to 'beam judge configure --key-stdin'.");
        let input = "";
        for await (const chunk of process.stdin) {
          input += chunk.toString();
          if (Buffer.byteLength(input) > 4096) throw new Error("API key input exceeds 4 KB.");
        }
        apiKey = input.trim();
        if (!apiKey) throw new Error("No API key received on stdin.");
      } else {
        try { apiKey = (await readJudgeConfig()).apiKey; } catch { /* configure repairs invalid settings */ }
        if (url === OPENAI && !apiKey && !process.env.BEAM_JUDGE_API_KEY?.trim()) throw new Error("Set BEAM_JUDGE_API_KEY or pipe a key to 'beam judge configure --key-stdin'.");
      }
      const config: JudgeConfig = {
        version: 1, enabled: true, mode: options.mode as JudgeConfig["mode"], provider: options.provider,
        url, model, timeoutMs: Number(options.timeoutMs), apiKey,
      };
      await writeJudgeConfig(config);
      console.log(`Judge enabled: ${config.mode}, ${config.provider}${model ? ` ${model}` : ""} at ${new URL(url).host}.\nEligible pre-tool hooks send redacted action fields there. Usage may incur charges with hosted models.\nConfig: ${judgeConfigPath()} (0600). Use 'beam judge disable' to stop checks and remove the stored key.`);
    });
  judge.command("status").description("Show settings and key presence without exposing credentials")
    .action(async () => {
      const { apiKey, ...config } = await readJudgeConfig();
      console.log(JSON.stringify({ ...config, keyConfigured: !!(process.env.BEAM_JUDGE_API_KEY?.trim() || apiKey), configPath: judgeConfigPath() }, null, 2));
    });
  judge.command("disable").description("Disable checks and remove the stored key")
    .action(async () => { await writeJudgeConfig({ ...DEFAULT_JUDGE_CONFIG }); console.log("Judge disabled. Stored key removed; BEAM_JUDGE_API_KEY, if set externally, is unchanged."); });
  judge.command("check <file>").description("Judge a JSON action/context file (same format as 'beam jev judge'); exit 0 allow, 2 review/deny, 1 error")
    .option("--dry-run", "print the redacted request locally without sending it")
    .action(async (filename: string, options: { dryRun?: boolean }) => {
      const input = await readJevInput(filename);
      const config = await readJudgeConfig();
      if (options.dryRun) {
        console.log(JSON.stringify(judgeRequest(jevState(input, process.env.BEAM_JUDGE_API_KEY?.trim() || config.apiKey || ""), config), null, 2));
        return;
      }
      const result = await judgeAction(input, config);
      console.log(JSON.stringify(result, null, 2));
      process.exitCode = result.verdict === "allow" ? 0 : result.verdict === "error" ? 1 : 2;
    });
}
