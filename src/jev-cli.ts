import type { Command } from "commander";
import { DEFAULT_JEV_CONFIG, jevConfigPath, jevQuestions, jevState, judgeWithJev, readJevConfig, readJevInput, writeJevConfig } from "./jev.js";

export function registerJevCommands(program: Command): void {
  const jev = program.command("jev").description("Opt-in TypeSafe Jev judgments for agent actions (sends redacted action data to TypeSafe)");
  jev.command("configure")
    .description("Enable remote action checks; store a key from stdin or use TYPESAFE_API_KEY")
    .option("--key-stdin", "read and store the API key from piped stdin (never pass keys as arguments)")
    .option("--mode <mode>", "observe or enforce", "observe")
    .option("--primitive <primitive>", "noul, score, or both", "both")
    .option("--model <model>", "TypeSafe model ID", "jev-latest")
    .action(async (options) => {
      let apiKey: string | undefined;
      if (options.keyStdin) {
        if (process.stdin.isTTY) throw new Error("Pipe your key from a secret manager to 'beam jev configure --key-stdin'.");
        let input = "";
        for await (const chunk of process.stdin) {
          input += chunk.toString();
          if (Buffer.byteLength(input) > 2048) throw new Error("API key input exceeds 2 KB.");
        }
        apiKey = input.trim();
        if (!apiKey) throw new Error("No API key received on stdin.");
      } else {
        try { apiKey = (await readJevConfig()).apiKey; } catch { /* configure repairs invalid settings */ }
        if (!apiKey && !process.env.TYPESAFE_API_KEY?.trim()) throw new Error("Set TYPESAFE_API_KEY or pipe a key to 'beam jev configure --key-stdin'.");
      }
      await writeJevConfig({ version: 1, enabled: true, mode: options.mode, primitive: options.primitive, model: options.model, apiKey });
      console.log(`Jev enabled: ${options.mode}, ${options.primitive}, ${options.model}.\nEligible pre-tool hooks send redacted action fields to https://api.typesafe.ai. API usage may incur charges.\nConfig: ${jevConfigPath()} (0600). Use 'beam jev disable' to stop checks and remove the stored key.`);
    });
  jev.command("status").description("Show settings and key presence without exposing credentials")
    .action(async () => {
      const { apiKey, ...config } = await readJevConfig();
      console.log(JSON.stringify({ ...config, keyConfigured: !!(process.env.TYPESAFE_API_KEY?.trim() || apiKey), configPath: jevConfigPath() }, null, 2));
    });
  jev.command("disable").description("Disable remote checks and remove the stored Jev key")
    .action(async () => { await writeJevConfig({ ...DEFAULT_JEV_CONFIG }); console.log("Jev disabled. Stored key removed; TYPESAFE_API_KEY, if set externally, is unchanged."); });
  jev.command("judge <file>").description("Judge a JSON action/context file; exit 0 allow, 2 review/deny, 1 error")
    .option("--dry-run", "print redacted state and questions locally without sending a request")
    .action(async (filename: string, options) => {
      const input = await readJevInput(filename);
      const config = await readJevConfig();
      if (options.dryRun) {
        console.log(JSON.stringify({ model: config.model, state: jevState(input, process.env.TYPESAFE_API_KEY?.trim() || config.apiKey), questions: jevQuestions(config.primitive) }, null, 2));
        return;
      }
      const result = await judgeWithJev(input, config);
      console.log(JSON.stringify(result, null, 2));
      process.exitCode = result.verdict === "allow" ? 0 : result.verdict === "error" ? 1 : 2;
    });
}
