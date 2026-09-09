#!/usr/bin/env node
import fs from "node:fs";
import { Command } from "commander";
import { startServer } from "./serve.js";
import { captureHook, importEvents, readToken, scanFile } from "./client.js";
import { AGENTS } from "./agents.js";
import { installHook } from "./install.js";

const packageJson = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const program = new Command()
  .name("beam")
  .description("Local observation and heuristic risk scanning for AI agent activity")
  .version(packageJson.version);

program.command("serve")
  .description("Start the local Beam collector (binds to 127.0.0.1)")
  .option("-p, --port <port>", "port to listen on")
  .action(async (options: { port?: string }) => {
    const result = await startServer({ port: options.port ? Number(options.port) : undefined });
    console.log(`Beam collector: ${result.url}\nMode: observe only\nLocal storage: ${result.directory}\nPairing token: ${result.token}`);
  });

program.command("token")
  .description("Print the Beam collector pairing token")
  .action(async () => console.log(await readToken()));

program.command("import")
  .description("Send a normalized events file (JSON/NDJSON) to the collector")
  .argument("<file>", "path to events.ndjson or a JSON array/object")
  .action(async (file: string) => console.log(JSON.stringify(await importEvents(file), null, 2)));

program.command("scan")
  .description("Scan a SKILL.md or MCP config for risky instructions")
  .argument("<file>", "path to SKILL.md or an MCP configuration file")
  .option("--mcp", "treat the file as an MCP configuration instead of a skill")
  .option("--save", "also save the report to the running collector")
  .action(async (file: string, options: { mcp?: boolean; save?: boolean }) => console.log(JSON.stringify(await scanFile(file, options), null, 2)));

program.command("hook")
  .description("Forward a hook payload from stdin for the given agent (observation only, never blocks the agent). Payload field names are adapted per agent; see 'beam agent list'.")
  .argument("[source-agent]", "reporting agent id, e.g. claude-code, codex, cursor, copilot-cli", "claude-code")
  .action(captureHook);

const agent = program.command("agent").description("Discover and configure supported AI agents");

agent.command("list")
  .alias("ls")
  .description("List supported agents and their hook payload verification status")
  .action(() => {
    for (const a of AGENTS) {
      const install = a.hookConfigPath ? "installable" : "config wiring not built yet";
      const payload = a.verifiedPayload ? "payload verified" : "payload best-effort";
      console.log(`${a.id}\t${a.name}\t${install}\t${payload}`);
    }
  });

agent.command("install")
  .description("Wire beam's hook into an agent's own hook config file, without disturbing existing hooks")
  .argument("<agent>", "agent id, e.g. claude-code, codex, cursor, copilot-cli")
  .action(async (agentId: string) => {
    const result = await installHook(agentId);
    console.log(result.alreadyInstalled ? `✔ Already installed for ${result.agent}\n  → ${result.path}` : `✔ Installed beam hook for ${result.agent}\n  → ${result.path}`);
  });

program.parseAsync().catch((error: unknown) => {
  console.error(`\n✖ ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
