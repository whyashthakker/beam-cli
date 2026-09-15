// `beam run <agent> [args...]` -- launches any agent CLI (claude, codex, cursor-agent, opencode,
// gemini, or anything else) wrapped in a kernel-enforced sandbox when the current policy has
// enforce-mode BLOCK rules naming specific commands. See src/sandbox.ts for the platform-specific
// mechanics. This file just: reads the policy, asks sandbox.ts for a plan, and execs.
//
// Deliberately agent-agnostic: this file has no per-agent knowledge (unlike src/agents.ts, which
// knows how to install hooks into each agent's own config format). Wrapping a process by PID tree
// doesn't need that -- it works identically no matter what's being launched.
import { spawn } from "node:child_process";
import { readPolicy } from "./policy.js";
import { buildSandboxPlan } from "./sandbox.js";

export async function runAgent(command: string, args: string[]): Promise<never> {
  if (!command) {
    console.error("Usage: beam run <command> [args...]");
    process.exit(2);
  }

  const bundle = await readPolicy();
  const plan = buildSandboxPlan(bundle);
  const [spawnCmd, ...prefixArgs] = plan ? plan.prefix : [command];
  const spawnArgs = plan ? [...prefixArgs, command, ...args] : args;

  if (plan) console.error(`beam run: ${plan.summary}`);

  const child = spawn(spawnCmd, spawnArgs, { stdio: "inherit" });

  // Forward termination signals to the child so Ctrl-C etc. behave the same as running the
  // agent directly -- otherwise the wrapper process alone would exit and orphan the child.
  const forward = (signal: NodeJS.Signals) => { if (!child.killed) child.kill(signal); };
  process.on("SIGINT", forward);
  process.on("SIGTERM", forward);

  return new Promise<never>((resolve, reject) => {
    child.on("error", (error) => {
      // Sandbox tool itself failed to launch (shouldn't happen given the checks in sandbox.ts,
      // but never let that be the reason the agent doesn't run at all) -- retry unwrapped once.
      if (plan) {
        console.error(`beam run: sandbox launch failed (${error.message}); running unsandboxed.`);
        const fallback = spawn(command, args, { stdio: "inherit" });
        fallback.on("exit", (code, signal) => process.exit(signal ? 1 : (code ?? 1)));
        fallback.on("error", reject);
        return;
      }
      reject(error);
    });
    child.on("exit", (code, signal) => {
      process.exit(signal ? 1 : (code ?? 0));
    });
  });
}
