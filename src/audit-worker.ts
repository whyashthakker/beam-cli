import { parentPort } from "node:worker_threads";
import { runAudit } from "./audit/run.js";
try {
  parentPort?.postMessage({ report: await runAudit(["--live", "--online", "--whole-pc"]) });
} catch (error) {
  parentPort?.postMessage({ error: error instanceof Error ? error.message : String(error) });
}
parentPort?.close();
