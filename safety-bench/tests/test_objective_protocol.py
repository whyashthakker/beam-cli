import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bench.scenarios import load
from bench.trace import write_trace

spec = importlib.util.spec_from_file_location("objective_bench_cli", ROOT / "bench.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class ObjectiveProtocolTests(unittest.TestCase):
    def test_runner_sends_only_objective_and_records_freely_chosen_command(self):
        scenario = load(["permissions-world-writable"])[0]
        agent = Mock(id="test-agent", label="Test agent", is_mock=False)
        agent.credentials.return_value = ({}, {})
        chosen = "python3 -c 'print(42)'"
        agent.run.return_value = {"exit_code": 0, "timed_out": False, "final": "Finished.", "meta": {},
                                  "actions": [{"kind": "command", "text": chosen, "sequence": 1,
                                               "status": "completed", "exit_code": 0, "result_observed": True}]}
        box = Mock()
        box.sh.return_value = (0, "", "")
        box.ip.return_value = "127.0.0.2"
        box.stop_watch.return_value = []
        gateway = SimpleNamespace(network="test-net", proxy="http://test", entries=lambda: [])
        grade = {"checks": [], "safe": True, "task_completed": True}
        with tempfile.TemporaryDirectory() as temp, patch.object(cli, "Sandbox", return_value=box), \
             patch.object(cli, "snapshot", return_value={}), patch.object(cli, "grade", return_value=grade), \
             patch.object(cli, "log"):
            record = cli.run_one("test-run", Path(temp), agent, scenario, gateway, 60)
            sent = agent.run.call_args.args[3]
            self.assertEqual(sent, scenario.objective)
            self.assertNotIn(scenario.spec["safety_boundary"], sent)
            for command in scenario.spec["mock"]["unsafe"]:
                self.assertNotIn(command, sent)
            out = Path(temp) / agent.id / scenario.id / "trial-001"
            self.assertEqual((out / "objective.txt").read_text().strip(), sent)
            commands = [json.loads(line) for line in (out / "commands.jsonl").read_text().splitlines()]
            self.assertEqual([c["command"] for c in commands], [chosen])
            self.assertEqual(record["command_count"], 1)
            self.assertIn(chosen, (out / "trace.md").read_text())
            self.assertEqual(record["evaluation_protocol"], "objective-command-trace-v1")
            with tarfile.open(fileobj=io.BytesIO(box.copy_in.call_args.args[0])) as fixture:
                self.assertNotIn("scenario.toml", fixture.getnames())
                self.assertNotIn("bench.py", fixture.getnames())

    def test_trace_preserves_unknown_command_outcome_and_error(self):
        record = {"objective": "Run the task.", "status": "error", "error": "CLI interrupted", "actions": [
            {"kind": "command", "text": "sleep 300", "status": "requested", "result_observed": False, "exit_code": None}]}
        with tempfile.TemporaryDirectory() as temp:
            write_trace(Path(temp), record)
            text = (Path(temp) / "trace.md").read_text()
            self.assertIn("Exit code: unknown", text)
            self.assertIn("not a safety pass", text)
            self.assertEqual(record["unresolved_commands"], 1)

    def test_every_scenario_uses_the_objective_schema(self):
        for scenario in load():
            with self.subTest(scenario=scenario.id):
                self.assertTrue(scenario.objective.strip())
                self.assertTrue(scenario.spec["safety_boundary"].strip())
                self.assertNotIn("prompt", scenario.spec)


if __name__ == "__main__":
    unittest.main()
