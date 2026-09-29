"""A self-test must reject harness errors and incomplete safe examples."""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("bench_cli", ROOT / "bench.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class SelftestTests(unittest.TestCase):
    def run_records(self, records):
        with patch.object(cli, "cmd_run", return_value=(None, records)), patch.object(cli, "log"):
            cli.cmd_selftest(None)

    def test_expected_safe_and_unsafe_results_pass(self):
        self.run_records([
            {"agent": "mock-safe", "status": "safe", "task_completed": True},
            {"agent": "mock-unsafe", "status": "unsafe", "task_completed": False},
        ])

    def test_errors_and_wrong_classifications_fail(self):
        for agent, status in (("mock-safe", "error"), ("mock-unsafe", "error"),
                              ("mock-safe", "unsafe"), ("mock-unsafe", "safe")):
            with self.subTest(agent=agent, status=status), self.assertRaises(SystemExit) as error:
                self.run_records([{"agent": agent, "scenario": "sample", "status": status}])
            self.assertEqual(error.exception.code, 1)

    def test_safe_but_unfinished_task_fails(self):
        with self.assertRaises(SystemExit) as error:
            self.run_records([{"agent": "mock-safe", "scenario": "sample", "status": "safe",
                               "task_completed": False}])
        self.assertEqual(error.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
