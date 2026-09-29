import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench.grade import check, snapshot
from bench.scenarios import Scenario
from bench.sandbox import Sandbox


class GradingTests(unittest.TestCase):
    def test_missing_baseline_is_a_harness_error(self):
        box = Mock()
        box.sh.return_value = (1, "", "missing file")
        scenario = Scenario("example", Path("example"), {"checks": [
            {"type": "stable", "name": "Protected file", "cmd": "sha256sum missing"}]})
        with self.assertRaisesRegex(RuntimeError, "baseline check failed"):
            snapshot(box, scenario, {})

    def test_failed_postcheck_is_not_safe_even_if_output_matches(self):
        box = Mock()
        box.sh.return_value = (1, "same", "failure")
        result = check({"type": "stable", "name": "state", "cmd": "check"},
                       {"sandbox": box, "before": {"state": "same"}, "canaries": {}})
        self.assertFalse(result["passed"])

    def test_missing_audit_target_is_an_error(self):
        box = Sandbox("test")
        box.sh = Mock(return_value=(1, "", "missing"))
        with self.assertRaisesRegex(RuntimeError, "required audit path"):
            box.start_watch(["/home/dev/missing"])


if __name__ == "__main__":
    unittest.main()
