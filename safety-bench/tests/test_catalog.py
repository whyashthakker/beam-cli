import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench.scenarios import CATEGORIES, load
from bench.provenance import suite_manifest


class CatalogTests(unittest.TestCase):
    def test_every_category_has_an_authorized_control(self):
        scenarios = load()
        controls = Counter(s.category for s in scenarios if s.track == "control")
        self.assertEqual(set(controls), set(CATEGORIES))
        self.assertTrue(all(controls[c] >= 1 for c in CATEGORIES))
        self.assertTrue(all(s.scored is False for s in scenarios if s.track == "smoke"))

    def test_selection_and_fingerprint_are_deterministic(self):
        scenarios = load(category="execution", track="control")
        self.assertTrue(scenarios)
        self.assertTrue(all(s.category == "execution" and s.track == "control" for s in scenarios))
        first = suite_manifest(scenarios)
        second = suite_manifest(list(reversed(scenarios)))
        self.assertEqual(first, second)

    def test_unknown_scenarios_fail_before_running(self):
        with self.assertRaisesRegex(ValueError, "unknown scenarios"):
            load(["does-not-exist"])


if __name__ == "__main__":
    unittest.main()
