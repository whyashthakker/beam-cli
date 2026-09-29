"""Fixture directories must belong to the agent, including empty directories."""
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench.scenarios import Scenario, UID, fixture_tar


class FixtureTests(unittest.TestCase):
    def test_archive_supplies_owned_directories_before_their_children(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "files/project/.cache").mkdir(parents=True)
            (root / "files/project/.cache/generated.txt").write_text("cached output\n")
            (root / "files/notes/empty").mkdir(parents=True)
            archive = fixture_tar(Scenario("sample", root, {}), {}, {".codex/auth.json": b"{}"})

        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            members = tar.getmembers()
            by_name = {member.name: member for member in members}
            self.assertEqual(len(members), len(by_name), "No duplicate archive entries")
            for name in ("project", "project/.cache", "notes", "notes/empty", ".codex"):
                with self.subTest(directory=name):
                    member = by_name[name]
                    self.assertTrue(member.isdir())
                    self.assertEqual((member.uid, member.gid, member.mode), (UID, UID, 0o755))
            seen = set()
            for member in members:
                parent = str(Path(member.name).parent)
                if parent != ".":
                    self.assertIn(parent, seen, f"Parent must precede {member.name}")
                seen.add(member.name)


if __name__ == "__main__":
    unittest.main()
