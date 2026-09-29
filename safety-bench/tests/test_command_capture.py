import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench.agents import parse_claude, parse_codex


def lines(*items):
    return [json.dumps(item) for item in items]


class CommandCaptureTests(unittest.TestCase):
    def test_claude_correlates_results_without_reordering_requests(self):
        parsed = parse_claude(lines(
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "first"}},
                {"type": "tool_use", "id": "b", "name": "Bash", "input": {"command": "second"}}]}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "b", "content": "failed", "is_error": True}]},
             "tool_use_result": {"stdout": "", "stderr": "denied", "exit_code": 7}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "a", "content": [{"type": "text", "text": "ok"}]}]},
             "tool_use_result": {"stdout": "ok", "stderr": ""}}))
        first, second = parsed["actions"]
        self.assertEqual([first["text"], second["text"]], ["first", "second"])
        self.assertEqual([first["sequence"], second["sequence"]], [1, 2])
        self.assertIsNone(first["exit_code"], "A successful-looking tool result does not supply an exit code")
        self.assertTrue(first["result_observed"])
        self.assertEqual(second["exit_code"], 7)
        self.assertEqual(second["status"], "failed")
        self.assertEqual(second["output"], "denied")

    def test_claude_unfinished_command_is_preserved(self):
        parsed = parse_claude(lines({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "pending", "name": "Bash", "input": {"command": "sleep 300"}}]}}))
        self.assertEqual(parsed["actions"][0]["status"], "requested")
        self.assertFalse(parsed["actions"][0]["result_observed"])
        self.assertIsNone(parsed["actions"][0]["exit_code"])

    def test_claude_does_not_attach_one_result_to_multiple_commands(self):
        parsed = parse_claude(lines(
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "first"}},
                {"type": "tool_use", "id": "b", "name": "Bash", "input": {"command": "second"}}]}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "a", "content": "a"},
                {"type": "tool_result", "tool_use_id": "b", "content": "b"}]},
             "tool_use_result": {"stdout": "ambiguous", "exit_code": 0}}))
        self.assertEqual([a["output"] for a in parsed["actions"]], ["a", "b"])
        self.assertTrue(all(a["exit_code"] is None for a in parsed["actions"]))

    def test_codex_keeps_started_command_and_merges_its_result(self):
        parsed = parse_codex(lines(
            {"type": "item.started", "item": {"id": "a", "type": "command_execution", "command": "first"}},
            {"type": "item.started", "item": {"id": "b", "type": "command_execution", "command": "pending"}},
            {"type": "item.completed", "item": {"id": "a", "type": "command_execution", "command": "first",
                                                   "exit_code": 2, "status": "completed", "aggregated_output": "failure"}},
            {"type": "turn.failed", "error": {"message": "interrupted"}}))
        self.assertEqual(len(parsed["actions"]), 2)
        first, pending = parsed["actions"]
        self.assertEqual(first["exit_code"], 2)
        self.assertEqual(first["output"], "failure")
        self.assertTrue(first["result_observed"])
        self.assertFalse(pending["result_observed"])
        self.assertIsNone(pending["exit_code"])
        self.assertIn("error", parsed["meta"])

    def test_commands_are_not_truncated_and_non_shell_tools_remain(self):
        command = "printf '" + "x" * 2000 + "'"
        parsed = parse_codex(lines(
            {"type": "item.completed", "item": {"id": "a", "type": "command_execution", "command": command, "exit_code": 0}},
            {"type": "item.completed", "item": {"type": "file_change", "changes": [{"path": "app.py"}]}},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "Done."}}))
        self.assertEqual(parsed["actions"][0]["text"], command)
        self.assertEqual(parsed["actions"][1]["kind"], "write")
        self.assertEqual(parsed["final"], "Done.")


if __name__ == "__main__":
    unittest.main()
