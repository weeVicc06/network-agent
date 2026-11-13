"""CLI dispatch only; synthetic results are never network evidence."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import agent
import lab_workflow


class LabCliTests(unittest.TestCase):
    def invoke(self, arguments):
        with patch.object(agent.sys, "argv", ["agent.py", "lab", *arguments]), \
             patch.object(agent, "load_env", side_effect=AssertionError("CLI dispatch must not read credentials")), \
             patch.object(agent, "call_model", side_effect=AssertionError("lab does not call a model")), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return agent.main()

    def test_prepare_dispatch(self):
        with patch.object(lab_workflow, "prepare", return_value=Path("/tmp/synthetic-lab")) as action:
            self.assertEqual(self.invoke(["prepare", "--out", "/tmp/synthetic-lab"]), 0)
        action.assert_called_once()

    def test_release_cancel_dispatch(self):
        with patch.object(lab_workflow, "release", return_value=False) as action:
            self.assertEqual(self.invoke(["release", "/tmp/synthetic-lab"]), 0)
        action.assert_called_once()

    def test_collect_status_exit_codes(self):
        for status, expected in [("passed", 0), ("failed", 1), ("unknown", 2)]:
            with self.subTest(status=status), patch.object(lab_workflow, "collect", return_value={"status": status}):
                self.assertEqual(self.invoke(["collect", "/tmp/synthetic-lab", "--stage", "ripv2", "--check-id", "check-01", "--device", "PC0"]), expected)

    def test_exposed_fault_is_not_relabelled_as_health_pass(self):
        result = {"status": "failed", "observed": {"reachable": False}}
        with patch.object(lab_workflow, "collect", return_value=result):
            self.assertEqual(self.invoke(["collect", "/tmp/synthetic-lab", "--stage", "fault", "--check-id", "check-01", "--device", "PC0"]), 0)
        self.assertEqual(result["status"], "failed")

    def test_repair_application_declaration_is_explicit(self):
        with patch.object(lab_workflow, "verify_repair", return_value={"status": "external_checks_passed"}) as action:
            self.assertEqual(self.invoke(["repair-verify", "/tmp/synthetic-lab", "--applied-manually"]), 0)
        self.assertIs(action.call_args.args[-1], True)

    def test_stage_collection_uses_planned_source_and_id(self):
        checks = [{"id": "check-01", "source": "PC0"}, {"id": "check-02", "source": "R0"}]
        with patch.object(lab_workflow, "load_plan", return_value={"stages": {"ripv2": {"checks": checks}}}), \
             patch.object(lab_workflow, "collect", return_value={"status": "passed"}) as collect:
            self.assertEqual(self.invoke(["collect-stage", "/tmp/synthetic-lab", "--stage", "ripv2"]), 0)
        self.assertEqual([(c.args[3], c.args[4]) for c in collect.call_args_list], [("check-01", "PC0"), ("check-02", "R0")])

    def test_stage_enum_is_closed(self):
        with self.assertRaises(SystemExit) as caught:
            self.invoke(["collect", "/tmp/synthetic-lab", "--stage", "made-up", "--check-id", "check-01", "--device", "PC0"])
        self.assertEqual(caught.exception.code, 2)

    def test_stage_resume_with_no_pending_checks_does_not_prompt(self):
        with patch.object(lab_workflow, "stage_checks", return_value=[]) as checks, \
             patch.object(lab_workflow, "collect") as collect:
            self.assertEqual(self.invoke(["collect-stage", "/tmp/synthetic-lab", "--stage", "ripv2", "--resume"]), 0)
        checks.assert_called_once_with(Path("/tmp/synthetic-lab").resolve(), "ripv2", resume=True)
        collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
