"""Synthetic archived evaluations exercise local recheck; no real model is called."""
from contextlib import ExitStack
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

import workflow


PROJECT = Path(__file__).resolve().parents[1]


class ArchivedEvaluationRecheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        case = self.root / "cases/CASE01"
        case.mkdir(parents=True)
        self.request_file = case / "request.txt"
        self.contract_file = case / "contract.json"
        self.requirement = "Synthetic unit-test requirement for the CIDR reference."
        self.request_file.write_text(self.requirement + "\n", encoding="utf-8")
        self.contract = json.loads((PROJECT / "cases/CASE01/contract.json").read_text(encoding="utf-8"))
        self.contract_file.write_text(json.dumps(self.contract), encoding="utf-8")
        workflow.write_json(self.root / "cases/index.json", [{
            "id": "CASE01", "request_file": "CASE01/request.txt",
            "contract_file": "CASE01/contract.json",
        }])
        self.run = self.root / "runs/synthetic-archived-run"
        self.run.mkdir(parents=True)
        (self.run / "requirement.txt").write_text(self.requirement + "\n", encoding="utf-8")
        self.reference = yaml.safe_load((PROJECT / "cases/CASE01/expected.yaml").read_text(encoding="utf-8"))
        (self.run / "topology.yaml").write_text(yaml.safe_dump(self.reference), encoding="utf-8")
        self.evaluation = self.root / "evaluations/synthetic-archive"
        self.evaluation.mkdir(parents=True)
        # The label below is a controlled unit-test fixture, never a real result.
        self.original = {
            "mode": "live_llm", "api_calls": 1,
            "cases": [{"case_id": "CASE01", "run": str(self.run), "status": "planned"}],
        }
        workflow.write_json(self.evaluation / "results.json", self.original)
        self.output = self.root / "evaluations/local-recheck"
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        # Recheck must remain usable without API configuration or a transport.
        self.load_env = self.guards.enter_context(patch("agent.load_env", side_effect=AssertionError("recheck must not read API configuration")))
        self.call_model = self.guards.enter_context(patch("agent.call_model", side_effect=AssertionError("recheck must not call a model")))
        self.generate = self.guards.enter_context(patch.object(workflow, "generate", side_effect=AssertionError("recheck must not regenerate")))
        self.network = self.guards.enter_context(patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("recheck must not open a network connection")))

    def assert_no_api_work(self):
        for guarded in [self.load_env, self.call_model, self.generate, self.network]:
            guarded.assert_not_called()

    def test_valid_archive_is_revalidated_locally_without_new_success_or_mutation(self):
        archive_before = (self.evaluation / "results.json").read_bytes()
        requirement_before = (self.run / "requirement.txt").read_bytes()
        topology_before = (self.run / "topology.yaml").read_bytes()
        runs_before = set((self.root / "runs").iterdir())
        result = workflow.recheck(self.root, self.evaluation, self.output)
        self.assertEqual(result["mode"], "offline_recheck_of_live_outputs")
        self.assertEqual(result["model_calls"], 0)
        self.assertEqual(result["cases"][0]["status"], "revalidated")
        self.assertEqual(result["cases"][0]["old_status"], "planned")
        self.assertEqual(result["cases"][0]["current_request_sha256"], workflow.digest(self.request_file))
        self.assertEqual(result["cases"][0]["current_contract_sha256"], workflow.digest(self.contract_file))
        self.assertEqual(result["source_evaluation"], str(self.evaluation.resolve()))
        self.assertEqual(json.loads((self.output / "recheck.json").read_text()), result)
        self.assertFalse((self.output / "metrics.json").exists())
        self.assertEqual((self.evaluation / "results.json").read_bytes(), archive_before)
        self.assertEqual((self.run / "requirement.txt").read_bytes(), requirement_before)
        self.assertEqual((self.run / "topology.yaml").read_bytes(), topology_before)
        self.assertEqual(set((self.root / "runs").iterdir()), runs_before)
        self.assert_no_api_work()

    def test_changed_requirement_requires_regeneration_instead_of_new_model_success(self):
        self.request_file.write_text(self.requirement + " This is now a different request.\n", encoding="utf-8")
        result = workflow.recheck(self.root, self.evaluation, self.output)
        row = result["cases"][0]
        self.assertEqual(row["status"], "needs_regeneration")
        self.assertTrue(row["errors"])
        self.assertEqual(result["model_calls"], 0)
        self.assertNotIn("contract_passed", row)
        self.assertNotIn("first_pass", row)
        self.assertEqual(json.loads((self.evaluation / "results.json").read_text()), self.original)
        self.assert_no_api_work()

    def test_stricter_current_contract_can_fail_unchanged_archived_output(self):
        stricter = copy.deepcopy(self.contract)
        router = next(d for d in stricter["required"]["devices"] if d["id"] == "R0")
        router["routing"]["static_routes"][0]["distance"] = 10
        self.contract_file.write_text(json.dumps(stricter), encoding="utf-8")
        result = workflow.recheck(self.root, self.evaluation, self.output)
        self.assertEqual(result["cases"][0]["status"], "regression_failed")
        self.assertTrue(result["cases"][0]["errors"])
        self.assertEqual(result["model_calls"], 0)
        self.assert_no_api_work()

    def test_offline_fixture_evaluation_is_rejected(self):
        workflow.write_json(self.evaluation / "results.json", {**self.original, "mode": "offline_fixture"})
        with self.assertRaisesRegex(ValueError, "真实模型评估"):
            workflow.recheck(self.root, self.evaluation, self.output)
        self.assertFalse(self.output.exists())
        self.assert_no_api_work()

    def test_existing_output_directory_is_never_overwritten(self):
        self.output.mkdir(parents=True)
        marker = self.output / "keep.txt"
        marker.write_text("preserve existing output", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            workflow.recheck(self.root, self.evaluation, self.output)
        self.assertEqual(marker.read_text(), "preserve existing output")
        self.assertFalse((self.output / "recheck.json").exists())
        self.assert_no_api_work()

    def test_clarification_is_local_match_not_a_new_planned_result(self):
        workflow.write_json(self.evaluation / "results.json", {
            **self.original,
            "cases": [{"case_id": "CASE01", "run": str(self.run), "status": "needs_clarification"}],
        })
        self.contract_file.write_text(json.dumps({"expect": "clarification", "required": {}}), encoding="utf-8")
        result = workflow.recheck(self.root, self.evaluation, self.output)
        self.assertEqual(result["cases"][0]["status"], "clarification_matched")
        self.assertEqual(result["model_calls"], 0)
        self.assert_no_api_work()

    def test_removed_case_is_reported_without_reusing_a_different_requirement(self):
        workflow.write_json(self.root / "cases/index.json", [])
        result = workflow.recheck(self.root, self.evaluation, self.output)
        self.assertEqual(result["cases"][0]["status"], "case_removed")
        self.assertTrue(result["cases"][0]["errors"])
        self.assert_no_api_work()


if __name__ == "__main__":
    unittest.main()
