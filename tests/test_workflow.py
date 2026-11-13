"""Workflow regressions with synthetic model responses; never real model/network evidence."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

import agent
import workflow


SOURCE = Path(__file__).resolve().parents[1]
TEST_KEY = "unit-test-secret-never-a-real-api-key"
SETTINGS = {"LLM_MODEL": "unit-test-mock", "LLM_BASE_URL": "https://example.invalid",
            "LLM_API_KEY": TEST_KEY}


def small_topology():
    return {
        "schema_version": "0.2", "name": "Synthetic workflow test", "environment": "packet_tracer",
        "vlans": [{"id": 1, "name": "default"}], "acls": [],
        "devices": [
            {"id": "PC0", "type": "pc", "model": "PC-PT", "interfaces": [
                {"name": "FastEthernet0", "ipv4": "192.168.1.1/24", "mode": "routed"}]},
            {"id": "SW1", "type": "switch", "model": "2960", "interfaces": [
                {"name": "FastEthernet0/1", "ipv4": None, "mode": "access", "vlan": 1},
                {"name": "FastEthernet0/2", "ipv4": None, "mode": "access", "vlan": 1}]},
            {"id": "PC1", "type": "pc", "model": "PC-PT", "interfaces": [
                {"name": "FastEthernet0", "ipv4": "192.168.1.2/24", "mode": "routed"}]},
        ],
        "links": [
            {"a": {"device": "PC0", "interface": "FastEthernet0"}, "b": {"device": "SW1", "interface": "FastEthernet0/1"}},
            {"a": {"device": "PC1", "interface": "FastEthernet0"}, "b": {"device": "SW1", "interface": "FastEthernet0/2"}},
        ],
        "checks": [{"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": True},
                   {"kind": "ping", "source": "PC1", "destination": "PC0", "reachable": True}],
    }


def contract():
    return {"exact_device_ids": ["PC0", "PC1", "SW1"], "required": {
        "devices": [{"id": "PC0", "interfaces": [{"ipv4": "192.168.1.1/24"}]}],
        "checks": [{"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": True}],
    }}


def reply(value=None, envelope=None):
    return (json.dumps(value if value is not None else small_topology()), envelope or {
        "source": "unit_test_mock", "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}})


class ContractTests(unittest.TestCase):
    def test_device_order_is_free_but_address_and_exact_device_set_are_preserved(self):
        data = small_topology()
        data["devices"].reverse()
        self.assertEqual(workflow.check_contract(data, contract()), [])
        data["devices"].append({"id": "EXTRA"})
        self.assertTrue(workflow.check_contract(data, contract()))
        data = small_topology()
        data["devices"][0]["interfaces"][0]["ipv4"] = "192.168.1.3/24"
        self.assertTrue(workflow.check_contract(data, contract()))

    def test_acl_order_and_count_are_semantics(self):
        permit = {"action": "permit", "protocol": "tcp", "destination_port": 80}
        deny = {"action": "deny", "protocol": "ip"}
        expected = {"required": {"acls": [{"name": "WEB", "rules": [permit, deny]}]}}
        good = {"acls": [{"name": "WEB", "rules": [permit, deny]}]}
        self.assertEqual(workflow.check_contract(good, expected), [])
        for rules in [[deny, permit], [permit, deny, permit], [permit]]:
            self.assertTrue(workflow.check_contract({"acls": [{"name": "WEB", "rules": rules}]}, expected))

    def test_multiplicity_and_bool_integer_are_not_interchangeable(self):
        self.assertTrue(workflow.subset_errors([{"id": "PC0"}, {"id": "PC0"}], [{"id": "PC0"}]))
        self.assertTrue(workflow.subset_errors(True, 1))
        self.assertTrue(workflow.subset_errors(1, True))

    def test_overlapping_unordered_subsets_do_not_depend_on_expected_order(self):
        actual = [{"id": "R0", "type": "router"}, {"id": "R1", "type": "router"}]
        expected = [{"type": "router"}, {"id": "R0"}]
        self.assertEqual(workflow.subset_errors(expected, actual), [])


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ["agent.py", "network_core.py", "workflow.py", "schema/topology-v2.schema.json"]:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / name, target)
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        # Every test must explicitly opt into mock settings. A missing patch must
        # fail rather than reading the developer's real .env.
        self.no_env = patch.object(agent, "load_env", side_effect=AssertionError("Real configuration must not be read"))
        self.no_env.start()

    def tearDown(self):
        self.no_env.stop()
        self.quiet.__exit__(None, None, None)
        self.temp.cleanup()

    def generate(self, responses=None, **kwargs):
        mock = Mock(side_effect=responses or [reply()])
        result = workflow.generate(self.root, "Synthetic request only", settings=copy.deepcopy(SETTINGS),
                                   model_call=mock, contract=contract(), **kwargs)
        return result, mock

    def read(self, run, name):
        return json.loads((Path(run) / name).read_text())

    def test_plan_is_static_and_never_invents_runtime_success(self):
        outcome, mock = self.generate()
        self.assertEqual(mock.call_count, 1)
        self.assertEqual(outcome["status"], "planned")
        self.assertTrue(outcome["first_pass"])
        self.assertFalse(outcome["network_runtime_verified"])
        metadata = self.read(outcome["run"], "metadata.json")
        self.assertEqual(metadata["mode"], "live_llm")
        self.assertFalse(metadata["network_deployed"])
        verification = self.read(outcome["run"], "verification.json")
        self.assertEqual(verification["status"], "not_run")
        self.assertIsNone(verification["repair_rounds"])
        self.assertTrue(all(c["actual"] is None for c in verification["checks"]))
        self.assertFalse((Path(outcome["run"]) / "packet-tracer").exists())

    def test_semantically_valid_but_wrong_intent_retries_with_original_requirement(self):
        wrong = small_topology()
        wrong["devices"][0]["interfaces"][0]["ipv4"] = "192.168.1.3/24"
        outcome, mock = self.generate([reply(wrong), reply()])
        self.assertEqual(outcome["status"], "planned")
        self.assertEqual(outcome["attempts"], 2)
        self.assertFalse(outcome["first_pass"])
        second_messages = mock.call_args_list[1].args[1]
        self.assertEqual(second_messages[1]["content"], "Synthetic request only")
        self.assertIn("192.168.1.1/24", second_messages[-1]["content"])
        self.assertEqual(self.read(outcome["run"], "validation-1.json")["passed"], False)

    def test_three_attempt_cap_and_shared_api_budget_stop_calls(self):
        outcome, mock = self.generate([("not JSON", {})] * 3)
        self.assertEqual(mock.call_count, 3)
        self.assertEqual(outcome["status"], "failed")
        self.assertFalse((Path(outcome["run"]) / "topology.yaml").exists())
        budget = {"remaining": 1}
        outcome, mock = self.generate([("not JSON", {})], call_budget=budget)
        self.assertEqual(mock.call_count, 1)
        self.assertEqual(budget["remaining"], 0)
        self.assertEqual(outcome["status"], "failed")
        self.assertIn("上限", outcome["reason"])
        for attempts in [0, 4]:
            with self.assertRaises(ValueError):
                self.generate(max_attempts=attempts)

    def test_explicit_clarification_stops_without_retry_or_plan(self):
        mock = Mock(return_value=reply({"error": "两个固定地址冲突，需要澄清"}))
        outcome = workflow.generate(self.root, "Conflicting test addresses", contract={"expect": "clarification"},
                                    settings=SETTINGS, model_call=mock)
        self.assertEqual(outcome["status"], "needs_clarification")
        self.assertEqual(mock.call_count, 1)
        self.assertTrue(outcome["contract_passed"])
        self.assertFalse(outcome["first_pass"])
        self.assertFalse((Path(outcome["run"]) / "topology.yaml").exists())
        self.assertEqual(self.read(outcome["run"], "validation-1.json")["status"], "needs_clarification")

    def test_empty_or_nontext_error_does_not_pass_clarification_contract(self):
        for reason in ["", "   ", None, {}]:
            mock = Mock(return_value=reply({"error": reason}))
            outcome = workflow.generate(self.root, "Contradictory synthetic request", contract={"expect": "clarification"},
                                        settings=SETTINGS, model_call=mock)
            self.assertFalse(outcome.get("contract_passed", False))
            self.assertNotEqual(outcome["status"], "needs_clarification")

    def test_null_provider_usage_does_not_discard_valid_plan(self):
        outcome, mock = self.generate([reply(envelope={"usage": None})])
        self.assertEqual(mock.call_count, 1)
        self.assertEqual(outcome["status"], "planned")

    def test_response_secret_echo_is_redacted_from_all_run_artifacts(self):
        value = small_topology()
        value["name"] = f"Echo {TEST_KEY}"
        outcome, _ = self.generate([reply(value, {"unexpected_secret_echo": TEST_KEY})])
        for path in Path(outcome["run"]).rglob("*"):
            if path.is_file():
                self.assertNotIn(TEST_KEY.encode(), path.read_bytes(), str(path))
        self.assertIn("REDACTED_API_KEY", (Path(outcome["run"]) / "raw-output-1.txt").read_text())

    def test_transport_error_secret_is_redacted_from_all_run_artifacts(self):
        mock = Mock(side_effect=ValueError(f"Provider error; accidentally echoed {TEST_KEY}"))
        outcome = workflow.generate(self.root, "Synthetic request", settings=SETTINGS, model_call=mock)
        self.assertEqual(outcome["status"], "failed")
        for path in Path(outcome["run"]).rglob("*"):
            if path.is_file():
                self.assertNotIn(TEST_KEY.encode(), path.read_bytes(), str(path))

    def test_modified_manifest_or_draft_is_rejected_before_handoff(self):
        outcome, _ = self.generate()
        run = Path(outcome["run"])
        self.assertTrue(workflow.verify_handoff(run))
        manifest = self.read(run, "manifest.json")
        manifest["extra-unreviewed-file"] = "0" * 64
        workflow.write_json(run / "manifest.json", manifest)
        with self.assertRaises(ValueError):
            workflow.verify_handoff(run)
        outcome, _ = self.generate()
        run = Path(outcome["run"])
        path = run / "draft/SW1.cfg"
        path.write_text(path.read_text() + "\n")
        manifest = self.read(run, "manifest.json")
        manifest["draft/SW1.cfg"] = workflow.digest(path)
        workflow.write_json(run / "manifest.json", manifest)
        with self.assertRaisesRegex(ValueError, "不一致"):
            workflow.verify_handoff(run)

    def install_cases(self):
        cases = self.root / "cases"
        cases.mkdir()
        index = []
        for number, category in [(1, "benchmark"), (2, "challenge")]:
            case = cases / f"case{number}"
            case.mkdir()
            (case / "request.txt").write_text(f"Synthetic model request {number}")
            (case / "contract.json").write_text(json.dumps(contract() if number == 1 else {"expect": "clarification"}))
            (case / "expected.yaml").write_text("DELIBERATELY INVALID: must never substitute for a model response [")
            index.append({"id": f"TEST{number}", "title": f"Synthetic {number}", "course": str(number),
                          "category": category, "request_file": f"case{number}/request.txt",
                          "contract_file": f"case{number}/contract.json", "reference_file": f"case{number}/expected.yaml"})
        (cases / "index.json").write_text(json.dumps(index))

    def test_benchmark_calls_model_and_never_substitutes_reference_or_counts_challenge_as_error(self):
        self.install_cases()
        responses = [reply(), reply({"error": "Test conflict requires clarification"})]
        with patch.object(agent, "load_env", return_value=SETTINGS), patch.object(agent, "call_model", side_effect=responses) as model:
            metrics = workflow.benchmark(self.root, self.root / "evaluation", include_challenges=True, max_calls=2)
        self.assertEqual(model.call_count, 2)
        self.assertEqual(metrics["evaluated_requirements"], 1)
        self.assertEqual(metrics["topology_contract_pass_rate"], 1)
        rows = self.read(self.root / "evaluation", "results.json")["cases"]
        self.assertEqual(rows[1]["status"], "needs_clarification")
        self.assertTrue(rows[1]["contract_passed"])
        self.assertEqual(rows[1]["category"], "challenge")
        self.assertEqual(metrics["api_calls"], 2)

    def test_no_runtime_data_means_no_deployed_repair_mean(self):
        output = self.root / "evaluation"
        output.mkdir()
        data = {"mode": "live_llm", "api_calls": 3, "cases": [{
            "case_id": "TEST", "course": "4.5", "title": "Synthetic", "status": "planned",
            "attempts": 3, "first_pass": False, "contract_passed": True,
            "repair_rounds": 2, "network_runtime_verified": False,
        }]}
        workflow.write_json(output / "results.json", data)
        metrics = workflow.summarize(self.root, output)
        self.assertIsNone(metrics["mean_deployed_repair_rounds"])
        self.assertEqual(metrics["deployed_repair_denominator"], 0)
        self.assertIsNone(metrics["runtime_config_first_pass_rate"])
        self.assertEqual(metrics["runtime_config_first_pass_denominator"], 0)

    def test_offline_fixture_results_cannot_be_summarized_as_live_model_evaluation(self):
        output = self.root / "evaluation"
        output.mkdir()
        workflow.write_json(output / "results.json", {"mode": "offline_fixture", "api_calls": 0, "cases": [{
            "case_id": "OFFLINE", "course": "4.5", "title": "Fixture only", "status": "planned",
            "first_pass": True, "contract_passed": True,
        }]})
        with self.assertRaises(ValueError):
            workflow.summarize(self.root, output)

    def test_case_paths_cannot_escape_dataset(self):
        cases = self.root / "cases"
        cases.mkdir()
        with self.assertRaises(ValueError):
            workflow.safe_case_path(cases, "../agent.py")


if __name__ == "__main__":
    unittest.main()
