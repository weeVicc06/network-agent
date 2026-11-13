"""CLI integration regressions with synthetic evidence; no real API or device use."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

import agent
import cli_extensions as ext
import workflow
from tests.test_diagnostics import running
from tests.test_network_core import fixture
from tests.test_verification import windows_ping
from tests.test_workflow import small_topology


TEST_SECRET = "synthetic-cli-test-key-not-a-real-credential"


class CliIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.number = 0
        self.env = patch.object(agent, "load_env", return_value={"LLM_API_KEY": TEST_SECRET})
        self.env_mock = self.env.start()
        self.no_model = patch.object(agent, "call_model", side_effect=AssertionError("No model call is allowed"))
        self.no_model.start()
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        self.no_model.stop()
        self.env.stop()
        self.temp.cleanup()

    def compile(self, topology=None):
        self.number += 1
        path = self.root / f"authored-{self.number}.yaml"
        path.write_text(yaml.safe_dump(topology if topology is not None else fixture()), encoding="utf-8")
        output = self.root / f"run-{self.number}"
        return ext.compile_file(self.root, path, output)

    def output(self, text, name="output.txt"):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def read(self, path):
        return json.loads(path.read_text(encoding="utf-8"))

    def ping(self, run, received=4, sent=4, check_id="check-01", device="PC0"):
        output = self.output(windows_ping("192.168.2.1", received=received, sent=sent))
        return ext.import_result(self.root, run, check_id, output, device)

    def candidate(self, run, topology=None, failed_check_id=None):
        topology = topology or fixture()
        text = running(topology).replace("ip address 192.168.1.254 255.255.255.0", "ip address 192.168.1.254 255.255.255.128")
        return ext.diagnose_run(self.root, run, "R0", self.output(text, "running.txt"), failed_check_id)

    def confirm(self, run):
        with patch("builtins.input", return_value="CONFIRM"):
            ext.release_repair(run, "R0")

    def test_compile_is_offline_has_no_runtime_results_and_never_reads_api_configuration(self):
        run = self.compile()
        self.env_mock.assert_not_called()
        metadata = self.read(run / "metadata.json")
        self.assertEqual(metadata["mode"], "offline_authored_topology")
        self.assertTrue(metadata["not_a_model_response"])
        self.assertFalse(metadata["network_deployed"])
        verification = self.read(run / "verification.json")
        self.assertEqual(verification["status"], "not_run")
        self.assertTrue(all(c["actual"] is None for c in verification["checks"]))
        self.assertFalse((run / "packet-tracer").exists())
        self.assertTrue(workflow.verify_handoff(run))

    def test_agent_main_dispatches_compile_without_model_or_env_access(self):
        source = self.root / "source.yaml"
        source.write_text(yaml.safe_dump(small_topology()))
        output = self.root / "compiled-via-main"
        with patch("sys.argv", ["agent.py", "compile", str(source), "--out", str(output)]):
            self.assertEqual(agent.main(), 0)
        self.env_mock.assert_not_called()
        self.assertEqual(self.read(output / "metadata.json")["mode"], "offline_authored_topology")

    def test_verify_archives_raw_output_and_preserves_external_execution_provenance(self):
        run = self.compile()
        raw = windows_ping("192.168.2.1")
        result = ext.import_result(self.root, run, "check-01", self.output(raw), "PC0")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["execution"], "user_manual_packet_tracer")
        archived = run / result["file"]
        self.assertEqual(archived.read_text(), raw)
        self.assertEqual(result["evidence"]["sha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(self.read(archived.with_suffix(".json")), result)
        state = self.read(run / "verification.json")
        self.assertFalse(state["automatic_execution"])
        self.assertEqual(state["status"], "partial_or_unknown")  # path and route were not imported.

    def test_declared_source_wrong_cisco_prompt_and_unknown_check_are_rejected(self):
        run = self.compile()
        with self.assertRaisesRegex(ValueError, "声明设备"):
            ext.import_result(self.root, run, "check-01", self.output("anything"), "PC1")
        with self.assertRaisesRegex(ValueError, "check-id"):
            ext.import_result(self.root, run, "check-99", self.output("anything"), "PC0")
        raw = "R1#show ip route\nCodes: C - connected\nGateway of last resort is not set\nR1#\n"
        with self.assertRaisesRegex(ValueError, "提示符"):
            ext.import_result(self.root, run, "check-03", self.output(raw), "R0")
        self.assertFalse((run / "evidence/imports").exists())

    def test_changed_plan_is_rejected_before_output_is_archived(self):
        run = self.compile()
        topology = yaml.safe_load((run / "topology.yaml").read_text())
        topology["name"] = "A valid but unreviewed change"
        (run / "topology.yaml").write_text(yaml.safe_dump(topology))
        with self.assertRaises(ValueError):
            self.ping(run)
        self.assertFalse((run / "evidence/imports").exists())

    def test_modified_archived_output_or_result_cannot_inflate_acceptance_status(self):
        run = self.compile()
        result = self.ping(run)
        (run / result["file"]).write_text("Changed evidence\n")
        with self.assertRaisesRegex(ValueError, "原始输出"):
            self.ping(run)
        run = self.compile()
        self.ping(run)
        state = self.read(run / "verification.json")
        state["imported_results"]["check-01"]["status"] = "failed"
        workflow.write_json(run / "verification.json", state)
        with self.assertRaisesRegex(ValueError, "归档记录"):
            self.ping(run)

    def test_malformed_evidence_and_repair_state_raise_readable_validation_errors(self):
        run = self.compile()
        self.ping(run)
        state = self.read(run / "verification.json")
        state["imported_results"]["check-01"]["evidence"] = None
        workflow.write_json(run / "verification.json", state)
        with self.assertRaises(ValueError):
            self.ping(run)
        run = self.compile()
        self.candidate(run)
        workflow.write_json(run / "repairs/R0/state.json", {"rounds": [None], "max_rounds": 3})
        with patch("builtins.input") as confirm:
            with self.assertRaisesRegex(ValueError, "格式无效"):
                ext.release_repair(run, "R0")
            confirm.assert_not_called()

    def test_missing_output_and_http_remain_unknown(self):
        data = fixture()
        data["devices"][-1].update(type="server", model="Server-PT", services={"http": True})
        data["checks"].append({"kind": "http", "source": "PC0", "destination": "PC1", "reachable": True})
        run = self.compile(data)
        result = ext.import_result(self.root, run, "check-01", self.output(""), "PC0")
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["actual"])
        result = ext.import_result(self.root, run, "check-04", self.output("HTTP/1.1 200 OK\n"), "PC0")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(self.read(run / "verification.json")["status"], "partial_or_unknown")

    def test_credentials_and_credential_symlinks_are_rejected_without_archiving(self):
        run = self.compile()
        with self.assertRaisesRegex(ValueError, "密钥"):
            ext.import_result(self.root, run, "check-01", self.output(TEST_SECRET), "PC0")
        # This is a disposable synthetic file, never the developer's real .env.
        fake_env = self.root / ".env"
        fake_env.write_text("SYNTHETIC=not-real\n")
        alias = self.root / "pretend-output.txt"
        alias.symlink_to(fake_env)
        with self.assertRaisesRegex(ValueError, "凭据"):
            ext.import_result(self.root, run, "check-01", alias, "PC0")
        self.assertFalse((run / "evidence/imports").exists())

    def test_pending_confirmation_cancels_and_old_result_cannot_be_post_repair_evidence(self):
        run = self.compile()
        self.ping(run, received=0)
        result = self.candidate(run, failed_check_id="check-01")
        self.assertTrue(result["requires_human_confirmation"])
        with patch("builtins.input", return_value="no"):
            ext.release_repair(run, "R0")
        self.assertFalse((run / "packet-tracer/R0-repair-1.cfg").exists())
        with self.assertRaisesRegex(ValueError, "CONFIRM"):
            ext.verify_repair(run, "R0", "check-01")
        self.confirm(run)
        with self.assertRaisesRegex(ValueError, "之后新导入"):
            ext.verify_repair(run, "R0", "check-01")
        self.ping(run)
        state = ext.verify_repair(run, "R0", "check-01")
        self.assertEqual(state["status"], "external_checks_passed")
        self.assertFalse(state["automatic_repair_success"])
        self.assertFalse(state["rounds"][-1]["applied_by_program"])

    def test_passing_evidence_from_before_candidate_cannot_be_reused(self):
        run = self.compile()
        self.ping(run)
        self.candidate(run)
        self.confirm(run)
        with self.assertRaisesRegex(ValueError, "之后新导入"):
            ext.verify_repair(run, "R0", "check-01")

    def test_another_check_to_same_target_cannot_substitute_for_original_failure(self):
        data = fixture()
        data["checks"].append({"kind": "ping", "source": "R0", "destination": "PC1", "reachable": True})
        run = self.compile(data)
        self.ping(run, received=0)
        self.candidate(run, data, "check-01")
        self.confirm(run)
        raw = "R0#ping 192.168.2.1\nSending 5, 100-byte ICMP Echos to 192.168.2.1, timeout is 2 seconds:\n!!!!!\nSuccess rate is 100 percent (5/5)\nR0#\n"
        ext.import_result(self.root, run, "check-04", self.output(raw), "R0")
        with self.assertRaisesRegex(ValueError, "同一项验收"):
            ext.verify_repair(run, "R0", "check-04")

    def test_candidate_edit_or_plan_edit_blocks_handoff_and_post_repair_verification(self):
        run = self.compile()
        result = self.candidate(run)
        candidate = run / result["candidate_file"]
        original = candidate.read_text()
        candidate.write_text(original + "\n")
        with patch("builtins.input") as confirm:
            with self.assertRaisesRegex(ValueError, "候选修复已修改"):
                ext.release_repair(run, "R0")
            confirm.assert_not_called()
        candidate.write_text(original)
        self.confirm(run)
        self.ping(run)
        (run / "draft/verification-plan.json").write_text("{}")
        with self.assertRaises(ValueError):
            ext.verify_repair(run, "R0", "check-01")
        state = self.read(run / "repairs/R0/state.json")
        self.assertEqual(state["status"], "awaiting_external_verification")

    def test_three_rounds_are_bounded_and_confirmed_per_round(self):
        run = self.compile()
        self.ping(run, received=0)
        for number in range(1, 4):
            result = self.candidate(run, failed_check_id="check-01")
            self.assertEqual(result["candidate_file"], f"repairs/R0/candidate-{number}.cfg")
            self.confirm(run)
            self.ping(run, received=0, sent=4 + number)
            state = ext.verify_repair(run, "R0", "check-01")
            self.assertEqual(len(state["rounds"]), number)
        self.assertEqual(state["status"], "exhausted")
        result = self.candidate(run, failed_check_id="check-01")
        self.assertFalse(result["repairable"])
        self.assertFalse(result["requires_human_confirmation"])
        self.assertEqual(result["patch_cli"], "")
        self.assertFalse((run / "repairs/R0/candidate-4.cfg").exists())

    def test_old_uc06_is_rejected_without_overwriting_its_state_or_evidence(self):
        run = self.root / "old-uc06"
        run.mkdir()
        (run / "topology.yaml").write_text("schema_version: '0.1'\nname: legacy\n")
        (run / "verification.json").write_text('{"status":"passed_manual_ping"}\n')
        (run / "evidence").mkdir()
        (run / "evidence/original.txt").write_text("Synthetic legacy evidence\n")
        before = {str(p.relative_to(run)): p.read_bytes() for p in run.rglob("*") if p.is_file()}
        calls = [lambda: ext.import_result(self.root, run, "check-01", self.output(""), "PC0"),
                 lambda: ext.diagnose_run(self.root, run, "SW1", self.output("")),
                 lambda: ext.release_repair(run, "SW1"), lambda: ext.verify_repair(run, "SW1", "check-01")]
        for call in calls:
            with self.assertRaisesRegex(ValueError, "旧UC06"):
                call()
        after = {str(p.relative_to(run)): p.read_bytes() for p in run.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse((run / ".observation-lock").exists())

    def test_concurrent_mutation_is_rejected_instead_of_overwriting(self):
        run = self.compile()
        lock = run / ".observation-lock"
        lock.mkdir()
        before = (run / "verification.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "正在导入"):
            self.ping(run)
        self.assertTrue(lock.is_dir())
        self.assertEqual((run / "verification.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
