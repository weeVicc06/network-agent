"""SYNTHETIC temporary lab fixtures ONLY: no live LLM, Packet Tracer or real evidence.

Temp source metadata deliberately simulates live_llm to exercise the provenance
guard; the synthetic_unit_test_fixture marker makes this unsuitable as coursework
evidence. No developer .env is read and every model call is forbidden.
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import yaml

import agent
import cli_extensions as ext
import lab_workflow as lab
import workflow as wf
from tests.test_diagnostics import running
from tests.test_verification import windows_ping


SOURCE = Path(__file__).resolve().parents[1]


class LabWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "synthetic-project"
        self.root.mkdir()
        self.project_patch = patch.object(lab, "PROJECT_ROOT", self.root)
        self.project_patch.start()
        self.env_patch = patch.object(agent, "load_env", return_value={"LLM_API_KEY": "synthetic-lab-key-not-real"})
        self.env_mock = self.env_patch.start()
        self.model_patch = patch.object(agent, "call_model", side_effect=AssertionError("No API calls in synthetic lab tests"))
        self.model_patch.start()
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.topologies, self.runs = {}, {}
        entries = []
        for stage, case_id in lab.CASE_IDS.items():
            destination = self.root / "cases" / case_id
            destination.mkdir(parents=True)
            for name in ["request.txt", "contract.json"]:
                shutil.copyfile(SOURCE / "cases" / case_id / name, destination / name)
            topology = yaml.safe_load((SOURCE / "cases" / case_id / "expected.yaml").read_text())
            self.topologies[stage] = topology
            run = self.make_run(case_id, topology)
            self.runs[stage] = run
            entries.append({"case_id": case_id, "run": str(run)})
        self.registry = {"synthetic_unit_test_fixture": True, "cases": entries}
        wf.write_json(self.root / "evaluations/current-agent-validation.json", self.registry)
        self.directory = self.root / "labs/unit-test-only"

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        self.model_patch.stop()
        self.env_patch.stop()
        self.project_patch.stop()
        self.temp.cleanup()

    def make_run(self, case_id, topology, name=None):
        authored = self.root / f"authored-{name or case_id}.yaml"
        authored.write_text(yaml.safe_dump(topology), encoding="utf-8")
        run = self.root / "runs" / (name or case_id)
        ext.compile_file(self.root, authored, run)
        metadata = self.read(run / "metadata.json")
        metadata.update(mode="live_llm", synthetic_unit_test_fixture=True, case_id=None)
        wf.write_json(run / "metadata.json", metadata)
        shutil.copyfile(self.root / "cases" / case_id / "request.txt", run / "requirement.txt")
        return run

    def read(self, path):
        return json.loads(path.read_text(encoding="utf-8"))

    def prepare(self, approve=False):
        lab.prepare(self.root, self.directory)
        if approve:
            with patch("builtins.input", return_value="CONFIRM"):
                self.assertTrue(lab.release(self.directory))
        return self.directory

    def test_portable_registry_paths_resolve_from_project_not_working_directory(self):
        for entry in self.registry["cases"]:
            entry["run"] = str(Path(entry["run"]).relative_to(self.root))
        wf.write_json(self.root / "evaluations/current-agent-validation.json", self.registry)
        self.prepare()
        self.assertEqual(lab.load_plan(self.directory)["project_root"], str(self.root.resolve()))

    def state(self):
        return self.read(self.directory / "state.json")

    def save_state(self, value):
        wf.write_json(self.directory / "state.json", value)

    def rehash(self, *names):
        manifest = self.read(self.directory / "manifest.json")
        for name in names:
            manifest[name] = wf.digest(self.directory / name)
        wf.write_json(self.directory / "manifest.json", manifest)

    def output(self, text):
        path = self.root / "synthetic-output.txt"
        path.write_text(text, encoding="utf-8")
        return path

    def check_output(self, check, *, reachable=True):
        if check["kind"] == "ping":
            return windows_ping(check["target"], received=4 if reachable else 0)
        if check["kind"] == "route":
            source = check["source"]
            entry = ""
            if check.get("present", True):
                entry = f"R {check['prefix']} [120/1] via {check['next_hop']}\n"
            return f"{source}#show ip route\nCodes: C - connected, R - RIP\nGateway of last resort is not set\n{entry}{source}#\n"
        raise AssertionError("This synthetic helper supports ping/route only")

    def healthy(self):
        plan = lab.load_plan(self.directory)
        for check in plan["stages"]["ripv2"]["checks"]:
            lab.import_result(self.root, self.directory, "ripv2", check["id"], check["source"],
                              self.output(self.check_output(check)))

    def fault(self):
        check = lab.load_plan(self.directory)["stages"]["fault"]["checks"][0]
        return lab.import_result(self.root, self.directory, "fault", check["id"], check["source"],
                                 self.output(self.check_output(check, reachable=False)))

    def test_resume_retries_unfinished_checks_and_verifies_skipped_evidence(self):
        self.prepare(approve=True)
        checks = lab.stage_checks(self.directory, "ripv2")
        observations = [self.check_output(checks[0]), self.check_output(checks[1], reachable=False), "incomplete route output\n"]
        for check, text in zip(checks, observations):
            lab.import_result(self.root, self.directory, "ripv2", check["id"], check["source"], self.output(text))
        self.assertEqual(lab.stage_checks(self.directory, "ripv2", resume=True), checks[1:])
        self.assertEqual(lab.stage_checks(self.directory, "ripv2"), checks)

        passed = self.state()["results"]["ripv2"][checks[0]["id"]]
        (self.runs["ripv2"] / passed["file"]).write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "原始输出缺失或已篡改"):
            lab.stage_checks(self.directory, "ripv2", resume=True)

    def test_resume_fault_only_skips_confirmed_unreachability(self):
        self.prepare(approve=True)
        self.healthy()
        check, = lab.stage_checks(self.directory, "fault")
        lab.import_result(self.root, self.directory, "fault", check["id"], check["source"],
                          self.output(self.check_output(check)))
        self.assertEqual(lab.stage_checks(self.directory, "fault", resume=True), [check])
        self.fault()
        self.assertEqual(lab.stage_checks(self.directory, "fault", resume=True), [])

    def diagnose(self):
        text = running(self.topologies["ripv2"], "R0").replace("ip address 192.168.16.126 255.255.255.128",
                                                                    "ip address 192.168.16.126 255.255.255.192")
        path = self.root / "synthetic-running.txt"
        path.write_text(text, encoding="utf-8")
        return lab.diagnose(self.root, self.directory, "R0", path)

    def confirmed_candidate(self):
        self.prepare(approve=True)
        self.healthy()
        self.fault()
        result = self.diagnose()
        self.assertTrue(result["repairable"])
        with patch("builtins.input", return_value="CONFIRM"):
            lab.release_repair(self.directory, "R0")

    def repaired(self):
        check = lab.load_plan(self.directory)["stages"]["repaired"]["checks"][0]
        return lab.import_result(self.root, self.directory, "repaired", check["id"], check["source"],
                                 self.output(self.check_output(check)))

    def test_prepare_does_not_confirm_deploy_or_invent_runtime_data(self):
        original = {name: ((run / "metadata.json").read_bytes(), (run / "verification.json").read_bytes())
                    for name, run in self.runs.items()}
        self.prepare()
        self.env_mock.assert_not_called()
        self.assertIsNone(self.state()["approval"])
        self.assertEqual(self.state()["results"], {})
        self.assertFalse((self.directory / "ready").exists())
        self.assertFalse(lab.load_plan(self.directory)["network_executed"])
        self.assertFalse(lab.status(self.directory)["automatic_execution"])
        for name, run in self.runs.items():
            self.assertEqual((run / "metadata.json").read_bytes(), original[name][0])
            self.assertEqual((run / "verification.json").read_bytes(), original[name][1])

    def test_release_cancel_and_confirmation_only_create_local_handoff(self):
        self.prepare()
        with patch("builtins.input", return_value="no"):
            self.assertFalse(lab.release(self.directory))
        self.assertIsNone(self.state()["approval"])
        self.assertFalse((self.directory / "ready").exists())
        with patch("builtins.input", return_value="CONFIRM"):
            self.assertTrue(lab.release(self.directory))
        state = self.state()
        self.assertEqual(state["approval"]["source"], "human_terminal_CONFIRM")
        self.assertEqual(state["results"], {})
        self.assertEqual(lab.status(self.directory)["stages"]["ripv2"]["status"], "incomplete_or_not_passed")
        self.assertTrue((self.directory / "ready/fault/R0.cfg").is_file())
        for run in self.runs.values():
            self.assertFalse(self.read(run / "metadata.json")["network_deployed"])

    def test_forged_approval_without_matching_confirm_audit_is_rejected(self):
        self.prepare()
        state = self.state()
        state["approval"] = {"manifest_sha256": wf.digest(self.directory / "manifest.json"),
                             "source": "human_terminal_CONFIRM", "time_utc": wf.stamp(), "confirmation_id": "invented"}
        self.save_state(state)
        with self.assertRaisesRegex(ValueError, "CONFIRM审计"):
            lab.import_result(self.root, self.directory, "ripv1", "check-01", "PC0", self.output(""))

    def test_canonical_compiler_blocks_cli_change_even_with_recomputed_manifest(self):
        self.prepare()
        path = self.directory / "review/ripv2/R0.cfg"
        path.write_text(path.read_text() + "\n")
        self.rehash("review/ripv2/R0.cfg")
        with self.assertRaisesRegex(ValueError, "规范|不一致"):
            lab.load_plan(self.directory)

    def test_stage_cli_file_list_and_expected_checks_cannot_be_redefined(self):
        self.prepare()
        plan = self.read(self.directory / "plan.json")
        plan["stages"]["ripv2"]["cli_files"] = ["R0.cfg"]
        wf.write_json(self.directory / "plan.json", plan)
        self.rehash("plan.json")
        with self.assertRaisesRegex(ValueError, "CLI清单"):
            lab.load_plan(self.directory)
        plan["stages"]["ripv2"]["cli_files"] = ["R0.cfg", "R1.cfg", "R2.cfg"]
        plan["stages"]["ripv2"]["checks"][0]["reachable"] = False
        wf.write_json(self.directory / "plan.json", plan)
        checks_path = self.directory / "review/ripv2/checks.json"
        document = self.read(checks_path)
        document["checks"] = plan["stages"]["ripv2"]["checks"]
        wf.write_json(checks_path, document)
        self.rehash("plan.json", "review/ripv2/checks.json")
        with self.assertRaises(ValueError):
            lab.load_plan(self.directory)

    def test_manifest_cannot_include_extra_unreviewed_file(self):
        self.prepare()
        (self.directory / "extra.cfg").write_text("enable\n")
        self.rehash("extra.cfg")
        with self.assertRaisesRegex(ValueError, "文件集合"):
            lab.load_plan(self.directory)

    def test_plan_source_cannot_escape_actual_project_runs(self):
        self.prepare()
        plan = self.read(self.directory / "plan.json")
        plan["stages"]["ripv1"]["source_run"] = str(Path(self.temp.name) / "outside-run")
        wf.write_json(self.directory / "plan.json", plan)
        self.rehash("plan.json")
        with self.assertRaises(ValueError):
            lab.load_plan(self.directory)
        registry = copy.deepcopy(self.registry)
        registry["cases"][0]["run"] = str(Path(self.temp.name) / "outside-run")
        wf.write_json(self.root / "evaluations/current-agent-validation.json", registry)
        with self.assertRaisesRegex(ValueError, "runs目录"):
            lab.load_plan(self.directory)

    def test_runs_directory_itself_cannot_be_an_escape_symlink(self):
        outside = Path(self.temp.name) / "outside-runs"
        (self.root / "runs").rename(outside)
        (self.root / "runs").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "软链接逃逸"):
            self.prepare()

    def test_source_live_mode_request_and_current_contract_are_checked(self):
        metadata = self.read(self.runs["ripv1"] / "metadata.json")
        metadata["mode"] = "offline_authored_topology"
        wf.write_json(self.runs["ripv1"] / "metadata.json", metadata)
        with self.assertRaisesRegex(ValueError, "离线fixture"):
            self.prepare()
        metadata["mode"] = "live_llm"
        wf.write_json(self.runs["ripv1"] / "metadata.json", metadata)
        (self.runs["ripv1"] / "requirement.txt").write_text("Wrong synthetic requirement")
        with self.assertRaisesRegex(ValueError, "来源需求"):
            self.prepare()
        shutil.copyfile(self.root / "cases/CASE04/request.txt", self.runs["ripv1"] / "requirement.txt")
        wrong = self.make_run("CASE04", self.topologies["ripv2"], name="same-hardware-wrong-protocol")
        registry = copy.deepcopy(self.registry)
        registry["cases"][0]["run"] = str(wrong)
        wf.write_json(self.root / "evaluations/current-agent-validation.json", registry)
        with self.assertRaisesRegex(ValueError, "需求契约"):
            self.prepare()

    def test_plan_change_during_confirm_requires_new_review(self):
        self.prepare()
        def change_during_prompt(_):
            plan = self.read(self.directory / "plan.json")
            plan["created_at_utc"] += " "
            wf.write_json(self.directory / "plan.json", plan)
            self.rehash("plan.json")
            return "CONFIRM"
        with patch("builtins.input", side_effect=change_during_prompt):
            with self.assertRaisesRegex(ValueError, "确认期间"):
                lab.release(self.directory)
        self.assertIsNone(self.state()["approval"])
        self.assertFalse((self.directory / "ready").exists())

    def test_fault_requires_all_four_healthy_checks_before_paste_or_import(self):
        self.prepare(approve=True)
        with patch.object(lab, "_collect_text") as paste:
            with self.assertRaisesRegex(ValueError, "四项健康基线"):
                lab.collect(self.root, self.directory, "fault", "check-01", "PC0")
            paste.assert_not_called()
        with self.assertRaisesRegex(ValueError, "四项健康基线"):
            self.fault()
        self.healthy()
        self.assertEqual(self.fault()["status"], "failed")
        self.assertEqual(lab.status(self.directory)["stages"]["fault"]["status"], "fault_exposed")

    def test_fault_gate_revalidates_archived_raw_not_just_passed_fields(self):
        self.prepare(approve=True)
        self.healthy()
        healthy = self.state()["results"]["ripv2"]["check-03"]
        path = self.runs["ripv2"] / healthy["file"]
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "原始输出"):
            self.fault()

    def test_status_does_not_count_deleted_or_hash_modified_attachments_as_received(self):
        self.prepare(approve=True)
        fake_pkt = self.root / "SYNTHETIC-NOT-A-REAL-PROJECT.pkt"
        fake_pkt.write_bytes(b"SYNTHETIC unit-test bytes, not a Packet Tracer capture")
        receipt = lab.attach(self.directory, "ripv2", fake_pkt)
        snapshot = lab.status(self.directory)
        self.assertEqual(snapshot["stages"]["ripv2"]["pkt_files_received"], 1)
        self.assertFalse(snapshot["attachment_contents_independently_verified"])
        path = self.directory / receipt["file"]
        path.write_bytes(b"Changed synthetic attachment")
        snapshot = lab.status(self.directory)
        self.assertEqual(snapshot["stages"]["ripv2"]["pkt_files_received"], 0)
        self.assertTrue(snapshot["invalid_attachments"])
        path.unlink()
        self.assertEqual(lab.status(self.directory)["stages"]["ripv2"]["pkt_files_received"], 0)

    def test_diagnose_and_repair_release_require_consistent_fault_device(self):
        self.prepare(approve=True)
        self.healthy()
        self.fault()
        with patch.object(lab, "_collect_text") as paste:
            with self.assertRaisesRegex(ValueError, "仅针对R0"):
                lab.diagnose(self.root, self.directory, "R1")
            paste.assert_not_called()
        self.assertTrue(self.diagnose()["repairable"])
        with patch("builtins.input") as confirm:
            with self.assertRaisesRegex(ValueError, "设备或来源run"):
                lab.release_repair(self.directory, "R1")
            confirm.assert_not_called()

    def test_repair_verify_requires_manual_declaration_and_same_current_source_file(self):
        self.confirmed_candidate()
        record = self.repaired()
        with self.assertRaisesRegex(ValueError, "applied-manually"):
            lab.verify_repair(self.directory, "R0", "check-01")
        # A second, otherwise valid source import must not silently substitute
        # for the specific repaired-stage capture registered in this lab.
        ext.import_result(self.root, self.runs["ripv2"], "check-01", self.output(windows_ping("192.168.16.129")), "PC0")
        with self.assertRaisesRegex(ValueError, "同一原始输出文件"):
            lab.verify_repair(self.directory, "R0", "check-01", applied_manually=True)
        self.assertIsNone(self.state()["repair"]["verification"])
        self.assertEqual(self.state()["results"]["repaired"]["check-01"]["file"], record["file"])

    def test_successful_synthetic_repair_still_never_claims_automatic_application(self):
        self.confirmed_candidate()
        self.repaired()
        result = lab.verify_repair(self.directory, "R0", "check-01", applied_manually=True)
        self.assertEqual(result["status"], "external_checks_passed")
        self.assertFalse(result["automatic_repair_success"])
        self.assertFalse(self.state()["repair"]["application_declaration"]["applied_by_program"])
        self.assertFalse(self.read(self.runs["ripv2"] / "metadata.json")["network_deployed"])


if __name__ == "__main__":
    unittest.main()
