"""只验证程序行为。模拟模型调用不计入真实 LLM 或网络实验结果。"""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml
import agent


FIXTURE = yaml.safe_load((agent.ROOT / "examples/uc06.yaml").read_text())


class ValidationTests(unittest.TestCase):
    def test_valid_fixture(self):
        self.assertEqual(agent.validate(FIXTURE), [])

    def test_duplicate_address(self):
        data = copy.deepcopy(FIXTURE)
        data["devices"][1]["interfaces"][0]["ipv4"] = "192.168.1.1/24"
        self.assertTrue(any("地址冲突" in e for e in agent.validate(data)))

    def test_wrong_mask_and_gateway(self):
        data = copy.deepcopy(FIXTURE)
        data["devices"][1]["interfaces"][0]["ipv4"] = "192.168.1.2/25"
        self.assertTrue(any("地址/掩码" in e for e in agent.validate(data)))
        data = copy.deepcopy(FIXTURE)
        data["devices"][1]["gateway"] = "192.168.2.1"
        self.assertTrue(agent.validate(data))  # UC-06 明确不支持网关字段。

    def test_broadcast_and_network_address(self):
        for address in ["192.168.1.0/24", "192.168.1.255/24"]:
            with self.subTest(address=address):
                data = copy.deepcopy(FIXTURE)
                data["devices"][0]["interfaces"][0]["ipv4"] = address
                self.assertTrue(any("网络地址或广播地址" in e for e in agent.validate(data)))

    def test_reused_port_and_nonexistent_device(self):
        data = copy.deepcopy(FIXTURE)
        data["links"][1]["b"]["interface"] = "FastEthernet0/1"
        self.assertTrue(any("重复连接" in e for e in agent.validate(data)))
        data["links"][0]["a"]["device"] = "MISSING"
        self.assertTrue(any("不存在" in e for e in agent.validate(data)))

    def test_must_check_both_directions(self):
        data = copy.deepcopy(FIXTURE)
        data["checks"][1] = data["checks"][0]
        self.assertTrue(any("双向" in e for e in agent.validate(data)))

    def test_command_injection_and_dangerous_commands(self):
        for text in ["reload", "write erase", "format flash:", "enable\nreload", "enable; reload", "do ping 8.8.8.8", "hostname SW1\nunknown-command"]:
            with self.subTest(text=text):
                self.assertTrue(agent.check_commands(text))
        self.assertEqual(agent.check_commands(agent.render(FIXTURE)["switch.cfg"]), [])


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "examples").mkdir()
        (self.root / "examples/uc06.yaml").write_text(yaml.safe_dump(FIXTURE))
        self.patcher = patch.object(agent, "ROOT", self.root)
        self.patcher.start()
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        self.patcher.stop()
        self.temp.cleanup()

    def test_demo_is_labelled_and_has_no_fabricated_network_result(self):
        with patch.object(agent, "call_model", side_effect=AssertionError("demo 不应调用 API")):
            run = agent.run_agent(True, "fixture test")
        self.assertEqual(json.loads((run / "metadata.json").read_text())["mode"], "offline_fixture")
        verification = json.loads((run / "verification.json").read_text())
        self.assertEqual(verification["status"], "not_run")
        self.assertTrue(all(c["actual"] is None for c in verification["checks"]))
        self.assertFalse((run / "packet-tracer").exists())
        self.assertEqual(set(agent.verify_release(run)), {"switch.cfg", "pc-addresses.csv", "操作与验收.md"})

    def test_confirmation_is_required(self):
        run = agent.run_agent(True, "fixture test")
        with patch("builtins.input", return_value="no"):
            agent.release(run)
        self.assertFalse((run / "packet-tracer").exists())
        events = [json.loads(s) for s in (run / "audit.jsonl").read_text().splitlines()]
        self.assertTrue(any(e["event"] == "human_confirmation" and not e["accepted"] for e in events))

    def test_modified_draft_is_blocked_and_logged(self):
        run = agent.run_agent(True, "fixture test")
        with (run / "draft/switch.cfg").open("a") as f:
            f.write("reload\n")
        with self.assertRaisesRegex(ValueError, "命令被拦截"):
            agent.verify_release(run)
        self.assertIn("reload", (run / "audit.jsonl").read_text())

    def test_model_validation_feedback_and_bounded_retry(self):
        invalid = copy.deepcopy(FIXTURE)
        invalid["devices"][1]["interfaces"][0]["ipv4"] = "192.168.1.1/24"
        outputs = [(json.dumps(invalid), {"test_mock": True}), (json.dumps(FIXTURE), {"test_mock": True})]
        with patch.object(agent, "load_env", return_value={"LLM_MODEL": "unit-test-mock", "LLM_BASE_URL": "http://127.0.0.1"}), patch.object(agent, "call_model", side_effect=outputs) as mock:
            run = agent.run_agent(False, "unit test only; no live model")
        self.assertEqual(mock.call_count, 2)
        self.assertFalse(json.loads((run / "validation-1.json").read_text())["passed"])
        self.assertTrue(json.loads((run / "validation-2.json").read_text())["passed"])
        feedback = json.loads((run / "request-2.json").read_text())["messages"][-1]["content"]
        self.assertIn("地址冲突", feedback)
        with patch.object(agent, "load_env", return_value={"LLM_MODEL": "unit-test-mock", "LLM_BASE_URL": "http://127.0.0.1"}), patch.object(agent, "call_model", return_value=("not JSON", {"test_mock": True})) as mock:
            with self.assertRaisesRegex(ValueError, "拓扑校验未通过"):
                agent.run_agent(False, "unit test only")
        self.assertEqual(mock.call_count, 3)

    def test_model_refusal_stops_instead_of_rewriting_requirement(self):
        with patch.object(agent, "load_env", return_value={"LLM_MODEL": "unit-test-mock", "LLM_BASE_URL": "http://127.0.0.1"}), patch.object(agent, "call_model", return_value=(json.dumps({"error": "当前不支持路由器"}), {"test_mock": True})) as mock:
            with self.assertRaisesRegex(ValueError, "需求需澄清"):
                agent.run_agent(False, "unit test router")
        self.assertEqual(mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
