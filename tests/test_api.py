"""接口配置和传输的隔离测试；不使用真实密钥，不发送真实请求。"""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import agent


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root_patch = patch.object(agent, "ROOT", self.root)
        self.root_patch.start()
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.root_patch.stop()
        self.temp.cleanup()

    def test_local_configuration_is_private_and_never_echoes_key(self):
        key = "unit-test-dummy-key-not-real"
        output = io.StringIO()
        with patch.object(agent.sys.stdin, "isatty", return_value=True), patch("builtins.input", return_value=""), patch.object(agent.getpass, "getpass", return_value=key), contextlib.redirect_stdout(output):
            agent.configure_api()
        self.assertNotIn(key, output.getvalue())
        self.assertEqual(stat.S_IMODE((self.root / ".env").stat().st_mode), 0o600)
        self.assertEqual(agent.load_env()["LLM_BASE_URL"], "https://api.deepseek.com")
        self.assertEqual(agent.load_env()["LLM_MODEL"], "deepseek-flash")
        self.assertEqual(agent.load_env()["LLM_REASONING_EFFORT"], "high")
        with self.assertRaisesRegex(ValueError, "已存在"):
            agent.configure_api()

    def test_config_read_does_not_poison_process_environment(self):
        path = self.root / ".env"
        path.write_text("LLM_BASE_URL=https://api.openai.com/v1\nLLM_MODEL=one\nLLM_API_KEY=dummy\n")
        self.assertEqual(agent.load_env()["LLM_MODEL"], "one")
        path.write_text("LLM_BASE_URL=https://api.openai.com/v1\nLLM_MODEL=two\nLLM_API_KEY=dummy\n")
        self.assertEqual(agent.load_env()["LLM_MODEL"], "two")
        self.assertNotIn("LLM_API_KEY", os.environ)
        with patch.dict(os.environ, {"LLM_MODEL": "shell-value"}):
            self.assertEqual(agent.load_env()["LLM_MODEL"], "shell-value")

    def test_unsafe_remote_transport_and_url_credentials_are_rejected(self):
        for url in ["http://example.com/v1", "https://key@example.com/v1", "https://example.com/v1?key=secret"]:
            with self.subTest(url=url), patch.dict(os.environ, {"LLM_BASE_URL": url, "LLM_MODEL": "test", "LLM_API_KEY": "dummy"}):
                with self.assertRaisesRegex(ValueError, "Base URL"):
                    agent.load_env()

    def test_noninteractive_configuration_is_rejected(self):
        with patch.object(agent.sys.stdin, "isatty", return_value=False), self.assertRaisesRegex(ValueError, "交互终端"):
            agent.configure_api()

    def test_custom_endpoint_is_saved_without_replacing_it_with_official(self):
        with patch.object(agent.sys.stdin, "isatty", return_value=True), patch("builtins.input", return_value=""), patch.object(agent.getpass, "getpass", return_value="unit-test-dummy-key-not-real"), contextlib.redirect_stdout(io.StringIO()):
            agent.configure_api("http://127.0.0.1:12345/v1", "relay/deepseek-flash")
        result = agent.load_env()
        self.assertEqual(result["LLM_BASE_URL"], "http://127.0.0.1:12345/v1")
        self.assertEqual(result["LLM_MODEL"], "relay/deepseek-flash")

    def test_full_endpoint_is_not_mistaken_for_base_url(self):
        with self.assertRaisesRegex(ValueError, "前缀"):
            agent.validate_base_url("https://api.deepseek.com/chat/completions")


class TransportTests(unittest.TestCase):
    settings = {"LLM_BASE_URL": "https://api.openai.com/v1", "LLM_MODEL": "gpt-6-luna", "LLM_API_KEY": "unit-test-dummy-key-not-real"}

    def test_deepseek_probe_and_generation_use_correct_reasoning_modes(self):
        settings = {**self.settings, "LLM_BASE_URL": "https://api.deepseek.com", "LLM_MODEL": "deepseek-flash"}
        envelope = {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]}
        for short, effort, limit in [(True, "none", 128), (False, "high", 8192)]:
            with self.subTest(short=short), patch.object(agent.request, "build_opener") as factory:
                factory.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(envelope).encode()
                agent.call_model(settings, [{"role": "user", "content": "test"}], short=short)
                req = factory.return_value.open.call_args.args[0]
                self.assertEqual(req.full_url, "https://api.deepseek.com/chat/completions")
                payload = json.loads(req.data)
                self.assertEqual(payload["reasoning_effort"], effort)
                self.assertEqual(payload["max_tokens"], limit)
                self.assertNotIn("max_completion_tokens", payload)

    def test_custom_relay_does_not_receive_unverified_provider_specific_parameters(self):
        settings = {**self.settings, "LLM_BASE_URL": "http://127.0.0.1:12345/v1", "LLM_MODEL": "relay/deepseek-flash"}
        envelope = {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]}
        with patch.object(agent.request, "build_opener") as factory:
            factory.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(envelope).encode()
            agent.call_model(settings, [{"role": "user", "content": "test"}], short=True)
        req = factory.return_value.open.call_args.args[0]
        self.assertEqual(req.full_url, "http://127.0.0.1:12345/v1/chat/completions")
        self.assertEqual(set(json.loads(req.data)), {"model", "messages"})

    def test_probe_uses_exact_endpoint_and_small_limit(self):
        envelope = {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}], "usage": {"total_tokens": 12}}
        with patch.object(agent.request, "build_opener") as factory:
            factory.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(envelope).encode()
            content, _ = agent.call_model(self.settings, [{"role": "user", "content": "Reply OK"}], short=True)
        req = factory.return_value.open.call_args.args[0]
        self.assertEqual(req.full_url, "https://api.openai.com/v1/chat/completions")
        payload = json.loads(req.data)
        self.assertEqual(payload["max_completion_tokens"], 128)
        self.assertEqual(payload["reasoning_effort"], "none")
        self.assertNotIn(self.settings["LLM_API_KEY"], req.data.decode())
        self.assertEqual(content, "OK")

    def test_quota_error_does_not_echo_server_text_or_key(self):
        message = {"error": {"code": "insufficient_quota", "message": self.settings["LLM_API_KEY"]}}
        failure = HTTPError("https://api.openai.com/v1/chat/completions", 429, "test", {}, io.BytesIO(json.dumps(message).encode()))
        with patch.object(agent.request, "build_opener") as factory:
            factory.return_value.open.side_effect = failure
            with self.assertRaisesRegex(ValueError, "额度不足") as caught:
                agent.call_model(self.settings, [])
        self.assertNotIn(self.settings["LLM_API_KEY"], str(caught.exception))

    def test_connectivity_check_does_not_dump_provider_content(self):
        output = io.StringIO()
        with patch.object(agent, "load_env", return_value=self.settings), patch.object(agent, "call_model", return_value=("not-for-terminal", {"usage": {"total_tokens": 12, "other": "hidden"}})) as mock, contextlib.redirect_stdout(output):
            agent.check_api()
        self.assertEqual(mock.call_count, 1)
        self.assertTrue(mock.call_args.kwargs["short"])
        self.assertIn("连接成功", output.getvalue())
        self.assertNotIn("not-for-terminal", output.getvalue())
        self.assertNotIn(self.settings["LLM_API_KEY"], output.getvalue())


if __name__ == "__main__":
    unittest.main()
