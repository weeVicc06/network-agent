"""Synthetic output-budget regressions; mocked HTTP/model calls, no real API usage."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import agent
import workflow
from tests.test_workflow import small_topology


SOURCE = Path(__file__).resolve().parents[1]
SETTINGS = {"LLM_BASE_URL": "https://api.deepseek.com", "LLM_MODEL": "deepseek-flash",
            "LLM_API_KEY": "synthetic-output-budget-key-not-real", "LLM_REASONING_EFFORT": "high"}


def envelope(content, reason="stop", usage=None):
    return {"choices": [{"message": {"content": content}, "finish_reason": reason}],
            "usage": usage if usage is not None else {"prompt_tokens": 50, "completion_tokens": 1000, "total_tokens": 1050}}


class TransportBudgetTests(unittest.TestCase):
    def call(self, response, settings=None, short=False):
        with patch.object(agent.request, "build_opener") as factory:
            factory.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(response).encode()
            result = agent.call_model(settings or copy.deepcopy(SETTINGS), [{"role": "user", "content": "Return JSON."}], short=short)
            req = factory.return_value.open.call_args.args[0]
        return result, json.loads(req.data)

    def test_legacy_default_limits_and_probe_behavior_are_unchanged(self):
        _, normal = self.call(envelope("OK"))
        self.assertEqual(normal["max_tokens"], 8192)
        self.assertNotIn("response_format", normal)
        _, short = self.call(envelope("OK"), {**SETTINGS, "LLM_MAX_TOKENS": 65536, "_JSON_OUTPUT": True}, short=True)
        self.assertEqual(short["max_tokens"], 128)
        self.assertEqual(short["reasoning_effort"], "none")
        self.assertNotIn("response_format", short)

    def test_custom_deepseek_limit_and_internal_json_mode_reach_request(self):
        for limit in [24000, "24000"]:
            _, payload = self.call(envelope("{}"), {**SETTINGS, "LLM_MAX_TOKENS": limit, "_JSON_OUTPUT": True})
            self.assertEqual(payload["max_tokens"], 24000)
            self.assertEqual(payload["response_format"], {"type": "json_object"})

    def test_custom_relay_does_not_receive_deepseek_specific_json_or_limit_flags(self):
        settings = {**SETTINGS, "LLM_BASE_URL": "http://127.0.0.1:12345/v1", "LLM_MAX_TOKENS": 24000,
                    "_JSON_OUTPUT": True, "_RETURN_PARTIAL": True}
        _, payload = self.call(envelope("{}"), settings)
        self.assertEqual(set(payload), {"model", "messages"})

    def test_partial_mode_returns_truncated_or_filtered_content_including_empty_text(self):
        for reason in ["length", "content_filter"]:
            for content in [None, "", '{"schema_version":']:
                response = envelope(content, reason)
                (actual_content, actual_envelope), _ = self.call(response, {**SETTINGS, "_RETURN_PARTIAL": True})
                self.assertEqual(actual_content, content or "")
                self.assertEqual(actual_envelope, response)

    def test_default_transport_still_rejects_truncated_or_filtered_output(self):
        for reason in ["length", "content_filter"]:
            with self.assertRaises(ValueError):
                self.call(envelope("part of a response", reason))


class WorkflowBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ["agent.py", "network_core.py", "workflow.py", "schema/topology-v2.schema.json"]:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / name, destination)
        self.no_env = patch.object(agent, "load_env", side_effect=AssertionError("Real .env must not be read"))
        self.no_env.start()
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        self.no_env.stop()
        self.temp.cleanup()

    def generate(self, responses, settings=None, **kwargs):
        captured = []
        iterator = iter(responses)
        def model_call(settings_arg, messages):
            captured.append({"settings": copy.deepcopy(settings_arg), "messages": copy.deepcopy(messages)})
            response = next(iterator)
            if isinstance(response, Exception):
                raise response
            content, returned_envelope = response
            return content, copy.deepcopy(returned_envelope)
        result = workflow.generate(self.root, "Synthetic output-budget requirement", settings=settings or copy.deepcopy(SETTINGS),
                                   model_call=model_call, **kwargs)
        return result, captured

    def read(self, run, filename):
        return json.loads((Path(run) / filename).read_text())

    def test_truncation_is_saved_and_limits_double_without_exceeding_three_calls(self):
        valid_json = json.dumps(small_topology())
        # Even syntactically valid JSON cannot bypass finish_reason=length.
        responses = [(valid_json, envelope(valid_json, "length"))] * 2 + [(valid_json, envelope(valid_json))]
        original = copy.deepcopy(SETTINGS)
        result, captured = self.generate(responses, settings=original)
        self.assertEqual([c["settings"]["LLM_MAX_TOKENS"] for c in captured], [16384, 32768, 65536])
        self.assertTrue(all(c["settings"]["_JSON_OUTPUT"] and c["settings"]["_RETURN_PARTIAL"] for c in captured))
        self.assertEqual(original, SETTINGS)
        self.assertEqual(result["status"], "planned")
        self.assertEqual(result["api_calls"], 3)
        self.assertFalse(result["first_pass"])
        self.assertEqual(result["usage"]["total_tokens"], 3150)
        self.assertTrue(result["usage_complete"])
        run = Path(result["run"])
        self.assertEqual((run / "raw-output-1.txt").read_text(), valid_json)
        self.assertEqual(self.read(run, "provider-response-1.json")["choices"][0]["finish_reason"], "length")
        self.assertFalse(self.read(run, "validation-1.json")["passed"])
        self.assertFalse(self.read(run, "validation-2.json")["passed"])
        self.assertTrue(self.read(run, "validation-3.json")["passed"])

    def test_repeated_truncation_never_becomes_a_plan_or_fourth_request(self):
        content = '{"schema_version":'
        response = (content, envelope(content, "length"))
        result, captured = self.generate([response] * 3)
        self.assertEqual(len(captured), 3)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["api_calls"], 3)
        self.assertFalse((Path(result["run"]) / "topology.yaml").exists())
        self.assertEqual(len(list(Path(result["run"]).glob("raw-output-*.txt"))), 3)

    def test_configured_starting_budget_is_respected_and_growth_is_capped(self):
        valid_json = json.dumps(small_topology())
        responses = [("partial", envelope("partial", "length")), (valid_json, envelope(valid_json))]
        result, captured = self.generate(responses, settings={**SETTINGS, "LLM_MAX_TOKENS": 50000})
        self.assertEqual([c["settings"]["LLM_MAX_TOKENS"] for c in captured], [50000, 65536])
        self.assertEqual(result["status"], "planned")

    def test_partial_output_usage_survives_shared_call_budget_exhaustion(self):
        content = '{"schema_version":'
        remaining = {"remaining": 1}
        result, captured = self.generate([(content, envelope(content, "length"))], call_budget=remaining)
        self.assertEqual(len(captured), 1)
        self.assertEqual(remaining["remaining"], 0)
        self.assertEqual(result["usage"]["total_tokens"], 1050)
        self.assertEqual(result["api_calls"], 1)
        self.assertTrue((Path(result["run"]) / "provider-response-1.json").is_file())

    def test_filter_is_archived_and_not_automatically_retried_even_with_valid_json(self):
        valid_json = json.dumps(small_topology())
        result, captured = self.generate([(valid_json, envelope(valid_json, "content_filter"))])
        self.assertEqual(len(captured), 1)
        self.assertNotEqual(result["status"], "planned")
        self.assertEqual(result["api_calls"], 1)
        self.assertEqual(result["usage"]["total_tokens"], 1050)
        self.assertFalse(self.read(result["run"], "validation-1.json")["passed"])
        self.assertFalse((Path(result["run"]) / "topology.yaml").exists())
        self.assertEqual(self.read(result["run"], "provider-response-1.json")["choices"][0]["finish_reason"], "content_filter")

    def test_empty_partial_content_is_still_saved_with_usage(self):
        result, captured = self.generate([("", envelope(None, "content_filter"))])
        self.assertEqual(len(captured), 1)
        self.assertEqual((Path(result["run"]) / "raw-output-1.txt").read_text(), "")
        self.assertEqual(result["usage"]["total_tokens"], 1050)

    def test_missing_usage_is_marked_incomplete_instead_of_claiming_zero_actual_cost(self):
        valid_json = json.dumps(small_topology())
        for usage in [None, {}, {"total_tokens": 23}, {"prompt_tokens": True, "completion_tokens": 2, "total_tokens": 3}]:
            response = envelope(valid_json)
            response["usage"] = usage
            result, _ = self.generate([(valid_json, response)])
            self.assertEqual(result["status"], "planned")
            self.assertFalse(result["usage_complete"])

    def test_transport_failure_has_incomplete_usage_even_if_no_response_was_received(self):
        result, captured = self.generate([TimeoutError("Synthetic timeout")])
        self.assertEqual(len(captured), 1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["api_calls"], 1)
        self.assertFalse(result["usage_complete"])


if __name__ == "__main__":
    unittest.main()
