"""Human-authored regression requirements are never counted as live LLM runs."""
import copy
import json
from pathlib import Path
import unittest

import yaml

import network_core
import workflow


CASES = Path(__file__).resolve().parents[1] / "cases"
INDEX = json.loads((CASES / "index.json").read_text(encoding="utf-8"))


def load_reference(case_id):
    case = next(c for c in INDEX if c["id"] == case_id)
    return yaml.safe_load((CASES / case["reference_file"]).read_text(encoding="utf-8"))


class CaseDatasetTests(unittest.TestCase):
    def test_ten_benchmarks_cover_five_actual_course_experiments(self):
        benchmarks = [c for c in INDEX if c["category"] == "benchmark"]
        self.assertEqual(len(benchmarks), 10)
        self.assertEqual({c["course"] for c in benchmarks}, {"4.5", "4.10", "4.11", "6.6", "7.1"})
        self.assertEqual(len({c["id"] for c in INDEX}), len(INDEX))
        self.assertGreaterEqual(sum(c["first_pass_candidate"] for c in benchmarks), 3)

    def test_case_paths_are_contained_and_inputs_are_not_reference_answers(self):
        for case in INDEX:
            with self.subTest(case=case["id"]):
                for field in ["request_file", "reference_file", "contract_file"]:
                    path = (CASES / case[field]).resolve()
                    self.assertTrue(path.is_relative_to(CASES.resolve()))
                    self.assertTrue(path.is_file())
                request = (CASES / case["request_file"]).read_text(encoding="utf-8")
                self.assertTrue(request.strip())
                self.assertLess(len(request), 20000)
                self.assertNotIn("schema_version", request)
                self.assertTrue(case["adaptation"].strip())

    def test_all_human_references_validate_and_compile_through_guardrails(self):
        for case in INDEX:
            if case["category"] != "benchmark":
                continue
            with self.subTest(case=case["id"]):
                reference = load_reference(case["id"])
                self.assertEqual(network_core.validate(reference), [])
                files = network_core.render(reference)
                self.assertTrue(files)
                for filename, text in files.items():
                    if filename.endswith(".cfg"):
                        self.assertEqual(network_core.check_commands(text), [])

    def test_contracts_constrain_intent_without_arbitrary_display_values(self):
        for case in INDEX:
            if case["category"] != "benchmark":
                continue
            with self.subTest(case=case["id"]):
                contract = json.loads((CASES / case["contract_file"]).read_text(encoding="utf-8"))
                expected = load_reference(case["id"])
                expected.pop("name")
                if any(d["type"] == "switch" for d in expected["devices"]):
                    expected["vlans"] = [{"id": v["id"]} for v in expected["vlans"]]
                else:
                    expected.pop("vlans")
                for device in expected["devices"]:
                    if device.get("routing", {}).get("protocol") == "rip":
                        device["routing"].pop("networks")
                    if case["id"] in {"CASE03", "CASE04", "CASE05", "CASE06"} and device["type"] == "router":
                        device["routing"]["static_routes"] = []
                    if case["id"] == "CASE05" and device["type"] == "router":
                        for interface in device["interfaces"]:
                            interface.setdefault("ospf_cost", 1)
                self.assertEqual(contract["expect"], "plan")
                self.assertEqual(contract["required"], expected)
                self.assertEqual(set(contract["exact_device_ids"]), {d["id"] for d in expected["devices"]})
                self.assertEqual(contract["reference_provenance"], "human_authored_reference_not_llm_output")
                self.assertNotIn("name", contract["required"])
                self.assertTrue(all(set(v) == {"id"} for v in contract["required"].get("vlans", [])))
                self.assertEqual(contract["counts"]["checks"], len(expected["checks"]))
                self.assertEqual(workflow.check_contract(load_reference(case["id"]), contract), [])

    def test_rip_comparison_keeps_vlsm_and_intentional_failure(self):
        v2, v1 = load_reference("CASE03"), load_reference("CASE04")
        v2_devices = {d["id"]: d for d in v2["devices"]}
        self.assertEqual(v1["links"], v2["links"])
        for device in v1["devices"]:
            self.assertEqual(device["interfaces"], v2_devices[device["id"]]["interfaces"])
            if device["type"] == "router":
                self.assertEqual(device["routing"]["version"], 1)
                self.assertTrue(device["routing"]["auto_summary"])
                self.assertEqual(v2_devices[device["id"]]["routing"]["version"], 2)
                self.assertFalse(v2_devices[device["id"]]["routing"]["auto_summary"])
        self.assertTrue(all(not c["reachable"] for c in v1["checks"] if c["kind"] == "ping"))
        absent_routes = [c for c in v1["checks"] if c["kind"] == "route"]
        self.assertEqual(len(absent_routes), 2)
        self.assertEqual({(c["source"], c["prefix"]) for c in absent_routes}, {("R0", "192.168.16.128/26"), ("R1", "192.168.16.0/25")})
        self.assertTrue(all(c["present"] is False for c in absent_routes))
        self.assertTrue(all("protocol" not in c and "next_hop" not in c for c in absent_routes))
        v2_cfg = network_core.render(v2)["R0.cfg"]
        v1_cfg = network_core.render(v1)["R0.cfg"]
        self.assertIn("network 192.168.16.0\n", v2_cfg)
        self.assertIn("version 2\nno auto-summary", v2_cfg)
        self.assertIn("version 1\nauto-summary", v1_cfg)
        self.assertNotIn("network 192.168.16.128", v2_cfg)

    def test_ospf_costs_wildcards_and_area_boundary_are_explicit(self):
        topology = load_reference("CASE05")
        configs = network_core.render(topology)
        self.assertIn("ip ospf cost 64", configs["R0.cfg"])
        self.assertIn("ip ospf cost 64", configs["R1.cfg"])
        self.assertIn("network 192.168.16.0 0.0.0.127 area 0", configs["R0.cfg"])
        self.assertIn("network 192.168.16.128 0.0.0.63 area 0", configs["R1.cfg"])
        self.assertIn("network 10.0.0.0 0.0.0.3 area 0", configs["R0.cfg"])
        self.assertEqual(next(c for c in topology["checks"] if c["kind"] == "route" and c["source"] == "R0")["next_hop"], "10.0.0.2")
        multiarea = load_reference("CASE06")
        r1_cfg = network_core.render(multiarea)["R1.cfg"]
        self.assertIn("network 10.0.0.0 0.0.0.3 area 0", r1_cfg)
        self.assertIn("network 172.16.0.0 0.0.0.3 area 100", r1_cfg)
        self.assertIn("ospf_inter_area", [c.get("protocol") for c in multiarea["checks"]])

    def test_http_and_icmp_are_not_conflated(self):
        checks = load_reference("CASE09")["checks"]
        self.assertEqual(next(c for c in checks if c["kind"] == "ping")["reachable"], False)
        self.assertEqual(next(c for c in checks if c["kind"] == "http")["reachable"], True)
        http_reference = load_reference("CASE07")
        self.assertEqual(len(http_reference["devices"]), 2)
        server = next(d for d in http_reference["devices"] if d["id"] == "Server0")
        self.assertEqual(server["services"], {"http": True})

    def test_acl_matrix_keeps_order_and_specific_router_interface_target(self):
        topology = load_reference("CASE10")
        rules = topology["acls"][0]["rules"]
        self.assertEqual(len(rules), 6)
        self.assertEqual([r.get("destination_port") for r in rules[:3]], [80, 20, 21])
        self.assertEqual([r["action"] for r in rules], ["deny"] * 5 + ["permit"])
        self.assertEqual(topology["acls"][0]["interface"], "GigabitEthernet0/1")
        self.assertEqual(topology["acls"][0]["direction"], "in")
        check = next(c for c in topology["checks"] if c.get("target_ipv4"))
        self.assertEqual(check["destination"], "R1")
        self.assertEqual(check["target_ipv4"], "10.0.0.2")
        self.assertFalse(check["reachable"])

    def test_challenges_expect_clarification_not_fabricated_llm_failures(self):
        challenges = [c for c in INDEX if c["category"] == "challenge"]
        self.assertEqual(len(challenges), 2)
        for case in challenges:
            contract = json.loads((CASES / case["contract_file"]).read_text(encoding="utf-8"))
            self.assertEqual(contract["expect"], "clarification")
            self.assertEqual(contract["required"], {})
            self.assertEqual(contract["reference_provenance"], "human_authored_expectation_not_llm_output")

    def test_contract_rejects_unsolicited_static_routes_that_bypass_protocol(self):
        for case_id in ["CASE03", "CASE04", "CASE05"]:
            with self.subTest(case=case_id):
                topology = load_reference(case_id)
                contract = json.loads((CASES / case_id / "contract.json").read_text(encoding="utf-8"))
                next(d for d in topology["devices"] if d["id"] == "R0")["routing"]["static_routes"] = [{"prefix": "192.168.16.128/26", "next_hop": "30.0.0.2"}]
                next(d for d in topology["devices"] if d["id"] == "R1")["routing"]["static_routes"] = [{"prefix": "192.168.16.0/25", "next_hop": "30.0.0.1"}]
                self.assertTrue(workflow.check_contract(topology, contract))

    def test_contract_rejects_forbidden_default_route_in_cidr_baseline(self):
        topology = load_reference("CASE02")
        contract = json.loads((CASES / "CASE02/contract.json").read_text(encoding="utf-8"))
        next(d for d in topology["devices"] if d["id"] == "R0")["routing"]["static_routes"].append({"prefix": "0.0.0.0/0", "next_hop": "218.75.230.82"})
        self.assertTrue(workflow.check_contract(topology, contract))

    def test_contract_rejects_nondefault_cost_that_changes_ospf_path(self):
        topology = load_reference("CASE05")
        contract = json.loads((CASES / "CASE05/contract.json").read_text(encoding="utf-8"))
        r2 = next(d for d in topology["devices"] if d["id"] == "R2")
        next(i for i in r2["interfaces"] if i["name"] == "GigabitEthernet0/1")["ospf_cost"] = 100
        self.assertTrue(workflow.check_contract(topology, contract))

    def test_contract_rejects_extra_contradictory_ripv1_route_assertion(self):
        topology = load_reference("CASE04")
        contract = json.loads((CASES / "CASE04/contract.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["counts"]["checks"], 4)
        topology["checks"].append({"kind": "route", "source": "R0", "prefix": "192.168.16.128/26", "present": True, "protocol": "rip"})
        self.assertTrue(workflow.check_contract(topology, contract))


if __name__ == "__main__":
    unittest.main()
