"""Synthetic parser fixtures only; these tests are not network experiment evidence."""
import copy
import hashlib
import unittest

from verification import (verify_text, new_repair_state, propose_repair,
                          record_repair_verification)


def windows_ping(target="192.168.1.2", received=4, delay=1, sent=4):
    replies = "\n".join(f"Reply from {target}: bytes=32 time={delay}ms TTL=128" for _ in range(received))
    lost = sent - received
    return f"""C:\\>ping {target}
Pinging {target} with 32 bytes of data:
{replies}
Ping statistics for {target}:
    Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({int(100 * lost / sent)}% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 2ms, Average = 0ms
C:\\>
"""


def route_text(entries, header=""):
    return f"""R1#show ip route
Codes: C - connected, L - local, S - static, R - RIP, O - OSPF
Gateway of last resort is not set
{header}
{entries}
R1#
"""


class PingTests(unittest.TestCase):
    def test_windows_success(self):
        result = verify_text("ping", windows_ping(), {"target": "192.168.1.2"})
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["observed"]["received"], 4)
        self.assertEqual(result["observed"]["loss_percent"], 0)
        self.assertEqual(result["execution"], "external_manual")
        self.assertEqual(len(result["evidence"]["sha256"]), 64)

    def test_reachability_is_not_zero_loss_assertion(self):
        result = verify_text("ping", windows_ping(received=3), {"target": "192.168.1.2"})
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["observed"]["loss_percent"], 25)

    def test_complete_failure_and_expected_isolation(self):
        output = windows_ping(received=0)
        self.assertEqual(verify_text("ping", output, {"target": "192.168.1.2"})["status"], "failed")
        self.assertEqual(verify_text("ping", output, {"target": "192.168.1.2", "reachable": False})["status"], "passed")

    def test_missing_truncated_wrong_target_and_mixed_outputs_are_unknown(self):
        for output in ["", windows_ping().split("Ping statistics")[0],
                       windows_ping("192.168.1.3"), windows_ping() + windows_ping()]:
            with self.subTest(output=output[:50]):
                result = verify_text("ping", output, {"target": "192.168.1.2"})
                self.assertEqual(result["status"], "unknown")
                self.assertIsNone(result["actual"])

    def test_inconsistent_counters_or_missing_replies_are_unknown(self):
        for output in [windows_ping().replace("Received = 4", "Received = 3"),
                       windows_ping().replace("(0% loss)", "(75% loss)"),
                       windows_ping().replace("Reply from", "Removed", 1)]:
            self.assertEqual(verify_text("ping", output, {"target": "192.168.1.2"})["status"], "unknown")

    def test_cisco_success_and_failure(self):
        template = """R1#ping 10.0.0.2
Type escape sequence to abort.
Sending 5, 100-byte ICMP Echos to 10.0.0.2, timeout is 2 seconds:
{symbols}
Success rate is {rate} percent ({received}/5), round-trip min/avg/max = 1/2/4 ms
R1#
"""
        for received, symbols, status in [(5, "!!!!!", "passed"), (0, ".....", "failed")]:
            output = template.format(symbols=symbols, rate=received * 20, received=received)
            result = verify_text("ping", output, {"target": "10.0.0.2"})
            self.assertEqual(result["status"], status)

    def test_invalid_expectation_and_unrelated_text_are_unknown(self):
        for kind, expected in [("unknown", {}), ("ping", {}), ("ping", {"target": "server.local"}),
                               ("ping", {"target": "192.168.1.2", "reachable": "yes"})]:
            self.assertEqual(verify_text(kind, windows_ping(), expected)["status"], "unknown")


class TraceTests(unittest.TestCase):
    WINDOWS = """C:\\>tracert 192.168.2.2
Tracing route to 192.168.2.2 over a maximum of 30 hops:
  1    1 ms    0 ms    1 ms    192.168.1.254
  2    2 ms    1 ms    1 ms    192.168.2.2
Trace complete.
C:\\>
"""

    def test_exact_path_and_true_mismatch(self):
        expected = {"target": "192.168.2.2", "expected_hops": ["192.168.1.254", "192.168.2.2"]}
        self.assertEqual(verify_text("tracert", self.WINDOWS, expected)["status"], "passed")
        self.assertEqual(verify_text("path", self.WINDOWS, expected)["status"], "passed")
        expected["expected_hops"][0] = "192.168.1.253"
        self.assertEqual(verify_text("tracert", self.WINDOWS, expected)["status"], "failed")

    def test_linux_and_cisco_paths(self):
        for output in ["""traceroute to host (192.168.2.2), 30 hops max, 60 byte packets
 1 gateway (192.168.1.254) 0.1 ms 0.2 ms 0.3 ms
 2 host (192.168.2.2) 1.0 ms 1.1 ms 1.2 ms
""", """R1#traceroute 192.168.2.2
Type escape sequence to abort.
Tracing the route to 192.168.2.2
  1 192.168.1.254 1 msec 1 msec 1 msec
  2 192.168.2.2 1 msec 1 msec 1 msec
R1#
"""]:
            self.assertEqual(verify_text("traceroute", output, {"target": "192.168.2.2"})["status"], "passed")

    def test_timeout_missing_destination_wrong_target_and_ambiguous_path_unknown(self):
        variants = [self.WINDOWS.replace("192.168.1.254", "*"),
                    self.WINDOWS.replace("2    2 ms    1 ms    1 ms    192.168.2.2", "2    *    *    *"),
                    self.WINDOWS.replace("  1", "  3"),
                    self.WINDOWS.replace("192.168.1.254", "192.168.1.254 192.168.1.253")]
        for output in variants:
            self.assertEqual(verify_text("trace", output, {"target": "192.168.2.2"})["status"], "unknown")
        self.assertEqual(verify_text("trace", self.WINDOWS, {"target": "192.168.2.3"})["status"], "unknown")


class RouteTests(unittest.TestCase):
    def test_connected_local_static_rip_ospf_ia_and_default(self):
        cases = [
            ("C 192.168.1.0/24 is directly connected, FastEthernet0/0", "192.168.1.0/24", "C", None),
            ("L 192.168.1.1/32 is directly connected, FastEthernet0/0", "192.168.1.1/32", "local", None),
            ("S 192.168.2.0/24 [1/0] via 10.0.0.2", "192.168.2.0/24", "static", "10.0.0.2"),
            ("R 192.168.2.0/24 [120/1] via 10.0.0.2, 00:00:14, Serial0/0", "192.168.2.0/24", "RIP", "10.0.0.2"),
            ("O 192.168.2.0/24 [110/2] via 10.0.0.2, 00:00:14, Serial0/0", "192.168.2.0/24", "OSPF", "10.0.0.2"),
            ("O IA 192.168.2.0/24 [110/2] via 10.0.0.2, 00:00:14, Serial0/0", "192.168.2.0/24", "O IA", "10.0.0.2"),
            ("S* 0.0.0.0/0 [1/0] via 10.0.0.2", "0.0.0.0/0", "S", "10.0.0.2"),
        ]
        for entry, prefix, protocol, next_hop in cases:
            expected = {"prefix": prefix, "protocol": protocol}
            if next_hop:
                expected["next_hop"] = next_hop
            with self.subTest(protocol=protocol):
                self.assertEqual(verify_text("show ip route", route_text(entry), expected)["status"], "passed")

    def test_uniform_header_mask_inheritance_across_subnets(self):
        output = route_text("C 172.16.1.0 is directly connected, FastEthernet0/0\nR 172.16.2.0 [120/1] via 172.16.1.2",
                            "172.16.0.0/24 is subnetted, 2 subnets")
        self.assertEqual(verify_text("route", output, {"prefix": "172.16.2.0/24", "protocol": "R"})["status"], "passed")

    def test_variable_header_does_not_invent_mask(self):
        output = route_text("C 10.1.0.0 is directly connected, FastEthernet0/0",
                            "10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks")
        self.assertEqual(verify_text("route", output, {"prefix": "10.1.0.0/24"})["status"], "unknown")

    def test_complete_table_can_establish_absence_or_wrong_protocol(self):
        output = route_text("C 192.168.1.0/24 is directly connected, FastEthernet0/0")
        self.assertEqual(verify_text("route", output, {"prefix": "192.168.2.0/24"})["status"], "failed")
        self.assertEqual(verify_text("route", output, {"prefix": "192.168.2.0/24", "reachable": False})["status"], "passed")
        self.assertEqual(verify_text("route", output, {"prefix": "192.168.1.0/24", "protocol": "R"})["status"], "failed")

    def test_explicit_absent_route_requires_complete_recognizable_table(self):
        output = route_text("C 192.168.1.0/24 is directly connected, FastEthernet0/0")
        absent = {"prefix": "192.168.2.0/24", "present": False}
        result = verify_text("route", output, absent)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["observed"]["route_present"])
        self.assertEqual(result["assertions"][0]["expected"], False)
        self.assertEqual(verify_text("route", output, {"prefix": "192.168.1.0/24", "present": False})["status"], "failed")
        self.assertEqual(verify_text("route", output.rsplit("R1#", 1)[0], absent)["status"], "unknown")

    def test_absence_never_ignores_unknown_codes_or_malformed_rows(self):
        for entry in ["D 192.168.2.0/24 [90/2] via 10.0.0.2",
                      "B *> 192.168.2.0/24 via 10.0.0.2",
                      "i L1 192.168.2.0/24 [115/10] via 10.0.0.2",
                      "UNKNOWN route row with truncated prefix",
                      "O IA 192.168.2."]:
            with self.subTest(entry=entry):
                self.assertEqual(verify_text("route", route_text(entry),
                                             {"prefix": "192.168.2.0/24", "present": False})["status"], "unknown")

    def test_present_requires_boolean_and_absence_has_no_protocol_or_next_hop(self):
        output = route_text("C 192.168.1.0/24 is directly connected, FastEthernet0/0")
        for present in [None, 0, 1, "false"]:
            self.assertEqual(verify_text("route", output, {"prefix": "192.168.2.0/24", "present": present})["status"], "unknown")
        for extra in [{"protocol": "R"}, {"next_hop": "10.0.0.2"}]:
            self.assertEqual(verify_text("route", output, {"prefix": "192.168.2.0/24", "present": False, **extra})["status"], "unknown")

    def test_default_presence_and_wrapped_codes_legend_remain_compatible(self):
        entry = "C 192.168.1.0/24 is directly connected, FastEthernet0/0"
        output = route_text(entry).replace("Gateway of last resort", "       i - IS-IS, su - IS-IS summary\n       * - candidate default, U - per-user static route\nGateway of last resort")
        self.assertEqual(verify_text("route", output, {"prefix": "192.168.1.0/24"})["status"], "passed")
        self.assertEqual(verify_text("route", output, {"prefix": "192.168.1.0/24", "present": True})["status"], "passed")

    def test_truncated_paginated_unsupported_or_incomplete_route_unknown(self):
        base = route_text("R 192.168.2.0/24 [120/1] via 10.0.0.2")
        for output in [base.rsplit("R1#", 1)[0], base.replace("R1#show ip route", ""),
                       base.replace("Gateway", "--More--\nGateway"),
                       base.replace("R 192.168.2.0/24", "D 192.168.2.0/24"),
                       base.replace("via 10.0.0.2", ""), base + base,
                       base.replace("R 192.168.2.0/24", "O*E2 192.168.2.0/24")]:
            self.assertEqual(verify_text("route", output, {"prefix": "192.168.2.0/24"})["status"], "unknown")

    def test_ecmp_next_hop_continuation(self):
        output = route_text("O 192.168.2.0/24 [110/2] via 10.0.0.2\n    [110/2] via 10.0.0.3")
        self.assertEqual(verify_text("route", output, {"prefix": "192.168.2.0/24", "next_hop": "10.0.0.3"})["status"], "passed")
        self.assertEqual(verify_text("route", output, {"prefix": "192.168.2.0/24", "next_hop": "10.0.0.4"})["status"], "failed")

    def test_synthetic_wrapped_prefix_and_metric_or_connected_continuations(self):
        # SYNTHETIC narrow-window IOS fixtures; never counted as device evidence.
        entries = """C 192.168.1.0/24
    is directly connected, GigabitEthernet0/0
L 192.168.1.1/32
    is directly connected, GigabitEthernet0/0
O IA 192.168.2.0/24
    [110/2] via 10.0.0.2, 00:01:01, GigabitEthernet0/1
    [110/2] via 10.0.0.3, 00:01:01, GigabitEthernet0/2"""
        output = route_text(entries)
        for prefix, protocol in [("192.168.1.0/24", "connected"), ("192.168.1.1/32", "local"),
                                 ("192.168.2.0/24", "ospf_inter_area")]:
            result = verify_text("route", output, {"prefix": prefix, "protocol": protocol})
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["evidence"]["sha256"], hashlib.sha256(output.encode()).hexdigest())
        result = verify_text("route", output, {"prefix": "192.168.2.0/24", "next_hop": "10.0.0.3"})
        self.assertEqual(result["status"], "passed")

    def test_synthetic_wrapped_rows_do_not_mask_unknown_or_incomplete_routes(self):
        for entry in ["O 192.168.2.0/24", "O 192.168.2.0/24\n    [110/] via 10.0.0.2",
                      "O 192.168.2.0/24\n    [999/2] via 10.0.0.2",
                      "O 192.168.2.0/24\n    [110/2] via 999.0.0.2",
                      "O 192.168.2.0/24\n    [110/2] via 10.0.0.2, unexpected data",
                      "O 192.168.2.0/24\n    is directly connected, GigabitEthernet0/0",
                      "C 192.168.2.0/24\n    [110/2] via 10.0.0.2",
                      "D 192.168.2.0/24\n    [90/2] via 10.0.0.2",
                      "C 192.168.2.0/24\n    is directly connected,",
                      "C 192.168.2.0/24\n    is directly connected, nonsense"]:
            with self.subTest(entry=entry):
                result = verify_text("route", route_text(entry), {"prefix": "192.168.2.0/24", "present": False})
                self.assertEqual(result["status"], "unknown")


class RepairStateTests(unittest.TestCase):
    def result(self, received, delay=1):
        return verify_text("ping", windows_ping(received=received, delay=delay, sent=4 + delay if received == 0 else 4),
                           {"target": "192.168.1.2"})

    def test_candidate_never_applied_and_inputs_are_not_mutated(self):
        state = new_repair_state()
        original = copy.deepcopy(state)
        proposed = propose_repair(state, "interface FastEthernet0/1\nno shutdown")
        self.assertEqual(state, original)
        self.assertFalse(proposed["automatic_application"])
        self.assertFalse(proposed["automatic_repair_success"])
        self.assertFalse(proposed["rounds"][0]["applied_by_program"])
        self.assertEqual(proposed["rounds"][0]["application_status"], "not_observed")

    def test_missing_unknown_or_reused_evidence_cannot_claim_success(self):
        failure = self.result(0)
        state = propose_repair(new_repair_state(), "no shutdown", based_on=failure)
        for result in [None, {}, failure, verify_text("ping", "", {"target": "192.168.1.2"})]:
            updated = record_repair_verification(state, result)
            self.assertEqual(updated["status"], "awaiting_external_verification")
            self.assertFalse(updated["automatic_repair_success"])

    def test_fresh_passing_import_only_claims_external_checks_passed(self):
        state = propose_repair(new_repair_state(), "no shutdown", based_on=self.result(0))
        state = record_repair_verification(state, self.result(4))
        self.assertEqual(state["status"], "external_checks_passed")
        self.assertFalse(state["automatic_repair_success"])
        self.assertEqual(state["rounds"][0]["application_status"], "not_observed")
        with self.assertRaises(ValueError):
            propose_repair(state, "other config")

    def test_changed_target_or_expectation_does_not_verify_original_failure(self):
        state = propose_repair(new_repair_state(), "no shutdown", based_on=self.result(0))
        different_target = verify_text("ping", windows_ping("192.168.1.3"), {"target": "192.168.1.3"})
        changed_expectation = verify_text("ping", windows_ping(received=0, sent=7),
                                          {"target": "192.168.1.2", "reachable": False})
        for result in [different_target, changed_expectation]:
            self.assertEqual(record_repair_verification(state, result)["status"], "awaiting_external_verification")
        with self.assertRaises(ValueError):
            propose_repair(new_repair_state(), "config", based_on=self.result(4))

    def test_three_round_limit_and_pending_round_cannot_be_skipped(self):
        state = new_repair_state()
        for number in range(1, 4):
            state = propose_repair(state, f"candidate {number}")
            with self.assertRaises(ValueError):
                propose_repair(state, "skip pending round")
            state = record_repair_verification(state, self.result(0, delay=number))
        self.assertEqual(state["status"], "exhausted")
        state = propose_repair(state, "candidate 4")
        self.assertEqual(len(state["rounds"]), 3)
        for limit in [0, 4, True, 1.5]:
            with self.assertRaises(ValueError):
                new_repair_state(limit)


if __name__ == "__main__":
    unittest.main()
