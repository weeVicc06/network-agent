"""Synthetic config-drift tests; no device execution or automatic repair evidence."""
import copy
import unittest
from unittest.mock import patch

import diagnostics
import network_core as core
from tests.test_network_core import fixture


def running(topology, device="R0"):
    cli = core.render(topology)[f"{device}.cfg"]
    # IOS show running-config omits enable/configure terminal and uses ! section
    # boundaries. no shutdown is normally implicit and thus omitted as well.
    body = "\n".join("!" if line == "exit" else line for line in cli.splitlines()
                     if line not in {"enable", "configure terminal", "no shutdown"})
    return f"{device}#show running-config\nBuilding configuration...\nCurrent configuration : 1000 bytes\n!\nversion 15.1\n{body}\n{device}#\n"


class DiagnosticTests(unittest.TestCase):
    def test_equal_managed_config_needs_no_patch(self):
        for protocol in ["static", "rip", "ospf"]:
            data = fixture(protocol)
            result = diagnostics.diagnose(data, "R0", running(data))
            self.assertEqual(result["issues"], [], protocol)
            self.assertTrue(result["repairable"])
            self.assertEqual(result["patch_cli"], "")
            self.assertEqual(result["execution"], "not_executed")

    def test_wrong_interface_mask_only_proposes_expected_address_in_correct_context(self):
        data = fixture()
        text = running(data).replace("ip address 192.168.1.254 255.255.255.0", "ip address 192.168.1.254 255.255.255.128")
        original = copy.deepcopy(data)
        result = diagnostics.diagnose(data, "R0", text)
        self.assertTrue(result["repairable"])
        self.assertTrue(result["requires_human_confirmation"])
        self.assertIn("interface GigabitEthernet0/0\nip address 192.168.1.254 255.255.255.0\nexit", result["patch_cli"])
        self.assertNotIn("router ", result["patch_cli"])
        self.assertEqual(core.check_commands(result["patch_cli"]), [])
        self.assertEqual(data, original)

    def test_missing_primary_ip_can_be_added_but_secondary_ip_is_ambiguous(self):
        data = fixture()
        text = running(data).replace("ip address 192.168.1.254 255.255.255.0", "no ip address")
        self.assertTrue(diagnostics.diagnose(data, "R0", text)["repairable"])
        text = running(data).replace("ip address 192.168.1.254 255.255.255.0", "ip address 192.168.1.254 255.255.255.0 secondary")
        result = diagnostics.diagnose(data, "R0", text)
        self.assertFalse(result["repairable"])
        self.assertEqual(result["patch_cli"], "")

    def test_missing_rip_network_preserves_version_and_existing_networks(self):
        data = fixture("rip")
        text = running(data).replace("network 192.168.1.0\n", "")
        result = diagnostics.diagnose(data, "R0", text)
        self.assertTrue(result["repairable"])
        self.assertIn("router rip\nnetwork 192.168.1.0\nexit", result["patch_cli"])
        self.assertNotIn("network 10.0.0.0", result["patch_cli"])
        self.assertNotIn("version ", result["patch_cli"])
        self.assertEqual(core.check_commands(result["patch_cli"]), [])

    def test_missing_ospf_network_keeps_process_and_area(self):
        data = fixture("ospf")
        line = "network 192.168.1.0 0.0.0.255 area 0"
        text = running(data).replace(line + "\n", "")
        result = diagnostics.diagnose(data, "R0", text)
        self.assertTrue(result["repairable"])
        self.assertIn(f"router ospf 100\n{line}\nexit", result["patch_cli"])
        self.assertEqual(core.check_commands(result["patch_cli"]), [])

    def test_synthetic_ios_default_ospf_logging_does_not_block_missing_network_patch(self):
        # SYNTHETIC serialization fixture, not captured Packet Tracer evidence.
        data = fixture("ospf")
        text = running(data).replace("router ospf 100", "router ospf 100\n log-adjacency-changes")
        baseline = diagnostics.diagnose(data, "R0", text)
        self.assertEqual(baseline["issues"], [])
        self.assertEqual(baseline["patch_cli"], "")
        text = text.replace("network 192.168.1.0 0.0.0.255 area 0\n", "")
        result = diagnostics.diagnose(data, "R0", text)
        self.assertTrue(result["repairable"])
        self.assertIn("router ospf 100\nnetwork 192.168.1.0 0.0.0.255 area 0\nexit", result["patch_cli"])
        self.assertNotIn("log-adjacency-changes", result["patch_cli"])

    def test_ospf_logging_exemption_does_not_hide_router_id_passive_or_other_options(self):
        data = fixture("ospf")
        base = running(data).replace("network 192.168.1.0 0.0.0.255 area 0\n", "")
        for option in ["router-id 1.1.1.1", "passive-interface GigabitEthernet0/1", "log-adjacency-changes detail"]:
            text = base.replace("router ospf 100", "router ospf 100\n log-adjacency-changes\n " + option)
            result = diagnostics.diagnose(data, "R0", text)
            self.assertFalse(result["repairable"])
            self.assertEqual(result["patch_cli"], "")
        data = fixture("rip")
        text = running(data).replace("router rip", "router rip\n log-adjacency-changes")
        self.assertFalse(diagnostics.diagnose(data, "R0", text)["repairable"])

    def test_missing_static_route_only_adds_expected_route(self):
        data = fixture()
        line = "ip route 192.168.2.0 255.255.255.0 10.0.0.2"
        result = diagnostics.diagnose(data, "R0", running(data).replace(line + "\n", ""))
        self.assertTrue(result["repairable"])
        self.assertEqual(result["patch_cli"], f"enable\nconfigure terminal\n{line}\nend\n")

    def test_wrong_device_header_or_hostname_blocks_patch(self):
        data = fixture()
        for text in [running(data).replace("R0#", "R1#"), running(data).replace("hostname R0", "hostname R1")]:
            result = diagnostics.diagnose(data, "R0", text)
            self.assertFalse(result["repairable"])
            self.assertEqual(result["patch_cli"], "")
            self.assertTrue(any(i["code"] == "device_mismatch" for i in result["issues"]))

    def test_missing_end_header_or_pagination_blocks_all_candidates(self):
        data = fixture()
        base = running(data).replace("ip address 192.168.1.254 255.255.255.0", "no ip address")
        for text in ["", base.replace("\nend\n", "\n"),
                     core.render(data)["R0.cfg"], base.replace("version 15.1", "--More--")]:
            result = diagnostics.diagnose(data, "R0", text)
            self.assertFalse(result["repairable"])
            self.assertEqual(result["patch_cli"], "")

    def test_unknown_severe_config_and_shutdown_block_otherwise_supported_patch(self):
        data = fixture()
        base = running(data).replace("ip address 192.168.1.254 255.255.255.0", "ip address 192.168.1.253 255.255.255.0")
        for text in [base.replace("\nend\n", "\nip nat inside source list 1 interface GigabitEthernet0/0 overload\nend\n"),
                     base.replace("interface GigabitEthernet0/0\n", "interface GigabitEthernet0/0\n shutdown\n"),
                     base.replace("\nend\n", "\nenable secret SECRET_VALUE\nend\n")]:
            result = diagnostics.diagnose(data, "R0", text)
            self.assertFalse(result["repairable"])
            self.assertEqual(result["patch_cli"], "")
            self.assertNotIn("SECRET_VALUE", str(result))

    def test_different_protocol_process_network_or_extra_route_is_not_additive_repair(self):
        data = fixture("ospf")
        base = running(data)
        variants = [base.replace("router ospf 100", "router rip"),
                    base.replace("router ospf 100", "router ospf 200"),
                    base.replace("network 192.168.1.0 0.0.0.255 area 0", "network 192.168.1.0 0.0.0.255 area 1"),
                    base.replace("\nend\n", "\nip route 192.168.100.0 255.255.255.0 10.0.0.2\nend\n")]
        for text in variants:
            result = diagnostics.diagnose(data, "R0", text)
            self.assertFalse(result["repairable"])
            self.assertEqual(result["patch_cli"], "")

    def test_rip_version_or_summary_drift_blocks_missing_network_patch(self):
        data = fixture("rip")
        base = running(data).replace("network 192.168.1.0\n", "")
        for text in [base.replace("version 2", "version 1"), base.replace("no auto-summary", "auto-summary")]:
            result = diagnostics.diagnose(data, "R0", text)
            self.assertFalse(result["repairable"])
            self.assertEqual(result["patch_cli"], "")

    def test_acl_difference_blocks_patch_and_unchanged_acl_is_never_replayed(self):
        data = fixture()
        data["acls"] = [{"name": "WEB", "device": "R0", "interface": "GigabitEthernet0/0", "direction": "in", "rules": [
            {"action": "permit", "protocol": "tcp", "source": "any", "destination": "any", "destination_port": 80},
            {"action": "deny", "protocol": "ip", "source": "any", "destination": "any"},
        ]}]
        base = running(data).replace("ip address 192.168.1.254 255.255.255.0", "no ip address")
        result = diagnostics.diagnose(data, "R0", base)
        self.assertTrue(result["repairable"])
        self.assertNotIn("access-list", result["patch_cli"])
        self.assertNotIn("permit", result["patch_cli"])
        altered = base.replace("permit tcp any any eq 80\ndeny ip any any", "deny ip any any\npermit tcp any any eq 80")
        result = diagnostics.diagnose(data, "R0", altered)
        self.assertFalse(result["repairable"])
        self.assertEqual(result["patch_cli"], "")

    def test_normal_ios_defaults_and_unused_shutdown_interfaces_are_accepted(self):
        data = fixture()
        text = running(data).replace("version 15.1", "version 15.1\nno service timestamps debug datetime msec\nno service password-encryption\nip cef\nno ipv6 cef")
        text = text.replace("\nend\n", "\ninterface GigabitEthernet0/2\n no ip address\n shutdown\n duplex auto\n speed auto\n!\nline con 0\n!\nline vty 0 4\n login\n!\nend\n")
        result = diagnostics.diagnose(data, "R0", text)
        self.assertEqual(result["issues"], [])
        self.assertTrue(result["repairable"])

    def test_guardrail_rejection_suppresses_candidate(self):
        data = fixture()
        text = running(data).replace("ip address 192.168.1.254 255.255.255.0", "no ip address")
        with patch.object(core, "check_commands", side_effect=lambda cli: ["test rejection"] if "hostname" not in cli else []):
            result = diagnostics.diagnose(data, "R0", text)
        self.assertFalse(result["repairable"])
        self.assertEqual(result["patch_cli"], "")

    def test_unknown_or_pc_device_and_invalid_topology_do_not_propose_cli(self):
        data = fixture()
        for device in ["MISSING", "PC0"]:
            result = diagnostics.diagnose(data, device, running(data))
            self.assertFalse(result["repairable"])
            self.assertEqual(result["patch_cli"], "")
        invalid = copy.deepcopy(data)
        invalid["devices"][0]["interfaces"][0]["ipv4"] = "not-an-ip"
        self.assertFalse(diagnostics.diagnose(invalid, "R0", running(data))["repairable"])


if __name__ == "__main__":
    unittest.main()
