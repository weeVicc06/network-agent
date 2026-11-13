"""Routing migration candidate tests; never connect to Packet Tracer or an API."""
import copy
import unittest

import migration
import network_core as core
from test_network_core import fixture


class MigrationTests(unittest.TestCase):
    def test_ripv2_to_v1_clears_protocol_then_rebuilds(self):
        source, target = fixture("rip"), fixture("rip")
        for device in target["devices"]:
            if device["type"] == "router":
                device["routing"].update(version=1, auto_summary=True)
        old_source, old_target = copy.deepcopy(source), copy.deepcopy(target)
        files = migration.plan_migration(source, target)
        self.assertEqual(set(files), {"R0.cfg", "R1.cfg"})
        for cli in files.values():
            self.assertIn("configure terminal\nno router rip\nrouter rip\nversion 1\nauto-summary", cli)
            self.assertNotIn("ip address", cli)
            self.assertEqual(core.check_commands(cli), [])
        self.assertEqual(source, old_source)
        self.assertEqual(target, old_target)

    def test_rip_to_ospf_and_back_resets_old_cost(self):
        rip, ospf = fixture("rip"), fixture("ospf")
        ospf["devices"][1]["interfaces"][1]["ospf_cost"] = 64
        forward = migration.plan_migration(rip, ospf)
        self.assertIn("no router rip", forward["R0.cfg"])
        self.assertIn("ip ospf cost 64", forward["R0.cfg"])
        self.assertIn("router ospf 100", forward["R0.cfg"])
        self.assertIn("network 10.0.0.0 0.0.0.3 area 0", forward["R0.cfg"])
        reverse = migration.plan_migration(ospf, rip)
        self.assertIn("no router ospf 100", reverse["R0.cfg"])
        self.assertIn("interface GigabitEthernet0/1\nno ip ospf cost\nexit", reverse["R0.cfg"])
        self.assertNotIn("ip ospf cost 64", reverse["R0.cfg"])
        for cli in [*forward.values(), *reverse.values()]:
            self.assertEqual(core.check_commands(cli), [])

    def test_unchanged_config_is_empty_and_cost_only_is_minimal(self):
        source = fixture("ospf")
        self.assertEqual(migration.plan_migration(source, copy.deepcopy(source)), {})
        target = copy.deepcopy(source)
        target["devices"][1]["interfaces"][1]["ospf_cost"] = 64
        result = migration.plan_migration(source, target)
        self.assertEqual(set(result), {"R0.cfg"})
        self.assertEqual(result["R0.cfg"], "enable\nconfigure terminal\ninterface GigabitEthernet0/1\nip ospf cost 64\nexit\nend\n")

    def test_ospf_process_id_change_removes_old_process(self):
        source, target = fixture("ospf"), fixture("ospf")
        target["devices"][1]["routing"]["process_id"] = 1
        result = migration.plan_migration(source, target)
        self.assertIn("no router ospf 100\nrouter ospf 1", result["R0.cfg"])
        self.assertNotIn("R1.cfg", result)

    def test_semantically_unordered_collections_do_not_force_change(self):
        source, target = fixture("rip"), fixture("rip")
        target["name"] = "renamed scenario"
        target["checks"] = target["checks"][:1]
        target["devices"].reverse()
        target["links"].reverse()
        for link in target["links"]:
            link["a"], link["b"] = link["b"], link["a"]
        for device in target["devices"]:
            device["interfaces"].reverse()
            if device["type"] == "router":
                device["routing"]["networks"].reverse()
        self.assertEqual(migration.plan_migration(source, target), {})

    def test_gateway_vlan_services_and_model_changes_are_not_migrations(self):
        source = fixture("rip")
        for mutate in [
            lambda t: t["devices"][0].pop("gateway"),
            lambda t: t["vlans"].append({"id": 20, "name": "new_vlan"}),
            lambda t: t["devices"][0].update(type="server", model="Server-PT", services={"http": True}),
        ]:
            target = copy.deepcopy(source)
            mutate(target)
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    migration.plan_migration(source, target)

    def test_valid_ip_address_change_is_rejected(self):
        source, target = fixture("rip"), fixture("rip")
        target["devices"][0]["interfaces"][0]["ipv4"] = "192.168.1.10/24"
        with self.assertRaisesRegex(ValueError, "硬件或非路由配置不同"):
            migration.plan_migration(source, target)

    def test_static_routes_are_not_accepted(self):
        source = fixture("static")
        with self.assertRaisesRegex(ValueError, "仅支持"):
            migration.plan_migration(source, source)
        source = fixture("rip")
        source["devices"][1]["routing"]["static_routes"] = []
        with self.assertRaisesRegex(ValueError, "static_routes"):
            migration.plan_migration(source, source)

    def test_only_exact_cleanup_commands_are_whitelisted(self):
        good = "enable\nconfigure terminal\nno router rip\nno router ospf 100\ninterface GigabitEthernet0/1\nno ip ospf cost\nexit\nend\n"
        self.assertEqual(core.check_commands(good), [])
        for command in ["no router bgp 100", "no ip routing", "no ip address", "no router ospf 65536", "no router ospf 0", "no router rip;reload"]:
            with self.subTest(command=command):
                self.assertTrue(core.check_commands("enable\nconfigure terminal\n" + command + "\nend\n"))
        self.assertTrue(core.check_commands("enable\nconfigure terminal\ninterface GigabitEthernet0/1\nno router rip\nend\n"))
        self.assertTrue(core.check_commands("enable\nconfigure terminal\nno ip ospf cost\nend\n"))


if __name__ == "__main__":
    unittest.main()
