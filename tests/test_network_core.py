"""Compiler regressions only; these tests do not execute Packet Tracer."""
import copy
import json
import unittest

import network_core as core


def fixture(protocol="static"):
    def port(name, address):
        return {"name": name, "ipv4": address, "mode": "routed"}
    devices = [
        {"id": "PC0", "type": "pc", "model": "PC-PT", "gateway": "192.168.1.254", "interfaces": [port("FastEthernet0", "192.168.1.1/24")]},
        {"id": "R0", "type": "router", "model": "2911", "interfaces": [port("GigabitEthernet0/0", "192.168.1.254/24"), port("GigabitEthernet0/1", "10.0.0.1/30")]},
        {"id": "R1", "type": "router", "model": "2911", "interfaces": [port("GigabitEthernet0/0", "10.0.0.2/30"), port("GigabitEthernet0/1", "192.168.2.254/24")]},
        {"id": "PC1", "type": "pc", "model": "PC-PT", "gateway": "192.168.2.254", "interfaces": [port("FastEthernet0", "192.168.2.1/24")]},
    ]
    for device, networks, target, hop in [
        (devices[1], ["192.168.1.0/24", "10.0.0.0/30"], "192.168.2.0/24", "10.0.0.2"),
        (devices[2], ["192.168.2.0/24", "10.0.0.0/30"], "192.168.1.0/24", "10.0.0.1"),
    ]:
        if protocol == "static":
            device["routing"] = {"protocol": "static", "static_routes": [{"prefix": target, "next_hop": hop}]}
        elif protocol == "rip":
            device["routing"] = {"protocol": "rip", "version": 2, "auto_summary": False, "networks": [{"prefix": n} for n in networks]}
        elif protocol == "ospf":
            device["routing"] = {"protocol": "ospf", "process_id": 100, "networks": [{"prefix": n, "area": 0} for n in networks]}
        else:
            device["routing"] = {"protocol": "none"}
    def link(a, ai, b, bi):
        return {"a": {"device": a, "interface": ai}, "b": {"device": b, "interface": bi}}
    return {
        "schema_version": "0.2", "name": "Compiler fixture", "environment": "packet_tracer",
        "vlans": [{"id": 1, "name": "default"}], "devices": devices,
        "links": [link("PC0", "FastEthernet0", "R0", "GigabitEthernet0/0"), link("R0", "GigabitEthernet0/1", "R1", "GigabitEthernet0/0"), link("R1", "GigabitEthernet0/1", "PC1", "FastEthernet0")],
        "acls": [], "checks": [
            {"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": True},
            {"kind": "path", "source": "PC0", "destination": "PC1", "expected_hops": ["192.168.1.254", "10.0.0.2", "192.168.2.1"]},
            {"kind": "route", "source": "R0", "prefix": "192.168.2.0/24", "protocol": protocol if protocol != "none" else "connected", "next_hop": "10.0.0.2"},
        ],
    }


class CoreTests(unittest.TestCase):
    def test_static_gateway_and_next_hop(self):
        data = fixture()
        self.assertEqual(core.validate(data), [])
        files = core.render(data)
        self.assertIn("ip route 192.168.2.0 255.255.255.0 10.0.0.2", files["R0.cfg"])
        self.assertIn("192.168.1.1,255.255.255.0,192.168.1.254", files["pc-addresses.csv"])
        self.assertIn("Copper Cross-Over", files["links.csv"])

    def test_rip_classful_network_and_v2_behavior(self):
        data = fixture("rip")
        cli = core.render(data)["R0.cfg"]
        self.assertIn("version 2\nno auto-summary", cli)
        self.assertIn("network 10.0.0.0", cli)
        self.assertNotIn("network 10.0.0.0 0.0.0.3", cli)
        for router in data["devices"][1:3]:
            router["routing"].update(version=1, auto_summary=True)
        self.assertIn("version 1\nauto-summary", core.render(data)["R0.cfg"])

    def test_rip_wide_prefix_cannot_fake_classful_coverage(self):
        data = fixture("rip")
        data["devices"][1]["routing"]["networks"][0]["prefix"] = "192.168.0.0/16"
        errors = core.validate(data)
        self.assertTrue(any("跨越主类网络" in e for e in errors))
        self.assertTrue(any("漏配 network" in e for e in errors))
        with self.assertRaises(ValueError):
            core.render(data)
        data = fixture("rip")
        # A real connected subnet and its equivalent classful prefix both compile
        # to network 192.168.1.0 and must be accepted.
        data["devices"][0]["interfaces"][0]["ipv4"] = "192.168.1.1/25"
        data["devices"][0]["gateway"] = "192.168.1.126"
        data["devices"][1]["interfaces"][0]["ipv4"] = "192.168.1.126/25"
        data["checks"][1]["expected_hops"][0] = "192.168.1.126"
        for prefix in ["192.168.1.0/25", "192.168.1.0/24"]:
            data["devices"][1]["routing"]["networks"][0]["prefix"] = prefix
            self.assertEqual(core.validate(data), [])
            self.assertIn("network 192.168.1.0", core.render(data)["R0.cfg"])

    def test_rip_compiled_major_network_covers_other_local_subnets(self):
        data = fixture("rip")
        data["devices"][0]["interfaces"][0]["ipv4"] = "10.1.0.1/24"
        data["devices"][0]["gateway"] = "10.1.0.254"
        data["devices"][1]["interfaces"][0]["ipv4"] = "10.1.0.254/24"
        data["devices"][1]["routing"]["networks"] = [{"prefix": "10.0.0.0/30"}]
        data["checks"] = [{"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": True}]
        self.assertEqual(core.validate(data), [])
        self.assertEqual(core.render(data)["R0.cfg"].count("network 10.0.0.0"), 1)

    def test_ospf_wildcard_area_and_cost(self):
        data = fixture("ospf")
        data["devices"][1]["interfaces"][1]["ospf_cost"] = 64
        self.assertEqual(core.validate(data), [])
        cli = core.render(data)["R0.cfg"]
        self.assertIn("network 10.0.0.0 0.0.0.3 area 0", cli)
        self.assertIn("network 192.168.1.0 0.0.0.255 area 0", cli)
        self.assertIn("ip ospf cost 64", cli)

    def test_http_services_and_acl_order(self):
        data = fixture()
        data["devices"][-1].update(type="server", model="Server-PT", services={"http": True})
        data["acls"] = [{"name": "WEB_ONLY", "device": "R0", "interface": "GigabitEthernet0/0", "direction": "in", "rules": [
            {"action": "permit", "protocol": "tcp", "source": "192.168.1.0/24", "destination": "192.168.2.1/32", "destination_port": 80},
            {"action": "deny", "protocol": "ip", "source": "any", "destination": "any"},
        ]}]
        data["checks"].append({"kind": "http", "source": "PC0", "destination": "PC1", "reachable": True})
        files = core.render(data)
        self.assertIn("permit tcp 192.168.1.0 0.0.0.255 host 192.168.2.1 eq 80\ndeny ip any any", files["R0.cfg"])
        self.assertIn("ip access-group WEB_ONLY in", files["R0.cfg"])
        self.assertIn("Services → HTTP → On", files["操作与验收.md"])
        self.assertIn("http://192.168.2.1", files["verification-plan.json"])

    def test_duplicate_ip_and_overlap(self):
        data = fixture()
        data["devices"][1]["interfaces"][0]["ipv4"] = "192.168.1.1/24"
        self.assertTrue(any("地址冲突" in e for e in core.validate(data)))
        data = fixture()
        data["devices"][-1]["interfaces"][0]["ipv4"] = "192.168.1.2/25"
        self.assertTrue(any("重叠" in e for e in core.validate(data)))

    def test_same_l2_mismatched_mask(self):
        data = fixture()
        data["devices"][0]["interfaces"][0]["ipv4"] = "192.168.1.1/25"
        self.assertTrue(any("广播域地址/掩码不一致" in e for e in core.validate(data)))

    def test_gateway_must_exist_in_same_broadcast_domain(self):
        for gateway in ["192.168.1.2", "192.168.2.254", "192.168.1.1"]:
            data = fixture()
            data["devices"][0]["gateway"] = gateway
            self.assertTrue(any("网关错配" in e for e in core.validate(data)))

    def test_success_requires_forward_and_return_gateways(self):
        data = fixture()
        del data["devices"][0]["gateway"]
        self.assertTrue(any("跨网段验收缺少默认网关" in e for e in core.validate(data)))
        data = fixture()
        del data["devices"][-1]["gateway"]
        self.assertTrue(any("缺少回程默认网关" in e for e in core.validate(data)))
        data["checks"] = [{"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": False}]
        self.assertEqual(core.validate(data), [])

    def test_expected_success_needs_a_physical_vlan_path(self):
        data = {
            "schema_version": "0.2", "environment": "packet_tracer", "name": "Disconnected",
            "vlans": [{"id": 1, "name": "default"}], "devices": [], "links": [], "acls": [],
            "checks": [{"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": True}],
        }
        for index in range(2):
            pc, sw = f"PC{index}", f"SW{index}"
            data["devices"] += [
                {"id": pc, "type": "pc", "model": "PC-PT", "interfaces": [{"name": "FastEthernet0", "ipv4": f"192.168.{index + 1}.1/24", "mode": "routed"}]},
                {"id": sw, "type": "switch", "model": "2960", "interfaces": [{"name": "FastEthernet0/1", "ipv4": None, "mode": "access", "vlan": 1}]},
            ]
            data["links"].append({"a": {"device": pc, "interface": "FastEthernet0"}, "b": {"device": sw, "interface": "FastEthernet0/1"}})
        self.assertTrue(any("没有物理/VLAN路径" in e for e in core.validate(data)))
        data["checks"][0]["reachable"] = False
        self.assertEqual(core.validate(data), [])

    def test_next_hop_must_be_neighbor(self):
        data = fixture()
        data["devices"][1]["routing"]["static_routes"][0]["next_hop"] = "192.168.2.254"
        self.assertTrue(any("直连邻居" in e for e in core.validate(data)))

    def test_missing_routing_network_is_rejected(self):
        data = fixture("ospf")
        data["devices"][1]["routing"]["networks"].pop()
        self.assertTrue(any("漏配 network" in e for e in core.validate(data)))

    def test_ospf_neighbor_area_mismatch_is_rejected(self):
        data = fixture("ospf")
        data["devices"][2]["routing"]["networks"][1]["area"] = 100
        self.assertTrue(any("邻接 area 不一致" in e for e in core.validate(data)))

    def test_explicit_target_interface_and_expected_path(self):
        data = fixture()
        data["checks"].append({"kind": "ping", "source": "PC0", "destination": "R1", "target_ipv4": "192.168.2.254", "reachable": False})
        self.assertEqual(core.validate(data), [])
        plan = json.loads(core.render(data)["verification-plan.json"])
        self.assertEqual(plan["checks"][-1]["command"], "ping 192.168.2.254")
        self.assertFalse(plan["checks"][-1]["reachable"])
        data["checks"][-1]["target_ipv4"] = "192.168.99.254"
        self.assertTrue(any("target_ipv4必须属于" in e for e in core.validate(data)))
        data = fixture()
        data["checks"][1]["expected_hops"] = []
        self.assertTrue(any("非空expected_hops" in e for e in core.validate(data)))
        data["checks"][1]["expected_hops"] = ["192.168.9.1", "192.168.2.1"]
        self.assertTrue(any("未在拓扑配置" in e for e in core.validate(data)))
        data["checks"][1]["expected_hops"] = ["192.168.1.254", "10.0.0.2"]
        self.assertTrue(any("以目标IP结束" in e for e in core.validate(data)))

    def test_ripv1_expected_failure_is_a_valid_plan(self):
        data = fixture("rip")
        for device in data["devices"][1:3]:
            device["routing"].update(version=1, auto_summary=True)
        data["checks"] = [{"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": False}]
        self.assertEqual(core.validate(data), [])
        plan = json.loads(core.render(data)["verification-plan.json"])
        self.assertFalse(plan["checks"][0]["reachable"])

    def test_route_absence_is_explicit_and_unambiguous(self):
        data = fixture("rip")
        data["checks"] = [{"kind": "route", "source": "R0", "prefix": "192.168.2.0/24", "present": False}]
        self.assertEqual(core.validate(data), [])
        files = core.render(data)
        plan = json.loads(files["verification-plan.json"])
        self.assertFalse(plan["checks"][0]["present"])
        self.assertIn('"present": false', files["操作与验收.md"])
        for field, value in [("protocol", "rip"), ("next_hop", "10.0.0.2")]:
            with self.subTest(field=field):
                invalid = copy.deepcopy(data)
                invalid["checks"][0][field] = value
                self.assertTrue(any("缺失路由断言" in e for e in core.validate(invalid)))
        data["checks"] = [{"kind": "route", "source": "R0", "prefix": "192.168.2.0/24"}]
        # The parser defaults absent present to true. Do not inject the field
        # during compilation: existing audited 0.2 plans must render identically.
        default_files = core.render(data)
        default_check = json.loads(default_files["verification-plan.json"])["checks"][0]
        self.assertNotIn("present", default_check)
        self.assertNotIn('"present":', default_files["操作与验收.md"])
        data["checks"] = [{"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": True, "present": False}]
        self.assertTrue(any("非route检查不能带present" in e for e in core.validate(data)))

    def test_schema_rejects_untyped_cli_and_unknown_fields(self):
        data = fixture()
        data["devices"][1]["commands"] = "reload"
        self.assertTrue(core.validate(data))
        data = fixture()
        data["devices"][1]["id"] = "R0\nreload"
        self.assertTrue(core.validate(data))

    def test_port_and_reference_errors(self):
        data = fixture()
        data["links"][0]["a"]["interface"] = "FastEthernet0/99"
        self.assertTrue(any("不存在" in e for e in core.validate(data)))
        data = fixture()
        data["devices"][1]["interfaces"][0]["name"] = "GigabitEthernet0/3"
        self.assertTrue(any("型号不存在接口" in e for e in core.validate(data)))

    def test_vlan_access_trunk_and_same_domain(self):
        data = {
            "schema_version": "0.2", "environment": "packet_tracer", "name": "VLAN",
            "vlans": [{"id": 10, "name": "office"}],
            "devices": [
                {"id": "PC0", "type": "pc", "model": "PC-PT", "interfaces": [{"name": "FastEthernet0", "ipv4": "192.168.1.1/24", "mode": "routed"}]},
                {"id": "SW0", "type": "switch", "model": "2960", "interfaces": [{"name": "FastEthernet0/1", "ipv4": None, "mode": "access", "vlan": 10}, {"name": "GigabitEthernet0/1", "ipv4": None, "mode": "trunk", "allowed_vlans": [10]}]},
                {"id": "SW1", "type": "switch", "model": "2960", "interfaces": [{"name": "FastEthernet0/1", "ipv4": None, "mode": "access", "vlan": 10}, {"name": "GigabitEthernet0/1", "ipv4": None, "mode": "trunk", "allowed_vlans": [10]}]},
                {"id": "PC1", "type": "pc", "model": "PC-PT", "interfaces": [{"name": "FastEthernet0", "ipv4": "192.168.1.2/24", "mode": "routed"}]},
            ],
            "links": [], "acls": [], "checks": [{"kind": "ping", "source": "PC0", "destination": "PC1", "reachable": True}],
        }
        for a, ai, b, bi in [("PC0", "FastEthernet0", "SW0", "FastEthernet0/1"), ("SW0", "GigabitEthernet0/1", "SW1", "GigabitEthernet0/1"), ("SW1", "FastEthernet0/1", "PC1", "FastEthernet0")]:
            data["links"].append({"a": {"device": a, "interface": ai}, "b": {"device": b, "interface": bi}})
        self.assertEqual(core.validate(data), [])
        self.assertIn("switchport trunk allowed vlan 10", core.render(data)["SW0.cfg"])
        data["devices"][2]["interfaces"][0]["vlan"] = 20
        self.assertTrue(any("VLAN" in e for e in core.validate(data)))

    def test_check_plan_has_no_fabricated_results(self):
        plan = json.loads(core.render(fixture())["verification-plan.json"])
        self.assertEqual(plan["status"], "not_run")
        self.assertTrue(all(c["actual"] is None for c in plan["checks"]))

    def test_command_guardrails_and_context(self):
        for text in ["reload", "enable\nconfigure terminal\nhostname R0;reload", "ip address 10.0.0.1 255.0.255.0", "enable\nconfigure terminal\nrouter ospf 1\nnetwork 10.0.0.0 0.0.1.1 area 0", "enable\nconfigure terminal\ninterface GigabitEthernet0/0\nrouter rip", "enable\nconfigure terminal\nrouter rip\nnetwork 10.0.0.1", "enable\nconfigure terminal\nip access-list extended BAD\npermit tcp 192.168.1.1 0.0.0.255 any", "enable\nconfigure terminal\nip access-list extended BAD\npermit ip any any eq 80", "enable\nconfigure terminal\nip access-list extended BAD\npermit ip 192.168.0.0 0.1.0.1 any"]:
            with self.subTest(text=text):
                self.assertTrue(core.check_commands(text))
        for protocol in ["static", "rip", "ospf"]:
            for name, text in core.render(fixture(protocol)).items():
                if name.endswith(".cfg"):
                    self.assertEqual(core.check_commands(text), [])


if __name__ == "__main__":
    unittest.main()
