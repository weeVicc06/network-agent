"""Produce reviewed-candidate routing migrations; never execute or authorize CLI.

Source and target must describe the same local Packet Tracer hardware, addresses,
L2 configuration and unchanged ACL/services. The orchestration layer remains
responsible for original run manifests and a fresh human confirmation.
"""
import copy
import ipaddress as ip
import json

import network_core as core


def _ordered(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hardware(topology):
    """Canonicalize only collections whose ordering has no configuration meaning."""
    hardware = copy.deepcopy(topology)
    hardware.pop("name", None)
    hardware.pop("checks", None)
    hardware["devices"] = sorted(hardware["devices"], key=lambda d: d["id"])
    for device in hardware["devices"]:
        if device["type"] == "router":
            device.pop("routing", None)
        device["interfaces"] = sorted(device["interfaces"], key=lambda p: p["name"])
        for interface in device["interfaces"]:
            interface.pop("ospf_cost", None)
            if "allowed_vlans" in interface:
                interface["allowed_vlans"] = sorted(interface["allowed_vlans"])
        # An absent gateway and explicit null both mean no host default gateway.
        if device.get("gateway") is None:
            device.pop("gateway", None)
    hardware["vlans"] = sorted(hardware["vlans"], key=lambda v: v["id"])
    hardware["links"] = sorted([
        sorted([(link[side]["device"], link[side]["interface"]) for side in ("a", "b")])
        for link in hardware["links"]
    ])
    # ACL order between separate bindings is immaterial; rule order is preserved.
    hardware["acls"] = sorted(hardware["acls"], key=lambda a: (a["device"], a["name"], a["interface"], a["direction"]))
    return hardware


def _routing_signature(routing):
    if routing["protocol"] == "rip":
        networks = sorted({str(core._major_network(ip.IPv4Network(n["prefix"]).network_address).network_address) for n in routing["networks"]})
        return ("rip", routing["version"], routing["auto_summary"], tuple(networks))
    return ("ospf", routing["process_id"], tuple(sorted({(str(ip.IPv4Network(n["prefix"])), n["area"]) for n in routing["networks"]})))


def _routing_commands(routing):
    if routing["protocol"] == "rip":
        result = ["router rip", f"version {routing['version']}", "auto-summary" if routing["auto_summary"] else "no auto-summary"]
        networks = sorted({core._major_network(ip.IPv4Network(n["prefix"]).network_address).network_address for n in routing["networks"]})
        result += [f"network {network}" for network in networks]
    else:
        result = [f"router ospf {routing['process_id']}"]
        for network, area in sorted({(str(ip.IPv4Network(n["prefix"])), n["area"]) for n in routing["networks"]}):
            prefix = ip.IPv4Network(network)
            result.append(f"network {prefix.network_address} {prefix.hostmask} area {area}")
    return result + ["exit"]


def plan_migration(source_topology, target_topology):
    """Return {router.cfg: CLI}; unchanged routers are omitted.

    Raises ValueError if either topology is invalid or any non-routing setting
    changes. Changes to names of the overall scenario and verification checks
    are allowed. No source/target object is modified and no files are written.
    """
    for label, topology in (("源", source_topology), ("目标", target_topology)):
        errors = core.validate(topology)
        if errors:
            raise ValueError(f"{label}拓扑校验失败：" + "；".join(errors))
        for device in topology["devices"]:
            if device["type"] != "router":
                continue
            routing = device.get("routing", {})
            if routing.get("protocol") not in {"rip", "ospf"} or "static_routes" in routing:
                raise ValueError("迁移仅支持原/目标均为 RIP 或 OSPF 的路由器，不能包含 static_routes")
    if _ordered(_hardware(source_topology)) != _ordered(_hardware(target_topology)):
        raise ValueError("硬件或非路由配置不同：设备、接口IP、网关、连线、VLAN、ACL、services必须一致")
    source_devices = {d["id"]: d for d in source_topology["devices"]}
    files = {}
    for target in sorted(target_topology["devices"], key=lambda d: d["id"]):
        if target["type"] != "router":
            continue
        source = source_devices[target["id"]]
        old, new = source["routing"], target["routing"]
        routing_changed = _routing_signature(old) != _routing_signature(new)
        old_ports = {p["name"]: p for p in source["interfaces"]}
        cost_changes = [(p["name"], p.get("ospf_cost")) for p in target["interfaces"] if p.get("ospf_cost") != old_ports[p["name"]].get("ospf_cost")]
        if not routing_changed and not cost_changes:
            continue
        commands = ["enable", "configure terminal"]
        if routing_changed:
            commands.append("no router rip" if old["protocol"] == "rip" else f"no router ospf {old['process_id']}")
        for name, cost in sorted(cost_changes):
            commands += [f"interface {name}", "no ip ospf cost" if cost is None else f"ip ospf cost {cost}", "exit"]
        if routing_changed:
            commands += _routing_commands(new)
        commands.append("end")
        cli = "\n".join(commands) + "\n"
        errors = core.check_commands(cli)
        if errors:
            raise ValueError("迁移候选命令被护栏拦截：" + "；".join(errors))
        files[f"{target['id']}.cfg"] = cli
    return files
