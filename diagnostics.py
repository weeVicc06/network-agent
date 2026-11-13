"""Conservative candidate patches from complete, externally collected IOS configs.

No commands are executed. Only interface primary IPv4 replacement and missing
network/static-route statements are proposed. Unsupported drift blocks all patches.
"""
from __future__ import annotations

import re

import network_core as core


_PROMPT = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_-]{0,19})(?:\([^\n]*\))?[>#]\s*(.*)$")
_SAFE_GLOBAL = [
    r"version [0-9.()A-Za-z-]+", r"(?:no )?service timestamps (?:debug|log) datetime(?: msec)?",
    r"no service password-encryption", r"(?:no )?ip cef", r"no ipv6 cef", r"ip classless",
    r"ip flow-export version 9", r"spanning-tree mode pvst", r"no ip domain-lookup",
    r"license udi [A-Za-z0-9 /_-]+", r"boot-start-marker", r"boot-end-marker",
    r"memory-size iomem \d+",
]
_SAFE_INTERFACE = {"duplex auto", "speed auto", "negotiation auto"}


def _issue(result, code, context, detail, *, repairable=False, expected=None, observed=None):
    item = {"code": code, "context": context, "detail": detail, "repairable": repairable}
    if expected is not None:
        item["expected"] = expected
    if observed is not None:
        item["observed"] = observed
    result["issues"].append(item)


def _normalize(line):
    line = " ".join(line.strip().split())
    # IOS serializes several well-known service ports as names in access lists.
    ports = {"www": "80", "http": "80", "https": "443", "domain": "53", "ftp": "21",
             "smtp": "25", "pop3": "110"}
    if line.startswith(("permit ", "deny ")) and " eq " in line:
        before, port = line.rsplit(" eq ", 1)
        line = before + " eq " + ports.get(port, port)
    return line


def _parse(lines):
    """Preserve IOS section boundaries; unknown commands are never reinterpreted."""
    config = {"hostname": [], "interfaces": {}, "routers": {}, "acls": {}, "vlans": {},
              "routes": [], "unknown": []}
    context, values = "global", None
    for raw in lines:
        line = _normalize(raw)
        if not line:
            continue
        if line in {"!", "exit", "end"}:
            context, values = "global", None
            continue
        if line in {"enable", "configure terminal"}:
            continue
        if line.startswith("hostname "):
            if context != "global":
                config["unknown"].append(context)
            config["hostname"].append(line.split(" ", 1)[1])
            context, values = "global", None
            continue
        section = re.fullmatch(r"(interface|router|ip access-list extended|vlan|line) (.+)", line)
        if section:
            kind, name = section.groups()
            if kind == "line":
                context, values = "line", []
            else:
                group = {"interface": "interfaces", "router": "routers", "ip access-list extended": "acls", "vlan": "vlans"}[kind]
                if name in config[group]:
                    config["unknown"].append(f"duplicate {kind} section")
                values = config[group].setdefault(name, [])
                context = f"{kind} {name}"
            continue
        if line == "control-plane":
            context, values = "control-plane", []
            continue
        if context == "global":
            if line.startswith("ip route "):
                config["routes"].append(line)
            elif not any(re.fullmatch(pattern, line) for pattern in _SAFE_GLOBAL):
                # Do not echo unknown commands; they may contain credentials.
                config["unknown"].append("global")
        elif context == "line":
            if line != "login":
                config["unknown"].append("line")
        elif context == "control-plane":
            config["unknown"].append("control-plane")
        elif context.startswith("interface "):
            if line in _SAFE_INTERFACE or line.startswith("description "):
                continue
            values.append(line)
        else:
            values.append(line)
    return config


def _running_body(text, device_id, result):
    if not isinstance(text, str) or not text.strip():
        _issue(result, "missing_output", "transcript", "No running-config output was supplied.")
        return None
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text).replace("\r", "")
    if "--More--" in clean:
        _issue(result, "incomplete_output", "transcript", "The captured configuration is still paginated.")
        return None
    lines, saw_header, saw_end, body = clean.splitlines(), False, False, []
    for raw in lines:
        line = raw.strip()
        prompt = _PROMPT.fullmatch(raw)
        if prompt:
            hostname, command = prompt.groups()
            if hostname != device_id:
                _issue(result, "device_mismatch", "transcript", "A device prompt differs from the requested device ID.")
                return None
            if not command:
                continue
            if re.fullmatch(r"show (?:running-config|run)", command, re.I) and not saw_end:
                saw_header = True
                continue
            _issue(result, "mixed_transcript", "transcript", "Only one show running-config output may be imported.")
            return None
        if re.fullmatch(r"show (?:running-config|run)", line, re.I):
            if saw_end:
                _issue(result, "mixed_transcript", "transcript", "Multiple command outputs were supplied.")
                return None
            saw_header = True
            continue
        if line.startswith("Building configuration") or re.fullmatch(r"Current configuration\s*:\s*\d+ bytes", line):
            if saw_end:
                _issue(result, "mixed_transcript", "transcript", "Multiple configuration headers were supplied.")
                return None
            saw_header = True
            continue
        if line == "end":
            saw_end = True
            body.append(raw)
            continue
        if saw_end and line:
            _issue(result, "incomplete_or_mixed_output", "transcript", "Unexpected text follows the final configuration end marker.")
            return None
        body.append(raw)
    if not saw_header or not saw_end:
        _issue(result, "incomplete_output", "transcript", "A show running-config header and final end marker are required.")
        return None
    return body


def diagnose(expected_topology, device_id, running_config_text):
    """Compare a complete imported config and return a reviewable candidate patch.

    A patch is suppressed if any unsupported drift is present. The function is
    pure with respect to caller data, files and network; rendering reads the
    schema already loaded by network_core and never executes generated CLI.
    """
    result = {"issues": [], "patch_cli": "", "repairable": False,
              "limitations": ["Only complete imported IOS output is analyzed; authenticity and application are not verified.",
                              "Only primary interface IPv4 replacement and missing existing-protocol networks/static routes are repair candidates.",
                              "ACL/VLAN/protocol changes, removals, shutdown state and unknown configuration block the entire patch."],
              "execution": "not_executed", "requires_human_confirmation": False}
    try:
        expected_files = core.render(expected_topology)
    except (ValueError, TypeError, KeyError):
        _issue(result, "invalid_expected_topology", "expected", "The expected topology did not pass independent validation.")
        return result
    filename = f"{device_id}.cfg"
    if filename not in expected_files:
        _issue(result, "unsupported_device", "expected", "The device has no supported IOS configuration in the expected topology.")
        return result
    body = _running_body(running_config_text, device_id, result)
    if body is None:
        return result
    expected = _parse(expected_files[filename].splitlines())
    observed = _parse(body)
    if observed["hostname"] != [device_id]:
        _issue(result, "device_mismatch", "hostname", "Exactly one matching hostname is required in the running configuration.")
        return result
    if observed["unknown"]:
        _issue(result, "unsupported_configuration", "transcript",
               "Unsupported commands or duplicate sections were observed; no full configuration overwrite will be proposed.",
               observed=sorted(set(observed["unknown"])))
    patches = []
    for name, expected_lines in expected["interfaces"].items():
        context = f"interface {name}"
        if name not in observed["interfaces"]:
            _issue(result, "missing_interface_section", context, "The complete output does not contain the expected interface section.")
            continue
        actual = observed["interfaces"][name]
        e_ip = [line for line in expected_lines if line.startswith("ip address ")]
        a_ip = [line for line in actual if line.startswith("ip address ")]
        # A missing explicit no-shutdown command is normal IOS serialization;
        # an explicit shutdown statement is a real unsupported state difference.
        e_other = [line for line in expected_lines if not line.startswith("ip address ") and line != "no shutdown"]
        a_other = [line for line in actual if not line.startswith("ip address ") and line not in {"no shutdown", "no ip address"}]
        if "switchport access vlan 1" in e_other and "switchport access vlan 1" not in a_other:
            a_other.append("switchport access vlan 1")  # IOS omits the default access VLAN.
        if sorted(e_other) != sorted(a_other):
            _issue(result, "unsupported_interface_drift", context, "Interface ACL, switching, OSPF cost, shutdown or other settings differ.")
        if e_ip != a_ip:
            if len(e_ip) != 1 or len(a_ip) > 1 or any(len(line.split()) != 4 for line in a_ip):
                _issue(result, "unsupported_address_shape", context, "Secondary or ambiguous addressing cannot be repaired conservatively.")
            else:
                _issue(result, "interface_ipv4_mismatch", context, "Primary IPv4 address or mask differs or is missing.",
                       repairable=True, expected=e_ip[0], observed=a_ip[0] if a_ip else "no ip address")
                patches.extend([context, e_ip[0], "exit"])
    for name, actual in observed["interfaces"].items():
        if name in expected["interfaces"]:
            continue
        if set(actual) - {"no ip address", "shutdown"}:
            _issue(result, "unexpected_interface_configuration", f"interface {name}",
                   "An interface outside the expected topology has active or unsupported configuration.")
    if observed["acls"] != expected["acls"]:
        _issue(result, "unsupported_acl_drift", "ACL", "ACL contents/order differ; appending or replaying a full ACL is prohibited.")
    if observed["vlans"] != expected["vlans"]:
        _issue(result, "unsupported_vlan_drift", "VLAN", "VLAN definitions differ and are outside the supported repair scope.")
    if set(observed["routers"]) != set(expected["routers"]):
        _issue(result, "unsupported_routing_context", "router", "The routing protocol or process context differs or is absent.")
    for name, expected_lines in expected["routers"].items():
        if name not in observed["routers"]:
            continue
        actual = observed["routers"][name]
        e_networks = [line for line in expected_lines if line.startswith("network ")]
        a_networks = [line for line in actual if line.startswith("network ")]
        e_other = [line for line in expected_lines if not line.startswith("network ")]
        a_other = [line for line in actual if not line.startswith("network ")]
        if re.fullmatch(r"ospf [1-9][0-9]*", name):
            # Packet Tracer IOS serializes this default OSPF logging option even
            # though the compiler does not configure it. It changes logging,
            # not adjacency policy. Do not exempt router-id/passive-interface
            # or other protocol options from drift detection.
            a_other = [line for line in a_other if line != "log-adjacency-changes"]
        if name == "rip":
            # Enabled auto-summary is normally omitted in a show running-config.
            if not any(line in {"auto-summary", "no auto-summary"} for line in a_other):
                a_other.append("auto-summary")
        if sorted(e_other) != sorted(a_other) or set(a_networks) - set(e_networks):
            _issue(result, "unsupported_protocol_drift", f"router {name}",
                   "Protocol options or extra/different network statements require explicit redesign, not additive repair.")
        missing = [line for line in e_networks if line not in a_networks]
        if missing:
            for line in missing:
                _issue(result, "missing_network", f"router {name}", "An expected network statement is missing.",
                       repairable=True, expected=line)
            patches.extend([f"router {name}", *missing, "exit"])
    extra_routes = set(observed["routes"]) - set(expected["routes"])
    if extra_routes:
        _issue(result, "unsupported_static_route_drift", "ip route", "Extra or different static routes require removal/review and cannot be fixed by adding routes.")
    for line in expected["routes"]:
        if line not in observed["routes"]:
            _issue(result, "missing_static_route", "ip route", "An expected static route is missing.", repairable=True, expected=line)
            patches.append(line)
    if any(not issue["repairable"] for issue in result["issues"]):
        return result
    result["repairable"] = True
    if not patches:
        return result
    candidate = "\n".join(["enable", "configure terminal", *patches, "end", ""])
    if core.check_commands(candidate):
        _issue(result, "candidate_guardrail_rejected", "patch", "The candidate did not pass the command whitelist and context checks.")
        result["repairable"] = False
        return result
    result.update(patch_cli=candidate, requires_human_confirmation=True)
    return result
