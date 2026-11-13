"""Conservative, offline assertions over user-imported Packet Tracer text.

These functions parse evidence; they neither run network commands nor prove the
authenticity of imported text. ``unknown`` is deliberately distinct from failure.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import ipaddress
import re


_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
_PROMPT = re.compile(r"^\s*[A-Za-z][\w()./:-]*[>#]\s*$", re.M)
_ALIASES = {"ping": "ping", "trace": "traceroute", "path": "traceroute", "tracert": "traceroute",
            "traceroute": "traceroute", "route": "route", "show ip route": "route"}


def _ipv4(value):
    try:
        return str(ipaddress.IPv4Address(str(value)))
    except (ValueError, TypeError):
        return None


def _addresses(text):
    return [ip for token in re.findall(_IP, text) if (ip := _ipv4(token))]


def _unknown(result, reason, **observed):
    result.update(status="unknown", actual=None, reason=reason)
    result["observed"].update(observed)
    return result


def _assert(result, name, expected, actual):
    result["assertions"].append({"name": name, "expected": expected, "actual": actual,
                                 "status": "passed" if expected == actual else "failed"})


def _finish(result):
    passed = all(a["status"] == "passed" for a in result["assertions"])
    result.update(status="passed" if passed else "failed", actual=passed,
                  reason="All requested assertions matched imported evidence." if passed
                  else "Complete imported evidence contradicts at least one assertion.")
    return result


def verify_text(kind, text, expected: dict | None = None) -> dict:
    """Verify one complete command output, without executing any command.

    ``kind``: ping, tracert/traceroute/trace, or route/show ip route.
    Ping/trace require expected.target (IPv4); reachable defaults to True.
    expected_hops is an exact ordered list of responding IPv4 hops, INCLUDING
    the destination. Route requires an exact IPv4 prefix; protocol and next_hop
    are optional. A route import must include the command, table header and
    final router prompt, so a truncated table cannot establish route absence.
    The returned ``actual`` means the requested assertions matched, not that a
    command was automatically executed. Inspect observed.reachable/route_present
    for the measured network property.
    """
    canonical = _ALIASES.get(str(kind).strip().lower())
    raw = text if isinstance(text, str) else ""
    result = {"kind": canonical or str(kind), "status": "unknown", "actual": None,
              "source": "user_imported_text", "execution": "external_manual",
              "assertions": [], "observed": {}, "reason": "",
              "evidence": {"sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                           "nonempty": bool(raw.strip())}}
    if canonical is None:
        return _unknown(result, "Unsupported verification kind.")
    if not raw.strip():
        return _unknown(result, "No raw command output was supplied.")
    if expected is None:
        expected = {}
    if not isinstance(expected, dict):
        return _unknown(result, "Expected assertions must be a dictionary.")
    if "reachable" in expected and not isinstance(expected["reachable"], bool):
        return _unknown(result, "reachable must be a boolean.")
    # ANSI control codes occur in some pasted terminal exports.
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw).replace("\r", "")
    if canonical == "route":
        return _verify_route(clean, expected, result)
    target = _ipv4(expected.get("target"))
    if target is None:
        return _unknown(result, "An explicit IPv4 target is required; hostnames are not inferred.")
    if canonical == "ping":
        return _verify_ping(clean, expected, target, result)
    return _verify_trace(clean, expected, target, result)


def _verify_ping(text, expected, target, result):
    windows_headers = re.findall(r"^\s*Pinging\s+(.+?)\s+with\s+\d+\s+bytes", text, re.M | re.I)
    cisco_headers = re.findall(r"Sending\s+(\d+),\s*\d+-byte ICMP Echos to\s+([^,\n]+),", text, re.I)
    headers = windows_headers + [line for _, line in cisco_headers]
    if len(headers) != 1:
        return _unknown(result, "One complete ping output is required; missing or multiple ping headers.")
    found = _addresses(headers[0])
    if len(set(found)) != 1 or found[0] != target:
        return _unknown(result, "The ping destination is missing, ambiguous, or differs from expected.target.")
    observed = {"target": target}
    if windows_headers:
        stats = re.findall(r"Ping statistics for\s+(" + _IP + r")\s*:", text, re.I)
        counters = re.findall(r"Packets:\s*Sent\s*=\s*(\d+)\s*,\s*Received\s*=\s*(\d+)\s*,\s*Lost\s*=\s*(\d+)\s*\(\s*(\d+)%\s*loss\s*\)", text, re.I)
        if stats != [target] or len(counters) != 1:
            return _unknown(result, "Missing, incomplete, or ambiguous Windows ping summary.")
        sent, received, lost, percent = map(int, counters[0])
        if sent <= 0 or not 0 <= received <= sent or lost != sent - received or abs(percent - 100 * lost / sent) > 1:
            return _unknown(result, "Ping packet counters or loss percentage are inconsistent.")
        replies = re.findall(r"Reply from\s+(" + _IP + r")\s*:\s*bytes\s*=", text, re.I)
        if any(ip != target for ip in replies) or len(replies) != received:
            return _unknown(result, "Successful reply lines do not match the destination and received counter.")
        observed.update(format="windows", sent=sent, received=received, lost=lost, loss_percent=percent)
    else:
        rates = re.findall(r"Success rate is\s+(\d+)\s*percent\s*\(\s*(\d+)\s*/\s*(\d+)\s*\)", text, re.I)
        if len(rates) != 1:
            return _unknown(result, "Missing, incomplete, or ambiguous Cisco ping summary.")
        rate, received, sent = map(int, rates[0])
        if sent <= 0 or not 0 <= received <= sent or sent != int(cisco_headers[0][0]) or abs(rate - 100 * received / sent) > 1:
            return _unknown(result, "Cisco success rate and packet counters are inconsistent.")
        observed.update(format="cisco", sent=sent, received=received, lost=sent - received,
                        loss_percent=100 - rate)
    observed["reachable"] = received > 0
    result["observed"].update(observed)
    _assert(result, "reachable", expected.get("reachable", True), received > 0)
    return _finish(result)


def _verify_trace(text, expected, target, result):
    headers = re.findall(r"^\s*(?:Tracing route to|Tracing the route to|traceroute to)\s+([^\n]+)", text, re.M | re.I)
    if len(headers) != 1:
        return _unknown(result, "One trace output with an explicit destination header is required.")
    header_ips = _addresses(headers[0])
    if len(set(header_ips)) != 1 or header_ips[0] != target:
        return _unknown(result, "The trace destination is missing, ambiguous, or differs from expected.target.")
    expected_hops = expected.get("expected_hops")
    if expected_hops is not None:
        if not isinstance(expected_hops, (list, tuple)) or not expected_hops or any(_ipv4(x) is None for x in expected_hops):
            return _unknown(result, "expected_hops must be a nonempty ordered list of IPv4 addresses.")
        expected_hops = [_ipv4(x) for x in expected_hops]
    rows = []
    for number, body in re.findall(r"^\s*(\d+)\s+([^\n]+)", text, re.M):
        ips = list(dict.fromkeys(_addresses(body)))
        rows.append({"number": int(number), "addresses": ips, "timeout": "*" in body,
                     "error": bool(re.search(r"![A-Za-z]|unreachable|timed out", body, re.I))})
    result["observed"].update(target=target, hops=rows)
    if not rows or [r["number"] for r in rows] != list(range(1, len(rows) + 1)):
        return _unknown(result, "Trace hop rows are missing, truncated, or contain more than one trace.")
    if any(r["timeout"] or r["error"] or len(r["addresses"]) != 1 for r in rows):
        return _unknown(result, "Timeouts, errors or ambiguous responding addresses prevent a complete path assertion.")
    path = [r["addresses"][0] for r in rows]
    if path[-1] != target or target in path[:-1]:
        return _unknown(result, "The destination was not reached in a complete, unambiguous final hop.")
    result["observed"].update(path=path, reachable=True)
    _assert(result, "reachable", expected.get("reachable", True), True)
    if expected_hops is not None:
        _assert(result, "expected_hops", expected_hops, path)
    return _finish(result)


def _protocol(value):
    normalized = re.sub(r"\s+", " ", str(value).replace("_", " ").strip().upper()).replace("*", "")
    aliases = {"CONNECTED": "C", "LOCAL": "L", "STATIC": "S", "RIP": "R", "OSPF": "O",
               "OSPF IA": "O IA", "OSPF INTER AREA": "O IA"}
    code = aliases.get(normalized, normalized)
    return code if code in {"C", "L", "S", "R", "O", "O IA", "O E1", "O E2", "O N1", "O N2"} else None


def _major_network(address):
    """Cisco unmasked subnet rows inherit the header mask inside its classful major network."""
    first = int(str(address).split(".")[0])
    length = 8 if first < 128 else 16 if first < 192 else 24
    return ipaddress.IPv4Network(f"{address}/{length}", strict=False)


def _logical_route_lines(body):
    """Join only a recognizable prefix-only row and its immediate IOS continuation.

    This is a parser view, never a rewrite of evidence or its digest. Unknown
    codes, malformed metrics/addresses and truncated rows remain separate so the
    caller will conservatively return unknown rather than infer route absence.
    """
    prefix_only = re.compile(r"^\s*(C|L|S\*?|R|O(?:\s+(?:IA|E1|E2|N1|N2))?)\s+(" + _IP + r"(?:/\d+)?)\s*$")
    interface = r"[A-Za-z][A-Za-z-]*\d+(?:[./:]\d+)*"
    age = r"(?:\d{1,3}:\d{2}:\d{2}|\d+[wdhms](?:\d+[wdhms])*)"
    tail = r"(?:\s*,\s*(?:" + age + r")(?:\s*,\s*" + interface + r")?|\s*,\s*" + interface + r")?"
    metric_row = re.compile(r"^\s+\[(\d+)/(\d+)\]\s+via\s+(" + _IP + r")" + tail + r"\s*$")
    connected_row = re.compile(r"^\s+is directly connected,\s*" + interface + r"\s*$")
    lines = body.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        prefix = prefix_only.fullmatch(line)
        if prefix and index + 1 < len(lines):
            continuation = lines[index + 1]
            metric = metric_row.fullmatch(continuation)
            valid_metric = (metric is not None and 0 <= int(metric[1]) <= 255
                            and 0 <= int(metric[2]) <= 2**32 - 1 and _ipv4(metric[3]) is not None)
            code = prefix[1].replace("*", "")
            if ((code not in {"C", "L"} and valid_metric)
                    or (code in {"C", "L", "S"} and connected_row.fullmatch(continuation))):
                yield line.rstrip() + " " + continuation.strip()
                index += 2
                continue
        yield line
        index += 1


def _verify_route(text, expected, result):
    if "present" in expected and type(expected["present"]) is not bool:
        return _unknown(result, "present must be a boolean.")
    # reachable is retained only for compatibility with earlier direct parser
    # callers; DSL 0.2 route checks use present and never conflate the concepts.
    wanted_present = expected.get("present", expected.get("reachable", True))
    if not wanted_present and any(key in expected for key in ("protocol", "next_hop")):
        return _unknown(result, "An absent-route assertion cannot require a protocol or next hop.")
    try:
        prefix = ipaddress.IPv4Network(str(expected.get("prefix")), strict=True)
    except (ValueError, TypeError):
        return _unknown(result, "An explicit canonical IPv4 network prefix is required.")
    wanted_protocol = _protocol(expected["protocol"]) if "protocol" in expected else None
    if "protocol" in expected and wanted_protocol is None:
        return _unknown(result, "Unsupported expected routing protocol.")
    wanted_hop = _ipv4(expected["next_hop"]) if "next_hop" in expected else None
    if "next_hop" in expected and wanted_hop is None:
        return _unknown(result, "next_hop must be an IPv4 address.")
    commands = list(re.finditer(r"^\s*(?:[\w()./:-]+[>#]\s*)?show\s+ip\s+route\s*$", text, re.M | re.I))
    command = commands[0] if len(commands) == 1 else None
    prompts = list(_PROMPT.finditer(text))
    if not command or not prompts or prompts[-1].start() <= command.end() or text[prompts[-1].end():].strip():
        return _unknown(result, "A complete show ip route transcript including its final router prompt is required.")
    body = text[command.end():prompts[-1].start()]
    if not re.search(r"Codes:|Gateway of last resort", body, re.I) or "--More--" in body:
        return _unknown(result, "The routing table header is missing or output is still paginated.")
    routes, unresolved = [], []
    inherited = None
    entry_pattern = re.compile(r"^\s*(C|L|S\*?|R|O(?:\s+(?:IA|E1|E2|N1|N2))?)\s+(" + _IP + r"(?:/\d+)?)\s+(.+)$")
    for line in _logical_route_lines(body):
        if not line.strip() or re.match(r"^\s*(?:Codes:|Gateway of last resort\b)", line, re.I):
            continue
        # IOS wraps its Codes legend. Only legend-shaped lines WITHOUT an IP
        # can be ignored; an unknown route code or malformed route stays unknown.
        if not _addresses(line) and re.match(r"^\s*[A-Za-z0-9*+%]+(?:\s+[A-Za-z0-9*+%]+)?\s+-\s+", line):
            continue
        header = re.match(r"^\s*(" + _IP + r")/(\d+)\s+is\s+(variably\s+)?subnetted\b", line)
        if header:
            inherited = None
            if not header[3] and _ipv4(header[1]) and 0 <= int(header[2]) <= 32:
                inherited = (_major_network(header[1]), int(header[2]))
            continue
        entry = entry_pattern.match(line)
        if entry:
            code, destination, details = entry.groups()
            try:
                if "/" in destination:
                    network = ipaddress.IPv4Network(destination, strict=True)
                elif inherited and ipaddress.IPv4Address(destination) in inherited[0]:
                    network = ipaddress.IPv4Network(f"{destination}/{inherited[1]}", strict=True)
                else:
                    unresolved.append(line)
                    continue
            except ValueError:
                unresolved.append(line)
                continue
            hops = [_ipv4(x) for x in re.findall(r"\bvia\s+(" + _IP + r")", details)]
            direct = bool(re.search(r"is directly connected", details, re.I))
            if (not hops and not direct) or any(h is None for h in hops):
                unresolved.append(line)
                continue
            routes.append({"prefix": str(network), "protocol": _protocol(code), "next_hops": hops,
                           "directly_connected": direct, "raw": line.strip()})
            continue
        continuation = re.match(r"^\s+\[\d+/\d+\]\s+via\s+(" + _IP + r")", line)
        if continuation and routes:
            hop = _ipv4(continuation[1])
            if hop:
                routes[-1]["next_hops"].append(hop)
            else:
                unresolved.append(line)
            continue
        # No other nonempty table line is silently discarded. In particular,
        # lowercase/unknown route codes and truncated prefixes can hide the
        # desired prefix, so they cannot establish an absent-route assertion.
        unresolved.append(line)
    matching = [r for r in routes if r["prefix"] == str(prefix)]
    result["observed"].update(prefix=str(prefix), routes=matching, parsed_route_count=len(routes),
                              unresolved_lines=unresolved, table_complete=True)
    if unresolved:
        return _unknown(result, "Some routing entries cannot be interpreted safely; no route assertion was made.")
    present = bool(matching)
    result["observed"]["route_present"] = present
    _assert(result, "route_present", wanted_present, present)
    if wanted_protocol is not None:
        _assert(result, "protocol", wanted_protocol, matching[0]["protocol"] if len(matching) == 1 else
                wanted_protocol if matching and all(r["protocol"] == wanted_protocol for r in matching) else None)
    if wanted_hop is not None:
        _assert(result, "next_hop_present", True, any(wanted_hop in r["next_hops"] for r in matching))
    return _finish(result)


def new_repair_state(max_rounds=3):
    """Create bounded candidate-only state. No network access or config execution."""
    if isinstance(max_rounds, bool) or not isinstance(max_rounds, int) or not 1 <= max_rounds <= 3:
        raise ValueError("max_rounds must be an integer between 1 and 3")
    return {"status": "not_started", "max_rounds": max_rounds, "rounds": [],
            "automatic_application": False, "automatic_repair_success": False}


def _copy_state(state):
    copied = deepcopy(state)
    if not isinstance(copied, dict) or not isinstance(copied.get("rounds"), list):
        raise ValueError("Invalid repair state")
    limit = copied.get("max_rounds")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 3 or len(copied["rounds"]) > limit:
        raise ValueError("Invalid repair round limit")
    copied.update(automatic_application=False, automatic_repair_success=False)
    return copied


def _usable_result(result):
    return (isinstance(result, dict) and result.get("source") == "user_imported_text"
            and result.get("status") in {"passed", "failed"}
            and result.get("actual") is (result.get("status") == "passed")
            and isinstance(result.get("evidence"), dict)
            and result["evidence"].get("nonempty") is True
            and bool(re.fullmatch(r"[a-f0-9]{64}", str(result["evidence"].get("sha256", ""))))
            and bool(result.get("assertions")))


def propose_repair(state, candidate_config, based_on=None):
    """Append a proposal only; a human must review/apply it outside this module.

    No failure evidence is required to draft a candidate, but that absence is
    recorded explicitly and can never be interpreted as successful repair.
    """
    out = _copy_state(state)
    if not isinstance(candidate_config, str) or not candidate_config.strip():
        raise ValueError("A nonempty candidate configuration is required")
    if _usable_result(based_on) and based_on["status"] == "passed":
        raise ValueError("The supplied checks already passed; a repair proposal is not justified")
    if out["rounds"] and out["rounds"][-1]["status"] == "awaiting_external_verification":
        raise ValueError("Import verification evidence for the pending round before proposing another")
    if out["status"] == "external_checks_passed":
        raise ValueError("Checks already passed; no additional candidate is needed")
    if len(out["rounds"]) >= out["max_rounds"]:
        out["status"] = "exhausted"
        return out
    out["rounds"].append({"round": len(out["rounds"]) + 1, "candidate_config": candidate_config,
                          "applied_by_program": False, "application_status": "not_observed",
                          "requires_human_confirmation": True, "status": "awaiting_external_verification",
                          "based_on": deepcopy(based_on) if _usable_result(based_on) else None,
                          "verification": None})
    out["status"] = "awaiting_external_verification"
    return out


def record_repair_verification(state, result):
    """Record fresh externally obtained evidence, without claiming causality.

    Even a passing check only sets external_checks_passed. This module never
    asserts that the candidate was applied or that an automatic repair succeeded.
    Missing, unknown, and reused evidence leave the round awaiting verification.
    """
    out = _copy_state(state)
    if not out["rounds"]:
        raise ValueError("No repair candidate exists")
    current = out["rounds"][-1]
    if current["status"] != "awaiting_external_verification":
        raise ValueError("The latest repair round has already been verified")
    used = [item["verification"]["evidence"]["sha256"] for item in out["rounds"][:-1]
            if _usable_result(item.get("verification"))]
    if _usable_result(current.get("based_on")):
        used.append(current["based_on"]["evidence"]["sha256"])
    if not _usable_result(result) or result["evidence"]["sha256"] in used:
        out["verification_issue"] = "Fresh, complete imported output is required; no repair success is claimed."
        return out
    basis = current.get("based_on")
    if _usable_result(basis):
        def scope(item):
            return (item["kind"], item["observed"].get("target"), item["observed"].get("prefix"),
                    [(a["name"], a["expected"]) for a in item["assertions"]])
        if scope(result) != scope(basis):
            out["verification_issue"] = "Verification scope differs from the failed check; no repair success is claimed."
            return out
    current["verification"] = deepcopy(result)
    if result["status"] == "passed":
        current["status"] = out["status"] = "external_checks_passed"
    else:
        current["status"] = "external_checks_failed"
        out["status"] = "exhausted" if len(out["rounds"]) >= out["max_rounds"] else "ready_for_next_candidate"
    out.pop("verification_issue", None)
    return out
