"""One-topology PT lab orchestration. Every observation is externally supplied."""
from contextlib import contextmanager
from datetime import datetime
import json
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

import yaml

import cli_extensions as ext
import migration
import network_core as core
import workflow as wf


STAGES = ("ripv1", "ripv2", "fault", "repaired", "ospf")
PROJECT_ROOT = Path(__file__).resolve().parent
CASE_IDS = {"ripv1": "CASE04", "ripv2": "CASE03", "ospf": "CASE05"}
FAULT_PROVENANCE = "assistant_prepared_controlled_fault_user_must_apply_in_local_PT"


def _json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _trusted_root(root=None):
    trusted = PROJECT_ROOT.resolve()
    if root is not None and Path(root).resolve() != trusted:
        raise ValueError("实验来源必须属于当前实际项目，不能用计划内容指定其他项目根目录")
    return trusted


def _sources(root):
    """Registry paths are constrained independently of the editable lab manifest."""
    runs_root = (root / "runs").resolve()
    if not runs_root.is_relative_to(root.resolve()) or runs_root == root.resolve():
        raise ValueError("项目runs目录不能通过软链接逃逸到项目外")
    registry = json.loads((root / "evaluations/current-agent-validation.json").read_text(encoding="utf-8"))
    if not isinstance(registry, dict) or not isinstance(registry.get("cases"), list):
        raise ValueError("当前案例来源登记无效")
    entries = {}
    for entry in registry["cases"]:
        if not isinstance(entry, dict) or entry.get("case_id") in entries:
            raise ValueError("当前案例来源登记重复或无效")
        entries[entry.get("case_id")] = entry
    runs, topologies = {}, {}
    for name, case_id in CASE_IDS.items():
        if case_id not in entries or not isinstance(entries[case_id].get("run"), str):
            raise ValueError(f"缺少 {case_id} 的当前模型来源")
        supplied = Path(entries[case_id]["run"])
        run = (supplied if supplied.is_absolute() else root / supplied).resolve()
        if not run.is_relative_to(runs_root) or run == runs_root:
            raise ValueError("来源run必须在本项目runs目录，不能逃逸到其他项目")
        metadata = json.loads((run / "metadata.json").read_text(encoding="utf-8"))
        if not isinstance(metadata, dict) or metadata.get("mode") != "live_llm":
            raise ValueError("只能使用真实模型来源；离线fixture不能作为本实验来源")
        wf.verify_handoff(run)
        requirement = (run / "requirement.txt").read_text(encoding="utf-8").strip()
        expected_requirement = (root / "cases" / case_id / "request.txt").read_text(encoding="utf-8").strip()
        if requirement != expected_requirement:
            raise ValueError(f"{case_id} 来源需求与当前案例不一致，请重新生成并审阅")
        topology = yaml.safe_load((run / "topology.yaml").read_text(encoding="utf-8"))
        contract = json.loads((root / "cases" / case_id / "contract.json").read_text(encoding="utf-8"))
        wf.validate_contract(contract)
        if wf.check_contract(topology, contract):
            raise ValueError(f"{case_id} 来源拓扑不符合当前需求契约")
        runs[name], topologies[name] = run, topology
    return runs, topologies


def _canonical_artifacts(root, lab, runs, topologies):
    """Recompile the fixed lab; recomputed hashes alone cannot authorize drift."""
    rendered = {name: core.render(topology) for name, topology in topologies.items()}
    to_v2 = migration.plan_migration(topologies["ripv1"], topologies["ripv2"])
    to_ospf = migration.plan_migration(topologies["ripv2"], topologies["ospf"])
    router = next((d for d in topologies["ripv2"]["devices"] if d["id"] == "R0"), {})
    interface = next((p for p in router.get("interfaces", []) if p["name"] == "GigabitEthernet0/0"), {})
    if interface.get("ipv4") != "192.168.16.126/25":
        raise ValueError("预置错掩码演练仅适用于当前已审阅R0地址")
    fault = "enable\nconfigure terminal\ninterface GigabitEthernet0/0\nip address 192.168.16.126 255.255.255.192\nexit\nend\n"
    if core.check_commands(fault):
        raise ValueError("故障演练命令未通过护栏")
    artifacts, stages = {}, {}
    specs = [
        ("ripv1", "ripv1", {k: v for k, v in rendered["ripv1"].items() if k.endswith(".cfg")}, "new_blank_topology"),
        ("ripv2", "ripv2", to_v2, "ripv1_to_ripv2"),
        ("fault", "ripv2", {"R0.cfg": fault}, "intentional_mask_fault_after_healthy_ripv2"),
        ("repaired", "ripv2", {}, "external_candidate_repair_only"),
        ("ospf", "ospf", to_ospf, "healthy_ripv2_to_ospf"),
    ]
    for name, source, files, transition in specs:
        checks = json.loads(rendered[source]["verification-plan.json"])
        if name == "fault":
            checks["checks"] = [check for check in checks["checks"] if check["id"] == "check-01"]
            checks["note"] = "这是健康RIPv2计划的断言；注入故障后预期本项被判failed，用作真实修复前证据。"
        for filename, text in files.items():
            artifacts[f"review/{name}/{filename}"] = text
        artifacts[f"review/{name}/checks.json"] = _json_text(checks)
        stages[name] = {"source_run": str(runs[source]), "source_manifest_sha256": wf.digest(runs[source] / "manifest.json"),
                        "transition": transition, "cli_files": sorted(files), "checks": checks["checks"]}
    for filename in ("pc-addresses.csv", "links.csv", "topology.mmd"):
        artifacts[filename] = rendered["ripv1"][filename]
    artifacts["开始实测.md"] = _guide(root, lab)
    return artifacts, stages


@contextmanager
def lab_lock(lab):
    lock = lab / ".lab-lock"
    try:
        lock.mkdir()
    except FileExistsError:
        raise ValueError("该实验正在操作，请等待当前导入完成") from None
    try:
        yield
    finally:
        lock.rmdir()


def load_plan(lab):
    root = _trusted_root()
    manifest = json.loads((lab / "manifest.json").read_text())
    if (not isinstance(manifest, dict) or "plan.json" not in manifest
            or any(not isinstance(name, str) or not isinstance(value, str) for name, value in manifest.items())):
        raise ValueError("实验计划清单无效")
    for name, expected in manifest.items():
        path = (lab / name).resolve()
        if not path.is_relative_to(lab.resolve()) or not path.is_file() or wf.digest(path) != expected:
            raise ValueError("实验计划或配置已变更，请重新准备并审阅")
    plan = json.loads((lab / "plan.json").read_text())
    if (not isinstance(plan, dict) or plan.get("type") != "local_packet_tracer_route_lab"
            or plan.get("project_root") != str(root) or plan.get("sequence") != list(STAGES)
            or not isinstance(plan.get("stages"), dict) or set(plan["stages"]) != set(STAGES)
            or plan.get("network_executed") is not False or plan.get("fault_provenance") != FAULT_PROVENANCE):
        raise ValueError("实验阶段清单无效")
    runs, topologies = _sources(root)
    canonical, stages = _canonical_artifacts(root, lab, runs, topologies)
    if plan["stages"] != stages:
        raise ValueError("阶段来源、CLI清单或验收断言与原拓扑规范编译结果不一致")
    if set(manifest) != {"plan.json", *canonical}:
        raise ValueError("实验manifest文件集合与规范计划不一致")
    for name, text in canonical.items():
        if (lab / name).read_text(encoding="utf-8") != text:
            raise ValueError("实验CLI或验收计划与来源拓扑/迁移候选不一致，重算manifest不能绕过审阅")
    return plan


def _state(lab):
    path = lab / "state.json"
    data = json.loads(path.read_text())
    if (not isinstance(data, dict) or not isinstance(data.get("results"), dict) or not isinstance(data.get("attachments"), list)
            or any(name not in STAGES or not isinstance(rows, dict) for name, rows in data["results"].items())
            or data.get("repair") is not None and not isinstance(data["repair"], dict)):
        raise ValueError("实验状态损坏，不能推断通过")
    return data


def prepare(root, output):
    root = _trusted_root(root)
    runs, topologies = _sources(root)
    artifacts, stages = _canonical_artifacts(root, output, runs, topologies)
    output.mkdir(parents=True, exist_ok=False)
    for name, text in artifacts.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    wf.write_json(output / "plan.json", {"type": "local_packet_tracer_route_lab", "created_at_utc": wf.stamp(),
                  "project_root": str(root), "sequence": list(STAGES), "stages": stages, "network_executed": False,
                  "fault_provenance": FAULT_PROVENANCE})
    manifest = {str(p.relative_to(output)): wf.digest(p) for p in output.rglob("*") if p.is_file()}
    wf.write_json(output / "manifest.json", manifest)
    wf.write_json(output / "state.json", {"status": "prepared_not_deployed", "approval": None, "results": {}, "attachments": [], "repair": None})
    wf.audit(output, "lab_prepared", source_runs={key: str(value) for key, value in runs.items()}, network_executed=False)
    return output


def release(lab):
    with lab_lock(lab):
        plan = load_plan(lab)
        state = _state(lab)
        reviewed_manifest = wf.digest(lab / "manifest.json")
        print("请审阅 开始实测.md、编址/连线表及 review/ 各阶段CLI。")
        print("范围：本地PT，3台2911+2台PC；RIPv1→RIPv2→R0错掩码演练→人工候选修复→OSPF。")
        print("预置故障会把R0 G0/0的192.168.16.126/25暂改成/26，仅用于本地故障演练。")
        accepted = input("确认已审阅上述整个固定计划，部署前输入 CONFIRM：") == "CONFIRM"
        if accepted:
            plan = load_plan(lab)
            if wf.digest(lab / "manifest.json") != reviewed_manifest:
                raise ValueError("确认期间计划已改变，请重新审阅；本次未批准新计划")
        confirmation_id = uuid.uuid4().hex
        confirmed_at = wf.stamp()
        wf.audit(lab, "lab_human_confirmation", accepted=accepted, manifest_sha256=reviewed_manifest,
                 confirmation_id=confirmation_id, confirmed_at_utc=confirmed_at)
        if not accepted:
            return False
        for stage_name, stage in plan["stages"].items():
            for filename in stage["cli_files"]:
                text = (lab / "review" / stage_name / filename).read_text()
                if core.check_commands(text):
                    raise ValueError("配置未通过护栏")
                target = lab / "ready" / stage_name / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
        state.update(status="approved_waiting_for_external_tests", approval={"time_utc": confirmed_at, "source": "human_terminal_CONFIRM",
                     "manifest_sha256": reviewed_manifest, "confirmation_id": confirmation_id})
        wf.write_json(lab / "state.json", state)
        wf.audit(lab, "lab_handoff_created", directory="ready", network_executed=False)
        return True


def _approved(lab, state):
    approval = state.get("approval")
    if (not isinstance(approval, dict) or approval.get("source") != "human_terminal_CONFIRM"
            or not isinstance(approval.get("time_utc"), str) or not approval.get("confirmation_id")
            or approval.get("manifest_sha256") != wf.digest(lab / "manifest.json")):
        raise ValueError("请先审阅并运行 lab release，由人工输入CONFIRM；程序没有代替你部署")
    events = [json.loads(line) for line in (lab / "audit.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    if not any(isinstance(event, dict) and event.get("event") == "lab_human_confirmation" and event.get("accepted") is True
               and event.get("confirmation_id") == approval["confirmation_id"]
               and event.get("manifest_sha256") == approval["manifest_sha256"]
               and event.get("confirmed_at_utc") == approval["time_utc"] for event in events):
        raise ValueError("缺少与当前计划绑定的真实人工CONFIRM审计，不能推断批准")


def _stage(plan, name):
    if name not in STAGES:
        raise ValueError("实验阶段不存在")
    return plan["stages"][name]


def _verified_stage_rows(plan, state, name):
    stage = _stage(plan, name)
    rows = state["results"].get(name, {})
    checks = {check["id"]: check for check in stage["checks"]}
    for check_id, record in rows.items():
        if check_id not in checks:
            raise ValueError("实验状态包含不属于当前阶段的验收项")
        ext._verified_record(Path(stage["source_run"]), record, checks[check_id])
    return rows


def fault_exposed(record):
    return record.get("status") == "failed" and record.get("observed", {}).get("reachable") is False


def stage_checks(lab, name, *, resume=False):
    plan = load_plan(lab)
    checks = _stage(plan, name)["checks"]
    if not resume:
        return checks
    state = _state(lab)
    _approved(lab, state)
    rows = _verified_stage_rows(plan, state, name)
    if name == "fault":
        _healthy_ripv2(plan, state)
        return [check for check in checks if not fault_exposed(rows.get(check["id"], {}))]
    return [check for check in checks if rows.get(check["id"], {}).get("status") != "passed"]


def _healthy_ripv2(plan, state):
    rows = _verified_stage_rows(plan, state, "ripv2")
    expected_ids = {check["id"] for check in plan["stages"]["ripv2"]["checks"]}
    if len(expected_ids) != 4 or set(rows) != expected_ids or any(record.get("status") != "passed" for record in rows.values()):
        raise ValueError("fault阶段前必须先导入并通过RIPv2四项健康基线，不能只修改状态字段")


def _repair_context(plan, state, device):
    repair = state.get("repair")
    expected_run = Path(plan["stages"]["fault"]["source_run"])
    if (device != "R0" or not isinstance(repair, dict) or repair.get("device") != device
            or repair.get("source_run") != str(expected_run)):
        raise ValueError("缺少本实验R0对应的真实诊断，设备或来源run不一致")
    diagnosis = repair.get("diagnosis")
    if not isinstance(diagnosis, dict) or not diagnosis.get("repairable") or not diagnosis.get("patch_cli"):
        raise ValueError("本次诊断没有可审阅的修复候选")
    candidate_state = ext._read_repair_state(expected_run / "repairs" / device / "state.json")
    if not candidate_state["rounds"]:
        raise ValueError("来源run没有当前修复候选")
    number = len(candidate_state["rounds"])
    candidate_file = f"repairs/{device}/candidate-{number}.cfg"
    candidate_path = expected_run / candidate_file
    observed_file = diagnosis.get("source_file")
    observed_path = (expected_run / observed_file).resolve() if isinstance(observed_file, str) else None
    if (diagnosis.get("candidate_file") != candidate_file
            or diagnosis["patch_cli"] != candidate_state["rounds"][-1]["candidate_config"]
            or not candidate_path.is_file() or candidate_path.read_text(encoding="utf-8") != diagnosis["patch_cli"]
            or observed_path is None or observed_path.parent != (expected_run / "repairs" / device).resolve()
            or not observed_path.is_file() or wf.digest(observed_path) != diagnosis.get("source_sha256")):
        raise ValueError("实验诊断与当前候选/原始running-config不一致")
    return expected_run


def import_result(root, lab, stage_name, check_id, device, file):
    with lab_lock(lab):
        plan, state = load_plan(lab), _state(lab)
        _approved(lab, state)
        stage = _stage(plan, stage_name)
        if stage_name == "fault":
            _healthy_ripv2(plan, state)
        if check_id not in {c["id"] for c in stage["checks"]}:
            raise ValueError("该检查不属于此阶段")
        result = ext.import_result(root, Path(stage["source_run"]), check_id, file, device)
        state["results"].setdefault(stage_name, {})[check_id] = result
        wf.write_json(lab / "state.json", state)
        wf.audit(lab, "lab_external_result_imported", stage=stage_name, check_id=check_id, status=result["status"],
                 observed=result["observed"], evidence=result["file"], source="user_manual_PT_output")
        return result


def _collect_text(label):
    print(label)
    print("粘贴完整原始输出；最后单独输入 __END__ 并回车。不会执行粘贴内容。", flush=True)
    lines = []
    size = 0
    for line in sys.stdin:
        if line.rstrip("\r\n") == "__END__":
            break
        size += len(line.encode("utf-8"))
        if size > 2_000_000:
            raise ValueError("原始输出超过2MB")
        lines.append(line)
    if not "".join(lines).strip():
        raise ValueError("未收到原始输出")
    return "".join(lines)


def collect(root, lab, stage_name, check_id, device, file=None):
    plan = load_plan(lab)
    stage = _stage(plan, stage_name)
    check = next((c for c in stage["checks"] if c["id"] == check_id), None)
    if not check or check["source"] != device:
        raise ValueError("阶段、check-id和源设备不匹配")
    if file:
        return import_result(root, lab, stage_name, check_id, device, file)
    state = _state(lab)
    _approved(lab, state)
    if stage_name == "fault":
        _healthy_ripv2(plan, state)
    text = _collect_text(f"请在Packet Tracer的 {device} 执行：{check['command']}")
    # A private temporary file is removed even if a paste contains credentials.
    with tempfile.TemporaryDirectory(prefix="network-agent-observation-") as directory:
        path = Path(directory) / "output.txt"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return import_result(root, lab, stage_name, check_id, device, path)


def diagnose(root, lab, device="R0", file=None):
    with lab_lock(lab):
        plan, state = load_plan(lab), _state(lab)
        _approved(lab, state)
        if device != "R0":
            raise ValueError("本次受控错掩码仅针对R0，诊断设备必须一致")
        _healthy_ripv2(plan, state)
        failed = _verified_stage_rows(plan, state, "fault").get("check-01")
        if not failed or failed.get("status") != "failed" or failed.get("observed", {}).get("reachable") is not False:
            raise ValueError("请先导入fault阶段check-01的真实失败输出；RIPv1预期失败不能当作修复前故障")
        run = Path(plan["stages"]["fault"]["source_run"])
        _, active = ext._verified_imports(run, plan["stages"]["ripv2"]["checks"])
        if active.get("check-01") != failed:
            raise ValueError("fault阶段记录不是来源run当前同一原始输出，请重新采集故障证据")
        if file:
            result = ext.diagnose_run(root, run, device, file, "check-01")
        else:
            text = _collect_text(f"请在 {device} 执行 show running-config，完整复制含头尾的单次输出。")
            with tempfile.TemporaryDirectory(prefix="network-agent-config-") as directory:
                path = Path(directory) / "running.txt"
                path.write_text(text, encoding="utf-8")
                path.chmod(0o600)
                result = ext.diagnose_run(root, run, device, path, "check-01")
        state["repair"] = {"device": device, "source_run": str(run), "diagnosis": result, "verification": None}
        wf.write_json(lab / "state.json", state)
        wf.audit(lab, "lab_configuration_diagnosed", device=device, repairable=result["repairable"], source_sha256=result.get("source_sha256"), automatic_application=False)
        return result


def release_repair(lab, device):
    with lab_lock(lab):
        plan, state = load_plan(lab), _state(lab)
        _approved(lab, state)
        run = _repair_context(plan, state, device)
        return ext.release_repair(run, device)


def verify_repair(lab, device, check_id, applied_manually=False):
    with lab_lock(lab):
        plan, state = load_plan(lab), _state(lab)
        _approved(lab, state)
        if not applied_manually:
            raise ValueError("需要操作人明确声明已手动应用候选；确认后加 --applied-manually")
        run = _repair_context(plan, state, device)
        if check_id != "check-01":
            raise ValueError("本次错掩码修复必须使用原fault阶段check-01")
        repaired = _verified_stage_rows(plan, state, "repaired").get(check_id)
        if not repaired:
            raise ValueError("先导入repaired阶段同一检查的新输出")
        # Hold the same source-run lock across identity validation and recording.
        # The adapter's underlying function still performs all confirmation,
        # freshness, manifest and raw-evidence checks; avoid nested lock entry.
        with ext._run_lock(run):
            _, active = ext._verified_imports(run, plan["stages"]["ripv2"]["checks"])
            if active.get(check_id) != repaired:
                raise ValueError("repaired阶段与来源run当前导入的不是同一原始输出文件")
            result = ext.verify_repair.__wrapped__(run, device, check_id)
        state["repair"]["verification"] = result
        state["repair"]["application_declaration"] = {"source": "user_cli_applied_manually_flag", "time_utc": wf.stamp(), "applied_by_program": False}
        wf.write_json(lab / "state.json", state)
        wf.audit(lab, "lab_repair_external_verification", device=device, check_id=check_id, result=result["status"], applied_by_program=False)
        return result


def attach(lab, stage_name, file):
    with lab_lock(lab):
        load_plan(lab)
        state = _state(lab)
        _approved(lab, state)
        if stage_name not in STAGES or file.suffix.lower() not in {".pkt", ".png", ".jpg", ".jpeg"}:
            raise ValueError("仅接受已知阶段的.pkt或原始图片")
        if not file.is_file() or not 0 < file.stat().st_size <= 50_000_000:
            raise ValueError("证据文件缺失、为空或超过50MB")
        target = lab / "evidence" / stage_name / (uuid.uuid4().hex[:8] + "-" + file.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, target)
        item = {"stage": stage_name, "file": str(target.relative_to(lab)), "sha256": wf.digest(target), "source": "user_supplied_file", "content_independently_verified": False}
        state["attachments"].append(item)
        wf.write_json(lab / "state.json", state)
        wf.audit(lab, "lab_evidence_attached", **item)
        return item


def _attachment_inventory(lab, items):
    valid, invalid = [], []
    for item in items:
        if not isinstance(item, dict) or item.get("stage") not in STAGES or not isinstance(item.get("file"), str):
            invalid.append({"integrity": "invalid_attachment_record"})
            continue
        path = (lab / item["file"]).resolve()
        expected_directory = (lab / "evidence" / item["stage"]).resolve()
        if (path.parent != expected_directory or path.suffix.lower() not in {".pkt", ".png", ".jpg", ".jpeg"}
                or not path.is_file() or wf.digest(path) != item.get("sha256")):
            invalid.append({"stage": item["stage"], "file": item["file"], "integrity": "missing_or_modified"})
        else:
            valid.append(item)
    return valid, invalid


def status(lab):
    plan, state = load_plan(lab), _state(lab)
    attachments, invalid_attachments = _attachment_inventory(lab, state["attachments"])
    stages = {}
    for name, stage in plan["stages"].items():
        rows = _verified_stage_rows(plan, state, name)
        phases = {c["id"]: rows[c["id"]]["status"] if c["id"] in rows else "not_run" for c in stage["checks"]}
        if name == "fault":
            label = "fault_exposed" if fault_exposed(rows.get("check-01", {})) else "not_exposed_or_not_run"
        else:
            label = "passed_imported_checks" if phases and all(v == "passed" for v in phases.values()) else "incomplete_or_not_passed"
        stages[name] = {"status": label, "checks": phases, "pkt_files_received": sum(a["stage"] == name and a["file"].lower().endswith(".pkt") for a in attachments)}
    return {"status": state["status"], "stages": stages, "repair_status": (state.get("repair") or {}).get("verification"),
            "invalid_attachments": invalid_attachments, "automatic_execution": False,
            "attachment_contents_independently_verified": False}


def _guide(root, lab):
    command = f"cd {root}\n.venv/bin/python agent.py lab"
    base = f".venv/bin/python agent.py lab"
    path = str(lab.resolve())
    return f'''# 路由与真实故障验证 - 一套硬件，只搭一次

本文件是待执行操作方案。没有运行Packet Tracer、没有获得任何新网络通过结果。只在本地模拟器内操作。

## 1. 审阅并人工确认

阅读本手册、pc-addresses.csv、links.csv和review/下所有CLI，然后在项目终端执行：

```bash
cd {root}
{base} release '{path}'
```

输入CONFIRM才生成ready/粘贴包。评分表E要求部署前人工确认；这次确认覆盖固定的初始配置、协议迁移和标明的错掩码演练，不代表后续未知修复候选已被批准。

## 2. 搭建硬件与填地址

添加三台2911：R0、R1、R2；两台PC-PT：PC0、PC1；不加交换机。按links.csv连接5条线，同类接口直连用交叉线或PT自动选线，但端口必须一致。

| 两端 | 端口与地址 |
|---|---|
| PC0 - R0 | PC0 Fa0 192.168.16.1/25，网关192.168.16.126；R0 G0/0 192.168.16.126/25 |
| R0 - R2 | R0 G0/1 10.0.0.1/30；R2 G0/0 10.0.0.2/30 |
| R2 - R1 | R2 G0/1 20.0.0.2/30；R1 G0/1 20.0.0.1/30 |
| R0 - R1 | R0 G0/2 30.0.0.1/30；R1 G0/2 30.0.0.2/30 |
| R1 - PC1 | R1 G0/0 192.168.16.190/26；PC1 Fa0 192.168.16.129/26，网关192.168.16.190 |

PC在Desktop → IP Configuration填地址，DNS留空。路由器初始询问选择no，按回车进入提示符。

## 3. RIPv1对照

把ready/ripv1/R0.cfg、R1.cfg、R2.cfg分别完整粘贴到对应路由器CLI。等待稳定后按review/ripv1/checks.json测试四项。双向ping应不通，两项指定精确前缀应缺失；这是预期的RIPv1/VLSM对照，不是应修复的故障。

推荐按阶段逐项采集，程序自动提示每项命令和源设备；每项粘贴后输入__END__：

```bash
{base} collect-stage '{path}' --stage ripv1
```

也可只采集第一项：

```bash
{base} collect '{path}' --stage ripv1 --check-id check-01 --device PC0
```

程序会显示要在PT执行的命令。将PT单次完整输出复制回终端，最后单独输入__END__。check-02来自PC1；check-03来自R0、check-04来自R1，两者命令为show ip route。路由输出需包含命令、Codes/Gateway表头和最后提示符。保存RIPv1.pkt。

## 4. RIPv2健康基线

同一工程依次粘贴ready/ripv2/三份迁移CLI。它们先删除旧RIP再启用v2/no auto-summary，不改地址和连线。等待收敛，采集review/ripv2/checks.json中的4项，阶段改为--stage ripv2。双向ping应通，R0/R1应学习指定R路由。保存RIPv2-healthy.pkt。

可用`{base} collect-stage '{path}' --stage ripv2`依次采集四项。

只有健康基线四项都通过后，再做下一步。最初ARP或收敛可能丢包，保留首测原文后可重测；不能修改原文让它看起来通过。

## 5. 预置一个真实错掩码

仅在R0粘贴ready/fault/R0.cfg。它把R0 G0/0从/25暂改成/26，故障由本方案预置并由你手动应用，不冒称教师或同学预置。

等待旧/25路由撤销后，在PC0执行ping 192.168.16.129。采集真实失败：

```bash
{base} collect '{path}' --stage fault --check-id check-01 --device PC0
```

此时Agent健康断言应为failed，实验状态显示fault_exposed；若实际仍通，保留结果，检查收敛与是否正确应用，不虚构失败。保存RIPv2-fault.pkt。

## 6. 自动定位与候选修复

```bash
{base} diagnose '{path}' --device R0
```

在R0执行show running-config，复制完整一次输出到终端。包含头、hostname R0、全部接口/协议、最终end和提示符；分页请完成翻页，不把--More--或多个历史命令混入。

Agent应依据真实输出定位掩码错配并生成最小候选。它不会直接应用。审阅候选后：

```bash
{base} repair-release '{path}' --device R0
```

再次人工CONFIRM后，按终端给出的文件在R0手动粘贴。重新测试并采集：

```bash
{base} collect '{path}' --stage repaired --check-id check-01 --device PC0
{base} repair-verify '{path}' --device R0 --check-id check-01 --applied-manually
```

随后在repaired阶段补check-02、03、04，确认反向ping和回程路由都恢复；保存RIPv2-repaired.pkt。最多3轮候选，不得把旧输出当作修复后证据。记录区分用户手动应用与程序自动执行。

## 7. OSPF与路径断言

仅在恢复健康RIPv2后，依次粘贴ready/ospf/三份迁移CLI。它们显式删除RIP，启用进程100/area0，并将R0/R1直连链路的G0/2 cost设为64。

采集review/ospf/checks.json中的5项，--stage ospf：PC0/PC1双向ping，R0/R1 show ip route，以及PC0 tracert 192.168.16.129。

推荐执行`{base} collect-stage '{path}' --stage ospf`，按提示依次粘贴五项完整输出。

预期O路由经R2，tracert依次为192.168.16.126、10.0.0.2、20.0.0.1、192.168.16.129。星号、未到达、缺跳或多应答会保持unknown；保留原测，稳定后再测。保存OSPF.pkt。

## 8. 归档工程与查看状态

```bash
{base} attach '{path}' --stage ripv2 --file /实际保存路径/RIPv2-healthy.pkt
{base} status '{path}'
```

各阶段.pkt和原始截图可用attach归档；接收文件仅说明已保存，不等于自动验证了工程内部。所有计划文件有哈希保护，原始输出和修复结果追加审计。此过程不产生模型API调用费用。
'''
