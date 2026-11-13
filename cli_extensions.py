"""CLI adapters for local plans, imported observations and bounded repair proposals."""
import json
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path
import re
import shutil
import stat
import uuid

import yaml

import workflow as wf


@contextmanager
def _run_lock(run):
    """Refuse concurrent mutations instead of silently losing imported results."""
    lock = run / ".observation-lock"
    try:
        lock.mkdir()
    except FileExistsError:
        raise ValueError("当前run正在导入或审阅其他证据，请完成后重试；未覆盖现有记录") from None
    try:
        yield
    finally:
        lock.rmdir()


def _serialized(run_index):
    def decorate(function):
        @wraps(function)
        def guarded(*args, **kwargs):
            run = kwargs.get("run", args[run_index] if len(args) > run_index else None)
            if run is None:
                raise ValueError("缺少run目录")
            with _run_lock(Path(run)):
                return function(*args, **kwargs)
        return guarded
    return decorate


def _check_prompt_source(text, device):
    # PC's C:\\> does not identify a device. Cisco prompts do, and must agree
    # with --device; the PC source remains explicitly user-declared evidence.
    prompts = re.findall(r"^\s*([A-Za-z][A-Za-z0-9_-]{0,19})(?:\([^\n)]*\))?[>#][^\n]*$", text, re.M)
    if any(name != device for name in prompts):
        raise ValueError("原始输出中的设备提示符与本项声明源设备不匹配")


def _verified_record(run, record, check):
    from verification import verify_text
    if not isinstance(record, dict) or record.get("check_id") != check["id"] or record.get("declared_device") != check["source"]:
        raise ValueError("已归档验收的检查ID或源设备已修改")
    name = record.get("file")
    if not isinstance(name, str):
        raise ValueError("已归档验收缺少原始输出文件")
    path = (run / name).resolve()
    directory = (run / "evidence/imports").resolve()
    if path.parent != directory or not re.fullmatch(re.escape(check["id"]) + r"-[a-f0-9]{8}\.txt", path.name):
        raise ValueError("已归档原始输出路径无效")
    evidence = record.get("evidence")
    if not isinstance(evidence, dict) or not path.is_file() or wf.digest(path) != evidence.get("sha256"):
        raise ValueError("已归档原始输出缺失或已篡改")
    companion = path.with_suffix(".json")
    if not companion.is_file() or json.loads(companion.read_text(encoding="utf-8")) != record:
        raise ValueError("验收状态与归档记录不一致，可能已被修改")
    text = path.read_text(encoding="utf-8")
    _check_prompt_source(text, check["source"])
    parsed = verify_text(check["kind"], text, check)
    for key in ("kind", "status", "actual", "source", "assertions", "observed", "evidence"):
        if record.get(key) != parsed.get(key):
            raise ValueError("验收状态与原始输出重新解析结果不一致")
    return record


def _verified_imports(run, checks):
    state = run / "verification.json"
    previous = json.loads(state.read_text(encoding="utf-8")) if state.exists() else {}
    if not isinstance(previous, dict) or not isinstance(previous.get("imported_results", {}), dict):
        raise ValueError("验收状态文件格式无效")
    imported = previous.get("imported_results", {})
    by_id = {check["id"]: check for check in checks}
    for check_id, record in imported.items():
        if check_id not in by_id:
            raise ValueError("已归档验收项不属于当前已审阅计划")
        _verified_record(run, record, by_id[check_id])
    return previous, imported


def _read_repair_state(path):
    state = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(state, dict) or not isinstance(state.get("rounds"), list)
            or type(state.get("max_rounds")) is not int or not 1 <= state["max_rounds"] <= 3
            or len(state["rounds"]) > state["max_rounds"]):
        raise ValueError("修复状态文件格式无效或轮次上限已修改")
    for number, entry in enumerate(state["rounds"], 1):
        if (not isinstance(entry, dict) or entry.get("round") != number
                or not isinstance(entry.get("candidate_config"), str)
                or not entry["candidate_config"].strip()
                or entry.get("applied_by_program") is not False
                or not isinstance(entry.get("human_confirmation", {}), dict)):
            raise ValueError("修复轮次记录格式无效，不能跳过审阅")
    return state


def compile_file(root, path, output):
    import network_core as core
    topology = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = core.validate(topology)
    if errors:
        raise ValueError("\n".join(errors))
    files = core.render(topology)
    output.mkdir(parents=True, exist_ok=False)
    (output / "topology.yaml").write_text(yaml.safe_dump(topology, allow_unicode=True, sort_keys=False), encoding="utf-8")
    for name, text in files.items():
        target = output / "draft" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    wf.write_json(output / "metadata.json", {"mode": "offline_authored_topology", "source_file": str(path.resolve()), "created_at_utc": wf.stamp(), "schema_version": "0.2", "network_deployed": False, "not_a_model_response": True})
    wf.write_json(output / "manifest.json", {"topology.yaml": wf.digest(output / "topology.yaml"), **{f"draft/{name}": wf.digest(output / "draft" / name) for name in files}})
    wf.write_json(output / "verification.json", {"status": "not_run", "source": None, "checks": json.loads(files["verification-plan.json"])["checks"], "repair_rounds": None})
    wf.audit(output, "offline_compile", input=str(path.resolve()), source="authored_topology", model_called=False, network_deployed=False)
    return output


def read_observation(path, root):
    if path.suffix.lower() not in {".txt", ".log"} or path.name.startswith(".env") or path.resolve().name.startswith(".env"):
        raise ValueError("原始输出仅接受 .txt/.log 文件，不能导入配置凭据文件")
    if path.stat().st_size > 2_000_000:
        raise ValueError("原始输出超过2MB上限")
    text = path.read_text(encoding="utf-8")
    # Configuration is read only to reject an accidental key in an observation.
    import agent
    try:
        secret = agent.load_env().get("LLM_API_KEY")
    except ValueError:
        secret = None
    if secret and secret in text:
        raise ValueError("输出包含当前API密钥，拒绝归档；请删除凭据后重试")
    return text


def plan_for(run):
    topology = yaml.safe_load((run / "topology.yaml").read_text(encoding="utf-8"))
    if not isinstance(topology, dict) or topology.get("schema_version") != "0.2":
        raise ValueError("此验收入口使用DSL0.2；旧UC06截图记录保留在原evidence目录")
    # Regenerate and verify the manifest so altered checks cannot silently pass.
    files = wf.verify_handoff(run)
    return topology, json.loads(files["verification-plan.json"])["checks"]


@_serialized(1)
def import_result(root, run, check_id, output_file, device):
    from verification import verify_text
    _, checks = plan_for(run)
    check = next((c for c in checks if c["id"] == check_id), None)
    if check is None:
        raise ValueError("check-id 不存在，请查看 draft/verification-plan.json")
    if device != check["source"]:
        raise ValueError(f"本项要求从 {check['source']} 执行，声明设备不匹配")
    previous, imported = _verified_imports(run, checks)
    text = read_observation(output_file, root)
    _check_prompt_source(text, device)
    result = verify_text(check["kind"], text, check)
    result.update(check_id=check_id, declared_device=device, execution="user_manual_packet_tracer", reviewed_at_utc=wf.stamp())
    directory = run / "evidence" / "imports"
    directory.mkdir(parents=True, exist_ok=True)
    evidence_name = f"{check_id}-{uuid.uuid4().hex[:8]}.txt"
    (directory / evidence_name).write_text(text, encoding="utf-8")
    result["file"] = f"evidence/imports/{evidence_name}"
    wf.write_json(directory / evidence_name.replace(".txt", ".json"), result)
    state_path = run / "verification.json"
    imported[check_id] = result
    statuses = [imported[c["id"]]["status"] if c["id"] in imported else "not_run" for c in checks]
    status = ("passed_imported_checks" if all(s == "passed" for s in statuses) else
              "failed_imported_checks" if "failed" in statuses else "partial_or_unknown")
    wf.write_json(state_path, {"status": status, "source": "user_imported_text", "checks": checks,
                              "imported_results": imported, "repair_rounds": previous.get("repair_rounds"),
                              "automatic_execution": False})
    wf.audit(run, "external_output_imported", check_id=check_id, device=device, file=result["file"],
             sha256=wf.digest(directory / evidence_name), status=result["status"], automatic_execution=False)
    return result


@_serialized(1)
def diagnose_run(root, run, device, running_config_file, failed_check_id=None):
    from diagnostics import diagnose
    from verification import new_repair_state, propose_repair
    topology, checks = plan_for(run)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,19}", device):
        raise ValueError("设备ID格式无效")
    text = read_observation(running_config_file, root)
    result = diagnose(topology, device, text)
    directory = run / "repairs" / device
    directory.mkdir(parents=True, exist_ok=True)
    observation_id = uuid.uuid4().hex[:8]
    observed_path = directory / f"observed-{observation_id}.txt"
    observed_path.write_text(text, encoding="utf-8")
    result.update(source_file=f"repairs/{device}/{observed_path.name}", source_sha256=wf.digest(observed_path), diagnosed_at_utc=wf.stamp())
    if result["repairable"] and result["patch_cli"]:
        state_path = directory / "state.json"
        state = _read_repair_state(state_path) if state_path.exists() else new_repair_state(3)
        _, imported = _verified_imports(run, checks)
        basis = None
        if state["rounds"]:
            previous_round = state["rounds"][-1]
            basis = previous_round.get("verification") or previous_round.get("based_on")
            if basis:
                check = next((check for check in checks if check["id"] == basis.get("check_id")), None)
                if check is None:
                    raise ValueError("此前修复关联的验收项已修改")
                _verified_record(run, basis, check)
        if failed_check_id:
            if basis and basis.get("check_id") != failed_check_id:
                raise ValueError("连续修复必须保留同一验收项，不能切换检查目标")
            basis = imported.get(failed_check_id)
            if not basis or basis.get("status") != "failed":
                raise ValueError("failed-check-id 必须引用已导入并明确失败的验收项")
        state = propose_repair(state, result["patch_cli"], based_on=basis)
        wf.write_json(state_path, state)
        if state["status"] == "exhausted":
            result.update(repairable=False, patch_cli="", requires_human_confirmation=False, reason="三轮修复候选已用尽，停止并请求人工定位")
        else:
            number = len(state["rounds"])
            (directory / f"candidate-{number}.cfg").write_text(result["patch_cli"], encoding="utf-8")
            result["candidate_file"] = f"repairs/{device}/candidate-{number}.cfg"
    wf.write_json(directory / f"diagnosis-{observation_id}.json", result)
    wf.audit(run, "configuration_diagnosed", device=device, observed_sha256=result["source_sha256"], repairable=result["repairable"], automatic_application=False)
    return result


@_serialized(0)
def release_repair(run, device):
    import network_core as core
    plan_for(run)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,19}", device):
        raise ValueError("设备ID格式无效")
    directory = run / "repairs" / device
    state = _read_repair_state(directory / "state.json")
    if state.get("status") != "awaiting_external_verification" or not state["rounds"]:
        raise ValueError("没有等待审阅的候选修复")
    number = len(state["rounds"])
    patch = (directory / f"candidate-{number}.cfg").read_text(encoding="utf-8")
    if patch != state["rounds"][-1]["candidate_config"] or core.check_commands(patch):
        raise ValueError("候选修复已修改或违反命令护栏")
    print(patch)
    accepted = input(f"请审阅 {device} 修复候选，确认仅用于本地PT，输入 CONFIRM：") == "CONFIRM"
    wf.audit(run, "repair_human_confirmation", device=device, round=number, accepted=accepted)
    if not accepted:
        print("已取消")
        return
    target = run / "packet-tracer" / f"{device}-repair-{number}.cfg"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(patch, encoding="utf-8")
    state["rounds"][-1]["human_confirmation"] = {"accepted": True, "time_utc": wf.stamp(), "scope": "local_PT_candidate_handoff"}
    wf.write_json(directory / "state.json", state)
    wf.audit(run, "repair_handoff_created", device=device, round=number, path=str(target), applied_by_program=False)
    print(f"已生成修复粘贴包：{target}；应用后重新执行并导入同一项验收输出。")


@_serialized(0)
def verify_repair(run, device, check_id):
    from verification import record_repair_verification
    _, checks = plan_for(run)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,19}", device):
        raise ValueError("设备ID格式无效")
    path = run / "repairs" / device / "state.json"
    state = _read_repair_state(path)
    _, results = _verified_imports(run, checks)
    if check_id not in results:
        raise ValueError("先用 verify 导入修复后的真实输出")
    if not state.get("rounds") or not state["rounds"][-1].get("human_confirmation", {}).get("accepted"):
        raise ValueError("当前候选尚未人工CONFIRM，不能记录其修复后验证")
    current = state["rounds"][-1]
    basis = current.get("based_on")
    if basis and basis.get("check_id") != check_id:
        raise ValueError("修复后必须重新导入同一项验收，不能改用其他check-id")
    try:
        confirmed_at = datetime.fromisoformat(current["human_confirmation"]["time_utc"])
        imported_at = datetime.fromisoformat(results[check_id]["reviewed_at_utc"])
        fresh = confirmed_at.tzinfo is not None and imported_at.tzinfo is not None and imported_at > confirmed_at
    except (KeyError, TypeError, ValueError):
        fresh = False
    if not fresh:
        raise ValueError("验收输出不是本轮CONFIRM之后新导入的记录，请重新执行并导入真实输出")
    state = record_repair_verification(state, results[check_id])
    wf.write_json(path, state)
    wf.audit(run, "repair_external_check_recorded", device=device, check_id=check_id, state=state["status"], automatic_repair_success=False)
    return state


def doctor(root):
    import agent
    import network_core
    result = {"schema": "valid", "schema_version": "0.2", "device_execution": "none_local_PT_handoff_only"}
    try:
        settings = agent.load_env()
        result.update(api_configured=True, model=settings["LLM_MODEL"], base_url=settings["LLM_BASE_URL"])
    except ValueError as exc:
        result.update(api_configured=False, config_issue=str(exc))
    path = root / ".env"
    if path.exists():
        result["env_permissions_private"] = stat.S_IMODE(path.stat().st_mode) == 0o600
    result["network_request_sent"] = False
    return result
