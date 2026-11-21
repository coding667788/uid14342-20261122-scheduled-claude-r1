"""audit：对每个 LAN 分区模拟一个中心失联后的可建立条件与保密性拒绝。

实现方式：在内存 SQLite 上重放整份事件流（不触碰用户的 --db 文件），
基线跑一遍；再对每个 (分区, 失联中心) 组合注入一条**不可补齐的缺号**
（该中心撤回序号 0 之后直接来序号 2，1 永远不到），随后重放全部接入。
缺号恢复期间的观察逐条保留，绝不跳过。
"""
from __future__ import annotations

from typing import Any

from . import model
from .engine import GatewayEngine
from .store import connect, loads

# 失联注入使用的高位撤回序号，保证在任何真实撤回之后仍构成缺号
FAULT_GAP_SEQ = 1_000_000


def _isolation_events(doc: dict[str, Any], lost_center: str
                      ) -> list[dict[str, Any]]:
    """构造让 lost_center 永久缺号的注入事件（序号 0 后跳号）。"""
    return [
        {
            "type": model.EV_REVOCATION,
            "event_id": f"__audit_fault_seq0__{lost_center}",
            "center_id": lost_center,
            "revocation_seq": 0,
            "application_id": doc["events"][0]["application_id"]
            if doc["events"] else "__audit__",
            "action": model.REV_SHORTEN,
            "new_end": 0,
        },
        {
            "type": model.EV_REVOCATION,
            "event_id": f"__audit_fault_gap__{lost_center}",
            "center_id": lost_center,
            "revocation_seq": FAULT_GAP_SEQ,
            "application_id": doc["events"][0]["application_id"]
            if doc["events"] else "__audit__",
            "action": model.REV_SHORTEN,
            "new_end": 0,
        },
    ]


def _replay(doc: dict[str, Any], extra_events: list[dict[str, Any]] | None
            ) -> tuple[GatewayEngine, list[dict[str, Any]], dict[str, Any]]:
    """在全新内存库上重放中心事件（可带注入），再逐条判定接入。"""
    conn = connect(":memory:")
    engine = GatewayEngine(conn)
    engine.install_environment(doc)
    center_events = [e for e in doc["events"]
                     if e["type"] in model.CENTER_EVENTS]
    for e in extra_events or ():
        center_events.append(e)
    learn_results: list[dict[str, Any]] = []
    for index, event in enumerate(center_events):
        learn_results.append(engine.learn_one(event, index))
    admission_events = [e for e in doc["events"]
                        if e["type"] == model.EV_ADMISSION]
    decisions: list[dict[str, Any]] = []
    base = len(center_events)
    for k, event in enumerate(admission_events):
        decisions.append(engine.admit_one(event, base + k))
    return engine, decisions, {"learn": learn_results}


def _predicates(engine: GatewayEngine, admission: dict[str, Any]
                ) -> dict[str, Any]:
    """对单条接入逐项评估八个谓词（含证据），与引擎主判定独立计算。"""
    app_id = admission["application_id"]
    gen = admission["generation"]
    ingress = admission["ingress_center"]
    app = engine._one(
        "SELECT * FROM applications WHERE application_id = ?", (app_id,))
    result: dict[str, Any] = {}

    def put(key: str, holds: bool, evidence: Any) -> None:
        result[key] = {"holds": bool(holds), "evidence": evidence}

    if app is None:
        for key in model.PREDICATE_KEYS:
            put(key, False, {"reason": model.REASON_UNKNOWN_APPLICATION})
        return result

    partition = engine._one("SELECT * FROM partitions WHERE partition_id = ?",
                            (app["partition_id"],))
    approvals = engine._all(
        "SELECT * FROM approvals WHERE application_id = ? AND generation = ?"
        " ORDER BY center_id", (app_id, gen))
    centers = sorted({a["center_id"] for a in approvals})
    put(model.PRED_TWO_CENTERS, len(centers) >= 2,
        {"centers_with_approval": centers})

    binding_fields = ("device_id", "user_id", "source_segment",
                      "destination_segment", "business_center")
    mismatch: dict[str, Any] | None = None
    for field in binding_fields:
        if len({a[field] for a in approvals}) > 1:
            mismatch = {"field": field}
            break
    ingress_sets = {tuple(sorted(loads(a["allowed_ingress_json"])))
                    for a in approvals}
    if mismatch is None and len(ingress_sets) > 1:
        mismatch = {"field": "allowed_ingress_centers"}
    if mismatch is None and approvals:
        checks = {"device_id": app["device_id"], "user_id": app["user_id"],
                  "source_segment": admission["source_segment"],
                  "destination_segment": admission["destination_segment"]}
        for field, want in checks.items():
            if approvals[0][field] != want:
                mismatch = {"field": field, "wanted": want}
                break
    put(model.PRED_BINDINGS_MATCH, mismatch is None and len(centers) >= 2,
        mismatch or {"checked_fields": list(binding_fields)
                     + ["allowed_ingress_centers"]})

    put(model.PRED_GENERATION_CURRENT,
        int(app["current_generation"]) == gen,
        {"current_generation": int(app["current_generation"]),
         "admission_generation": gen})

    gaps = {cid: engine._pending_seqs(cid)
            for cid in centers + [ingress]}
    gap_ok = all(not seqs for seqs in gaps.values())
    put(model.PRED_WATERMARKS, gap_ok,
        {"center_pending_gaps": {k: v for k, v in gaps.items() if v}})

    lo = max((a["validity_start"] for a in approvals), default=None)
    hi = min((a["validity_end"] for a in approvals), default=None)
    if lo is not None and lo < hi:
        rev_rows = engine._all(
            "SELECT * FROM revocations WHERE application_id = ?", (app_id,))
        for r in rev_rows:
            if r["action"] == model.REV_SHORTEN and r["new_end"] is not None \
                    and int(r["new_end"]) > lo:
                hi = min(hi, int(r["new_end"]))
    window_ok = lo is not None and lo < hi and \
        lo <= admission["lease"][0] and admission["lease"][1] <= hi
    put(model.PRED_INTERVAL, window_ok,
        {"effective_window": [lo, hi] if lo is not None else None,
         "lease": admission["lease"]})

    allowed = loads(partition["allowed_ingress_json"]) if partition else []
    disabled = {r["ingress_center"] for r in engine._all(
        "SELECT * FROM revocations WHERE application_id = ?"
        " AND action = ?", (app_id, model.REV_DISABLE))}
    alive = ingress in allowed and ingress not in disabled
    put(model.PRED_INGRESS_ALIVE, alive,
        {"ingress": ingress, "partition_allowed": allowed,
         "revoked_ingress": sorted(disabled)})

    downgrade = bool(partition["classification_downgrade"]) \
        if partition else False
    labels = {a["route_label"] for a in approvals}
    routing_ok = True
    routing_evidence: dict[str, Any] = {"downgrade": downgrade,
                                        "labels": sorted(x for x in labels
                                                         if x is not None)}
    if downgrade:
        routing_ok = len(labels) == 1 and all(labels)
        if not routing_ok:
            routing_evidence["reason"] = (
                model.REASON_ROUTE_LABEL_REQUIRED
                if any(not l for l in labels)
                else model.REASON_ROUTE_LABEL_MISMATCH)
    if bool(partition["require_distinct_ingress"]) if partition else False:
        bc = approvals[0]["business_center"] if approvals else None
        distinct_ok = ingress != bc
        routing_evidence["business_center"] = bc
        routing_ok = routing_ok and distinct_ok
    put(model.PRED_ROUTING, routing_ok, routing_evidence)

    consumed = engine._one(
        "SELECT * FROM consumed_seqs WHERE application_id = ?"
        " AND generation = ? AND seq = ?",
        (app_id, gen, admission["seq"]))
    put(model.PRED_SEQUENCE_FREE, consumed is None,
        {"owner_event_id": consumed["event_id"] if consumed else None})
    return result


def run_audit(doc: dict[str, Any]) -> dict[str, Any]:
    """执行完整失联审计，返回确定性排序后的报告。"""
    base_engine, base_decisions, base_meta = _replay(doc, None)

    partition_reports: list[dict[str, Any]] = []
    for partition in sorted(doc["partitions"],
                            key=lambda p: p["partition_id"]):
        pid = partition["partition_id"]
        segments = partition["segments"]
        local_events = [e for e in doc["events"]
                        if e["type"] == model.EV_ADMISSION
                        and _event_in_partition(base_engine, e, segments)]
        scenarios: list[dict[str, Any]] = []
        for center in sorted(c["center_id"] for c in doc["centers"]):
            fault_engine, fault_decisions, fault_meta = _replay(
                doc, _isolation_events(doc, center))
            fault_by_id = {d["event_id"]: d for d in fault_decisions}
            base_by_id = {d["event_id"]: d for d in base_decisions}

            observations: list[dict[str, Any]] = []
            for event in local_events:
                eid = event["event_id"]
                fault_decision = fault_by_id.get(eid)
                base_decision = base_by_id.get(eid)
                gap_open = fault_decision is not None and \
                    fault_decision.get("reason") == model.REASON_CENTER_GAP_OPEN
                observations.append({
                    "event_id": eid,
                    "baseline_decision": (base_decision["decision"]
                                          if base_decision else None),
                    "baseline_reason": (base_decision["reason"]
                                        if base_decision else
                                        model.REASON_NO_RECORD),
                    "fault_decision": (fault_decision["decision"]
                                       if fault_decision else None),
                    "fault_reason": (fault_decision["reason"]
                                     if fault_decision else
                                     model.REASON_NO_RECORD),
                    "during_center_gap": gap_open,
                    "predicates": _predicates(fault_engine, event),
                })

            # 仍可建立的条件：把八个谓词作为参数化条件，逐项给出是否成立
            conditions = [
                {"condition": key,
                 "holds": all(obs["predicates"][key]["holds"]
                              for obs in observations) if observations else False,
                 "evidence": [
                     {"event_id": obs["event_id"],
                      **obs["predicates"][key]}
                     for obs in observations]}
                for key in model.PREDICATE_KEYS
            ]
            any_admit = any(obs["fault_decision"] == model.DECISION_ADMIT
                            for obs in observations)
            # 保密性拒绝原因（去重排序，保留事件证据；缺号观察不跳过）
            confidentiality_denials = sorted({
                obs["fault_reason"]
                for obs in observations
                if obs["fault_decision"] == model.DECISION_DENY
                and obs["fault_reason"] in model.CONFIDENTIALITY_REASONS
            })
            availability_denials = sorted({
                obs["fault_reason"]
                for obs in observations
                if obs["fault_decision"] == model.DECISION_DENY
                and obs["fault_reason"] in model.AVAILABILITY_REASONS
            })
            gap_windows = [
                {"center": center,
                 "watermark": fault_engine._watermark(center),
                 "pending_gap_seqs": fault_engine._pending_seqs(center),
                 "observations_during_gap":
                     [obs["event_id"] for obs in observations
                      if obs["during_center_gap"]]}
            ]
            scenarios.append({
                "lost_center": center,
                "can_establish": any_admit,
                "establish_conditions": conditions,
                "confidentiality_denials": confidentiality_denials,
                "availability_denials": availability_denials,
                "gap_windows": gap_windows,
                "observations": observations,
            })
        partition_reports.append({
            "partition_id": pid,
            "segments": segments,
            "scenarios": scenarios,
        })

    return {
        "case_id": doc.get("case_id", ""),
        "command": "audit",
        "baseline": {
            "decisions": sorted(base_decisions,
                                key=lambda d: d["event_id"]),
            "watermarks": base_engine._watermark_snapshot(),
        },
        "partition_reports": partition_reports,
    }


def _event_in_partition(engine: GatewayEngine, event: dict[str, Any],
                        segments: list[str]) -> bool:
    app = engine._one("SELECT * FROM applications WHERE application_id = ?",
                      (event["application_id"],))
    if app is None:
        return False
    partition = engine._one("SELECT * FROM partitions WHERE partition_id = ?",
                            (app["partition_id"],))
    if partition is None:
        return False
    return event["source_segment"] in segments and \
        event["destination_segment"] in segments
