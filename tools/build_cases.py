"""生成 cases/ 下全部虚构接入案例（确定性 JSON，仅运行一次即可重建）。

目录约定::

    cases/learn/   只含中心事件（register/publish/approval/revocation）
    cases/admit/   中心事件 + 恰好一个 admission，逐场景判定
    cases/audit/   混合事件流，供 audit 与事件前缀交叉核对

运行::

    python tools/build_cases.py
"""
from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASE_ROOT = os.path.join(ROOT, "cases")

CENTERS = [{"center_id": "C-alpha"}, {"center_id": "C-beta"}]
PARTITIONS = [
    {"partition_id": "LAN-z1", "segments": ["seg-A", "seg-B"],
     "allowed_ingress_centers": ["C-alpha", "C-beta"],
     "require_distinct_ingress": False,
     "classification_downgrade": False},
    {"partition_id": "LAN-z2", "segments": ["seg-C", "seg-D"],
     "allowed_ingress_centers": ["C-alpha", "C-beta"],
     "require_distinct_ingress": True,
     "classification_downgrade": True},
]

# 每份申请的序号登记区间：两中心各分一段、跨中心互不重叠
ALLOC_APP1 = [
    {"center_id": "C-alpha", "interval": [0, 100]},
    {"center_id": "C-beta", "interval": [100, 200]},
]
ALLOC_APP2 = [
    {"center_id": "C-alpha", "interval": [0, 50]},
    {"center_id": "C-beta", "interval": [50, 100]},
]
ALLOC_APP2B = [
    {"center_id": "C-alpha", "interval": [0, 30]},
    {"center_id": "C-beta", "interval": [30, 60]},
]
ALLOC_APP3 = [
    {"center_id": "C-alpha", "interval": [0, 80]},
    {"center_id": "C-beta", "interval": [80, 160]},
]
ALLOC_APP4 = [
    {"center_id": "C-alpha", "interval": [0, 60]},
    {"center_id": "C-beta", "interval": [60, 120]},
]
ALLOC_APP5 = [
    {"center_id": "C-alpha", "interval": [0, 70]},
    {"center_id": "C-beta", "interval": [70, 140]},
]
ALLOC_APP6 = [
    {"center_id": "C-alpha", "interval": [0, 40]},
    {"center_id": "C-beta", "interval": [40, 80]},
]


def envelope(case_id: str, events: list[dict]) -> dict:
    return {"case_id": case_id, "centers": CENTERS,
            "partitions": PARTITIONS, "events": events}


def reg(event_id, app_id, partition, allocation, gen=0):
    return {"type": "register_application", "event_id": event_id,
            "application_id": app_id, "device_id": f"dev-{app_id}",
            "user_id": "user-yu", "partition_id": partition,
            "initial_generation": gen, "allocation": allocation}


def approval(event_id, app_id, center, gen, *, validity, device=None,
             user="user-yu", src="seg-A", dst="seg-B",
             ingresses=("C-alpha", "C-beta"), business=None, label=None):
    return {"type": "approval", "event_id": event_id,
            "application_id": app_id, "center_id": center,
            "generation": gen,
            "device_id": device or f"dev-{app_id}",
            "user_id": user, "source_segment": src,
            "destination_segment": dst, "validity": validity,
            "allowed_ingress_centers": list(ingresses),
            "business_center": business or ("C-beta"
                                            if center == "C-alpha"
                                            else "C-alpha"),
            "route_label": label}


def admission(event_id, app_id, seq, ingress, digest, *, gen=0,
              lease=(10, 20), src="seg-A", dst="seg-B"):
    return {"type": "admission", "event_id": event_id,
            "application_id": app_id, "generation": gen, "seq": seq,
            "lease": list(lease), "source_segment": src,
            "destination_segment": dst, "ingress_center": ingress,
            "request_digest": digest}


def revocation(event_id, center, rseq, app_id, action, *, new_end=None,
               ingress=None):
    payload = {"type": "revocation", "event_id": event_id,
               "center_id": center, "revocation_seq": rseq,
               "application_id": app_id, "action": action}
    if action == "shorten_lease":
        payload["new_end"] = new_end
    else:
        payload["ingress_center"] = ingress
    return payload


def publish(event_id, app_id, gen):
    return {"type": "publish_generation", "event_id": event_id,
            "application_id": app_id, "generation": gen}


def center_only(events: list[dict]) -> list[dict]:
    return [e for e in events if e["type"] != "admission"]


# ---------------------------------------------------------------------------
# 场景 1：快乐路径（乱序批准、双入口、重放）
# ---------------------------------------------------------------------------
def scenario_happy() -> list[dict]:
    return [
        reg("evt-reg-1", "app1", "LAN-z1", ALLOC_APP1),
        # 故意乱序：beta 的批准先到
        approval("evt-appr-1b", "app1", "C-beta", 0, validity=[5, 60]),
        approval("evt-appr-1a", "app1", "C-alpha", 0, validity=[0, 50]),
        admission("evt-adm-1", "app1", 10, "C-alpha", "digest-AAA",
                  lease=(10, 20)),
        # 另一备用入口、不同序号，正常准入
        admission("evt-adm-2", "app1", 110, "C-beta", "digest-BBB",
                  lease=(12, 30)),
        # 同入口同序号同摘要重传（event_id 不同）→ replay 原回执
        admission("evt-adm-1-retry", "app1", 10, "C-alpha", "digest-AAA",
                  lease=(10, 20)),
    ]


# ---------------------------------------------------------------------------
# 场景 2：两批独立批准不能拼接
# ---------------------------------------------------------------------------
def scenario_independent_batches() -> list[dict]:
    return [
        reg("evt-reg-2", "app2", "LAN-z1", ALLOC_APP2),
        approval("evt-appr-2a", "app2", "C-alpha", 0, validity=[0, 40],
                 src="seg-A", dst="seg-B"),
        # beta 的批准绑定了不同设备与目的段——属于另一批独立批准
        approval("evt-appr-2b", "app2", "C-beta", 0, validity=[0, 40],
                 device="dev-OTHER", dst="seg-X"),
        admission("evt-adm-2x", "app2", 10, "C-alpha", "digest-2A",
                  lease=(5, 15)),
        # 有效区间无交集的独立批次（端点相接 [0,10) 与 [10,20) 不算交叠）
        reg("evt-reg-2b", "app2b", "LAN-z1", ALLOC_APP2B),
        approval("evt-appr-2c", "app2b", "C-alpha", 0, validity=[0, 10]),
        approval("evt-appr-2d", "app2b", "C-beta", 0, validity=[10, 20]),
        admission("evt-adm-2y", "app2b", 5, "C-alpha", "digest-2C",
                  lease=(10, 12)),
    ]


# ---------------------------------------------------------------------------
# 场景 3：路由标签变化 + 入口撤回竞争
# ---------------------------------------------------------------------------
def scenario_route_revoke_race() -> list[dict]:
    return [
        reg("evt-reg-3", "app3", "LAN-z2", ALLOC_APP3),
        approval("evt-appr-3a", "app3", "C-alpha", 0,
                 validity=[0, 80], src="seg-C", dst="seg-D",
                 business="C-alpha", label="RL-7"),
        approval("evt-appr-3b", "app3", "C-beta", 0,
                 validity=[0, 80], src="seg-C", dst="seg-D",
                 business="C-alpha", label="RL-9"),
        # 标签不一致 → 路由拒绝
        admission("evt-adm-3-label", "app3", 10, "C-beta", "digest-3L",
                  lease=(10, 20), src="seg-C", dst="seg-D"),
        # 撤回禁用 beta 入口（alpha 撤回序号 0）
        revocation("evt-rev-3-disable", "C-alpha", 0, "app3",
                   "disable_ingress", ingress="C-beta"),
        # 入口已禁用 → 撤回竞争拒绝
        admission("evt-adm-3-revoke", "app3", 11, "C-beta", "digest-3R",
                  lease=(10, 20), src="seg-C", dst="seg-D"),
        # alpha 入口等于业务签发中心 → distinct 政策拒绝
        admission("evt-adm-3-distinct", "app3", 12, "C-alpha", "digest-3D",
                  lease=(10, 20), src="seg-C", dst="seg-D"),
    ]


# ---------------------------------------------------------------------------
# 场景 4：截止恰遇中心水位恢复
# ---------------------------------------------------------------------------
def scenario_gap_recovery() -> list[dict]:
    return [
        reg("evt-reg-4", "app4", "LAN-z1", ALLOC_APP4),
        approval("evt-appr-4a", "app4", "C-alpha", 0, validity=[0, 100]),
        approval("evt-appr-4b", "app4", "C-beta", 0, validity=[0, 100]),
        # beta 撤回序号 1 先到，0 缺失 → 缺号挂起、beta 保守关门
        revocation("evt-rev-4-gap", "C-beta", 1, "app4",
                   "shorten_lease", new_end=60),
        # 缺号期间经 beta 的接入 → 拒绝（水位停在 0）
        admission("evt-adm-4-during-gap", "app4", 70, "C-beta", "digest-4G",
                  lease=(10, 20)),
        # 补齐序号 0（缩短到 50）→ 按序应用 0、1，水位恢复到 2
        revocation("evt-rev-4-fill", "C-beta", 0, "app4",
                   "shorten_lease", new_end=50),
        # 恢复后：租约右端点恰好 50，左闭右开 [..,50) 合法 → 准入
        admission("evt-adm-4-at-boundary", "app4", 71, "C-beta",
                  "digest-4B", lease=(20, 50)),
        # 越过截断点 → 拒绝
        admission("evt-adm-4-over", "app4", 72, "C-beta", "digest-4O",
                  lease=(20, 51)),
        # 倒退序号重放 → 拒绝且不改变已处理撤回来源
        revocation("evt-rev-4-regress", "C-beta", 0, "app4",
                   "shorten_lease", new_end=10),
    ]


# ---------------------------------------------------------------------------
# 场景 5：新代次发布后，迟到旧代次批准/接入均被拒
# ---------------------------------------------------------------------------
def scenario_generation_cutover() -> list[dict]:
    return [
        reg("evt-reg-5", "app5", "LAN-z1", ALLOC_APP5),
        approval("evt-appr-5a0", "app5", "C-alpha", 0, validity=[0, 90]),
        approval("evt-appr-5b0", "app5", "C-beta", 0, validity=[0, 90]),
        # 发布代次 1（新代次序号从 0 重新开始）
        publish("evt-pub-5-1", "app5", 1),
        # 迟到的旧代次批准 → 拒绝混入
        approval("evt-appr-5-late", "app5", "C-alpha", 0, validity=[0, 90]),
        # 旧代次接入引用 → 拒绝
        admission("evt-adm-5-oldgen", "app5", 5, "C-alpha", "digest-5O",
                  gen=0, lease=(10, 20)),
        # 新代次双中心批准
        approval("evt-appr-5a1", "app5", "C-alpha", 1, validity=[0, 90]),
        approval("evt-appr-5b1", "app5", "C-beta", 1, validity=[0, 90]),
        # 新代次序号从 0 开始 → 准入
        admission("evt-adm-5-newgen", "app5", 0, "C-alpha", "digest-5N",
                  gen=1, lease=(10, 20)),
    ]


# ---------------------------------------------------------------------------
# 场景 6：双入口争同一个号
# ---------------------------------------------------------------------------
def scenario_dual_ingress_contention() -> list[dict]:
    return [
        reg("evt-reg-6", "app6", "LAN-z1", ALLOC_APP6),
        approval("evt-appr-6a", "app6", "C-alpha", 0, validity=[0, 90]),
        approval("evt-appr-6b", "app6", "C-beta", 0, validity=[0, 90]),
        # 先用 beta 区间内序号 65 准入
        admission("evt-adm-6-first", "app6", 65, "C-beta", "digest-6X",
                  lease=(10, 20)),
        # 同入口重传同序号但摘要不同 → 拒绝，不得判重放
        admission("evt-adm-6-digest", "app6", 65, "C-beta", "digest-6Y",
                  lease=(10, 20)),
        # 同序号同摘要但换入口 → 同样拒绝（争号）
        admission("evt-adm-6-ingress", "app6", 65, "C-alpha", "digest-6X",
                  lease=(10, 20)),
        # 同序号同摘要同入口重传 → replay
        admission("evt-adm-6-replay", "app6", 65, "C-beta", "digest-6X",
                  lease=(10, 20)),
    ]


# ---------------------------------------------------------------------------
# 场景 7：audit 专用混合流（两个分区、缺号、撤回）
# ---------------------------------------------------------------------------
def scenario_audit_fixture() -> list[dict]:
    return [
        reg("evt-reg-a1", "audit-app1", "LAN-z1", [
            {"center_id": "C-alpha", "interval": [0, 100]},
            {"center_id": "C-beta", "interval": [100, 200]}]),
        approval("evt-appr-a1a", "audit-app1", "C-alpha", 0,
                 validity=[0, 100]),
        approval("evt-appr-a1b", "audit-app1", "C-beta", 0,
                 validity=[0, 100]),
        admission("evt-adm-a1", "audit-app1", 10, "C-alpha", "digest-A1",
                  lease=(10, 20)),
        admission("evt-adm-a2", "audit-app1", 110, "C-beta", "digest-A2",
                  lease=(10, 20)),
        reg("evt-reg-a2", "audit-app2", "LAN-z2", [
            {"center_id": "C-alpha", "interval": [0, 100]},
            {"center_id": "C-beta", "interval": [100, 200]}]),
        approval("evt-appr-a2a", "audit-app2", "C-alpha", 0,
                 validity=[0, 100],
                 src="seg-C", dst="seg-D", business="C-beta", label="RL-1"),
        approval("evt-appr-a2b", "audit-app2", "C-beta", 0,
                 validity=[0, 100],
                 src="seg-C", dst="seg-D", business="C-beta", label="RL-1"),
        admission("evt-adm-a3", "audit-app2", 10, "C-alpha", "digest-A3",
                  lease=(10, 20), src="seg-C", dst="seg-D"),
        # beta 缺号：序号 2 先到（0、1 缺）→ 审计中可观察关门
        revocation("evt-rev-a-gap", "C-beta", 2, "audit-app1",
                   "shorten_lease", new_end=15),
        admission("evt-adm-a4-gapped", "audit-app1", 120, "C-beta",
                  "digest-A4", lease=(10, 12)),
    ]


SCENARIOS = {
    "01-happy-path": scenario_happy,
    "02-independent-batches": scenario_independent_batches,
    "03-route-label-and-revoke-race": scenario_route_revoke_race,
    "04-gap-watermark-recovery": scenario_gap_recovery,
    "05-generation-cutover": scenario_generation_cutover,
    "06-dual-ingress-seq-contention": scenario_dual_ingress_contention,
}


def _write(path: str, doc: dict) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, sort_keys=True, ensure_ascii=False, indent=2)
        fh.write("\n")


def main() -> None:
    for sub in ("learn", "admit", "audit"):
        os.makedirs(os.path.join(CASE_ROOT, sub), exist_ok=True)
    # 清理旧的平铺文件
    for old in os.listdir(CASE_ROOT):
        old_path = os.path.join(CASE_ROOT, old)
        if os.path.isfile(old_path):
            os.remove(old_path)

    for name, builder in SCENARIOS.items():
        events = builder()
        # learn：剥离全部接入事件
        _write(os.path.join(CASE_ROOT, "learn", f"{name}.learn.json"),
               envelope(f"{name}.learn", center_only(events)))
        # admit：每个接入事件切成独立案例，携带其**完整事件前缀**
        # （含此前的接入事件），因此争号/重放/撤回竞争在单文件内即可复现
        adm_index = 0
        for idx, event in enumerate(events):
            if event["type"] != "admission":
                continue
            adm_index += 1
            _write(os.path.join(
                CASE_ROOT, "admit",
                f"{name}.admit{adm_index:02d}.json"),
                envelope(f"{name}.admit{adm_index:02d}",
                         events[:idx + 1]))
        # audit：完整混合流
        _write(os.path.join(CASE_ROOT, "audit", f"{name}.audit.json"),
               envelope(f"{name}.audit", events))

    # 专用 audit 大案例
    _write(os.path.join(CASE_ROOT, "audit", "07-audit-fixture.audit.json"),
           envelope("07-audit-fixture.audit", scenario_audit_fixture()))
    print("cases generated under", os.path.relpath(CASE_ROOT, ROOT))


if __name__ == "__main__":
    main()
