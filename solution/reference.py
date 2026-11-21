"""独立小状态机：纯 dict 实现，与 ``engine``（SQLite 版）零代码复用。

用途：测试中对同一事件流的每个前缀分别驱动两套实现，逐事件比对决策，
防止单一实现把规则错误“自证正确”。判定原因码与 :mod:`solution.model`
共用词表（仅共享常量字符串，不共享任何逻辑）。
"""
from __future__ import annotations

from typing import Any

from . import model


class ReferenceFSM:
    """按事件顺序驱动的参考实现。"""

    def __init__(self, doc: dict[str, Any]) -> None:
        self.centers: set[str] = {c["center_id"] for c in doc["centers"]}
        self.partitions: dict[str, dict[str, Any]] = {
            p["partition_id"]: dict(p) for p in doc["partitions"]
        }
        # application_id -> 申请记录
        self.apps: dict[str, dict[str, Any]] = {}
        # (center, seq) -> 已应用撤回
        self.revocations: dict[tuple[str, int], dict[str, Any]] = {}
        # center -> 下一期望撤回序号
        self.watermark: dict[str, int] = {}
        # center -> {seq: event} 缺号挂起
        self.pending: dict[str, dict[int, dict[str, Any]]] = {}
        # event_id -> 处理摘要
        self.seen_events: dict[str, dict[str, Any]] = {}
        # (app, gen, seq) -> 消费记录
        self.consumed: dict[tuple[str, int, int], dict[str, Any]] = {}
        # event_id -> 回执
        self.receipts: dict[str, dict[str, Any]] = {}
        self.learn_log: list[dict[str, Any]] = []
        self.admit_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    def drive(self, events: list[dict[str, Any]]) -> None:
        """按顺序驱动整个前缀（中心事件 learn，接入事件 admit）。"""
        for index, event in enumerate(events):
            if event["type"] == model.EV_ADMISSION:
                self.admit_one(event, index)
            else:
                self.learn_one(event, index)

    # ------------------------------------------------------------------
    # learn 部分
    # ------------------------------------------------------------------
    def learn_one(self, event: dict[str, Any], index: int) -> dict[str, Any]:
        eid = event["event_id"]
        if eid in self.seen_events:
            out = {"event_id": eid, "type": event["type"],
                   "status": model.LEARN_REJECTED,
                   "reason": model.REASON_DUPLICATE_EVENT_ID,
                   "detail": {"message": "event_id 重复"},
                   "stream_index": index}
            self.learn_log.append(out)
            return out
        handler = {
            model.EV_REGISTER: self._ref_register,
            model.EV_PUBLISH: self._ref_publish,
            model.EV_APPROVAL: self._ref_approval,
            model.EV_REVOCATION: self._ref_revocation,
        }[event["type"]]
        status, reason, detail = handler(event, index)
        self.seen_events[eid] = {"type": event["type"], "status": status,
                                 "reason": reason, "stream_index": index}
        out = {"event_id": eid, "type": event["type"],
               "status": (model.LEARN_ACCEPTED if status == "accept"
                          else model.LEARN_REJECTED),
               "reason": reason, "detail": detail, "stream_index": index}
        self.learn_log.append(out)
        return out

    def _ref_register(self, event: dict[str, Any], index: int
                      ) -> tuple[str, str | None, Any]:
        app_id = event["application_id"]
        if app_id in self.apps:
            return ("reject", model.REASON_DUPLICATE_REGISTRATION,
                    {"message": "重复注册"})
        if event["partition_id"] not in self.partitions:
            return ("reject", model.REASON_UNKNOWN_PARTITION,
                    {"message": "未知分区"})
        self.apps[app_id] = {
            "application_id": app_id,
            "device_id": event["device_id"],
            "user_id": event["user_id"],
            "partition_id": event["partition_id"],
            "current_generation": event["initial_generation"],
            "allocation": {a["center_id"]: tuple(a["interval"])
                           for a in event["allocation"]},
            "generations": {event["initial_generation"]},
            "approvals": {},   # (gen, center) -> approval
        }
        return ("accept", None,
                {"allocation_centers":
                 [a["center_id"] for a in event["allocation"]]})

    def _ref_publish(self, event: dict[str, Any], index: int
                     ) -> tuple[str, str | None, Any]:
        app = self.apps.get(event["application_id"])
        if app is None:
            return ("reject", model.REASON_UNKNOWN_APPLICATION,
                    {"message": "未知申请"})
        gen = event["generation"]
        if gen in app["generations"]:
            return ("reject", model.REASON_DUPLICATE_APPROVAL,
                    {"message": "代次已发布"})
        if gen <= app["current_generation"]:
            return ("reject", model.REASON_OLD_GENERATION_MESSAGE,
                    {"message": "代次倒退"})
        if gen != app["current_generation"] + 1:
            return ("reject", model.REASON_GENERATION_NOT_PUBLISHED,
                    {"message": "代次跳号"})
        app["current_generation"] = gen
        app["generations"].add(gen)
        return ("accept", None, {"current_generation": gen})

    def _ref_approval(self, event: dict[str, Any], index: int
                      ) -> tuple[str, str | None, Any]:
        app = self.apps.get(event["application_id"])
        if app is None:
            return ("reject", model.REASON_UNKNOWN_APPLICATION,
                    {"message": "未知申请"})
        gen = event["generation"]
        if gen not in app["generations"]:
            return ("reject", model.REASON_GENERATION_NOT_PUBLISHED,
                    {"message": "代次未发布"})
        if gen < app["current_generation"]:
            return ("reject", model.REASON_OLD_GENERATION_MESSAGE,
                    {"message": "旧代次消息混入"})
        key = (gen, event["center_id"])
        if key in app["approvals"]:
            return ("reject", model.REASON_DUPLICATE_APPROVAL,
                    {"message": "重复批准"})
        app["approvals"][key] = {
            "center_id": event["center_id"],
            "device_id": event["device_id"],
            "user_id": event["user_id"],
            "source_segment": event["source_segment"],
            "destination_segment": event["destination_segment"],
            "validity": tuple(event["validity"]),
            "allowed_ingress_centers":
                tuple(sorted(event["allowed_ingress_centers"])),
            "business_center": event["business_center"],
            "route_label": event.get("route_label"),
        }
        return ("accept", None,
                {"center_id": event["center_id"], "generation": gen})

    def _ref_revocation(self, event: dict[str, Any], index: int
                        ) -> tuple[str, str | None, Any]:
        center_id = event["center_id"]
        seq = event["revocation_seq"]
        wm = self.watermark.get(center_id, 0)
        key = (center_id, seq)
        if seq < wm or key in self.revocations or \
                seq in self.pending.get(center_id, {}):
            return ("reject", model.REASON_REVOCATION_REGRESSION,
                    {"message": "撤回序号倒退/重复"})
        if seq > wm:
            self.pending.setdefault(center_id, {})[seq] = event
            return ("accept", None, {"gap": True, "center_id": center_id,
                                     "next_expected": wm, "received": seq})
        self._apply_revocation(event, index)
        drained = self._drain(center_id)
        return ("accept", None,
                {"gap": False, "applied": [seq] + drained,
                 "next_expected": self.watermark.get(center_id, 0)})

    def _apply_revocation(self, event: dict[str, Any], index: int) -> None:
        center_id = event["center_id"]
        seq = event["revocation_seq"]
        # 已处理撤回来源永久保留
        self.revocations[(center_id, seq)] = dict(event)
        self.watermark[center_id] = seq + 1

    def _drain(self, center_id: str) -> list[int]:
        applied: list[int] = []
        bucket = self.pending.get(center_id, {})
        while self.watermark.get(center_id, 0) in bucket:
            wm = self.watermark[center_id]
            event = bucket.pop(wm)
            self._apply_revocation(event, wm)
            applied.append(wm)
        if not bucket and center_id in self.pending:
            del self.pending[center_id]
        return applied

    # ------------------------------------------------------------------
    # admit 部分
    # ------------------------------------------------------------------
    def _is_trusted(self, center_id: str) -> bool:
        return not self.pending.get(center_id)

    def admit_one(self, event: dict[str, Any], index: int) -> dict[str, Any]:
        eid = event["event_id"]
        if eid in self.receipts:
            original = dict(self.receipts[eid])
            original["decision"] = model.DECISION_REPLAY
            original.setdefault("detail", {})["replayed"] = True
            self.admit_log.append(original)
            return original

        def deny(reason: str, message: str, *, consume: bool,
                 extra: dict[str, Any] | None = None) -> dict[str, Any]:
            return self._ref_deny(event, index, reason, message,
                                  consume=consume, extra=extra)

        app = self.apps.get(event["application_id"])
        if app is None:
            return deny(model.REASON_UNKNOWN_APPLICATION, "未知申请",
                        consume=False)
        gen, seq = event["generation"], event["seq"]
        ingress, digest = event["ingress_center"], event["request_digest"]

        if gen != app["current_generation"]:
            reason = (model.REASON_OLD_GENERATION_MESSAGE
                      if gen < app["current_generation"]
                      else model.REASON_GENERATION_NOT_PUBLISHED)
            return deny(reason, "代次不是当前代次", consume=False)

        interval = app["allocation"].get(ingress)
        if interval is None or not (interval[0] <= seq < interval[1]):
            return deny(model.REASON_SEQ_OUTSIDE_ALLOCATION,
                        "序号不属于入口中心区间", consume=False)

        partition = self.partitions[app["partition_id"]]
        if ingress not in partition["allowed_ingress_centers"]:
            return deny(model.REASON_INGRESS_NOT_ALLOWED,
                        "入口不在分区允许集", consume=False)

        if not self._is_trusted(ingress):
            return deny(model.REASON_CENTER_GAP_OPEN, "撤回流缺号关门",
                        consume=False,
                        extra={"watermark": self.watermark.get(ingress, 0),
                               "pending": sorted(self.pending[ingress])})

        ckey = (app["application_id"], gen, seq)
        if ckey in self.consumed:
            owner = self.consumed[ckey]
            if owner["request_digest"] == digest and \
                    owner["ingress_center"] == ingress:
                original = dict(self.receipts[owner["event_id"]])
                original["decision"] = model.DECISION_REPLAY
                original.setdefault("detail", {})["replayed"] = True
                original["detail"]["original_event_id"] = owner["event_id"]
                self.seen_events[eid] = {
                    "type": model.EV_ADMISSION,
                    "status": model.DECISION_REPLAY,
                    "reason": model.REASON_SEQ_CONSUMED_SAME,
                    "stream_index": index}
                self.admit_log.append(original)
                return original
            return deny(model.REASON_SEQ_CONSUMED_OTHER, "序号争用",
                        consume=False,
                        extra={"original_event_id": owner["event_id"]})

        approvals = [app["approvals"][(gen, c)]
                     for c in sorted(self.centers)
                     if (gen, c) in app["approvals"]]
        centers_present = sorted({a["center_id"] for a in approvals})
        if len(centers_present) < 2:
            return deny(model.REASON_NEED_TWO_CENTERS, "需要两中心批准",
                        consume=True,
                        extra={"centers_with_approval": centers_present})

        for field in ("device_id", "user_id", "source_segment",
                      "destination_segment", "business_center"):
            values = {a[field] for a in approvals}
            if len(values) != 1:
                return deny(model.REASON_BINDING_MISMATCH,
                            f"批准字段 {field} 不一致", consume=True,
                            extra={"field": field})
        expect = {"device_id": app["device_id"], "user_id": app["user_id"],
                  "source_segment": event["source_segment"],
                  "destination_segment": event["destination_segment"]}
        for field, want in expect.items():
            if approvals[0][field] != want:
                return deny(model.REASON_BINDING_MISMATCH,
                            f"批准与事件字段 {field} 不符", consume=True,
                            extra={"field": field})
        ingress_sets = {a["allowed_ingress_centers"] for a in approvals}
        if len(ingress_sets) != 1:
            return deny(model.REASON_BINDING_MISMATCH,
                        "批准入口集合不一致", consume=True,
                        extra={"field": "allowed_ingress_centers"})
        approved_ingress = list(approvals[0]["allowed_ingress_centers"])
        if ingress not in approved_ingress:
            return deny(model.REASON_INGRESS_NOT_ALLOWED,
                        "入口不在批准入口集", consume=True)

        if partition.get("require_distinct_ingress", False) and \
                ingress == approvals[0]["business_center"]:
            return deny(model.REASON_DISTINCT_CENTER_POLICY,
                        "入口必须异于业务签发中心", consume=True)

        labels = {a["route_label"] for a in approvals}
        if partition.get("classification_downgrade", False):
            if any(not l for l in labels):
                return deny(model.REASON_ROUTE_LABEL_REQUIRED,
                            "降级场景缺少路由标签", consume=True)
            if len(labels) != 1:
                return deny(model.REASON_ROUTE_LABEL_MISMATCH,
                            "路由标签不一致", consume=True,
                            extra={"labels": sorted(labels)})

        lo = max(a["validity"][0] for a in approvals)
        hi = min(a["validity"][1] for a in approvals)
        if not lo < hi:
            return deny(model.REASON_EMPTY_VALIDITY_INTERSECTION,
                        "有效区间无交集", consume=True,
                        extra={"validity": [list(a["validity"])
                                            for a in approvals]})

        disabled = sorted({r["ingress_center"]
                           for r in self.revocations.values()
                           if r["application_id"] == app["application_id"]
                           and r["action"] == model.REV_DISABLE})
        if ingress in disabled:
            return deny(model.REASON_INGRESS_DISABLED, "入口已被撤回禁用",
                        consume=True,
                        extra={"disabled_ingress_centers": disabled})
        for r in self.revocations.values():
            if r["application_id"] == app["application_id"] and \
                    r["action"] == model.REV_SHORTEN and \
                    r["new_end"] is not None and r["new_end"] > lo:
                hi = min(hi, r["new_end"])
        if not lo < hi:
            return deny(model.REASON_EMPTY_VALIDITY_INTERSECTION,
                        "撤回后区间为空", consume=True,
                        extra={"revoked_window": [lo, hi]})

        lease = event["lease"]
        if not (lo <= lease[0] and lease[1] <= hi):
            return deny(model.REASON_LEASE_OUTSIDE_INTERSECTION,
                        "租约超出共同区间", consume=True,
                        extra={"effective_window": [lo, hi]})

        # 通过：消费序号 + 回执
        self.consumed[ckey] = {"event_id": eid, "ingress_center": ingress,
                               "request_digest": digest,
                               "decision": model.DECISION_ADMIT}
        receipt = {
            "event_id": eid,
            "application_id": app["application_id"],
            "generation": gen, "seq": seq,
            "decision": model.DECISION_ADMIT, "reason": None,
            "request_digest": digest, "ingress_center": ingress,
            "lease": list(lease), "granted_window": [lo, hi],
            "detail": {"message": "参考状态机判定准入",
                       "approval_centers": centers_present,
                       "common_validity": [
                           max(a["validity"][0] for a in approvals),
                           min(a["validity"][1] for a in approvals)],
                       "effective_window": [lo, hi],
                       "route_label": (sorted(labels)[0]
                                       if partition.get(
                                           "classification_downgrade")
                                       else approvals[0]["route_label"])},
            "stream_index": index,
        }
        self.receipts[eid] = receipt
        self.seen_events[eid] = {"type": model.EV_ADMISSION,
                                 "status": model.DECISION_ADMIT,
                                 "reason": None, "stream_index": index}
        self.admit_log.append(receipt)
        return receipt

    def _ref_deny(self, event: dict[str, Any], index: int, reason: str,
                  message: str, *, consume: bool,
                  extra: dict[str, Any] | None) -> dict[str, Any]:
        detail = {"message": message}
        if extra:
            detail.update(extra)
        if consume:
            self.consumed[(event["application_id"], event["generation"],
                           event["seq"])] = {
                "event_id": event["event_id"],
                "ingress_center": event["ingress_center"],
                "request_digest": event["request_digest"],
                "decision": model.DECISION_DENY}
        receipt = {
            "event_id": event["event_id"],
            "application_id": event["application_id"],
            "generation": event["generation"], "seq": event["seq"],
            "decision": model.DECISION_DENY, "reason": reason,
            "request_digest": event["request_digest"],
            "ingress_center": event["ingress_center"],
            "lease": list(event["lease"]), "granted_window": None,
            "detail": detail, "stream_index": index,
        }
        self.receipts[event["event_id"]] = receipt
        self.seen_events[event["event_id"]] = {
            "type": model.EV_ADMISSION, "status": model.DECISION_DENY,
            "reason": reason, "stream_index": index}
        self.admit_log.append(receipt)
        return receipt

    # ------------------------------------------------------------------
    def watermark_snapshot(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for cid in sorted(self.centers):
            pending = sorted(self.pending.get(cid, {}))
            out[cid] = {"next_expected": self.watermark.get(cid, 0),
                        "pending_gap_seqs": pending,
                        "trusted": not pending}
        return out
