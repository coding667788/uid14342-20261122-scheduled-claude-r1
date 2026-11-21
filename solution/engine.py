"""规则引擎：learn（中心事件入库）、admit（单次接入判定）、inspect（回读）。

不变量速览
==========
* 序号区间在注册时按中心登记且跨中心互不重叠；admit 的序号必须落在入口
  中心分得的区间内，且每个 (申请, 代次, 序号) 全局只消费一次。
* 每个中心的撤回流带不可倒退序号：缺号期间该中心保守关门（所有相关场地
  拒绝新接入），补齐后按序应用并恢复信任；已处理撤回永久保留。
* 两份批准必须来自不同中心，且设备/用户/代次/源段/目的段/入口集合/
  业务中心逐字段一致；共同有效区间按左闭右开求交。
* 撤回只会缩短租约或禁用入口，迟到的旧批准无法重新打开。
* 全部复核与写入在同一笔 ``BEGIN IMMEDIATE`` 事务内完成。
"""
from __future__ import annotations

import sqlite3
from typing import Any

from . import model
from .errors import EngineIntegrityError
from .intervals import intersection_of, is_valid
from .store import begin_immediate, commit, dumps, loads, rollback


class GatewayEngine:
    """绑定一个 SQLite 连接的有状态引擎。"""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # ------------------------------------------------------------------
    # 基础读助手
    # ------------------------------------------------------------------
    def _one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def _all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, params).fetchall())

    def _event_seen(self, event_id: str) -> sqlite3.Row | None:
        return self._one(
            "SELECT * FROM processed_events WHERE event_id = ?", (event_id,))

    def _center_known(self, center_id: str) -> bool:
        return self._one("SELECT 1 FROM centers WHERE center_id = ?",
                         (center_id,)) is not None

    def _watermark(self, center_id: str) -> int:
        row = self._one("SELECT next_expected FROM watermarks WHERE center_id = ?",
                        (center_id,))
        return int(row["next_expected"]) if row else 0

    def _is_trusted(self, center_id: str) -> bool:
        """中心可信水位连续（无缺号）才允许其名下新接入。"""
        wm = self._watermark(center_id)
        gap = self._one(
            "SELECT MIN(revocation_seq) AS lo FROM pending_revocations "
            "WHERE center_id = ?", (center_id,))
        if gap is None or gap["lo"] is None:
            return True
        return int(gap["lo"]) <= wm  # 理论上不会发生：有 pending 即缺号

    # ------------------------------------------------------------------
    # 环境初始化（centers / partitions，幂等）
    # ------------------------------------------------------------------
    def install_environment(self, doc: dict[str, Any]) -> None:
        begin_immediate(self.conn)
        try:
            for c in doc["centers"]:
                self.conn.execute(
                    "INSERT OR IGNORE INTO centers(center_id) VALUES (?)",
                    (c["center_id"],))
            for p in doc["partitions"]:
                self.conn.execute(
                    "INSERT OR IGNORE INTO partitions(partition_id, segments_json,"
                    " allowed_ingress_json, require_distinct_ingress,"
                    " classification_downgrade) VALUES (?,?,?,?,?)",
                    (p["partition_id"], dumps(p["segments"]),
                     dumps(p["allowed_ingress_centers"]),
                     1 if p.get("require_distinct_ingress", False) else 0,
                     1 if p.get("classification_downgrade", False) else 0))
            commit(self.conn)
        except Exception:
            rollback(self.conn)
            raise

    # ------------------------------------------------------------------
    # learn：中心事件
    # ------------------------------------------------------------------
    def learn_stream(self, doc: dict[str, Any]) -> dict[str, Any]:
        """顺序处理案例中的全部中心事件，返回逐事件结果。"""
        self.install_environment(doc)
        results: list[dict[str, Any]] = []
        for index, event in enumerate(doc["events"]):
            results.append(self.learn_one(event, index))
        return {
            "case_id": doc.get("case_id", ""),
            "command": "learn",
            "processed": results,
            "watermarks": self._watermark_snapshot(),
        }

    def learn_one(self, event: dict[str, Any], stream_index: int) -> dict[str, Any]:
        event_id = event["event_id"]
        ev_type = event["type"]
        begin_immediate(self.conn)
        try:
            seen = self._event_seen(event_id)
            if seen is not None:
                result = self._reject(
                    event_id, ev_type, stream_index,
                    model.REASON_DUPLICATE_EVENT_ID,
                    f"event_id {event_id} 已在流位置 "
                    f"{seen['stream_index']} 处理过")
                commit(self.conn)
                return result

            if ev_type == model.EV_REGISTER:
                outcome = self._do_register(event)
            elif ev_type == model.EV_PUBLISH:
                outcome = self._do_publish(event)
            elif ev_type == model.EV_APPROVAL:
                outcome = self._do_approval(event)
            elif ev_type == model.EV_REVOCATION:
                outcome = self._do_revocation(event, stream_index)
            else:  # 结构校验已拦截，双保险
                outcome = ("reject", model.REASON_NOT_ADMISSION_EVENT,
                           "learn 只接受中心事件")

            status, reason, detail = (
                outcome if len(outcome) == 3 else (*outcome, None))
            self._record_event(event_id, ev_type, stream_index, status, reason)
            commit(self.conn)
            return {
                "event_id": event_id,
                "type": ev_type,
                "status": model.LEARN_ACCEPTED if status == "accept"
                else model.LEARN_REJECTED,
                "reason": reason,
                "detail": detail,
                "stream_index": stream_index,
            }
        except Exception:
            rollback(self.conn)
            raise

    def _record_event(self, event_id: str, ev_type: str, stream_index: int,
                      status: str, reason: str | None) -> None:
        self.conn.execute(
            "INSERT INTO processed_events(event_id, event_type, status, reason,"
            " stream_index) VALUES (?,?,?,?,?)",
            (event_id, ev_type,
             model.LEARN_ACCEPTED if status == "accept" else model.LEARN_REJECTED,
             reason, stream_index))

    def _reject(self, event_id: str, ev_type: str, stream_index: int,
                reason: str, message: str) -> dict[str, Any]:
        self._record_event(event_id, ev_type, stream_index,
                           model.LEARN_REJECTED, reason)
        return {
            "event_id": event_id,
            "type": ev_type,
            "status": model.LEARN_REJECTED,
            "reason": reason,
            "detail": {"message": message},
            "stream_index": stream_index,
        }

    # ---- 注册 ----------------------------------------------------------
    def _do_register(self, event: dict[str, Any]) -> tuple[str, str | None, Any]:
        app_id = event["application_id"]
        if self._one("SELECT 1 FROM applications WHERE application_id = ?",
                     (app_id,)) is not None:
            return ("reject", model.REASON_DUPLICATE_REGISTRATION,
                    {"message": f"申请 {app_id} 已注册"})
        partition = self._one(
            "SELECT * FROM partitions WHERE partition_id = ?",
            (event["partition_id"],))
        if partition is None:
            return ("reject", model.REASON_UNKNOWN_PARTITION,
                    {"message": f"分区 {event['partition_id']} 未声明"})
        allocation = event["allocation"]
        self.conn.execute(
            "INSERT INTO applications(application_id, device_id, user_id,"
            " partition_id, current_generation, allocation_json)"
            " VALUES (?,?,?,?,?,?)",
            (app_id, event["device_id"], event["user_id"],
             event["partition_id"], event["initial_generation"],
             dumps(allocation)))
        for item in allocation:
            self.conn.execute(
                "INSERT INTO allocations(application_id, center_id, seq_start,"
                " seq_end) VALUES (?,?,?,?)",
                (app_id, item["center_id"], item["interval"][0],
                 item["interval"][1]))
        self.conn.execute(
            "INSERT INTO generations(application_id, generation, published_index)"
            " VALUES (?,?,?)",
            (app_id, event["initial_generation"], 0))
        return ("accept", None, {"allocation_centers":
                                 [a["center_id"] for a in allocation]})

    # ---- 代次发布 ------------------------------------------------------
    def _do_publish(self, event: dict[str, Any]) -> tuple[str, str | None, Any]:
        app_id = event["application_id"]
        app = self._one("SELECT * FROM applications WHERE application_id = ?",
                        (app_id,))
        if app is None:
            return ("reject", model.REASON_UNKNOWN_APPLICATION,
                    {"message": f"申请 {app_id} 尚未注册"})
        gen = event["generation"]
        existing = self._one(
            "SELECT 1 FROM generations WHERE application_id = ? AND generation = ?",
            (app_id, gen))
        if existing is not None:
            return ("reject", model.REASON_DUPLICATE_APPROVAL,
                    {"message": f"代次 {gen} 已发布"})
        if gen <= int(app["current_generation"]):
            return ("reject", model.REASON_OLD_GENERATION_MESSAGE,
                    {"message": f"代次 {gen} 不大于当前代次 "
                     f"{app['current_generation']}"})
        if gen != int(app["current_generation"]) + 1:
            return ("reject", model.REASON_GENERATION_NOT_PUBLISHED,
                    {"message": f"代次必须逐代发布：当前 "
                     f"{app['current_generation']}，收到 {gen}"})
        self.conn.execute(
            "UPDATE applications SET current_generation = ? WHERE application_id = ?",
            (gen, app_id))
        self.conn.execute(
            "INSERT INTO generations(application_id, generation, published_index)"
            " VALUES (?,?,?)",
            (app_id, gen, self._stream_position()))
        return ("accept", None, {"current_generation": gen})

    def _stream_position(self) -> int:
        row = self._one(
            "SELECT COALESCE(MAX(stream_index), -1) + 1 AS nxt"
            " FROM processed_events")
        return int(row["nxt"])

    # ---- 批准 ----------------------------------------------------------
    def _do_approval(self, event: dict[str, Any]) -> tuple[str, str | None, Any]:
        app_id = event["application_id"]
        app = self._one("SELECT * FROM applications WHERE application_id = ?",
                        (app_id,))
        if app is None:
            return ("reject", model.REASON_UNKNOWN_APPLICATION,
                    {"message": f"申请 {app_id} 尚未注册"})
        gen = event["generation"]
        current = int(app["current_generation"])
        published = self._one(
            "SELECT 1 FROM generations WHERE application_id = ? AND generation = ?",
            (app_id, gen))
        if published is None:
            return ("reject", model.REASON_GENERATION_NOT_PUBLISHED,
                    {"message": f"代次 {gen} 尚未发布"})
        if gen < current:
            # 新代次发布后，旧代次消息一律不得混入
            return ("reject", model.REASON_OLD_GENERATION_MESSAGE,
                    {"message": f"当前代次 {current}，拒绝旧代次 {gen} 的批准"})
        dup = self._one(
            "SELECT 1 FROM approvals WHERE application_id = ? AND generation = ?"
            " AND center_id = ?",
            (app_id, gen, event["center_id"]))
        if dup is not None:
            return ("reject", model.REASON_DUPLICATE_APPROVAL,
                    {"message": f"中心 {event['center_id']} 在代次 {gen} "
                     "的批准已存在"})
        validity = event["validity"]
        self.conn.execute(
            "INSERT INTO approvals(application_id, generation, center_id,"
            " device_id, user_id, source_segment, destination_segment,"
            " validity_start, validity_end, allowed_ingress_json,"
            " business_center, route_label, stream_index)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (app_id, gen, event["center_id"], event["device_id"],
             event["user_id"], event["source_segment"],
             event["destination_segment"], validity[0], validity[1],
             dumps(event["allowed_ingress_centers"]),
             event["business_center"], event.get("route_label"),
             self._stream_position()))
        return ("accept", None, {"center_id": event["center_id"],
                                 "generation": gen})

    # ---- 撤回（不可倒退序号 + 缺号关门 + 补齐恢复）---------------------
    def _do_revocation(self, event: dict[str, Any], stream_index: int
                       ) -> tuple[str, str | None, Any]:
        center_id = event["center_id"]
        seq = event["revocation_seq"]
        wm = self._watermark(center_id)
        if seq < wm:
            return ("reject", model.REASON_REVOCATION_REGRESSION,
                    {"message": f"中心 {center_id} 撤回序号倒退：水位 {wm},"
                     f" 收到 {seq}"})
        # 同一序号重复投递（重传）：序号相同、已处理或已挂起 → 幂等拒绝
        if self._one(
                "SELECT 1 FROM revocations WHERE center_id = ? AND revocation_seq = ?",
                (center_id, seq)) is not None or self._one(
                "SELECT 1 FROM pending_revocations WHERE center_id = ?"
                " AND revocation_seq = ?", (center_id, seq)) is not None:
            return ("reject", model.REASON_REVOCATION_REGRESSION,
                    {"message": f"中心 {center_id} 序号 {seq} 的撤回已存在"})
        if seq > wm:
            # 缺号：挂起，相关场地即刻保守关门
            self.conn.execute(
                "INSERT INTO pending_revocations(center_id, revocation_seq,"
                " payload_json, stream_index) VALUES (?,?,?,?)",
                (center_id, seq, dumps(event), stream_index))
            return ("accept", None, {"gap": True, "center_id": center_id,
                                     "next_expected": wm, "received": seq})
        # seq == wm：按序到达，应用并继续排空补齐的挂起项
        applied = self._apply_revocation(event, stream_index)
        self._drain_pending(center_id)
        return ("accept", None, {"gap": False, "applied": applied,
                                 "next_expected": self._watermark(center_id)})

    def _apply_revocation(self, event: dict[str, Any], stream_index: int) -> int:
        center_id = event["center_id"]
        seq = event["revocation_seq"]
        self.conn.execute(
            "INSERT INTO revocations(center_id, revocation_seq, application_id,"
            " action, new_end, ingress_center, stream_index)"
            " VALUES (?,?,?,?,?,?,?)",
            (center_id, seq, event["application_id"], event["action"],
             event.get("new_end"), event.get("ingress_center"), stream_index))
        self.conn.execute(
            "INSERT INTO watermarks(center_id, next_expected) VALUES (?, ?)"
            " ON CONFLICT(center_id) DO UPDATE SET next_expected = excluded.next_expected",
            (center_id, seq + 1))
        return seq

    def _drain_pending(self, center_id: str) -> list[int]:
        """补齐缺号后按序应用挂起撤回；始终保留已处理来源（revocations 表）。"""
        applied: list[int] = []
        while True:
            wm = self._watermark(center_id)
            row = self._one(
                "SELECT * FROM pending_revocations WHERE center_id = ?"
                " AND revocation_seq = ?", (center_id, wm))
            if row is None:
                break
            payload = loads(row["payload_json"])
            self.conn.execute(
                "DELETE FROM pending_revocations WHERE center_id = ?"
                " AND revocation_seq = ?", (center_id, wm))
            self._apply_revocation(payload, int(row["stream_index"]))
            applied.append(wm)
        return applied

    def _watermark_snapshot(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for c in self._all("SELECT center_id FROM centers ORDER BY center_id"):
            cid = c["center_id"]
            pending = [int(r["revocation_seq"]) for r in self._all(
                "SELECT revocation_seq FROM pending_revocations"
                " WHERE center_id = ? ORDER BY revocation_seq", (cid,))]
            out[cid] = {
                "next_expected": self._watermark(cid),
                "pending_gap_seqs": pending,
                "trusted": not pending,
            }
        return out

    # ------------------------------------------------------------------
    # admit：单次接入，同事务全量复核后消费序号
    # ------------------------------------------------------------------
    def admit(self, doc: dict[str, Any]) -> dict[str, Any]:
        """处理带完整前缀的 admit 案例，返回最后一个接入事件的回执。

        前缀中的中心事件按序 learn，前缀中的接入事件按序判定，使争号、
        重放、撤回竞争等依赖历史的场景在单文件内可复现。
        """
        self.install_environment(doc)
        admissions: list[dict[str, Any]] = []
        last_receipt: dict[str, Any] | None = None
        for index, event in enumerate(doc["events"]):
            if event["type"] in model.CENTER_EVENTS:
                self.learn_one(event, index)
            else:
                admissions.append(event)
                last_receipt = self.admit_one(event, index)
        if not admissions:
            raise EngineIntegrityError("admit 案例必须包含 admission 事件")
        return last_receipt  # type: ignore[return-value]

    def admit_one(self, event: dict[str, Any], stream_index: int) -> dict[str, Any]:
        begin_immediate(self.conn)
        try:
            receipt = self._admit_locked(event, stream_index)
            commit(self.conn)
            return receipt
        except Exception:
            rollback(self.conn)
            raise

    def _deny(self, event: dict[str, Any], stream_index: int, reason: str,
              message: str, *, consume: bool, extra: dict[str, Any] | None = None
              ) -> dict[str, Any]:
        """落盘拒绝回执；consume=True 时同时占住序号（争号/重放语义）。"""
        detail = {"message": message}
        if extra:
            detail.update(extra)
        if consume:
            self._insert_consumed(event, model.DECISION_DENY)
        receipt_id = self._insert_receipt(
            event, stream_index, model.DECISION_DENY, reason, detail,
            granted=None)
        return self._receipt_payload(receipt_id)

    def _insert_consumed(self, event: dict[str, Any], decision: str) -> None:
        self.conn.execute(
            "INSERT INTO consumed_seqs(application_id, generation, seq, event_id,"
            " ingress_center, request_digest, decision)"
            " VALUES (?,?,?,?,?,?,?)",
            (event["application_id"], event["generation"], event["seq"],
             event["event_id"], event["ingress_center"],
             event["request_digest"], decision))

    def _insert_receipt(self, event: dict[str, Any], stream_index: int,
                        decision: str, reason: str | None, detail: dict[str, Any],
                        granted: tuple[int, int] | None) -> str:
        self.conn.execute(
            "INSERT INTO receipts(event_id, application_id, generation, seq,"
            " decision, reason, request_digest, ingress_center, lease_start,"
            " lease_end, granted_start, granted_end, detail_json, stream_index)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event["event_id"], event["application_id"], event["generation"],
             event["seq"], decision, reason, event["request_digest"],
             event["ingress_center"], event["lease"][0], event["lease"][1],
             granted[0] if granted else None,
             granted[1] if granted else None,
             dumps(detail), stream_index))
        self.conn.execute(
            "INSERT INTO processed_events(event_id, event_type, status, reason,"
            " stream_index) VALUES (?,?,?,?,?)",
            (event["event_id"], model.EV_ADMISSION, decision, reason,
             stream_index))
        return event["event_id"]

    def _receipt_payload(self, receipt_id: str) -> dict[str, Any]:
        row = self._one("SELECT * FROM receipts WHERE event_id = ?",
                        (receipt_id,))
        if row is None:  # 防御性分支
            raise EngineIntegrityError(f"回执 {receipt_id} 落盘后丢失")
        return self._row_to_receipt(row)

    @staticmethod
    def _row_to_receipt(row: sqlite3.Row) -> dict[str, Any]:
        out = {
            "event_id": row["event_id"],
            "application_id": row["application_id"],
            "generation": row["generation"],
            "seq": row["seq"],
            "decision": row["decision"],
            "reason": row["reason"],
            "request_digest": row["request_digest"],
            "ingress_center": row["ingress_center"],
            "lease": [row["lease_start"], row["lease_end"]],
            "granted_window": ([row["granted_start"], row["granted_end"]]
                               if row["granted_start"] is not None else None),
            "detail": loads(row["detail_json"]),
            "stream_index": row["stream_index"],
        }
        return out

    def _admit_locked(self, event: dict[str, Any], stream_index: int
                      ) -> dict[str, Any]:
        app_id = event["application_id"]
        gen = event["generation"]
        seq = event["seq"]
        ingress = event["ingress_center"]
        digest = event["request_digest"]

        # 0) event_id 幂等：重复 event_id 直接回放原回执（同序号同请求重放）
        seen = self._event_seen(event["event_id"])
        if seen is not None:
            row = self._one("SELECT * FROM receipts WHERE event_id = ?",
                            (event["event_id"],))
            if row is not None:
                payload = self._row_to_receipt(row)
                payload["decision"] = model.DECISION_REPLAY
                payload["detail"] = dict(payload["detail"])
                payload["detail"]["replayed"] = True
                payload["detail"]["original_stream_index"] = row["stream_index"]
                return payload
            # event_id 与某中心事件撞号
            return self._deny(event, stream_index,
                              model.REASON_DUPLICATE_EVENT_ID,
                              f"event_id {event['event_id']} 已被"
                              f" {seen['event_type']} 事件占用",
                              consume=False)

        # 1) 申请必须存在
        app = self._one("SELECT * FROM applications WHERE application_id = ?",
                        (app_id,))
        if app is None:
            return self._deny(event, stream_index,
                              model.REASON_UNKNOWN_APPLICATION,
                              f"申请 {app_id} 尚未注册", consume=False)

        # 2) 代次必须是当前代次（迟到旧准入引用新代次场景在此被拒）
        current_gen = int(app["current_generation"])
        if gen != current_gen:
            reason = (model.REASON_OLD_GENERATION_MESSAGE if gen < current_gen
                      else model.REASON_GENERATION_NOT_PUBLISHED)
            return self._deny(event, stream_index, reason,
                              f"接入引用代次 {gen}，当前代次 {current_gen}",
                              consume=False)

        # 3) 序号必须落在入口中心分得的登记区间内
        alloc = self._one(
            "SELECT * FROM allocations WHERE application_id = ? AND center_id = ?",
            (app_id, ingress))
        if alloc is None or not (int(alloc["seq_start"]) <= seq
                                 < int(alloc["seq_end"])):
            return self._deny(event, stream_index,
                              model.REASON_SEQ_OUTSIDE_ALLOCATION,
                              f"序号 {seq} 不属于入口中心 {ingress} 的登记区间",
                              consume=False)

        # 4) 入口必须是该分区允许的入口之一（支持两个以上备用入口）
        partition = self._one("SELECT * FROM partitions WHERE partition_id = ?",
                              (app["partition_id"]))
        allowed_ingress = loads(partition["allowed_ingress_json"])
        if ingress not in allowed_ingress:
            return self._deny(event, stream_index,
                              model.REASON_INGRESS_NOT_ALLOWED,
                              f"入口 {ingress} 不在分区允许入口集 "
                              f"{allowed_ingress} 中", consume=False)

        # 5) 入口中心可信水位必须连续；缺号期间保守关门
        if not self._is_trusted(ingress):
            wm = self._watermark(ingress)
            return self._deny(event, stream_index,
                              model.REASON_CENTER_GAP_OPEN,
                              f"中心 {ingress} 撤回流缺号，水位停在 {wm}",
                              consume=False,
                              extra={"watermark": wm,
                                     "pending": self._pending_seqs(ingress)})

        # 6) 序号争用 / 重放判定（多入口争同一个号只允许一个准入）
        consumed = self._one(
            "SELECT * FROM consumed_seqs WHERE application_id = ?"
            " AND generation = ? AND seq = ?", (app_id, gen, seq))
        if consumed is not None:
            if consumed["request_digest"] == digest and \
                    consumed["ingress_center"] == ingress:
                # 同一入口重传同请求：返回原持久化回执（replay）
                original = self._one(
                    "SELECT * FROM receipts WHERE event_id = ?",
                    (consumed["event_id"],))
                payload = self._row_to_receipt(original)
                payload["decision"] = model.DECISION_REPLAY
                payload["detail"] = dict(payload["detail"])
                payload["detail"]["replayed"] = True
                payload["detail"]["original_event_id"] = consumed["event_id"]
                # 重放本身仍登记 event_id，避免新 event_id 悬空
                self.conn.execute(
                    "INSERT INTO processed_events(event_id, event_type, status,"
                    " reason, stream_index) VALUES (?,?,?,?,?)",
                    (event["event_id"], model.EV_ADMISSION,
                     model.DECISION_REPLAY,
                     model.REASON_SEQ_CONSUMED_SAME, stream_index))
                return payload
            # 不同摘要（或不同入口）争号：不得判成无害重放
            return self._deny(event, stream_index,
                              model.REASON_SEQ_CONSUMED_OTHER,
                              f"序号 {seq} 已被事件 {consumed['event_id']} "
                              "消费，重传摘要/入口不一致",
                              consume=False,
                              extra={"original_event_id":
                                     consumed["event_id"]})

        # 7) 双中心批准齐备性
        approvals = self._all(
            "SELECT * FROM approvals WHERE application_id = ? AND generation = ?"
            " ORDER BY center_id", (app_id, gen))
        centers_present = sorted({a["center_id"] for a in approvals})
        if len(centers_present) < 2:
            return self._deny(event, stream_index,
                              model.REASON_NEED_TWO_CENTERS,
                              "两中心必须分别发放可信准入部分",
                              consume=True,
                              extra={"centers_with_approval": centers_present})

        # 8) 逐字段绑定一致性：设备/用户/代次/源段/目的段/入口集/业务中心
        binding_fields = ("device_id", "user_id", "source_segment",
                          "destination_segment", "business_center")
        mismatch = self._binding_mismatch(app, event, approvals, binding_fields)
        if mismatch is not None:
            return self._deny(event, stream_index,
                              model.REASON_BINDING_MISMATCH,
                              f"两份批准在字段 {mismatch['field']} 上绑定不一致"
                              "或与接入事件不符", consume=True, extra=mismatch)
        ingress_sets = {loads(a["allowed_ingress_json"])
                        for a in approvals}
        if len({tuple(sorted(s)) for s in ingress_sets}) != 1:
            return self._deny(event, stream_index,
                              model.REASON_BINDING_MISMATCH,
                              "两份批准允许入口中心集合不一致", consume=True,
                              extra={"field": "allowed_ingress_centers"})
        approved_ingress = sorted(
            loads(approvals[0]["allowed_ingress_json"]))
        if ingress not in approved_ingress:
            return self._deny(event, stream_index,
                              model.REASON_INGRESS_NOT_ALLOWED,
                              f"入口 {ingress} 不在批准绑定的入口集 "
                              f"{approved_ingress} 中", consume=True)

        # 9) 入口与业务签发中心不同的政策
        business_center = approvals[0]["business_center"]
        if bool(partition["require_distinct_ingress"]) and \
                ingress == business_center:
            return self._deny(event, stream_index,
                              model.REASON_DISTINCT_CENTER_POLICY,
                              f"政策要求入口中心与业务签发中心 {business_center}"
                              " 不同", consume=True)

        # 10) 分类降级：精确路由标签必须双份一致且非空
        downgrade = bool(partition["classification_downgrade"])
        labels = {a["route_label"] for a in approvals}
        if downgrade:
            if any(l is None or l == "" for l in labels):
                return self._deny(event, stream_index,
                                  model.REASON_ROUTE_LABEL_REQUIRED,
                                  "分类降级必须核对精确路由标签，存在缺失标签",
                                  consume=True)
            if len(labels) != 1:
                return self._deny(event, stream_index,
                                  model.REASON_ROUTE_LABEL_MISMATCH,
                                  "两份批准的精确路由标签不一致", consume=True,
                                  extra={"labels": sorted(labels)})

        # 11) 共同有效区间（左闭右开）
        validity = [(a["validity_start"], a["validity_end"])
                    for a in approvals]
        common = intersection_of(validity)
        if common is None:
            return self._deny(event, stream_index,
                              model.REASON_EMPTY_VALIDITY_INTERSECTION,
                              "两份批准有效区间无共同交集", consume=True,
                              extra={"validity": [list(v) for v in validity]})

        # 12) 撤回效果：禁用入口 / 缩短共同区间（旧批准无法重新打开）
        revocations = self._all(
            "SELECT * FROM revocations WHERE application_id = ?"
            " ORDER BY center_id, revocation_seq", (app_id,))
        disabled = sorted({r["ingress_center"] for r in revocations
                           if r["action"] == model.REV_DISABLE
                           and r["ingress_center"] is not None})
        if ingress in disabled:
            return self._deny(event, stream_index,
                              model.REASON_INGRESS_DISABLED,
                              f"入口 {ingress} 已被可信撤回禁用",
                              consume=True,
                              extra={"disabled_ingress_centers": disabled})
        upper_bounds = [common[1]]
        for r in revocations:
            if r["action"] == model.REV_SHORTEN and \
                    r["new_end"] is not None and \
                    int(r["new_end"]) > common[0]:
                upper_bounds.append(int(r["new_end"]))
        effective_end = min(upper_bounds)
        effective_window = (common[0], effective_end)
        if not is_valid(list(effective_window)):
            return self._deny(event, stream_index,
                              model.REASON_EMPTY_VALIDITY_INTERSECTION,
                              "撤回截断后共同有效区间已为空", consume=True,
                              extra={"revoked_window":
                                     list(effective_window)})

        # 13) 租约必须完整落在（可能已被撤回缩短的）共同区间内
        lease = tuple(event["lease"])
        if not (effective_window[0] <= lease[0] and lease[1] <= effective_end):
            return self._deny(event, stream_index,
                              model.REASON_LEASE_OUTSIDE_INTERSECTION,
                              "租约超出左闭右开共同有效区间（含撤回缩短）",
                              consume=True,
                              extra={"effective_window":
                                     list(effective_window)})

        # 14) 全部通过：消费序号并持久化准入回执（同事务原子提交）
        self._insert_consumed(event, model.DECISION_ADMIT)
        detail = {
            "message": "两中心批准齐备且全部绑定、水位、时限、路由复核通过",
            "approval_centers": centers_present,
            "common_validity": list(common),
            "effective_window": list(effective_window),
            "route_label": (sorted(labels)[0] if downgrade
                            else approvals[0]["route_label"]),
        }
        receipt_id = self._insert_receipt(
            event, stream_index, model.DECISION_ADMIT, None, detail,
            granted=effective_window)
        return self._receipt_payload(receipt_id)

    def _binding_mismatch(self, app: sqlite3.Row, event: dict[str, Any],
                          approvals: list[sqlite3.Row],
                          fields: tuple[str, ...]) -> dict[str, Any] | None:
        # 批准之间必须两两一致
        for field in fields:
            values = {a[field] for a in approvals}
            if len(values) != 1:
                return {"field": field,
                        "approval_values": sorted(values)}
        # 批准值必须与申请/接入事件绑定一致
        expect = {
            "device_id": app["device_id"],
            "user_id": app["user_id"],
            "source_segment": event["source_segment"],
            "destination_segment": event["destination_segment"],
        }
        for field, want in expect.items():
            if approvals[0][field] != want:
                return {"field": field, "approval_value":
                        approvals[0][field], "event_value": want}
        return None

    def _pending_seqs(self, center_id: str) -> list[int]:
        return [int(r["revocation_seq"]) for r in self._all(
            "SELECT revocation_seq FROM pending_revocations WHERE center_id = ?"
            " ORDER BY revocation_seq", (center_id,))]

    # ------------------------------------------------------------------
    # inspect：回读任一历史提交
    # ------------------------------------------------------------------
    def inspect(self, query: dict[str, Any]) -> dict[str, Any]:
        kind = query.get("kind", "receipt")
        if kind == "receipt":
            row = self._one("SELECT * FROM receipts WHERE event_id = ?",
                            (query["event_id"],))
            if row is None:
                return {"found": False, "event_id": query["event_id"],
                        "reason": model.REASON_NO_RECORD}
            return {"found": True, "receipt": self._row_to_receipt(row)}
        if kind == "event":
            row = self._one("SELECT * FROM processed_events WHERE event_id = ?",
                            (query["event_id"],))
            if row is None:
                return {"found": False, "event_id": query["event_id"],
                        "reason": model.REASON_NO_RECORD}
            return {"found": True, "event": dict(row)}
        if kind == "watermarks":
            return {"found": True, "watermarks": self._watermark_snapshot()}
        if kind == "application":
            row = self._one("SELECT * FROM applications WHERE application_id = ?",
                            (query["application_id"],))
            if row is None:
                return {"found": False,
                        "application_id": query["application_id"],
                        "reason": model.REASON_NO_RECORD}
            data = dict(row)
            data["allocation"] = loads(data.pop("allocation_json"))
            return {"found": True, "application": data}
        raise EngineIntegrityError(f"未知 inspect 类型 {kind}")
