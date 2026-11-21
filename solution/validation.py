"""手写结构校验：只检查 JSON 形态/类型/枚举/区间方向，并给出字段位置。

跨事件的语义规则（未知申请、代次新旧、水位缺号等）由 engine 判定，
不属于结构错误。字段路径形如 ``events[2].allocation[0].end``。
"""
from __future__ import annotations

from typing import Any, Callable

from . import model
from .errors import StructuralError
from .intervals import is_valid


# ---------------------------------------------------------------------------
# 基础取值助手
# ---------------------------------------------------------------------------
def _err(code: str, field: str, message: str) -> StructuralError:
    return StructuralError(code, field, message)


def require(obj: Any, field: str, path: str,
            typ: type | tuple[type, ...],
            code: str = "missing_or_wrong_type") -> Any:
    if not isinstance(obj, dict) or field not in obj:
        raise _err(code, path, f"字段缺失: {field}")
    value = obj[field]
    if not isinstance(value, typ) or isinstance(value, bool) and typ is int:
        want = typ.__name__ if isinstance(typ, type) else "/".join(
            t.__name__ for t in typ)
        raise _err("wrong_type", path, f"字段 {field} 应为 {want}")
    return value


def opt(obj: dict, field: str, path: str,
        typ: type | tuple[type, ...], default: Any) -> Any:
    if field not in obj or obj[field] is None:
        return default
    value = obj[field]
    if not isinstance(value, typ) or isinstance(value, bool) and typ is int:
        want = typ.__name__ if isinstance(typ, type) else "/".join(
            t.__name__ for t in typ)
        raise _err("wrong_type", path, f"字段 {field} 应为 {want}")
    return value


def _check_identifier(value: Any, path: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise _err("wrong_type", path, f"字段 {field} 应为非空字符串")
    return value


def _check_int(value: Any, path: str, field: str, *, min_value: int | None = None,
               forbidden_bool: bool = True) -> int:
    if forbidden_bool and isinstance(value, bool):
        raise _err("wrong_type", path, f"字段 {field} 应为整数（不接受布尔值）")
    if not isinstance(value, int):
        raise _err("wrong_type", path, f"字段 {field} 应为整数")
    if min_value is not None and value < min_value:
        raise _err("value_out_of_range", path,
                   f"字段 {field} 不得小于 {min_value}")
    return value


def _check_interval(value: Any, path: str) -> list[int]:
    if not isinstance(value, list) or len(value) != 2:
        raise _err("wrong_type", path, "区间必须是形如 [start, end) 的二元数组")
    lo = _check_int(value[0], f"{path}[0]", "start")
    hi = _check_int(value[1], f"{path}[1]", "end")
    if not lo < hi:
        raise _err("invalid_interval", path,
                   "左闭右开区间必须满足 start < end")
    return [lo, hi]


def _check_str_list(value: Any, path: str, field: str, *, min_items: int = 0
                    ) -> list[str]:
    if not isinstance(value, list) or len(value) < min_items:
        raise _err("wrong_type", path,
                   f"字段 {field} 应为至少 {min_items} 项的字符串数组")
    out: list[str] = []
    for i, item in enumerate(value):
        out.append(_check_identifier(item, f"{path}[{i}]", f"{field}[{i}]"))
    if len(set(out)) != len(out):
        raise _err("duplicate_entry", path, f"字段 {field} 不允许重复项")
    return out


# ---------------------------------------------------------------------------
# 顶层信封
# ---------------------------------------------------------------------------
def validate_case(doc: Any, *, allow_admission: bool) -> dict[str, Any]:
    """校验整个案例文档，返回原样 dict（已确认形态合法）。"""
    if not isinstance(doc, dict):
        raise _err("wrong_type", "$", "案例文档必须是 JSON 对象")
    case_id = opt(doc, "case_id", "$.case_id", str, "")
    if not isinstance(case_id, str):
        raise _err("wrong_type", "$.case_id", "case_id 应为字符串")
    centers = require(doc, "centers", "$.centers", list)
    partitions = require(doc, "partitions", "$.partitions", list)
    events = require(doc, "events", "$.events", list)

    center_ids = _validate_centers(centers)
    _validate_partitions(partitions, center_ids)
    allowed_types = model.ALL_EVENTS if allow_admission else model.CENTER_EVENTS
    for i, event in enumerate(events):
        validate_event(event, f"events[{i}]", center_ids,
                       {p["partition_id"] for p in partitions}, allowed_types)
    return doc


def _validate_centers(centers: list[Any]) -> set[str]:
    if not centers:
        raise _err("invalid_enum", "$.centers", "至少声明两个中心")
    ids: set[str] = set()
    for i, c in enumerate(centers):
        path = f"$.centers[{i}]"
        if not isinstance(c, dict):
            raise _err("wrong_type", path, "中心声明必须是对象")
        cid = _check_identifier(c.get("center_id"), f"{path}.center_id",
                                "center_id")
        if cid in ids:
            raise _err("duplicate_entry", path, f"中心 {cid} 重复声明")
        ids.add(cid)
    if len(ids) < 2:
        raise _err("invalid_enum", "$.centers", "双中心方案至少需要两个中心")
    return ids


def _validate_partitions(partitions: list[Any], center_ids: set[str]) -> None:
    if not partitions:
        raise _err("invalid_enum", "$.partitions", "至少声明一个 LAN 分区")
    seen: set[str] = set()
    for i, p in enumerate(partitions):
        path = f"$.partitions[{i}]"
        if not isinstance(p, dict):
            raise _err("wrong_type", path, "分区声明必须是对象")
        pid = _check_identifier(p.get("partition_id"), f"{path}.partition_id",
                                "partition_id")
        if pid in seen:
            raise _err("duplicate_entry", path, f"分区 {pid} 重复声明")
        seen.add(pid)
        _check_str_list(p.get("segments"), f"{path}.segments", "segments",
                        min_items=1)
        ingresses = _check_str_list(p.get("allowed_ingress_centers"),
                                    f"{path}.allowed_ingress_centers",
                                    "allowed_ingress_centers", min_items=1)
        for cid in ingresses:
            if cid not in center_ids:
                raise _err("invalid_enum",
                           f"{path}.allowed_ingress_centers",
                           f"入口中心 {cid} 未在 centers 中声明")
        opt(p, "require_distinct_ingress",
            f"{path}.require_distinct_ingress", bool, False)
        opt(p, "classification_downgrade",
            f"{path}.classification_downgrade", bool, False)


# ---------------------------------------------------------------------------
# 单事件分发
# ---------------------------------------------------------------------------
def validate_event(event: Any, path: str, center_ids: set[str],
                   partition_ids: set[str], allowed_types: frozenset[str]
                   ) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise _err("wrong_type", path, "事件必须是 JSON 对象")
    ev_type = require(event, "type", f"{path}.type", str)
    if ev_type not in model.ALL_EVENTS:
        raise _err("invalid_enum", f"{path}.type", f"未知事件类型 {ev_type}")
    if ev_type not in allowed_types:
        raise _err("invalid_event_for_command", f"{path}.type",
                   f"当前命令不接受事件类型 {ev_type}")
    _check_identifier(event.get("event_id"), f"{path}.event_id", "event_id")
    validators: dict[str, Callable[..., None]] = {
        model.EV_REGISTER: _validate_register,
        model.EV_PUBLISH: _validate_publish,
        model.EV_APPROVAL: _validate_approval,
        model.EV_REVOCATION: _validate_revocation,
        model.EV_ADMISSION: _validate_admission,
    }
    validators[ev_type](event, path, center_ids, partition_ids)
    return event


def _validate_register(event: dict, path: str, center_ids: set[str],
                       partition_ids: set[str]) -> None:
    _check_identifier(event.get("application_id"),
                      f"{path}.application_id", "application_id")
    _check_identifier(event.get("device_id"), f"{path}.device_id", "device_id")
    _check_identifier(event.get("user_id"), f"{path}.user_id", "user_id")
    _check_identifier(event.get("partition_id"),
                      f"{path}.partition_id", "partition_id")
    if event["partition_id"] not in partition_ids:
        raise _err("invalid_enum", f"{path}.partition_id",
                   f"分区 {event['partition_id']} 未声明")
    generation = _check_int(event.get("initial_generation"),
                            f"{path}.initial_generation",
                            "initial_generation", min_value=0)
    allocation = require(event, "allocation", f"{path}.allocation", list)
    if not allocation:
        raise _err("invalid_enum", f"{path}.allocation",
                   "每份申请至少登记一个中心的序号区间")
    seen_centers: set[str] = set()
    intervals: list[list[int]] = []
    for i, item in enumerate(allocation):
        sub = f"{path}.allocation[{i}]"
        if not isinstance(item, dict):
            raise _err("wrong_type", sub, "区间登记项必须是对象")
        cid = _check_identifier(item.get("center_id"), f"{sub}.center_id",
                                "center_id")
        if cid not in center_ids:
            raise _err("invalid_enum", f"{sub}.center_id",
                       f"中心 {cid} 未在 centers 中声明")
        if cid in seen_centers:
            raise _err("duplicate_entry", f"{sub}.center_id",
                       f"中心 {cid} 的序号区间重复登记")
        seen_centers.add(cid)
        iv = _check_interval(item.get("interval"), f"{sub}.interval")
        intervals.append(iv)
    # 跨中心区间两两不重叠（结构层面保证登记形态）
    for i in range(len(intervals)):
        for j in range(i + 1, len(intervals)):
            a, b = intervals[i], intervals[j]
            if max(a[0], b[0]) < min(a[1], b[1]):
                raise _err("overlapping_allocation",
                           f"{path}.allocation",
                           f"中心区间 [{i}] 与 [{j}] 交叠，"
                           "跨中心序号区间必须互不重叠")
    # 初始代次记录（结构校验只确认形态）
    gen_records = opt(event, "generations", f"{path}.generations", list, [])
    for i, g in enumerate(gen_records):
        sub = f"{path}.generations[{i}]"
        if not isinstance(g, dict):
            raise _err("wrong_type", sub, "代次记录必须是对象")
        _check_int(g.get("generation"), f"{sub}.generation", "generation",
                   min_value=0)
        if g["generation"] != generation:
            raise _err("invalid_enum", sub,
                       "注册事件只能登记 initial_generation 对应的代次")


def _validate_publish(event: dict, path: str, center_ids: set[str],
                      partition_ids: set[str]) -> None:
    _check_identifier(event.get("application_id"),
                      f"{path}.application_id", "application_id")
    _check_int(event.get("generation"), f"{path}.generation", "generation",
               min_value=0)


def _validate_approval(event: dict, path: str, center_ids: set[str],
                       partition_ids: set[str]) -> None:
    _check_identifier(event.get("application_id"),
                      f"{path}.application_id", "application_id")
    cid = _check_identifier(event.get("center_id"), f"{path}.center_id",
                            "center_id")
    if cid not in center_ids:
        raise _err("invalid_enum", f"{path}.center_id",
                   f"中心 {cid} 未在 centers 中声明")
    _check_int(event.get("generation"), f"{path}.generation", "generation",
               min_value=0)
    _check_identifier(event.get("device_id"), f"{path}.device_id", "device_id")
    _check_identifier(event.get("user_id"), f"{path}.user_id", "user_id")
    _check_identifier(event.get("source_segment"),
                      f"{path}.source_segment", "source_segment")
    _check_identifier(event.get("destination_segment"),
                      f"{path}.destination_segment", "destination_segment")
    _check_interval(event.get("validity"), f"{path}.validity")
    _check_str_list(event.get("allowed_ingress_centers"),
                    f"{path}.allowed_ingress_centers",
                    "allowed_ingress_centers", min_items=1)
    for ic in event["allowed_ingress_centers"]:
        if ic not in center_ids:
            raise _err("invalid_enum", f"{path}.allowed_ingress_centers",
                       f"入口中心 {ic} 未声明")
    _check_identifier(event.get("business_center"),
                      f"{path}.business_center", "business_center")
    if event["business_center"] not in center_ids:
        raise _err("invalid_enum", f"{path}.business_center",
                   f"业务签发中心 {event['business_center']} 未声明")
    # 分类降级时必须携带精确路由标签；标签在非降级场景可选
    label = opt(event, "route_label", f"{path}.route_label", str, None)
    if label is not None and not label:
        raise _err("wrong_type", f"{path}.route_label",
                   "route_label 必须是非空字符串或省略")


def _validate_revocation(event: dict, path: str, center_ids: set[str],
                         partition_ids: set[str]) -> None:
    cid = _check_identifier(event.get("center_id"), f"{path}.center_id",
                            "center_id")
    if cid not in center_ids:
        raise _err("invalid_enum", f"{path}.center_id",
                   f"中心 {cid} 未在 centers 中声明")
    _check_int(event.get("revocation_seq"), f"{path}.revocation_seq",
               "revocation_seq", min_value=0)
    _check_identifier(event.get("application_id"),
                      f"{path}.application_id", "application_id")
    action = _check_identifier(event.get("action"), f"{path}.action", "action")
    if action not in model.REVOCATION_ACTIONS:
        raise _err("invalid_enum", f"{path}.action",
                   f"撤回动作必须是 {sorted(model.REVOCATION_ACTIONS)} 之一")
    if action == model.REV_SHORTEN:
        _check_int(event.get("new_end"), f"{path}.new_end", "new_end")
    else:
        ic = _check_identifier(event.get("ingress_center"),
                               f"{path}.ingress_center", "ingress_center")
        if ic not in center_ids:
            raise _err("invalid_enum", f"{path}.ingress_center",
                       f"入口中心 {ic} 未声明")


def _validate_admission(event: dict, path: str, center_ids: set[str],
                        partition_ids: set[str]) -> None:
    _check_identifier(event.get("application_id"),
                      f"{path}.application_id", "application_id")
    _check_int(event.get("generation"), f"{path}.generation", "generation",
               min_value=0)
    _check_int(event.get("seq"), f"{path}.seq", "seq", min_value=0)
    _check_interval(event.get("lease"), f"{path}.lease")
    _check_identifier(event.get("source_segment"),
                      f"{path}.source_segment", "source_segment")
    _check_identifier(event.get("destination_segment"),
                      f"{path}.destination_segment", "destination_segment")
    ic = _check_identifier(event.get("ingress_center"),
                           f"{path}.ingress_center", "ingress_center")
    if ic not in center_ids:
        raise _err("invalid_enum", f"{path}.ingress_center",
                   f"入口中心 {ic} 未声明")
    _check_identifier(event.get("request_digest"),
                      f"{path}.request_digest", "request_digest")
