"""命令行入口：``python -m solution <命令> CASE.json [--db DB.sqlite]``。

stdout 约定为 UTF-8 JSON（键排序、无 ASCII 转义、尾换行），同逻辑案例
产出逐字节一致的结果。结构错误走 stderr + 退出码 2 的错误信封。
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from typing import Any

from . import model
from .audit import run_audit
from .engine import GatewayEngine
from .errors import (EXIT_CLI, EXIT_INTERNAL, EXIT_IO, EXIT_OK,
                     EXIT_STRUCTURAL, CaseFileError, StructuralError)
from .store import connect
from .validation import validate_case

COMMANDS = ("learn", "admit", "inspect", "audit")
# 需要持久状态的命令必须提供 --db
PERSISTENT_COMMANDS = frozenset({"learn", "admit", "inspect"})


def _emit(payload: Any) -> None:
    buf = io.StringIO()
    json.dump(payload, buf, sort_keys=True, ensure_ascii=False, indent=2)
    sys.stdout.buffer.write(buf.getvalue().encode("utf-8"))
    sys.stdout.buffer.write(b"\n")


def _emit_error(err: StructuralError | CaseFileError, code: int) -> int:
    payload = {"ok": False, "error": err.to_dict()}
    sys.stderr.buffer.write(
        (json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2)
         + "\n").encode("utf-8"))
    return code


def _load_case(path: str) -> dict[str, Any]:
    try:
        with io.open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise CaseFileError("case_file_unreadable",
                            f"无法读取案例文件 {path}: {exc}") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        loc = "" if exc.colno is None else f"[line {exc.lineno} col {exc.colno}]"
        raise StructuralError(
            "invalid_json", f"${loc}", f"JSON 解析失败: {exc.msg}") from exc
    if not isinstance(doc, dict):
        raise StructuralError("wrong_type", "$", "案例文档必须是 JSON 对象")
    return doc


def _validate_inspect_query(doc: dict[str, Any]) -> dict[str, Any]:
    query = doc.get("query")
    if not isinstance(query, dict):
        raise StructuralError("missing_or_wrong_type", "$.query",
                              "inspect 案例必须包含 query 对象")
    kind = query.get("kind", "receipt")
    if kind not in ("receipt", "event", "watermarks", "application"):
        raise StructuralError("invalid_enum", "$.query.kind",
                              "kind 必须是 receipt/event/watermarks/application")
    if kind in ("receipt", "event") and not isinstance(
            query.get("event_id"), str):
        raise StructuralError("missing_or_wrong_type", "$.query.event_id",
                              f"{kind} 查询需要非空 event_id 字符串")
    if kind == "application" and not isinstance(
            query.get("application_id"), str):
        raise StructuralError("missing_or_wrong_type",
                              "$.query.application_id",
                              "application 查询需要非空 application_id 字符串")
    return query


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="离线双中心安全网关准入模拟器（纯虚构事件）")
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("case_file", help="案例 JSON 路径")
    parser.add_argument("--db", dest="db_path", default=None,
                        help="SQLite 持久状态文件（learn/admit/inspect 必填）")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EXIT_CLI

    if args.command in PERSISTENT_COMMANDS and not args.db_path:
        parser.error(f"{args.command} 需要 --db DB.sqlite 指定持久状态")

    try:
        doc = _load_case(args.case_file)
        if args.command == "inspect":
            validate_case(doc, allow_admission=False)
            query = _validate_inspect_query(doc)
        else:
            allow_admission = args.command in ("admit", "audit")
            validate_case(doc, allow_admission=allow_admission)
            if args.command == "admit":
                admissions = [e for e in doc["events"]
                              if e["type"] == model.EV_ADMISSION]
                if not admissions:
                    raise StructuralError(
                        "invalid_event_count", "$.events",
                        "admit 案例必须包含一个 admission 事件（实际 0 个）")
    except StructuralError as exc:
        return _emit_error(exc, EXIT_STRUCTURAL)
    except CaseFileError as exc:
        return _emit_error(exc, EXIT_IO)

    try:
        if args.command == "audit":
            # 审计始终在内存库重放，不修改任何持久文件
            _emit(run_audit(doc))
            return EXIT_OK

        conn = connect(args.db_path)
        try:
            engine = GatewayEngine(conn)
            if args.command == "learn":
                _emit(engine.learn_stream(doc))
            elif args.command == "admit":
                _emit(engine.admit(doc))
            else:
                _emit({"case_id": doc.get("case_id", ""),
                       "command": "inspect",
                       "result": engine.inspect(query)})
        finally:
            conn.close()
        return EXIT_OK
    except StructuralError as exc:  # 运行期二次结构防护
        return _emit_error(exc, EXIT_STRUCTURAL)
    except Exception as exc:  # 内部不变量冲突
        err = StructuralError("internal_error", "$", repr(exc))
        return _emit_error(err, EXIT_INTERNAL)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
