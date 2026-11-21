"""结构化错误。

结构错误（JSON 形态、类型、必填字段、枚举、区间方向等）不参与规则判定，
CLI 以退出码 2 输出统一信封::

    {"ok": false, "error": {"code": "...", "field": "events[3].events[0].seq",
                            "message": "..."}}

规则拒绝（未知申请、水位缺号等语义问题）走正常判定信封、退出码 0。
"""
from __future__ import annotations

from typing import Any

# ---- 退出码 ---------------------------------------------------------------
EXIT_OK = 0
EXIT_STRUCTURAL = 2
EXIT_IO = 3
EXIT_CLI = 4
EXIT_INTERNAL = 70


class StructuralError(Exception):
    """输入 JSON 结构不合法；``field`` 使用点号/方括号路径定位字段。"""

    def __init__(self, code: str, field: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.field = field
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "field": self.field, "message": self.message}


class CaseFileError(Exception):
    """案例文件无法读取/解析（IO 层问题）。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "field": "$", "message": self.message}


class EngineIntegrityError(Exception):
    """持久状态与规则不变量冲突，属于模拟器内部错误，而非输入问题。"""
