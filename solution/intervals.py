"""左闭右开整数区间 ``[start, end)`` 的纯函数运算。

所有时限（批准有效区间、租约、撤回截断点）都用该约定：
长度为 ``end - start``，两个相邻区间 ``[a,b)`` 与 ``[b,c)`` 互不交叠。
"""
from __future__ import annotations

from typing import Iterable, Sequence


def is_valid(interval: Sequence[int]) -> bool:
    """合法区间：二元整数序列且 ``start < end``。"""
    return (
        isinstance(interval, (list, tuple))
        and len(interval) == 2
        and isinstance(interval[0], int)
        and not isinstance(interval[0], bool)
        and isinstance(interval[1], int)
        and not isinstance(interval[1], bool)
        and interval[0] < interval[1]
    )


def intersects(a: Sequence[int], b: Sequence[int]) -> bool:
    """两区间是否存在非空交集。"""
    return max(a[0], b[0]) < min(a[1], b[1])


def intersection(a: Sequence[int], b: Sequence[int]) -> tuple[int, int] | None:
    """非空交集，否则返回 ``None``（左闭右开）。"""
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    if lo < hi:
        return lo, hi
    return None


def intersection_of(intervals: Iterable[Sequence[int]]) -> tuple[int, int] | None:
    """多个区间的共同交集；空集合返回 ``None``。"""
    acc: tuple[int, int] | None = None
    for iv in intervals:
        if acc is None:
            acc = (iv[0], iv[1])
        else:
            acc = intersection(acc, iv)
            if acc is None:
                return None
    return acc


def contains(interval: Sequence[int], point: int) -> bool:
    """点是否落在区间内（左闭右开，右端点不算）。"""
    return interval[0] <= point < interval[1]


def covers(outer: Sequence[int], inner: Sequence[int]) -> bool:
    """``outer`` 是否完整覆盖 ``inner``（左闭右开，端点相接合法）。"""
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def disjoint_pairs(intervals: Sequence[Sequence[int]]) -> tuple[int, int] | None:
    """返回第一对交叠区间的下标；全部两两不重叠则返回 ``None``。"""
    for i in range(len(intervals)):
        for j in range(i + 1, len(intervals)):
            if intersects(intervals[i], intervals[j]):
                return i, j
    return None


def clip(interval: Sequence[int], bound: Sequence[int]) -> tuple[int, int] | None:
    """把 ``interval`` 裁剪进 ``bound``；无交集返回 ``None``。"""
    return intersection(interval, bound)
