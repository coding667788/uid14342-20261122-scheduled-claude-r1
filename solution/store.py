"""SQLite 持久层：建表 DDL、连接管理与确定性 JSON 序列化。

所有判定在单连接上进行，admit 的全部复核与序号消费在同一笔
``BEGIN IMMEDIATE`` 事务内完成；进程在提交前退出不会留下半成品状态。
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

SCHEMA_VERSION = 1

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS centers (
    center_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS partitions (
    partition_id            TEXT PRIMARY KEY,
    segments_json           TEXT NOT NULL,
    allowed_ingress_json    TEXT NOT NULL,
    require_distinct_ingress INTEGER NOT NULL,
    classification_downgrade INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_events (
    event_id   TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    status     TEXT NOT NULL,
    reason     TEXT,
    stream_index INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS applications (
    application_id   TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    partition_id     TEXT NOT NULL,
    current_generation INTEGER NOT NULL,
    allocation_json  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS allocations (
    application_id TEXT NOT NULL,
    center_id      TEXT NOT NULL,
    seq_start      INTEGER NOT NULL,
    seq_end        INTEGER NOT NULL,
    PRIMARY KEY (application_id, center_id)
);

CREATE TABLE IF NOT EXISTS generations (
    application_id TEXT NOT NULL,
    generation     INTEGER NOT NULL,
    published_index INTEGER NOT NULL,
    PRIMARY KEY (application_id, generation)
);

CREATE TABLE IF NOT EXISTS approvals (
    application_id   TEXT NOT NULL,
    generation       INTEGER NOT NULL,
    center_id        TEXT NOT NULL,
    device_id        TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    source_segment      TEXT NOT NULL,
    destination_segment TEXT NOT NULL,
    validity_start   INTEGER NOT NULL,
    validity_end     INTEGER NOT NULL,
    allowed_ingress_json TEXT NOT NULL,
    business_center  TEXT NOT NULL,
    route_label      TEXT,
    stream_index     INTEGER NOT NULL,
    PRIMARY KEY (application_id, generation, center_id)
);

CREATE TABLE IF NOT EXISTS watermarks (
    center_id     TEXT PRIMARY KEY,
    next_expected INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
    center_id      TEXT NOT NULL,
    revocation_seq INTEGER NOT NULL,
    application_id TEXT NOT NULL,
    action         TEXT NOT NULL,
    new_end        INTEGER,
    ingress_center TEXT,
    stream_index   INTEGER NOT NULL,
    PRIMARY KEY (center_id, revocation_seq)
);

CREATE TABLE IF NOT EXISTS pending_revocations (
    center_id      TEXT NOT NULL,
    revocation_seq INTEGER NOT NULL,
    payload_json   TEXT NOT NULL,
    stream_index   INTEGER NOT NULL,
    PRIMARY KEY (center_id, revocation_seq)
);

CREATE TABLE IF NOT EXISTS receipts (
    event_id       TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    generation     INTEGER NOT NULL,
    seq            INTEGER NOT NULL,
    decision       TEXT NOT NULL,
    reason         TEXT,
    request_digest TEXT NOT NULL,
    ingress_center TEXT NOT NULL,
    lease_start    INTEGER,
    lease_end      INTEGER,
    granted_start  INTEGER,
    granted_end    INTEGER,
    detail_json    TEXT NOT NULL,
    stream_index   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS consumed_seqs (
    application_id TEXT NOT NULL,
    generation     INTEGER NOT NULL,
    seq            INTEGER NOT NULL,
    event_id       TEXT NOT NULL,
    ingress_center TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    decision       TEXT NOT NULL,
    PRIMARY KEY (application_id, generation, seq)
);
"""


def dumps(value: Any) -> str:
    """确定性 JSON：键排序、无空白、保留 Unicode。"""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def loads(value: str) -> Any:
    return json.loads(value)


def connect(db_path: str = ":memory:") -> sqlite3.Connection:
    """打开（必要时创建）数据库并确保模式就绪。"""
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.executescript(SCHEMA)
    _ensure_meta(conn)
    return conn


def _ensure_meta(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    if row is None:
        conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', ?)",
                     (str(SCHEMA_VERSION),))
    elif int(row["value"]) != SCHEMA_VERSION:
        raise sqlite3.DatabaseError(
            f"schema 版本不匹配: 文件={row['value']} 代码={SCHEMA_VERSION}")


def begin_immediate(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN IMMEDIATE")


def commit(conn: sqlite3.Connection) -> None:
    conn.execute("COMMIT")


def rollback(conn: sqlite3.Connection) -> None:
    conn.execute("ROLLBACK")
