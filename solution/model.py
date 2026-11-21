"""领域常量与判定原因码。

时间与序号全部使用整数，所有时限区间统一为**左闭右开** ``[start, end)``。
模拟器只处理虚构事件，不包含任何真实密钥、套接字或设备控制。
"""
from __future__ import annotations

# ---- 事件类型（中心事件，经 learn 入库）----------------------------------
EV_REGISTER = "register_application"
EV_PUBLISH = "publish_generation"
EV_APPROVAL = "approval"
EV_REVOCATION = "revocation"
# 接入事件（经 admit 判定；audit 流中允许出现）
EV_ADMISSION = "admission"

CENTER_EVENTS = frozenset(
    {EV_REGISTER, EV_PUBLISH, EV_APPROVAL, EV_REVOCATION}
)
ALL_EVENTS = frozenset(CENTER_EVENTS | {EV_ADMISSION})

# ---- 撤回动作 -------------------------------------------------------------
REV_SHORTEN = "shorten_lease"
REV_DISABLE = "disable_ingress"
REVOCATION_ACTIONS = frozenset({REV_SHORTEN, REV_DISABLE})

# ---- 决策 -----------------------------------------------------------------
DECISION_ADMIT = "admit"
DECISION_DENY = "deny"
DECISION_REPLAY = "replay"
DECISION_DUPLICATE_EVENT = "duplicate_event"
DECISION_STRUCTURAL_ERROR = "structural_error"

# ---- 拒绝原因码（确定性词表，README 逐一解释）-----------------------------
REASON_DUPLICATE_EVENT_ID = "duplicate_event_id"
REASON_UNKNOWN_APPLICATION = "unknown_application"
REASON_UNKNOWN_PARTITION = "unknown_partition"
REASON_UNKNOWN_CENTER = "unknown_center"
REASON_GENERATION_NOT_PUBLISHED = "generation_not_published"
REASON_OLD_GENERATION_MESSAGE = "old_generation_message"
REASON_APPROVAL_GENERATION_MISMATCH = "approval_generation_mismatch"
REASON_NEED_TWO_CENTERS = "need_two_distinct_center_approvals"
REASON_BINDING_MISMATCH = "binding_mismatch"
REASON_EMPTY_VALIDITY_INTERSECTION = "empty_validity_intersection"
REASON_LEASE_OUTSIDE_INTERSECTION = "lease_outside_intersection"
REASON_SEQ_OUTSIDE_ALLOCATION = "seq_outside_center_allocation"
REASON_SEQ_CONSUMED_OTHER = "sequence_consumed_by_other_request"
REASON_SEQ_CONSUMED_SAME = "sequence_consumed_replay"
REASON_DIGEST_MISMATCH = "request_digest_mismatch"
REASON_INGRESS_NOT_ALLOWED = "ingress_center_not_allowed"
REASON_INGRESS_DISABLED = "ingress_center_revoked"
REASON_CENTER_GAP_OPEN = "center_gap_open"
REASON_DISTINCT_CENTER_POLICY = "ingress_must_differ_from_issuer"
REASON_ROUTE_LABEL_MISMATCH = "route_label_mismatch"
REASON_ROUTE_LABEL_REQUIRED = "route_label_required_on_downgrade"
REASON_REVOCATION_REGRESSION = "revocation_seq_regression"
REASON_DUPLICATE_APPROVAL = "duplicate_approval"
REASON_DUPLICATE_REGISTRATION = "duplicate_registration"
REASON_BAD_POLICY_REFERENCE = "unknown_policy_reference"
REASON_NO_RECORD = "record_not_found"
REASON_NOT_ADMISSION_EVENT = "not_an_admission_event"
REASON_INTERNAL_ERROR = "internal_error"

# ---- learn 事件级状态 ------------------------------------------------------
LEARN_ACCEPTED = "accepted"
LEARN_REJECTED = "rejected"

# ---- 审核输出中的谓词键 ----------------------------------------------------
PRED_TWO_CENTERS = "two_distinct_center_approvals_present"
PRED_BINDINGS_MATCH = "all_bindings_match_device_user_generation_segments"
PRED_GENERATION_CURRENT = "admission_generation_is_current"
PRED_WATERMARKS = "both_center_trust_watermarks_contiguous"
PRED_INTERVAL = "lease_inside_left_closed_right_open_intersection"
PRED_INGRESS_ALIVE = "chosen_ingress_allowed_and_not_revoked"
PRED_ROUTING = "routing_and_downgrade_labels_satisfied"
PRED_SEQUENCE_FREE = "message_sequence_not_consumed"

PREDICATE_KEYS = (
    PRED_TWO_CENTERS,
    PRED_BINDINGS_MATCH,
    PRED_GENERATION_CURRENT,
    PRED_WATERMARKS,
    PRED_INTERVAL,
    PRED_INGRESS_ALIVE,
    PRED_ROUTING,
    PRED_SEQUENCE_FREE,
)

# 与“保密性”相关的拒绝原因（audit 单列）
CONFIDENTIALITY_REASONS = frozenset(
    {
        REASON_BINDING_MISMATCH,
        REASON_EMPTY_VALIDITY_INTERSECTION,
        REASON_LEASE_OUTSIDE_INTERSECTION,
        REASON_ROUTE_LABEL_MISMATCH,
        REASON_ROUTE_LABEL_REQUIRED,
        REASON_INGRESS_NOT_ALLOWED,
        REASON_INGRESS_DISABLED,
        REASON_DISTINCT_CENTER_POLICY,
        REASON_SEQ_CONSUMED_OTHER,
        REASON_DIGEST_MISMATCH,
    }
)

# 仅与“可用性/信任水位”相关的拒绝原因
AVAILABILITY_REASONS = frozenset(
    {
        REASON_CENTER_GAP_OPEN,
        REASON_NEED_TWO_CENTERS,
        REASON_GENERATION_NOT_PUBLISHED,
        REASON_OLD_GENERATION_MESSAGE,
        REASON_APPROVAL_GENERATION_MISMATCH,
    }
)

# 校验用的布尔字段白名单
BOOLEAN_FIELDS = frozenset(
    {"require_distinct_ingress", "classification_downgrade", "missing_center"}
)
