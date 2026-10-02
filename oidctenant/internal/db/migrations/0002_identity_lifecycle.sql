-- 0002_identity_lifecycle.sql
-- 身份停用与恢复生命周期。
--
-- 设计原则：
--   * 身份行 (tenant_id, issuer, subject) 仍然是唯一业务锚点，永不删除；
--     停用/恢复只推进其 status，历史归属与绑定 member 全部保留。
--   * identity_lifecycles 记录每一次“停用/恢复意图”：必须由本人用该身份
--     完成一次新的 OIDC 证明后才进入终态；token 一次性、窗口明确。
--   * identity_events 是只追加的审计/历史表：issuer/subject/时间/原因
--     全部独立留档，恢复建立新行而不是覆写旧记录。
--   * 一切状态推进都带 status 谓词与部分唯一索引，过期/重复回调无法复活身份。

ALTER TABLE identities ADD COLUMN status text NOT NULL DEFAULT 'active';
ALTER TABLE identities ADD CONSTRAINT identities_status_check
    CHECK (status IN ('active', 'deactivation_pending', 'disabled'));

-- 停用/恢复的新 OIDC 证明同样走一次性 state，复用 auth_requests 表。
ALTER TABLE auth_requests DROP CONSTRAINT auth_requests_kind_check;
ALTER TABLE auth_requests ADD CONSTRAINT auth_requests_kind_check
    CHECK (kind IN ('login', 'link_a', 'link_b', 'lifecycle'));

CREATE TABLE identity_lifecycles (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id     uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    member_id       uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    -- deactivate：待证明后停用；reactivate：待证明后恢复
    kind            text NOT NULL CHECK (kind IN ('deactivate', 'reactivate')),
    -- pending -> deactivated/reactivated/expired/rejected（终态只写一次）
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'deactivated', 'reactivated', 'expired', 'rejected')),
    token_hash      bytea NOT NULL UNIQUE,
    idempotency_key text,
    issuer          text NOT NULL,
    subject         text NOT NULL,
    reason          text NOT NULL DEFAULT '',
    -- 发起者必须用哪一个已登录会话完成证明（证明回调沿用会话中间件）
    session_id      uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    proof_issuer    text NOT NULL DEFAULT '',
    proof_subject   text NOT NULL DEFAULT '',
    proof_auth_time timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    completed_at    timestamptz
);

-- 单个身份同一时刻最多只有一个开放中的生命周期流程（停用或恢复待证明）。
-- 终态记录（deactivated/reactivated/expired）互不冲突，形成完整历史链。
CREATE UNIQUE INDEX idx_identity_lifecycle_open
    ON identity_lifecycles (identity_id)
    WHERE status = 'pending';

-- 幂等键：同一次发起请求重放只命中同一行；不同意图必须使用不同键。
-- NULL 键不参与唯一约束，服务端对每次未带键的请求生成新流程。
CREATE UNIQUE INDEX idx_identity_lifecycle_idempotency
    ON identity_lifecycles (tenant_id, identity_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX idx_identity_lifecycle_status_expires
    ON identity_lifecycles (status, expires_at);

-- 只追加的生命周期事件历史。事件表刻意不对 identities/members 设外键：
-- 即便将来身份行被硬删除，“谁在何时因何原因停用了哪个 (issuer,subject)”仍可查询。
CREATE TABLE identity_events (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL,
    identity_id     uuid,
    lifecycle_id    uuid,
    member_id       uuid,
    kind            text NOT NULL CHECK (kind IN (
                        'deactivation_requested', 'identity_deactivated',
                        'reactivation_requested', 'identity_reactivated',
                        'lifecycle_expired', 'lifecycle_rejected')),
    issuer          text NOT NULL,
    subject         text NOT NULL,
    reason          text NOT NULL DEFAULT '',
    proof_issuer    text NOT NULL DEFAULT '',
    proof_subject   text NOT NULL DEFAULT '',
    proof_auth_time timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_identity_events_identity ON identity_events (tenant_id, identity_id, created_at);

-- 登录与关联路径只会对 active 身份建立/复用绑定。
CREATE INDEX idx_identities_active_member
    ON identities (member_id) WHERE status = 'active';
