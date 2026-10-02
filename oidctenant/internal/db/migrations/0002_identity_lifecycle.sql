-- 0002_identity_lifecycle.sql
-- 身份停用与恢复生命周期
--
-- 设计原则：
--   1. 身份永远不被物理删除，历史归属（issuer/subject/member_id）原样保留；
--   2. 停用/恢复是身份行上的状态机迁移，每次迁移在 identity_lifecycle_events
--      追加一条不可变历史（操作、原因、操作者、时间窗口），绝不覆写旧记录；
--   3. 恢复必须在明确的时间窗口内、且针对同一身份完成全新 OIDC 证明，
--      窗口外的恢复请求与迟到回调都不能把身份重新激活；
--   4. 所有回调都按 (tenant_id, issuer, subject) 锚点读取当前状态，
--      旧 state、旧回调只能看到它自己落库的那一版状态，无法复活身份。

-- ---------- identities：状态 + 时间窗口（非破坏性变更） ----------

ALTER TABLE identities ADD COLUMN status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'deactivated'));
-- 进入 deactivated 的时刻；active 时为 NULL。
ALTER TABLE identities ADD COLUMN deactivated_at timestamptz;
-- 恢复窗口开启时刻（停用时 now()+cooldown）；恢复必须在该时刻之后发起，
-- 且必须在 deactivated_at + reactivate_ttl 之前完成。
ALTER TABLE identities ADD COLUMN reactivate_after timestamptz;
-- 恢复窗口关闭时刻（停用时 now()+reactivate_ttl）。
ALTER TABLE identities ADD COLUMN reactivate_until timestamptz;

-- 停用身份查询（停用过的历史审计/排障）。
CREATE INDEX idx_identities_status ON identities (tenant_id, member_id, status);

-- ---------- 生命周期事件：只追加的历史 ----------
--
-- 每次停用/恢复的终态都在这里留下一行：issuer/subject 快照保证即使将来
-- 身份行被迁移或删除，历史仍可独立查询；reason 是发起方给出的停用原因。

CREATE TABLE identity_lifecycle_events (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    member_id   uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    -- 身份锚点快照（绝不依赖 email）。
    issuer      text NOT NULL,
    subject     text NOT NULL,
    action      text NOT NULL CHECK (action IN ('deactivated', 'reactivated')),
    reason      text NOT NULL DEFAULT '',
    -- 操作者会话（发起停用/恢复的已登录成员会话），便于审计。
    actor_session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,
    -- 本事件对应的已完成 OIDC 证明的 auth_time（恢复/停用都要求新证明）。
    proven_auth_time timestamptz NOT NULL,
    -- 停用时计算出的恢复窗口；reactivated 事件为 NULL。
    reactivate_after timestamptz,
    reactivate_until timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_lifecycle_events_identity
    ON identity_lifecycle_events (tenant_id, identity_id, created_at);

-- ---------- 生命周期会话：停用/恢复的进行中 OIDC 证明 ----------
--
-- 与 link_sessions 同构：一次性 token 绑定发起会话、身份、provider，
-- 回调时 state/nonce/PKCE 一次性消费；同一身份同一时刻至多一个 open 会话，
-- 使重复请求天然幂等（重放只能取回同一个 token，不会产生第二个终态）。

CREATE TABLE lifecycle_sessions (
    token          text PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id    uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    member_id      uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    session_id     uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    idp_id         uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    kind           text NOT NULL CHECK (kind IN ('deactivate', 'reactivate')),
    issuer         text NOT NULL,
    subject        text NOT NULL,
    reason         text NOT NULL DEFAULT '',
    -- 发起方提供的幂等键：同一身份同类操作同一键永远只对应这一行。
    idempotency_key text NOT NULL,
    pending_state  text NOT NULL DEFAULT '',
    status         text NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'completed', 'consumed')),
    -- 挑战自身的过期时间（OIDC 回调必须在此之前完成）。
    expires_at     timestamptz NOT NULL,
    -- 仅 reactivate：回调落库时仍要求身份满足的恢复窗口上界。
    window_until   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    completed_at   timestamptz
);
-- 重放同一幂等键只命中原有会话，不会产生第二个终态。
CREATE UNIQUE INDEX uq_lifecycle_idempotency
    ON lifecycle_sessions (identity_id, kind, idempotency_key);
-- 每个身份每类操作至多一个未完成（pending）会话：重放 INSERT 会直接撞唯一约束。
CREATE UNIQUE INDEX uq_lifecycle_open_per_identity
    ON lifecycle_sessions (identity_id, kind)
    WHERE status = 'pending';
CREATE INDEX idx_lifecycle_status ON lifecycle_sessions (status, expires_at);

-- ---------- auth_requests：新增两种 kind + 生命周期 token 回链 ----------

ALTER TABLE auth_requests DROP CONSTRAINT IF EXISTS auth_requests_kind_check;
ALTER TABLE auth_requests ADD CONSTRAINT auth_requests_kind_check
    CHECK (kind IN ('login', 'link_a', 'link_b', 'deactivate', 'reactivate'));
ALTER TABLE auth_requests ADD COLUMN lifecycle_token text;
