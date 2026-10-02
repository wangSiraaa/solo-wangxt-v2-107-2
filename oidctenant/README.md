# oidctenant —— 多租户 OIDC 登录与账号关联 API

无前端的后端服务，演示并落地以下安全目标：

1. **业务身份只基于已核实的提供方组合** `(tenant_id, issuer, subject)`，
   `email` 仅作展示，绝不参与账号匹配 —— 两家企业的员工邮箱相同也不会串号。
2. 完整校验 OIDC 授权码流程的**签名、受众（aud/azp）、issuer、有效期、nonce、state、PKCE**。
3. **账号关联要求两个身份各自重新认证**（OIDC `prompt=login` + `auth_time` 新鲜度窗口）。
4. **登录/关联回调重复到达不会创建多个成员**（state 一次性消费 + 咨询锁 + 唯一约束）。
5. **只允许已配置的回调地址**（精确白名单匹配）。
6. **身份令牌绝不写进日志**（只记录错误分类，不记录 code/token）。
7. **身份停用与恢复是完整生命周期**：非破坏性停用（保留归属与历史）、必须重新 OIDC 证明才生效、
   最后一个可用身份受保护、恢复有明确时间窗口、迟到回调无法复活身份（详见下文）。

## 目录结构

```
cmd/server/             HTTP 服务入口（含过期 state 定时清理）
cmd/seed/               幂等写入租户与 IdP 配置
internal/config/        环境配置
internal/db/            pgx 连接池 + 嵌入式 SQL 迁移
internal/models/        持久化数据结构
internal/store/         所有 PostgreSQL 访问（事务、咨询锁、原子关联）
internal/oidcx/         go-oidc + oauth2 封装（发现/校验/交换/PKCE/nonce）
internal/auth/          state/nonce/PKCE/会话令牌随机值与哈希、回调白名单
internal/api/           HTTP handler：登录、回调、me、登出、账号关联
deploy/keycloak/import  acme / globex 两个测试 realm（含同邮箱用户）
deploy/seed.json        租户/IdP 的 seed 规格
integration/            针对真实 Keycloak + 真实 PostgreSQL 的端到端集成测试
```

## 数据模型要点

| 表 | 关键约束 / 含义 |
| --- | --- |
| `tenants` | 租户 |
| `identity_providers` | 租户**授权**的 `(issuer, client_id, secret, redirect_uris[])`，按 `(tenant_id, issuer)` 唯一 |
| `members` | 租户内的成员（业务账号） |
| `identities` | 已核实身份；**`UNIQUE(tenant_id, issuer, subject)` 是身份锚点**；`email` 无唯一约束；`status` 为 `active`/`deactivated`，停用只翻状态不删行，并记录 `reactivate_after/until` 恢复窗口 |
| `auth_requests` | 进行中的授权请求：`state` 主键 + `nonce` + `pkce_verifier`，一次性消费（`consumed_at`）；`kind` 区分 login/link/deactivate/reactivate |
| `sessions` | 不透明会话令牌（数据库存 SHA-256 哈希） |
| `link_sessions` | 账号关联会话：A/B 两条 leg 的 issuer/subject/auth_time，一次性 token |
| `lifecycle_sessions` | 停用/恢复挑战：一次性 token + 幂等键 + 绑定的 pending state；部分唯一索引保证每身份每类操作至多一个 pending；过期 pending 会在再次发起时被消费 |
| `identity_lifecycle_events` | **只追加**的停用/恢复历史：issuer/subject 快照、原因、操作者会话、新证明的 `auth_time`、恢复窗口；恢复永远 INSERT 新事件，绝不覆写停用记录 |

> 关联外部身份时，身份行的 `tenant_id` 是**发起关联的租户**。
> 因此 A 公司成员关联 B 公司 IdP 的身份，锚点是 `(A租户, B的issuer, subject)`，
> 与 B 公司自己的同名身份互不影响。

## API

所有业务错误返回稳定的 JSON：

```json
{ "error": "<error_type>", "message": "<human readable>" }
```

| error_type | HTTP | 触发场景 |
| --- | --- | --- |
| `authentication_failed` | 401 | 签名/受众/issuer/过期/nonce/PKCE/授权码交换失败、会话无效 |
| `tenant_unauthorized` | 403 | 租户未启用该 issuer、provider 被禁用、跨租户使用会话 |
| `binding_conflict` | 409 | 目标身份已绑给别的成员、自关联、关联会话重放 |
| `invalid_request` | 400 | state 缺失/已用/伪造、回调地址不在白名单、参数非法 |
| `reauthentication_required` | 401 | 关联时某一身份未在 `auth_time_max_age` 窗口内重新认证；停用/恢复的新证明不新鲜或锚点不符 |
| `identity_deactivated` | 403 | 停用身份的登录/关联回调命中状态边界 |
| `last_active_identity` | 409 | 试图停用成员最后一个可用身份 |
| `recovery_window_closed` | 409 | 恢复不在 `reactivate_after..reactivate_until` 窗口内（冷却期未到或窗口已关闭） |
| `identity_lifecycle_conflict` | 409 | 生命周期会话过期/已消费/状态不符 |
| `not_found` | 404 | 身份不在本租户或不属于当前成员（不泄露是否属于他人） |

端点：

| 方法/路径 | 说明 |
| --- | --- |
| `GET  /healthz` | 健康检查 |
| `GET  /t/{slug}/login?issuer=...&return_to=/...` | 发起登录，302 到 IdP |
| `GET  /oauth/callback` | 登录回调（固定路径） |
| `GET  /t/{slug}/api/me` | 当前成员与其已绑定身份（需会话 Cookie `sid`） |
| `POST /t/{slug}/api/logout` | 吊销会话 |
| `POST /t/{slug}/api/links` | 发起账号关联，返回 `link_token` 与 `link_url`；body `{"issuer":"..."}` |
| `GET  /oauth/link/callback` | 关联第二身份的回调（强制重认证） |
| `GET  /t/{slug}/api/links/{token}` | 查询关联会话状态（一次性） |
| `POST /t/{slug}/api/identities/deactivations` | 发起停用：body `{"issuer","subject","reason","idempotency_key?"}`，返回 `lifecycle_token` 与强制重认证的 `auth_url` |
| `GET  /oauth/identities/deactivate/callback` | 停用挑战回调：新 OIDC 证明通过后才真正停用 |
| `POST /t/{slug}/api/identities/reactivations` | 发起恢复（仅在恢复窗口内接受），返回 `auth_url` |
| `GET  /oauth/identities/reactivate/callback` | 恢复挑战回调：新证明通过且窗口有效才恢复 |
| `GET  /t/{slug}/api/identities/history?issuer=&subject=` | 查询该身份只追加的停用/恢复历史 |

## 安全实现细节

- **state / nonce / PKCE**：均为 ≥256/128-bit 加密随机值，服务端持久化；
  PKCE 使用 S256；回调时 state 行被 `SELECT ... FOR UPDATE` 原子取出并标记消费，
  未知 state 与已消费 state 返回完全一致的错误（不泄露有效性）。
- **ID token 校验**（`internal/oidcx`，基于 coreos/go-oidc v3）：
  - 签名经 IdP JWKS 验证；go-oidc 的远程 KeySet 在遇到未知 `kid` 时自动重取 JWKS，
    **密钥轮换对应用透明**；
  - `iss` 必须等于发现文档 issuer；`aud` 必须包含本 client_id；`azp`（若有）必须等于本 client；
  - 过期/nbf/iat 由 go-oidc 校验；`nonce` 与 state 行中的值逐字节比较。
- **重复回调不重复建成员**：`LoginOrRegisterMember` 在事务内先取
  `pg_advisory_xact_lock(hashtextextended(issuer|subject))`，再查/插成员与身份；
  叠加 `UNIQUE(tenant_id, issuer, subject)`，并发首次登录也只产生一个成员。
- **账号关联双重认证**：发起记录 A 的认证时刻；对 B 的授权请求强制
  `prompt=login&max_age=0`，回调核对 IdP 的 `auth_time`；
  `CompleteLink` 在单事务里复核两条 leg 的新鲜度、A 锚点未被改动、B 非自身、
  B 是否已属于他人（冲突则整体回滚，不写入）。
- **回调白名单**：`redirect_uri` 与 `identity_providers.redirect_uris` 做**精确**匹配，
  不做前缀/通配，杜绝 open redirect。
- **日志脱敏**：访问日志把 query 中的 `code/id_token/access_token/refresh_token/state/token`
  统一替换为 `[REDACTED]`；认证失败只记录分类（signature/audience/nonce/...），
  全代码路径不打印原始令牌。

## 身份停用与恢复生命周期

当员工不再信任某个外部身份时，系统**非破坏性**地停用它，而不是删除：

1. **发起停用**：成员对本租户内自己已绑定的某条身份提交
   `{issuer, subject, reason, idempotency_key?}`。服务端在单事务里：
   - 锁定该身份行（`FOR UPDATE`）并确认它属于本租户、本成员；
   - 拒绝停用成员的**最后一个可用身份**（`409 last_active_identity`）；
   - 建立一次性 `lifecycle_sessions` 挑战，并强制 `prompt=login&max_age=0` 的新 OIDC 授权。
2. **新证明才生效**：回调走与登录相同的全套校验（state/nonce/PKCE/签名/受众），
   并且证明的 `(issuer,subject)` 必须逐字节等于目标身份、`auth_time` 必须新鲜。
   校验通过后在**同一事务**里把身份翻为 `deactivated` 并向
   `identity_lifecycle_events` 追加一条含 issuer/subject/原因/时间/窗口/操作者的事件。
   仅发起挑战、不完成证明，身份状态不变。
3. **统一状态边界**：停用后该身份的登录回调返回 `403 identity_deactivated`，
   不创建会话、不新建成员、不刷新字段；进行中的关联回调（锚点或目标身份被停用）
   同样被拒。身份行 `FOR UPDATE` + 咨询锁（key 含 tenant_id）让并发首登与停用串行化。
4. **幂等与重放**：同一 `idempotency_key` 的发起永远返回同一个挑战（`200` 而非新建）；
   回调 state 一次性；完成阶段的并发/重复提交只有一个成功并只产生一条终态历史。
5. **窗口内恢复**：停用时写入 `reactivate_after`（冷却期，默认 24h，可用
   `REACTIVATE_COOLDOWN` 配置）与 `reactivate_until`（窗口关闭，默认 7 天，
   `REACTIVATE_WINDOW_TTL`）。恢复必须在窗口内发起、在窗口内完成全新 OIDC 证明；
   窗口外（冷却期未到或已关闭）返回 `409 recovery_window_closed`。
   恢复是**新建 active 状态 + 追加 reactivated 事件**，旧的 deactivated 事件原样保留。
6. **跨租户隔离**：所有操作都以 `(tenant_id, issuer, subject)` 锚定，
   别的租户会话既看不到也无法操作本租户身份（`404 not_found`，不泄露存在性）；
   不同租户同邮箱身份的停用/恢复互不影响。

恢复窗口与挑战有效期相关配置：`LIFECYCLE_CHALLENGE_TTL`（默认 10m）、
`REACTIVATE_COOLDOWN`（默认 24h）、`REACTIVATE_WINDOW_TTL`（默认 168h）。

## 本地运行

需要 Go 1.23+、Docker（用于 Postgres 与 Keycloak）。

```bash
# 1) 起 Postgres + Keycloak（自动导入两个 realm）
docker compose -f deploy/docker-compose.yml up -d

# 2) 等 Keycloak 就绪后，写入租户/IdP 配置
export DATABASE_URL=postgres://oidc:oidc@localhost:5432/oidctenant?sslmode=disable
go run ./cmd/seed -file deploy/seed.json

# 3) 启动应用（回调固定为 BASE_URL + /oauth/callback）
BASE_URL=http://localhost:8080 ADDR=:8080 \
DATABASE_URL=postgres://oidc:oidc@localhost:5432/oidctenant?sslmode=disable \
  go run ./cmd/server
```

测试账号（两个 realm 各有一个 `alice@example.com`，刻意同邮箱）：

| realm | 用户名 | 密码 | 邮箱 |
| --- | --- | --- | --- |
| acme | `alice` | `alice-pass` | alice@example.com |
| acme | `carol` | `carol-pass` | carol@example.com |
| globex | `alice.globex` | `aliceg-pass` | alice@example.com |
| globex | `bob` | `bobg-pass` | bob@example.com |

浏览器手动走一遍（无前端，直接访问启动 URL）：

```
http://localhost:8080/t/acme/login?issuer=http://localhost:8180/realms/acme
```

## 测试

### 加密校验单元测试（不需要外部依赖）

```bash
go test ./internal/oidcx/...
```

覆盖：合法令牌基线、错误 nonce、错误受众、过期、伪造 issuer、不受信密钥签名。

### 端到端集成测试（真实 Keycloak + 真实 PostgreSQL）

测试用 `fergusstrange/embedded-postgres` 在进程内拉起真实 PostgreSQL，
但需要一个已导入 realm 的本地 Keycloak（见上）。可用 `KC_BASE_URL` 覆盖地址。

```bash
# Keycloak 已运行且导入了 acme/globex realm（并为测试端口注册回调）后：
KC_BASE_URL=http://localhost:8180 go test ./integration/... -v
```

> 集成测试默认把应用起在 **18080** 端口，因此需要在两个 realm 的 `*-rp` 客户端
> 额外注册 `http://localhost:18080/oauth/callback` 与
> `http://localhost:18080/oauth/link/callback`（生产部署只注册真实端口即可）。

集成用例与题目要求一一对应：

| 用例 | 验证内容 |
| --- | --- |
| `TestCrossTenantSameEmailIsolation` | **跨租户同邮箱**：两个 alice@example.com 落到不同 member；跨租户会话 403 |
| `TestLoginCallbackReplayDoesNotDuplicateMember` | 登录回调重放：第二次 400，成员/身份仍各 1 条 |
| `TestConcurrentFirstLoginsDoNotDuplicateMember` | 并发首次登录（咨询锁+唯一约束）只建一个成员 |
| `TestAuthorizationCodeReplay` | **授权码重复使用**：state 已消费即拒绝 |
| `TestStaleCodeWithFreshStateIsAuthnFailure` | 新 state + 旧 code：Keycloak invalid_grant → 401 `authentication_failed` |
| `TestUnknownAndReplayedState` | 伪造/已用 state 行为一致 |
| `TestSigningKeyRotation` | **密钥轮换**：新增更高优先级 RSA key 后不重启应用即可验证新 kid，旧 kid 仍在 JWKS |
| `TestAccountLinkingHappyPath` | 两个身份各自重认证后关联，一个成员持有两条已核实身份 |
| `TestLinkConflictWhenTargetAlreadyBound` | **绑定冲突**：目标身份已属他人 → 409 `binding_conflict`，不被抢占 |
| `TestLinkSameEmailAcrossTenants` | 跨租户**同邮箱**两身份也能正确关联（按 issuer+subject 而非邮箱） |
| `TestLinkRequiresReauthentication` | 认证超过新鲜度窗口 → 401 `reauthentication_required` |
| `TestLinkCannotBeReplayed` | 关联 state/token 一次性，重放 400，不产生第三条身份 |
| `TestUnauthorizedIssuerForTenant` | 未授权 issuer → 403 `tenant_unauthorized` |
| `TestRedirectURIMustBeWhitelisted` | 未登记回调地址 → 400 `invalid_request` |
| `TestLinkRejectsDisabledProvider` | 关联前禁用 provider 授权 → 403 `tenant_unauthorized` |
| `TestWrongPasswordIsAuthnFailure` | IdP 凭证错误不产生会话/成员 |
| `TestDeactivateOneOfTwoIdentities` | 停用两身份之一：该身份登录 403 不建会话，另一身份仍登录，归属/历史保留 |
| `TestCannotDeactivateLastIdentity` | 停用唯一身份 → 409 `last_active_identity`，数据不变仍可登录 |
| `TestDeactivationRequestReplayIsIdempotent` | 同幂等键重放只取回同一挑战、只产生一个终态与一条历史 |
| `TestOldDeactivationKeyAfterReactivationReflectsCurrentState` | 停用→恢复后旧键重放反映当前状态且不新增记录 |
| `TestHeldLoginCallbackDoesNotReactivate` / `TestHeldLinkCallbackDoesNotReactivate` | 延迟到达的旧登录/关联回调不能复活身份或完成绑定 |
| `TestReactivateWithinWindowSucceeds` / `TestReactivateOutsideWindowRejected` / `TestRecoveryCooldownNotYetOpen` | 窗口内恢复成功（两条历史不覆写）、窗口外/冷却期内恢复被 409 拒绝 |
| `TestCrossTenantSameEmailLifecycleIsolation` | 跨租户同邮箱身份停用互不影响、跨租户操作 404 |
| `TestDeactivation/ReactivationRequiresCompletedProof` | 仅发起挑战不完成新证明，状态不变 |
| `TestLifecycleProofMustMatchTargetIdentity` | 证明必须精确匹配目标身份（同 issuer 不同 subject 被 401 拒） |
| `TestLifecycleCallbackStateIsOneTime` | 生命周期回调 state 一次性，重放 400 |
| `TestConcurrentLoginsAgainstDeactivatedIdentity` 等 3 个 | 并发登录/并发发起/并发完成的唯一约束与行锁边界 |

## 生产化前还应补充（本项目刻意省略）

- provider `client_secret` / 会话存储的 KMS 加密与静态加密；
- CSRF 防护（state 已绑定浏览器会话，仍建议对发起端点加 CSRF token）；
- refresh token 轮转、会话固定防护、`sid`/`jti` 反向注销（back-channel logout）；
- issuer 级别允许的签名算法/时钟偏移（leeway）做成可配置；
- 审计日志（记录谁在何时把哪个 `(issuer,subject)` 关联给了哪个 member）。
