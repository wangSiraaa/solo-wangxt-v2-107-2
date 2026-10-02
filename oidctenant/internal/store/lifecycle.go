package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/example/oidctenant/internal/models"
)

// LifecycleStartInput 是发起停用/恢复挑战的入参。
//
// IdempotencyKey 由发起方提供（必填）：同一身份、同一类操作、同一 key 的
// 重复请求永远返回同一个生命周期会话，绝不会产生第二个终态或第二条历史。
type LifecycleStartInput struct {
	Kind           string
	TenantID       uuid.UUID
	IdentityID     uuid.UUID
	MemberID       uuid.UUID
	SessionID      uuid.UUID
	IDPID          uuid.UUID
	Issuer         string
	Subject        string
	Reason         string
	IdempotencyKey string
	// Token 是一次性生命周期会话令牌，由调用方以密码学随机值生成。
	Token        string
	ChallengeTTL time.Duration
}

// LifecycleStartResult 描述发起结果。
//
// Created=false 表示命中了同一身份上已存在的会话（重复请求/并发请求），
// 返回的就是原来那一条；Terminal=true 表示身份已处于该操作的目标终态
// （例如身份早已停用），此时 Session 可能为 nil。
type LifecycleStartResult struct {
	Session  *models.LifecycleSession
	Created  bool
	Terminal bool
}

// StartLifecycle 在单个事务里校验身份当前状态并创建（或取回）生命周期挑战会话。
//
// 关键并发控制：身份行 FOR UPDATE 串行化所有针对同一身份的停用/恢复/登录回调；
// uq_lifecycle_open_per_identity 保证同一身份同类操作至多一个 pending 会话；
// (identity_id, kind, idempotency_key) 唯一约束保证重放只取回同一行。
func (s *Store) StartLifecycle(ctx context.Context, in LifecycleStartInput) (*LifecycleStartResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		identityID, memberID, tenantID   uuid.UUID
		status                           string
		reactivateAfter, reactivateUntil sql.NullTime
	)
	err = tx.QueryRow(ctx,
		`SELECT id, member_id, tenant_id, status, reactivate_after, reactivate_until
		 FROM identities WHERE id = $1 FOR UPDATE`,
		in.IdentityID,
	).Scan(&identityID, &memberID, &tenantID, &status, &reactivateAfter, &reactivateUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// 一切身份操作都严格限定在“本租户 + 本成员”范围内，杜绝跨租户操作。
	if tenantID != in.TenantID || memberID != in.MemberID {
		return nil, ErrNotFound
	}

	now := time.Now()

	// 同一 idempotency key 的重放：无论 pending 还是终态，一律返回原会话。
	if existing, err := lifecycleSessionByIdem(ctx, tx, in.IdentityID, in.Kind, in.IdempotencyKey); err == nil {
		return &LifecycleStartResult{Session: existing, Created: false,
			Terminal: existing.Status != "pending"}, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	switch in.Kind {
	case "deactivate":
		if status == models.IdentityStatusDeactivated {
			// 身份已是停用终态，且重放 key 没有对应会话：不新建任何状态。
			return &LifecycleStartResult{Created: false, Terminal: true}, nil
		}
		// 最后一个可用身份不能被停用。
		var active int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM identities
			 WHERE tenant_id = $1 AND member_id = $2 AND status = 'active'`,
			in.TenantID, in.MemberID).Scan(&active); err != nil {
			return nil, err
		}
		if active < 2 {
			return nil, ErrLastIdentity
		}
	case "reactivate":
		if status == models.IdentityStatusActive {
			return &LifecycleStartResult{Created: false, Terminal: true}, nil
		}
		// 恢复必须落在明确窗口内：冷却期之后、窗口关闭之前。
		if !reactivateAfter.Valid || !reactivateUntil.Valid {
			return nil, ErrLifecycleState
		}
		if now.Before(reactivateAfter.Time) || now.After(reactivateUntil.Time) {
			return nil, ErrRecoveryWindow
		}
	default:
		return nil, ErrLifecycleState
	}

	// 不同 key、但该身份已有一个 open 的同类会话：
	// 未过期则直接取回（拒绝另起炉灶）；已过期则原子消费掉再新建。
	if open, err := openLifecycleSession(ctx, tx, in.IdentityID, in.Kind); err == nil {
		if open.ExpiresAt.After(now) {
			return &LifecycleStartResult{Session: open, Created: false}, nil
		}
		if _, err := tx.Exec(ctx,
			`UPDATE lifecycle_sessions SET status='consumed'
			 WHERE token=$1 AND status='pending'`, open.Token); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	token := in.Token
	ls := &models.LifecycleSession{
		Token:      token,
		TenantID:   in.TenantID,
		IdentityID: in.IdentityID,
		MemberID:   in.MemberID,
		SessionID:  in.SessionID,
		IDPID:      in.IDPID,
		Kind:       in.Kind,
		Issuer:     in.Issuer,
		Subject:    in.Subject,
		Reason:     in.Reason,
		Status:     "pending",
		ExpiresAt:  now.Add(in.ChallengeTTL),
		CreatedAt:  now,
	}
	if in.Kind == "reactivate" && reactivateUntil.Valid {
		ls.WindowUntil = sql.NullTime{Time: reactivateUntil.Time, Valid: true}
	}

	insert := `INSERT INTO lifecycle_sessions
	 (token, tenant_id, identity_id, member_id, session_id, idp_id, kind,
	  issuer, subject, reason, idempotency_key, status, expires_at, window_until, created_at)
	 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',$12,$13,$14)`
	if _, err := tx.Exec(ctx, insert,
		ls.Token, ls.TenantID, ls.IdentityID, ls.MemberID, ls.SessionID, ls.IDPID,
		ls.Kind, ls.Issuer, ls.Subject, ls.Reason, in.IdempotencyKey,
		ls.ExpiresAt, nullableTime(ls.WindowUntil), ls.CreatedAt); err != nil {
		return nil, mapErr(err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return &LifecycleStartResult{Session: ls, Created: true}, nil
}

func lifecycleSessionByIdem(ctx context.Context, tx pgx.Tx,
	identityID uuid.UUID, kind, key string) (*models.LifecycleSession, error) {
	row := tx.QueryRow(ctx,
		`SELECT token, tenant_id, identity_id, member_id, session_id, idp_id, kind,
		        issuer, subject, reason, pending_state, status, expires_at,
		        window_until, created_at
		 FROM lifecycle_sessions
		 WHERE identity_id = $1 AND kind = $2 AND idempotency_key = $3
		 ORDER BY created_at DESC LIMIT 1`,
		identityID, kind, key)
	return scanLifecycleSession(row)
}

func openLifecycleSession(ctx context.Context, tx pgx.Tx,
	identityID uuid.UUID, kind string) (*models.LifecycleSession, error) {
	row := tx.QueryRow(ctx,
		`SELECT token, tenant_id, identity_id, member_id, session_id, idp_id, kind,
		        issuer, subject, reason, pending_state, status, expires_at,
		        window_until, created_at
		 FROM lifecycle_sessions
		 WHERE identity_id = $1 AND kind = $2 AND status = 'pending'
		 ORDER BY created_at DESC LIMIT 1`,
		identityID, kind)
	return scanLifecycleSession(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanLifecycleSession(row rowScanner) (*models.LifecycleSession, error) {
	var ls models.LifecycleSession
	err := row.Scan(&ls.Token, &ls.TenantID, &ls.IdentityID, &ls.MemberID,
		&ls.SessionID, &ls.IDPID, &ls.Kind, &ls.Issuer, &ls.Subject, &ls.Reason,
		&ls.PendingState, &ls.Status, &ls.ExpiresAt, &ls.WindowUntil, &ls.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &ls, nil
}

// LifecycleSession 按 token 查询生命周期会话。
func (s *Store) LifecycleSession(ctx context.Context, token string) (*models.LifecycleSession, error) {
	return scanLifecycleSession(s.pool.QueryRow(ctx,
		`SELECT token, tenant_id, identity_id, member_id, session_id, idp_id, kind,
		        issuer, subject, reason, pending_state, status, expires_at,
		        window_until, created_at
		 FROM lifecycle_sessions WHERE token = $1`, token))
}

// SetLifecyclePendingState 把本次挑战的 OIDC state 绑定到 pending 会话。
// 只允许绑定一次；重放或非 pending 会话返回 ErrConflict。
func (s *Store) SetLifecyclePendingState(ctx context.Context, token, state string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_sessions SET pending_state = $1
		 WHERE token = $2 AND status = 'pending' AND pending_state = '' AND expires_at > now()`,
		state, token)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// LifecycleProof 是回调中已通过全套 OIDC 校验的新证明。
type LifecycleProof struct {
	Token    string
	State    string
	Issuer   string
	Subject  string
	AuthTime time.Time
	MaxAge   time.Duration
	Now      time.Time
	// ReactivateCooldown / ReactivateTTL 是停用时写入、恢复时复核的窗口参数。
	ReactivateCooldown time.Duration
	ReactivateTTL      time.Duration
}

// CompleteLifecycle 在单事务里把“已取得新 OIDC 证明”的挑战推进到终态。
//
// 所有检查与写入在同一事务、且在身份行 FOR UPDATE 下发生：
//   - 会话必须 pending、未过期，且回调 state 与发起时绑定值一致；
//   - 证明的 (issuer,subject) 必须就是被操作身份，认证时间必须新鲜；
//   - 停用：身份仍 active、成员仍有 >=2 个可用身份，然后原子地
//     翻状态 + 写不可变事件；
//   - 恢复：身份仍 deactivated、当前时间仍落在恢复窗口内，然后原子地
//     建立新状态（active）并追加事件，旧事件一行不改。
func (s *Store) CompleteLifecycle(ctx context.Context, p LifecycleProof) (*models.LifecycleEvent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var ls models.LifecycleSession
	err = tx.QueryRow(ctx,
		`SELECT token, tenant_id, identity_id, member_id, session_id, idp_id, kind,
		        issuer, subject, reason, pending_state, status, expires_at,
		        window_until, created_at
		 FROM lifecycle_sessions WHERE token = $1 FOR UPDATE`,
		p.Token,
	).Scan(&ls.Token, &ls.TenantID, &ls.IdentityID, &ls.MemberID, &ls.SessionID,
		&ls.IDPID, &ls.Kind, &ls.Issuer, &ls.Subject, &ls.Reason,
		&ls.PendingState, &ls.Status, &ls.ExpiresAt, &ls.WindowUntil, &ls.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if ls.Status != "pending" {
		return nil, ErrConflict
	}
	if ls.PendingState == "" || ls.PendingState != p.State {
		return nil, ErrConflict
	}
	if p.Now.After(ls.ExpiresAt) {
		_, _ = tx.Exec(ctx, `UPDATE lifecycle_sessions SET status='consumed' WHERE token=$1`, p.Token)
		_ = tx.Commit(ctx)
		return nil, ErrLifecycleState
	}

	// 证明锚点必须与被操作身份逐字节一致（不接受同邮箱的别的身份）。
	if p.Issuer != ls.Issuer || p.Subject != ls.Subject {
		return nil, reauthError("the new proof does not identify the targeted identity")
	}
	if p.AuthTime.IsZero() || p.Now.Sub(p.AuthTime) > p.MaxAge {
		return nil, reauthError("identity proof is not a fresh re-authentication")
	}

	var (
		status                         string
		identityID, memberID, tenantID uuid.UUID
		deactivatedAt                  sql.NullTime
		reactivateAfter                sql.NullTime
		reactivateUntil                sql.NullTime
	)
	err = tx.QueryRow(ctx,
		`SELECT id, member_id, tenant_id, status, deactivated_at,
		        reactivate_after, reactivate_until
		 FROM identities WHERE id = $1 FOR UPDATE`,
		ls.IdentityID,
	).Scan(&identityID, &memberID, &tenantID, &status, &deactivatedAt,
		&reactivateAfter, &reactivateUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if tenantID != ls.TenantID || memberID != ls.MemberID {
		return nil, ErrNotFound
	}

	event := &models.LifecycleEvent{
		ID:             uuid.New(),
		TenantID:       ls.TenantID,
		IdentityID:     ls.IdentityID,
		MemberID:       ls.MemberID,
		Issuer:         ls.Issuer,
		Subject:        ls.Subject,
		Reason:         ls.Reason,
		ActorSessionID: uuid.NullUUID{UUID: ls.SessionID, Valid: true},
		ProvenAuthTime: p.AuthTime,
	}

	switch ls.Kind {
	case "deactivate":
		if status != models.IdentityStatusActive {
			// 身份在挑战进行期间已被停用：不重复写终态/历史。
			_, _ = tx.Exec(ctx, `UPDATE lifecycle_sessions SET status='consumed' WHERE token=$1`, p.Token)
			_ = tx.Commit(ctx)
			return nil, ErrConflict
		}
		var active int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM identities
			 WHERE tenant_id = $1 AND member_id = $2 AND status = 'active'`,
			ls.TenantID, ls.MemberID).Scan(&active); err != nil {
			return nil, err
		}
		if active < 2 {
			return nil, ErrLastIdentity
		}
		after := p.Now.Add(p.ReactivateCooldown)
		until := p.Now.Add(p.ReactivateTTL)
		if _, err := tx.Exec(ctx,
			`UPDATE identities
			 SET status='deactivated', deactivated_at=$2,
			     reactivate_after=$3, reactivate_until=$4, updated_at=now()
			 WHERE id=$1 AND status='active'`,
			ls.IdentityID, p.Now, after, until); err != nil {
			return nil, err
		}
		event.Action = "deactivated"
		event.ReactivateAfter = sql.NullTime{Time: after, Valid: true}
		event.ReactivateUntil = sql.NullTime{Time: until, Valid: true}
		if err := insertLifecycleEvent(ctx, tx, event); err != nil {
			return nil, err
		}
	case "reactivate":
		if status != models.IdentityStatusDeactivated {
			_, _ = tx.Exec(ctx, `UPDATE lifecycle_sessions SET status='consumed' WHERE token=$1`, p.Token)
			_ = tx.Commit(ctx)
			return nil, ErrConflict
		}
		// 回调落库时再次用身份行上的窗口判定，迟到回调无法复活身份。
		if !reactivateAfter.Valid || !reactivateUntil.Valid ||
			p.Now.Before(reactivateAfter.Time) || p.Now.After(reactivateUntil.Time) {
			_, _ = tx.Exec(ctx, `UPDATE lifecycle_sessions SET status='consumed' WHERE token=$1`, p.Token)
			_ = tx.Commit(ctx)
			return nil, ErrRecoveryWindow
		}
		if _, err := tx.Exec(ctx,
			`UPDATE identities
			 SET status='active', deactivated_at=NULL,
			     reactivate_after=NULL, reactivate_until=NULL, updated_at=now()
			 WHERE id=$1 AND status='deactivated'`,
			ls.IdentityID); err != nil {
			return nil, err
		}
		event.Action = "reactivated"
		event.Reason = ""
		if err := insertLifecycleEvent(ctx, tx, event); err != nil {
			return nil, err
		}
	default:
		return nil, ErrLifecycleState
	}

	if _, err := tx.Exec(ctx,
		`UPDATE lifecycle_sessions SET status='completed', completed_at=now(),
		                                pending_state=''
		 WHERE token=$1`, p.Token); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return event, nil
}

func insertLifecycleEvent(ctx context.Context, tx pgx.Tx, e *models.LifecycleEvent) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO identity_lifecycle_events
		 (id, tenant_id, identity_id, member_id, issuer, subject, action, reason,
		  actor_session_id, proven_auth_time, reactivate_after, reactivate_until, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())`,
		e.ID, e.TenantID, e.IdentityID, e.MemberID, e.Issuer, e.Subject,
		e.Action, e.Reason, nullableUUID(e.ActorSessionID), e.ProvenAuthTime,
		nullableTime(e.ReactivateAfter), nullableTime(e.ReactivateUntil))
	return mapErr(err)
}

// ConsumeCompletedLifecycle 一次性消费已完成的生命周期会话，随后拒绝重放。
func (s *Store) ConsumeCompletedLifecycle(ctx context.Context, token string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_sessions SET status='consumed'
		 WHERE token = $1 AND status = 'completed'`, token)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// LifecycleEvents 返回某身份的全部生命周期历史（按时间正序），严格限定本租户。
func (s *Store) LifecycleEvents(ctx context.Context, tenantID, identityID uuid.UUID) ([]models.LifecycleEvent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT e.id, e.tenant_id, e.identity_id, e.member_id, e.issuer, e.subject,
		        e.action, e.reason, e.actor_session_id, e.proven_auth_time,
		        e.reactivate_after, e.reactivate_until, e.created_at
		 FROM identity_lifecycle_events e
		 WHERE e.tenant_id = $1 AND e.identity_id = $2
		 ORDER BY e.created_at, e.id`,
		tenantID, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.LifecycleEvent
	for rows.Next() {
		var e models.LifecycleEvent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.IdentityID, &e.MemberID,
			&e.Issuer, &e.Subject, &e.Action, &e.Reason, &e.ActorSessionID,
			&e.ProvenAuthTime, &e.ReactivateAfter, &e.ReactivateUntil, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullableUUID(v uuid.NullUUID) any {
	if !v.Valid {
		return nil
	}
	return v.UUID
}
