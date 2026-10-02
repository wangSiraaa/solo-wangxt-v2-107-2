package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/oidctenant/internal/models"
)

// LifecycleInput 是发起停用/恢复流程的输入。
type LifecycleInput struct {
	TenantID       uuid.UUID
	IdentityID     uuid.UUID
	MemberID       uuid.UUID
	Kind           string // deactivate | reactivate
	Issuer         string
	Subject        string
	Reason         string
	SessionID      uuid.UUID
	IdempotencyKey string
	TokenHash      []byte
}

// LifecycleResult 返回发起结果；Replayed=true 表示幂等命中了已开放的同一流程。
type LifecycleResult struct {
	Lifecycle *models.IdentityLifecycle
	Replayed  bool
}

// StartLifecycle 在单事务内开启一个停用或恢复流程。
//
// 状态边界：
//   - 身份必须属于本租户、本成员（跨租户/跨成员 -> ErrLifecycleConflict/ErrNotFound）；
//   - 停用要求身份 active，且该成员还有其它 active 身份（最后一个不能停用）；
//   - 恢复要求身份 disabled；不在恢复窗口内（created_at + window）-> ErrLifecycleExpired；
//   - 每个身份至多一个 pending 流程（部分唯一索引兜底）；同幂等键重放返回原行。
//
// 停用发起的同一事务里把身份推进到 deactivation_pending：从这一刻起旧登录/
// 旧关联回调都会被登录/关联路径拒绝，证明完成前不存在“还能再用”的窗口。
func (s *Store) StartLifecycle(ctx context.Context, in LifecycleInput,
	proofTTL, reactivationWindow time.Duration) (*LifecycleResult, error) {

	if in.Kind != "deactivate" && in.Kind != "reactivate" {
		return nil, ErrLifecycleConflict
	}
	now := time.Now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 先取成员级再取身份级咨询锁，固定加锁顺序：
	// 并发停用同一成员的两条身份时在成员锁上串行，“最后一个可用身份”检查才不会被穿透。
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('member|'||$1, 0))`,
		in.MemberID.String()); err != nil {
		return nil, err
	}
	// 与登录/关联路径同一把身份锁，串行化该身份的所有状态推进。
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1 || '|' || $2 || '|' || $3, 0))`,
		in.TenantID.String(), in.Issuer, in.Subject); err != nil {
		return nil, err
	}

	var (
		identityID, ownerID uuid.UUID
		status              string
		disabledAt          sql.NullTime
	)
	err = tx.QueryRow(ctx,
		`SELECT i.id, i.member_id, i.status,
		        (SELECT max(created_at) FROM identity_events e
		         WHERE e.identity_id = i.id AND e.kind = 'identity_deactivated')
		 FROM identities i
		 WHERE i.id = $1 AND i.tenant_id = $2
		 FOR UPDATE`,
		in.IdentityID, in.TenantID,
	).Scan(&identityID, &ownerID, &status, &disabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if ownerID != in.MemberID {
		// 不向其它成员暴露身份存在性，统一按冲突拒绝。
		return nil, ErrLifecycleConflict
	}

	// 已有开放流程：同幂等键重放返回原流程（只产生一个终态），其它一律冲突。
	existing, err := pendingLifecycle(ctx, tx, identityID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		keyMatch := in.IdempotencyKey != "" &&
			existing.IdempotencyKey.Valid && existing.IdempotencyKey.String == in.IdempotencyKey
		sameKind := existing.Kind == in.Kind
		if keyMatch && sameKind {
			if err := tx.Commit(ctx); err != nil {
				return nil, err
			}
			return &LifecycleResult{Lifecycle: existing, Replayed: true}, nil
		}
		return nil, ErrLifecycleConflict
	}

	switch in.Kind {
	case "deactivate":
		if status != "active" {
			return nil, ErrLifecycleConflict
		}
		// 最后一个可用身份不能停用（仅计 active，正在停用流程中的不算可用）。
		var n int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM identities
			 WHERE tenant_id = $1 AND member_id = $2 AND status = 'active'`,
			in.TenantID, in.MemberID).Scan(&n); err != nil {
			return nil, err
		}
		if n <= 1 {
			return nil, ErrLastIdentity
		}
	case "reactivate":
		if status != "disabled" {
			return nil, ErrLifecycleConflict
		}
		// 恢复只允许在明确窗口内发起；窗口外必须重新绑定，旧身份不可复活。
		if !disabledAt.Valid || now.Sub(disabledAt.Time) > reactivationWindow {
			return nil, ErrLifecycleExpired
		}
	}

	lc := &models.IdentityLifecycle{
		ID:             uuid.New(),
		TenantID:       in.TenantID,
		IdentityID:     identityID,
		MemberID:       in.MemberID,
		Kind:           in.Kind,
		Status:         "pending",
		TokenHash:      in.TokenHash,
		Issuer:         in.Issuer,
		Subject:        in.Subject,
		Reason:         in.Reason,
		SessionID:      in.SessionID,
		IdempotencyKey: models.NullString{String: in.IdempotencyKey, Valid: in.IdempotencyKey != ""},
		CreatedAt:      now,
		ExpiresAt:      now.Add(proofTTL),
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO identity_lifecycles
		 (id, tenant_id, identity_id, member_id, kind, status, token_hash, idempotency_key,
		  issuer, subject, reason, session_id, created_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8,$9,$10,$11,$12,$13)`,
		lc.ID, lc.TenantID, lc.IdentityID, lc.MemberID, lc.Kind, lc.TokenHash,
		nullableStr(lc.IdempotencyKey), lc.Issuer, lc.Subject, lc.Reason,
		lc.SessionID, lc.CreatedAt, lc.ExpiresAt); err != nil {
		return nil, mapErr(err)
	}

	eventKind := "deactivation_requested"
	if in.Kind == "reactivate" {
		eventKind = "reactivation_requested"
	}
	if err := insertEvent(ctx, tx, models.IdentityEvent{
		ID:          uuid.New(),
		TenantID:    in.TenantID,
		IdentityID:  uuidNull(identityID),
		LifecycleID: uuidNull(lc.ID),
		MemberID:    uuidNull(in.MemberID),
		Kind:        eventKind,
		Issuer:      in.Issuer,
		Subject:     in.Subject,
		Reason:      in.Reason,
		CreatedAt:   now,
	}); err != nil {
		return nil, err
	}

	if in.Kind == "deactivate" {
		// 立即关闭登录/关联边界；只有本次新 OIDC 证明才能把它推进到 disabled。
		if _, err := tx.Exec(ctx,
			`UPDATE identities SET status='deactivation_pending', updated_at=now()
			 WHERE id=$1 AND status='active'`, identityID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return &LifecycleResult{Lifecycle: lc, Replayed: false}, nil
}

func pendingLifecycle(ctx context.Context, tx pgx.Tx, identityID uuid.UUID) (*models.IdentityLifecycle, error) {
	lc, err := scanLifecycle(ctx, tx,
		`SELECT `+lifecycleColumns+` FROM identity_lifecycles
		 WHERE identity_id = $1 AND status = 'pending'
		 ORDER BY created_at DESC LIMIT 1`, identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return lc, nil
}

const lifecycleColumns = `id, tenant_id, identity_id, member_id, kind, status, token_hash,
	idempotency_key, issuer, subject, reason, session_id,
	proof_issuer, proof_subject, proof_auth_time, created_at, expires_at, completed_at`

type rowScanner interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func scanLifecycle(ctx context.Context, q rowScanner, query string, args ...any) (*models.IdentityLifecycle, error) {
	var lc models.IdentityLifecycle
	var idem sql.NullString
	var completed sql.NullTime
	var proofAuth sql.NullTime
	err := q.QueryRow(ctx, query, args...).Scan(
		&lc.ID, &lc.TenantID, &lc.IdentityID, &lc.MemberID, &lc.Kind, &lc.Status, &lc.TokenHash,
		&idem, &lc.Issuer, &lc.Subject, &lc.Reason, &lc.SessionID,
		&lc.ProofIssuer, &lc.ProofSubject, &proofAuth,
		&lc.CreatedAt, &lc.ExpiresAt, &completed)
	if err != nil {
		return nil, err
	}
	lc.IdempotencyKey = idem
	lc.ProofAuthTime = proofAuth
	lc.CompletedAt = completed
	return &lc, nil
}

// LifecycleByToken 按一次性令牌哈希查找生命周期流程。
func (s *Store) LifecycleByToken(ctx context.Context, tokenHash []byte) (*models.IdentityLifecycle, error) {
	lc, err := scanLifecycle(ctx, s.pool,
		`SELECT `+lifecycleColumns+` FROM identity_lifecycles WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return nil, mapErr(err)
	}
	return lc, nil
}

// LifecycleProof 是完成停用/恢复证明时已通过 OIDC 校验的声明。
type LifecycleProof struct {
	TokenHash []byte
	Issuer    string
	Subject   string
	AuthTime  time.Time
}

// CompleteLifecycleProof 在单事务里消费一次性生命周期令牌并推进身份状态。
//
// 不变量：
//   - 流程必须 pending、未过期；过期 -> ErrLifecycleExpired（停用意图过期时
//     身份安全地回到 active，并追加 lifecycle_expired 事件）；
//   - 必须由发起时的同一会话完成，且证明锚点必须就是目标身份本人；
//   - 终态用带 status 谓词的 UPDATE 写入，重放/竞争只会得到 ErrLifecycleConflict；
//   - 恢复只新建事件与新状态，绝不覆写停用记录。
func (s *Store) CompleteLifecycleProof(ctx context.Context, p LifecycleProof, now time.Time, maxAge time.Duration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 先做不加锁的定位，再按全局锁序（成员咨询锁 -> 身份咨询锁 -> 行锁）加锁，
	// 与 StartLifecycle/登录路径保持一致，杜绝“行锁 + 咨询锁”交叉死锁。
	lc, err := scanLifecycle(ctx, tx,
		`SELECT `+lifecycleColumns+` FROM identity_lifecycles
		 WHERE token_hash = $1`, p.TokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('member|'||$1, 0))`,
		lc.MemberID.String()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1 || '|' || $2 || '|' || $3, 0))`,
		lc.TenantID.String(), lc.Issuer, lc.Subject); err != nil {
		return err
	}

	lc, err = scanLifecycle(ctx, tx,
		`SELECT `+lifecycleColumns+` FROM identity_lifecycles
		 WHERE token_hash = $1 FOR UPDATE`, p.TokenHash)
	if err != nil {
		return err
	}
	if lc.Status != "pending" {
		// 令牌一次性：重放完成回调不能再次推进状态。
		return ErrLifecycleConflict
	}

	if now.After(lc.ExpiresAt) {
		if lc.Kind == "deactivate" {
			// 证明窗口已过：放弃这次停用，身份安全回到 active；
			// 本次旧回调本身仍按过期失败处理（不产生停用终态）。
			if err := expireDeactivate(ctx, tx, lc, now); err != nil {
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			return ErrLifecycleExpired
		}
		// 恢复流程过期：身份保持 disabled，旧回调无法复活它。
		if err := finishExpired(ctx, tx, lc, now); err != nil {
			return err
		}
		_ = tx.Commit(ctx)
		return ErrLifecycleExpired
	}
	if p.Issuer != lc.Issuer || p.Subject != lc.Subject {
		// 新证明必须来自被停用/恢复的那个身份本人，不能用同成员的另一身份顶替。
		return ErrLifecycleConflict
	}
	if p.AuthTime.IsZero() {
		return reauthError("provider did not report auth_time; cannot prove recent re-authentication")
	}
	if now.Sub(p.AuthTime) > maxAge {
		return reauthError("lifecycle proof authentication is stale; re-authenticate")
	}

	var identityStatus string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM identities WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
		lc.IdentityID, lc.TenantID).Scan(&identityStatus); err != nil {
		return err
	}

	switch lc.Kind {
	case "deactivate":
		if identityStatus != "deactivation_pending" {
			return ErrLifecycleConflict
		}
		// 证明期间另一条身份也被停用了：此时本身份已是最后一个可用身份。
		// 安全选择是不允许停用，流程记为 rejected、身份回到 active —— 绝不让成员零可用身份。
		var activeOthers int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM identities
			 WHERE tenant_id = $1 AND member_id = $2 AND status = 'active'`,
			lc.TenantID, lc.MemberID).Scan(&activeOthers); err != nil {
			return err
		}
		if activeOthers == 0 {
			if _, err := tx.Exec(ctx,
				`UPDATE identities SET status='active', updated_at=now()
				 WHERE id=$1 AND status='deactivation_pending'`, lc.IdentityID); err != nil {
				return err
			}
			if err := rejectLifecycle(ctx, tx, lc, now,
				"refused: this is the member's only usable identity at proof time"); err != nil {
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			return ErrLastIdentity
		}
		tag, err := tx.Exec(ctx,
			`UPDATE identities SET status='disabled', updated_at=now()
			 WHERE id=$1 AND status='deactivation_pending'`, lc.IdentityID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrLifecycleConflict
		}
		// 立即吊销发起停用的那个浏览器会话：停用证明一完成就不能再沿用旧 sid，
		// 强制成员改用其余可信身份重新登录。其它身份建立的会话不受影响。
		if _, err := tx.Exec(ctx,
			`UPDATE sessions SET revoked_at=now()
			 WHERE id=$1 AND tenant_id=$2 AND revoked_at IS NULL`,
			lc.SessionID, lc.TenantID); err != nil {
			return err
		}
		if err := finalizeLifecycle(ctx, tx, lc, "deactivated", p, now); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, models.IdentityEvent{
			ID:            uuid.New(),
			TenantID:      lc.TenantID,
			IdentityID:    uuidNull(lc.IdentityID),
			LifecycleID:   uuidNull(lc.ID),
			MemberID:      uuidNull(lc.MemberID),
			Kind:          "identity_deactivated",
			Issuer:        lc.Issuer,
			Subject:       lc.Subject,
			Reason:        lc.Reason,
			ProofIssuer:   p.Issuer,
			ProofSubject:  p.Subject,
			ProofAuthTime: models.NullTime{Time: p.AuthTime, Valid: true},
			CreatedAt:     now,
		}); err != nil {
			return err
		}
	case "reactivate":
		if identityStatus != "disabled" {
			return ErrLifecycleConflict
		}
		tag, err := tx.Exec(ctx,
			`UPDATE identities SET status='active', updated_at=now()
			 WHERE id=$1 AND status='disabled'`, lc.IdentityID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrLifecycleConflict
		}
		if err := finalizeLifecycle(ctx, tx, lc, "reactivated", p, now); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, models.IdentityEvent{
			ID:            uuid.New(),
			TenantID:      lc.TenantID,
			IdentityID:    uuidNull(lc.IdentityID),
			LifecycleID:   uuidNull(lc.ID),
			MemberID:      uuidNull(lc.MemberID),
			Kind:          "identity_reactivated",
			Issuer:        lc.Issuer,
			Subject:       lc.Subject,
			Reason:        lc.Reason,
			ProofIssuer:   p.Issuer,
			ProofSubject:  p.Subject,
			ProofAuthTime: models.NullTime{Time: p.AuthTime, Valid: true},
			CreatedAt:     now,
		}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func finalizeLifecycle(ctx context.Context, tx pgx.Tx, lc *models.IdentityLifecycle,
	terminal string, p LifecycleProof, now time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE identity_lifecycles
		 SET status=$2, proof_issuer=$3, proof_subject=$4, proof_auth_time=$5, completed_at=$6
		 WHERE id=$1 AND status='pending'`,
		lc.ID, terminal, p.Issuer, p.Subject, p.AuthTime, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLifecycleConflict
	}
	return nil
}

func finishExpired(ctx context.Context, tx pgx.Tx, lc *models.IdentityLifecycle, now time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE identity_lifecycles SET status='expired', completed_at=$2
		 WHERE id=$1 AND status='pending'`, lc.ID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLifecycleConflict
	}
	return insertEvent(ctx, tx, models.IdentityEvent{
		ID:          uuid.New(),
		TenantID:    lc.TenantID,
		IdentityID:  uuidNull(lc.IdentityID),
		LifecycleID: uuidNull(lc.ID),
		MemberID:    uuidNull(lc.MemberID),
		Kind:        "lifecycle_expired",
		Issuer:      lc.Issuer,
		Subject:     lc.Subject,
		Reason:      lc.Reason,
		CreatedAt:   now,
	})
}

// expirePendingDeactivateLocked 在已持有身份行锁（FOR UPDATE）的调用方事务内，
// 若该身份存在过期的停用待证明流程，就让它过期、身份回到 active。
// 返回是否发生了过期推进；不自行提交，由外层事务统一提交。
func (s *Store) expirePendingDeactivateLocked(ctx context.Context, tx pgx.Tx,
	tenantID, identityID uuid.UUID, now time.Time) (bool, error) {
	lc, err := scanLifecycle(ctx, tx,
		`SELECT `+lifecycleColumns+` FROM identity_lifecycles
		 WHERE identity_id = $1 AND status = 'pending' AND kind = 'deactivate'
		 ORDER BY created_at DESC LIMIT 1
		 FOR UPDATE`, identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		// 没有开放流程却处于 deactivation_pending（数据不一致）：保守拒绝。
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if now.Before(lc.ExpiresAt) {
		return false, nil
	}
	if err := expireDeactivate(ctx, tx, lc, now); err != nil {
		return false, err
	}
	return true, nil
}

// rejectLifecycle 把因证明时刻状态不再合法（如身份已成为最后一个可用身份）
// 的停用流程终态记为 rejected，并追加独立审计事件；身份由调用方先行恢复 active。
func rejectLifecycle(ctx context.Context, tx pgx.Tx, lc *models.IdentityLifecycle, now time.Time, reason string) error {
	tag, err := tx.Exec(ctx,
		`UPDATE identity_lifecycles SET status='rejected', reason=$2, completed_at=$3
		 WHERE id=$1 AND status='pending'`, lc.ID, reason, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLifecycleConflict
	}
	return insertEvent(ctx, tx, models.IdentityEvent{
		ID:          uuid.New(),
		TenantID:    lc.TenantID,
		IdentityID:  uuidNull(lc.IdentityID),
		LifecycleID: uuidNull(lc.ID),
		MemberID:    uuidNull(lc.MemberID),
		Kind:        "lifecycle_rejected",
		Issuer:      lc.Issuer,
		Subject:     lc.Subject,
		Reason:      reason,
		CreatedAt:   now,
	})
}

// expireDeactivate 让过期的停用流程落到 expired 并把身份安全恢复 active。
// 注意：这只是“放弃一次未完成的停用尝试”，与显式恢复无关，不触碰任何终态历史。
func expireDeactivate(ctx context.Context, tx pgx.Tx, lc *models.IdentityLifecycle, now time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE identity_lifecycles SET status='expired', completed_at=$2
		 WHERE id=$1 AND status='pending'`, lc.ID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLifecycleConflict
	}
	if _, err := tx.Exec(ctx,
		`UPDATE identities SET status='active', updated_at=now()
		 WHERE id=$1 AND status='deactivation_pending'`, lc.IdentityID); err != nil {
		return err
	}
	return insertEvent(ctx, tx, models.IdentityEvent{
		ID:          uuid.New(),
		TenantID:    lc.TenantID,
		IdentityID:  uuidNull(lc.IdentityID),
		LifecycleID: uuidNull(lc.ID),
		MemberID:    uuidNull(lc.MemberID),
		Kind:        "lifecycle_expired",
		Issuer:      lc.Issuer,
		Subject:     lc.Subject,
		Reason:      lc.Reason,
		CreatedAt:   now,
	})
}

// ExpireOverdueLifecycles 周期性收敛所有过期的 pending 流程（定时清理用）。
func (s *Store) ExpireOverdueLifecycles(ctx context.Context, now time.Time) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx,
		`SELECT `+lifecycleColumns+` FROM identity_lifecycles
		 WHERE status='pending' AND expires_at < $1
		 FOR UPDATE SKIP LOCKED`, now)
	if err != nil {
		return 0, err
	}
	var pending []*models.IdentityLifecycle
	for rows.Next() {
		// scanLifecycle 需要 rowScanner；直接复用逐行扫描逻辑。
		var lc models.IdentityLifecycle
		var idem sql.NullString
		var completed, proofAuth sql.NullTime
		if err := rows.Scan(
			&lc.ID, &lc.TenantID, &lc.IdentityID, &lc.MemberID, &lc.Kind, &lc.Status, &lc.TokenHash,
			&idem, &lc.Issuer, &lc.Subject, &lc.Reason, &lc.SessionID,
			&lc.ProofIssuer, &lc.ProofSubject, &proofAuth,
			&lc.CreatedAt, &lc.ExpiresAt, &completed); err != nil {
			rows.Close()
			return 0, err
		}
		lc.IdempotencyKey = idem
		lc.ProofAuthTime = proofAuth
		lc.CompletedAt = completed
		pending = append(pending, &lc)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var n int64
	for _, lc := range pending {
		switch lc.Kind {
		case "deactivate":
			// 锁定身份行，避免与正在进行的登录竞争。
			var status string
			if err := tx.QueryRow(ctx,
				`SELECT status FROM identities WHERE id=$1 FOR UPDATE`, lc.IdentityID).Scan(&status); err != nil {
				return 0, err
			}
			if err := expireDeactivate(ctx, tx, lc, now); err != nil {
				return 0, err
			}
		default:
			if err := finishExpired(ctx, tx, lc, now); err != nil {
				return 0, err
			}
		}
		n++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

// IdentityEvents 返回某身份只追加的生命周期历史（按时间升序），绝不按邮箱查询。
func (s *Store) IdentityEvents(ctx context.Context, tenantID, identityID uuid.UUID) ([]models.IdentityEvent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, identity_id, lifecycle_id, member_id,
		        kind, issuer, subject, reason, proof_issuer, proof_subject,
		        proof_auth_time, created_at
		 FROM identity_events
		 WHERE tenant_id=$1 AND identity_id=$2
		 ORDER BY created_at ASC, id ASC`, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// IdentityEventsByAnchor 按 (tenant, issuer, subject) 锚点查询历史，
// 供无法先解析 identity_id 的调用路径使用。
func (s *Store) IdentityEventsByAnchor(ctx context.Context,
	tenantID uuid.UUID, issuer, subject string) ([]models.IdentityEvent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, identity_id, lifecycle_id, member_id,
		        kind, issuer, subject, reason, proof_issuer, proof_subject,
		        proof_auth_time, created_at
		 FROM identity_events
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3
		 ORDER BY created_at ASC, id ASC`, tenantID, issuer, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows pgx.Rows) ([]models.IdentityEvent, error) {
	var out []models.IdentityEvent
	for rows.Next() {
		var e models.IdentityEvent
		var identityID, lifecycleID, memberID sql.Null[uuid.UUID]
		var proofAuth sql.NullTime
		if err := rows.Scan(
			&e.ID, &e.TenantID, &identityID, &lifecycleID, &memberID,
			&e.Kind, &e.Issuer, &e.Subject, &e.Reason,
			&e.ProofIssuer, &e.ProofSubject, &proofAuth, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.IdentityID = identityID
		e.LifecycleID = lifecycleID
		e.MemberID = memberID
		e.ProofAuthTime = proofAuth
		out = append(out, e)
	}
	return out, rows.Err()
}

func insertEvent(ctx context.Context, tx pgx.Tx, e models.IdentityEvent) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO identity_events
		 (id, tenant_id, identity_id, lifecycle_id, member_id, kind,
		  issuer, subject, reason, proof_issuer, proof_subject, proof_auth_time, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		e.ID, e.TenantID, nullableUUID(e.IdentityID), nullableUUID(e.LifecycleID),
		nullableUUID(e.MemberID), e.Kind, e.Issuer, e.Subject, e.Reason,
		e.ProofIssuer, e.ProofSubject, nullableTime(e.ProofAuthTime), e.CreatedAt)
	return err
}

func uuidNull(id uuid.UUID) sql.Null[uuid.UUID] {
	return sql.Null[uuid.UUID]{V: id, Valid: true}
}

func nullableUUID(v sql.Null[uuid.UUID]) any {
	if !v.Valid {
		return nil
	}
	return v.V
}

// 静态保证 pool 满足 rowScanner（仅用于文档化接口约束）。
var _ rowScanner = (*pgxpool.Pool)(nil)
