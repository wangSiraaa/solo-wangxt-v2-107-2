package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/store"
)

// 并发边界测试：不依赖 Keycloak，直接对真实（嵌入式）PostgreSQL 并发调用
// store 层事务，验证唯一约束 + 行锁 + 咨询锁共同保证：
//   - 已停用身份的并发登录回调全部停在状态边界，不复活、不重复建成员；
//   - 并发发起停用（同一幂等键）只产生一个生命周期会话；
//   - 并发“首次登录”与停用交错时，成员与身份都不重复。

// seedMemberWithIdentity 直接写入一个成员和一条身份（指定状态）。
func seedMemberWithIdentity(t *testing.T, env *testEnv, status string) (uuid.UUID, models.Identity) {
	t.Helper()
	memberID := uuid.New()
	identityID := uuid.New()
	iss := issuer("acme")
	sub := "user-" + identityID.String()[:8]
	ctx := context.Background()
	if _, err := env.store.DB().Exec(ctx,
		`INSERT INTO members(id, tenant_id, display_name) VALUES ($1,$2,'concurrent')`,
		memberID, tenantAcmeID); err != nil {
		t.Fatalf("insert member: %v", err)
	}
	if _, err := env.store.DB().Exec(ctx,
		`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified, status)
		 VALUES ($1,$2,$3,$4,$5,'c@example.com',true,$6)`,
		identityID, tenantAcmeID, memberID, iss, sub, status); err != nil {
		t.Fatalf("insert identity: %v", err)
	}
	return memberID, models.Identity{ID: identityID, TenantID: tenantAcmeID, MemberID: memberID,
		Issuer: iss, Subject: sub, Status: status}
}

// TestConcurrentLoginsAgainstDeactivatedIdentity 停用身份的并发登录回调：
// 全部返回 ErrIdentityDeactivated，成员/身份数不增加，状态仍为 deactivated。
func TestConcurrentLoginsAgainstDeactivatedIdentity(t *testing.T) {
	env := startEnv(t)
	_, ident := seedMemberWithIdentity(t, env, "deactivated")

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = env.store.LoginOrRegisterMember(context.Background(), store.LoginIdentity{
				TenantID: ident.TenantID, Issuer: ident.Issuer, Subject: ident.Subject,
				Email: "c@example.com", EmailVerified: true,
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != store.ErrIdentityDeactivated {
			t.Fatalf("concurrent login #%d err=%v, want ErrIdentityDeactivated", i, err)
		}
	}
	if n := countRows(t, env, `SELECT count(*) FROM members WHERE id=$1`, ident.MemberID); n != 1 {
		t.Fatalf("members=%d, want 1", n)
	}
	if n := countRows(t, env, `SELECT count(*) FROM identities WHERE id=$1`, ident.ID); n != 1 {
		t.Fatalf("identities=%d, want 1", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identities WHERE id=$1 AND status='deactivated'`, ident.ID); n != 1 {
		t.Fatalf("deactivated identity was resurrected")
	}
}

// TestConcurrentStartLifecycleSameKey 并发以同一幂等键发起停用：
// 唯一约束保证只有一个 pending 生命周期会话，且不触碰唯一身份保护之外的状态。
func TestConcurrentStartLifecycleSameKey(t *testing.T) {
	env := startEnv(t)
	memberID, ident := seedMemberWithIdentity(t, env, "active")
	// 再加一条 active 身份，使“最后一个身份”保护不触发。
	second := models.Identity{ID: uuid.New(), TenantID: tenantAcmeID, MemberID: memberID,
		Issuer: issuer("globex"), Subject: "second-" + memberID.String()[:8]}
	if _, err := env.store.DB().Exec(context.Background(),
		`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified, status)
		 VALUES ($1,$2,$3,$4,$5,'d@example.com',true,'active')`,
		second.ID, second.TenantID, second.MemberID, second.Issuer, second.Subject); err != nil {
		t.Fatalf("insert second identity: %v", err)
	}

	sessionID := uuid.New()
	if _, err := env.store.DB().Exec(context.Background(),
		`INSERT INTO sessions(id, tenant_id, member_id, token_hash, expires_at)
		 VALUES ($1,$2,$3, $4, now()+interval '1 hour')`,
		sessionID, tenantAcmeID, memberID, []byte("hash-"+sessionID.String())); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	const n = 8
	key := "concurrent-deactivation-key"
	var wg sync.WaitGroup
	results := make([]*store.LifecycleStartResult, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			r, err := env.store.StartLifecycle(context.Background(), store.LifecycleStartInput{
				Kind: "deactivate", TenantID: tenantAcmeID, IdentityID: ident.ID,
				MemberID: memberID, SessionID: sessionID, IDPID: idpAcmeSelfID,
				Issuer: ident.Issuer, Subject: ident.Subject, Reason: "concurrent",
				IdempotencyKey: key, Token: "tok-" + uuid.NewString(),
			})
			results[i], errs[i] = r, err
		}(i)
	}
	wg.Wait()

	created := 0
	var token string
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent start #%d err=%v", i, err)
		}
		if results[i].Created {
			created++
			token = results[i].Session.Token
		}
	}
	if created != 1 {
		t.Fatalf("created sessions=%d, want exactly 1", created)
	}
	for i, r := range results {
		if r.Session == nil || r.Session.Token != token {
			t.Fatalf("start #%d returned different/nil session: %+v", i, r)
		}
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM lifecycle_sessions WHERE identity_id=$1`, ident.ID); n != 1 {
		t.Fatalf("lifecycle_sessions=%d, want 1", n)
	}
	if n := countRows(t, env, `SELECT count(*) FROM identity_lifecycle_events`); n != 0 {
		t.Fatalf("events before proof=%d, want 0 (start must not finalize)", n)
	}
}

// TestCompleteLifecycleRejectsStaleAndDuplicateProofs 并发完成同一停用挑战：
// 只有一个能翻状态并写历史；其余因 state 不匹配/会话非 pending 被拒。
func TestCompleteLifecycleRejectsStaleAndDuplicateProofs(t *testing.T) {
	env := startEnv(t)
	memberID, ident := seedMemberWithIdentity(t, env, "active")
	secondID := uuid.New()
	if _, err := env.store.DB().Exec(context.Background(),
		`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified, status)
		 VALUES ($1,$2,$3,$4,'second-sub','d@example.com',true,'active')`,
		secondID, tenantAcmeID, memberID, issuer("globex")); err != nil {
		t.Fatalf("insert second identity: %v", err)
	}
	sessionID := uuid.New()
	if _, err := env.store.DB().Exec(context.Background(),
		`INSERT INTO sessions(id, tenant_id, member_id, token_hash, expires_at)
		 VALUES ($1,$2,$3,$4, now()+interval '1 hour')`,
		sessionID, tenantAcmeID, memberID, []byte("h-"+sessionID.String())); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	tok := "duplicate-proof-token"
	if _, err := env.store.DB().Exec(context.Background(),
		`INSERT INTO lifecycle_sessions
		 (token, tenant_id, identity_id, member_id, session_id, idp_id, kind,
		  issuer, subject, reason, idempotency_key, pending_state, status, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,'deactivate',$7,$8,'r','idem-dup','the-state','pending',
		         now()+interval '10 min', now())`,
		tok, tenantAcmeID, ident.ID, memberID, sessionID, idpAcmeSelfID,
		ident.Issuer, ident.Subject); err != nil {
		t.Fatalf("insert lifecycle session: %v", err)
	}

	now := time.Now()
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = env.store.CompleteLifecycle(context.Background(), store.LifecycleProof{
				Token: tok, State: "the-state", Issuer: ident.Issuer, Subject: ident.Subject,
				AuthTime: now, MaxAge: 300 * time.Second, Now: now,
				ReactivateCooldown: 0, ReactivateTTL: time.Hour,
			})
		}(i)
	}
	wg.Wait()

	ok, rejected := 0, 0
	for i, err := range errs {
		switch err {
		case nil:
			ok++
		case store.ErrConflict:
			rejected++
		default:
			t.Fatalf("complete #%d unexpected err=%v", i, err)
		}
	}
	if ok != 1 || rejected != n-1 {
		t.Fatalf("complete results: ok=%d rejected=%d, want ok=1 rejected=%d", ok, rejected, n-1)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identity_lifecycle_events WHERE identity_id=$1 AND action='deactivated'`,
		ident.ID); n != 1 {
		t.Fatalf("deactivated events=%d, want exactly 1", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identities WHERE id=$1 AND status='deactivated'`, ident.ID); n != 1 {
		t.Fatalf("identity not deactivated")
	}
	// 另一身份仍 active，成员仍可登录，未被连带停用。
	if n := countRows(t, env,
		`SELECT count(*) FROM identities WHERE id=$1 AND status='active'`, secondID); n != 1 {
		t.Fatalf("second identity should remain active")
	}
}
