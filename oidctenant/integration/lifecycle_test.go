package integration

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// 本文件覆盖“身份停用与恢复”生命周期的验收用例：
//
//  1. 有两个身份的成员成功停用其中一个：该身份不能再建立会话，另一身份仍可登录；
//  2. 试图停用唯一身份被明确拒绝，数据不变；
//  3. 同一停用请求重放只产生一个终态与一条可查询历史；
//  4. 停用过程中延迟到达的旧登录/关联回调不会恢复该身份；
//  5. 窗口内恢复后重新认证可用，窗口外恢复被拒绝；
//  6. 不同租户同邮箱身份互不影响。

var (
	kcAcmeAlice = keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}
	kcAcmeCarol = keycloakUser{realm: "acme", username: "carol", password: "carol-pass"}
	kcGlobexBob = keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"}
	kcGlobexA   = keycloakUser{realm: "globex", username: "alice.globex", password: "aliceg-pass"}
)

// linkAliceAndBob 让浏览器中的成员拥有 acme-alice 与 globex-bob 两条身份，
// 返回成员 ID 与两个身份的 subject。
func linkAliceAndBob(t *testing.T, b *browserClient) (memberID, acmeSub, globexSub string) {
	respA := b.login("acme", kcAcmeAlice)
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()
	memberID = b.memberID("acme")
	acmeSub = findIdentitySubject(t, b.identities("acme"), issuer("acme"))

	_, linkURL := b.startLink("acme", issuer("globex"))
	cb := b.finishLink(linkURL, kcGlobexBob)
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("setup link failed status=%d body=%s", cb.StatusCode, mustBody(t, cb))
	}
	_ = cb.Body.Close()
	globexSub = findIdentitySubject(t, b.identities("acme"), issuer("globex"))
	return memberID, acmeSub, globexSub
}

// deactivateIdentity 完成“发起 + 强制重认证”整个停用流程（沿用浏览器自带 KC 会话）。
func deactivateIdentity(t *testing.T, b *browserClient, tenantSlug, iss, sub, reason string,
	proof keycloakUser, idemKey ...string) map[string]any {
	t.Helper()
	status, out := b.startDeactivation(tenantSlug, iss, sub, reason, idemKey...)
	if status != http.StatusCreated {
		t.Fatalf("start deactivation status=%d body=%v, want 201", status, out)
	}
	cb := b.finishLifecycle(out["auth_url"].(string), proof)
	body := readBody(t, cb)
	if cb.StatusCode != http.StatusOK || body["status"] != "deactivated" {
		t.Fatalf("deactivation callback status=%d body=%v, want 200 deactivated", cb.StatusCode, body)
	}
	_ = cb.Body.Close()
	return body
}

// deactivateIdentityFreshKC 同 deactivateIdentity，但用全新 Keycloak SSO 上下文完成证明，
// 避免与浏览器内已有的同 realm 不同用户 SSO 会话冲突。
func deactivateIdentityFreshKC(t *testing.T, b *browserClient, tenantSlug, iss, sub, reason string,
	proof keycloakUser) map[string]any {
	t.Helper()
	status, out := b.startDeactivation(tenantSlug, iss, sub, reason)
	if status != http.StatusCreated {
		t.Fatalf("start deactivation status=%d body=%v, want 201", status, out)
	}
	cb := b.finishLifecycleFreshKC(out["auth_url"].(string), proof)
	body := readBody(t, cb)
	if cb.StatusCode != http.StatusOK || body["status"] != "deactivated" {
		t.Fatalf("fresh-KC deactivation callback status=%d body=%v, want 200 deactivated",
			cb.StatusCode, body)
	}
	_ = cb.Body.Close()
	return body
}

// reactivateIdentity 完成“发起恢复 + 强制重认证”。
func reactivateIdentity(t *testing.T, b *browserClient, tenantSlug, iss, sub string,
	proof keycloakUser) map[string]any {
	t.Helper()
	status, out := b.startReactivation(tenantSlug, iss, sub)
	if status != http.StatusCreated {
		t.Fatalf("start reactivation status=%d body=%v, want 201", status, out)
	}
	cb := b.finishLifecycle(out["auth_url"].(string), proof)
	body := readBody(t, cb)
	if cb.StatusCode != http.StatusOK || body["status"] != "reactivated" ||
		body["identity_status"] != "active" {
		t.Fatalf("reactivation callback status=%d body=%v, want 200 reactivated/active",
			cb.StatusCode, body)
	}
	_ = cb.Body.Close()
	return body
}

// TestDeactivateOneOfTwoIdentities 验收 1：
// 停用 globex-bob 身份后，该身份不能再建立会话，另一身份仍可登录，归属历史保留。
func TestDeactivateOneOfTwoIdentities(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	memberID, _, globexSub := linkAliceAndBob(t, b)

	reason := "employee trust revoked for globex identity"
	body := deactivateIdentity(t, b, "acme", issuer("globex"), globexSub, reason, kcGlobexBob)
	if body["identity_status"] != "deactivated" {
		t.Fatalf("identity_status=%v, want deactivated", body["identity_status"])
	}

	ids := b.identities("acme")
	if got := identityStatusOf(t, ids, issuer("globex")); got != "deactivated" {
		t.Fatalf("globex identity status=%s, want deactivated", got)
	}
	if got := identityStatusOf(t, ids, issuer("acme")); got != "active" {
		t.Fatalf("acme identity status=%s, want active", got)
	}

	// 历史保留 issuer/subject/原因/时间。
	hist := b.identityHistory("acme", issuer("globex"), globexSub, http.StatusOK)
	events := hist["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("history events=%d, want 1", len(events))
	}
	ev := events[0].(map[string]any)
	if ev["action"] != "deactivated" || ev["reason"] != reason ||
		ev["issuer"] != issuer("globex") || ev["subject"] != globexSub {
		t.Fatalf("history event mismatch: %v", ev)
	}
	if ev["created_at"] == "" || ev["proven_auth_time"] == "" {
		t.Fatalf("history event missing timestamps: %v", ev)
	}

	// 被停用身份在“acme 租户视角”下登录：403 identity_deactivated，不建立会话。
	stale := newBrowserClient(t)
	loginResp := stale.login("acme", kcGlobexBob)
	lb := readBody(t, loginResp)
	if loginResp.StatusCode != http.StatusForbidden || lb["error"] != "identity_deactivated" {
		t.Fatalf("deactivated-identity login status=%d body=%v, want 403 identity_deactivated",
			loginResp.StatusCode, lb)
	}
	meResp, err := stale.app.Get(appBaseURL + "/t/acme/api/me")
	if err != nil {
		t.Fatalf("me after blocked login: %v", err)
	}
	if meResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me status=%d, want 401 (no session established)", meResp.StatusCode)
	}
	_ = meResp.Body.Close()

	// 另一身份 acme-alice 仍可登录，并仍归属同一成员。
	other := newBrowserClient(t)
	resp := other.login("acme", kcAcmeAlice)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("other-identity login status=%d, want 302", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if id := other.memberID("acme"); id != memberID {
		t.Fatalf("other-identity login resolved to member %s, want original %s", id, memberID)
	}

	// 归属不被删除：成员 1 个、身份 2 条。
	if n := countRows(t, env, `SELECT count(*) FROM members WHERE id=$1`, memberID); n != 1 {
		t.Fatalf("members=%d, want 1 (history preserved)", n)
	}
	if n := countRows(t, env, `SELECT count(*) FROM identities WHERE member_id=$1`, memberID); n != 2 {
		t.Fatalf("identities=%d, want 2 (rows preserved)", n)
	}
}

// TestCannotDeactivateLastIdentity 验收 2：唯一身份停用被明确拒绝且数据不变。
func TestCannotDeactivateLastIdentity(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	resp := b.login("acme", kcAcmeCarol)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	sub := findIdentitySubject(t, b.identities("acme"), issuer("acme"))

	status, out := b.startDeactivation("acme", issuer("acme"), sub, "trying to kill the only identity")
	if status != http.StatusConflict || out["error"] != "last_active_identity" {
		t.Fatalf("last-identity deactivation status=%d body=%v, want 409 last_active_identity",
			status, out)
	}

	if got := identityStatusOf(t, b.identities("acme"), issuer("acme")); got != "active" {
		t.Fatalf("identity status=%s, want active (unchanged)", got)
	}
	if n := countRows(t, env, `SELECT count(*) FROM identity_lifecycle_events`); n != 0 {
		t.Fatalf("lifecycle events=%d, want 0", n)
	}
	if n := countRows(t, env, `SELECT count(*) FROM lifecycle_sessions`); n != 0 {
		t.Fatalf("lifecycle_sessions=%d, want 0", n)
	}
	if n := countRows(t, env, `SELECT count(*) FROM auth_requests WHERE consumed_at IS NULL`); n != 0 {
		t.Fatalf("open auth_requests=%d, want 0", n)
	}

	// 该身份仍可正常登录。
	again := newBrowserClient(t)
	r := again.login("acme", kcAcmeCarol)
	if r.StatusCode != http.StatusFound {
		t.Fatalf("login after rejected deactivation status=%d, want 302", r.StatusCode)
	}
	_ = r.Body.Close()
}

// TestDeactivationRequestReplayIsIdempotent 验收 3：
// 同一幂等键重放取回同一挑战；终态后重放仍是同一终态；历史只有一条。
func TestDeactivationRequestReplayIsIdempotent(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)

	idem := "fixed-deactivation-key-2026"
	st1, o1 := b.startDeactivation("acme", issuer("globex"), globexSub, "replay test", idem)
	if st1 != http.StatusCreated {
		t.Fatalf("first start status=%d body=%v, want 201", st1, o1)
	}
	tok1 := o1["lifecycle_token"].(string)
	url1 := o1["auth_url"].(string)

	st2, o2 := b.startDeactivation("acme", issuer("globex"), globexSub, "replay test", idem)
	if st2 != http.StatusOK {
		t.Fatalf("replayed start status=%d body=%v, want 200", st2, o2)
	}
	if o2["lifecycle_token"] != tok1 || o2["auth_url"] != url1 {
		t.Fatalf("replay created a second challenge: %v vs %v", o2, o1)
	}

	cb := b.finishLifecycle(url1, kcGlobexBob)
	body := readBody(t, cb)
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("complete status=%d body=%v", cb.StatusCode, body)
	}
	_ = cb.Body.Close()

	st3, o3 := b.startDeactivation("acme", issuer("globex"), globexSub, "replay test", idem)
	if st3 != http.StatusOK || o3["status"] != "deactivated" {
		t.Fatalf("post-terminal replay status=%d body=%v, want 200 deactivated", st3, o3)
	}

	if n := countRows(t, env,
		`SELECT count(*) FROM identity_lifecycle_events WHERE action='deactivated'`); n != 1 {
		t.Fatalf("deactivated events=%d, want exactly 1", n)
	}
	if n := countRows(t, env, `SELECT count(*) FROM lifecycle_sessions`); n != 1 {
		t.Fatalf("lifecycle sessions=%d, want 1", n)
	}
}

// TestHeldLoginCallbackDoesNotReactivate 验收 4a：
// 身份停用后才到达的旧登录回调必须停在状态边界，不能建立会话或复活身份。
func TestHeldLoginCallbackDoesNotReactivate(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)
	deactivateIdentity(t, b, "acme", issuer("globex"), globexSub, "held callback test", kcGlobexBob)

	// 停用之后才从 IdP 取得一个 globex-bob 的登录回调（全新浏览器/全新 SSO）。
	startURL := appBaseURL + "/t/acme/login?issuer=" + issuer("globex")
	stale := newBrowserClient(t)
	kcAuthURL := stale.appStartRedirectsToKeycloak(startURL)
	heldCallback := heldKCLogin(t, kcAuthURL, kcGlobexBob)

	resp := stale.deliverCallback(heldCallback)
	lb := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden || lb["error"] != "identity_deactivated" {
		t.Fatalf("held login callback status=%d body=%v, want 403 identity_deactivated",
			resp.StatusCode, lb)
	}

	var status string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT status FROM identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, issuer("globex"), globexSub).Scan(&status); err != nil {
		t.Fatalf("load identity status: %v", err)
	}
	if status != "deactivated" {
		t.Fatalf("identity status=%s after held callback, want deactivated", status)
	}
	if n := countRows(t, env, `SELECT count(*) FROM members`); n != 1 {
		t.Fatalf("members=%d, want 1 (no duplicate from held callback)", n)
	}
}

// TestHeldLinkCallbackDoesNotReactivate 验收 4b：
// 关联 B 已重认证、回调延迟到达期间锚点身份被停用，迟到的关联回调必须被拒绝，
// 不能完成绑定，也不能复活身份。
func TestHeldLinkCallbackDoesNotReactivate(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, acmeSub, _ := linkAliceAndBob(t, b)

	// 再发起一次关联，目标为 globex/alice.globex（与 bob 不同），仅在 KC 侧完成 B 重认证。
	_, linkURL := b.startLink("acme", issuer("globex"), map[string]string{
		"anchor_issuer": issuer("acme"),
	})
	held := heldKCLogin(t, linkURL, kcGlobexA)

	// 在关联回调到达前，停用 A 锚点 acme-alice（成员仍持有 active 的 globex-bob）。
	// 用全新 KC SSO 上下文完成 acme 重认证，避免与 globex SSO 会话相互影响。
	deactivateIdentityFreshKC(t, b, "acme", issuer("acme"), acmeSub,
		"anchor disabled mid-link", kcAcmeAlice)

	resp := b.deliverCallback(held)
	lb := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden || lb["error"] != "identity_deactivated" {
		t.Fatalf("held link callback status=%d body=%v, want 403 identity_deactivated",
			resp.StatusCode, lb)
	}

	// 目标 alice.globex 不应被绑定进 acme 租户（邮箱在 acme 视角唯一标识该 B 身份）。
	if n := countRows(t, env,
		`SELECT count(*) FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND email='alice@example.com'`,
		tenantAcmeID, issuer("globex")); n != 0 {
		t.Fatalf("held link target rows=%d, want 0 (must not bind)", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identities WHERE tenant_id=$1`, tenantAcmeID); n != 2 {
		t.Fatalf("acme identities=%d, want 2 (1 active + 1 deactivated)", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identities
		 WHERE tenant_id=$1 AND status='active'`, tenantAcmeID); n != 1 {
		t.Fatalf("active acme identities=%d, want 1", n)
	}
}

// TestReactivateWithinWindowSucceeds 验收 5a：窗口内恢复后重新认证可用，
// 且停用与恢复是两条历史，恢复没有覆写停用记录。
func TestReactivateWithinWindowSucceeds(t *testing.T) {
	startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)
	deactivateIdentity(t, b, "acme", issuer("globex"), globexSub, "temp disable", kcGlobexBob)

	reactivateIdentity(t, b, "acme", issuer("globex"), globexSub, kcGlobexBob)

	if got := identityStatusOf(t, b.identities("acme"), issuer("globex")); got != "active" {
		t.Fatalf("post-reactivate status=%s, want active", got)
	}

	hist := b.identityHistory("acme", issuer("globex"), globexSub, http.StatusOK)
	events := hist["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("events=%d, want 2 (deactivate record must survive reactivation)", len(events))
	}
	if events[0].(map[string]any)["action"] != "deactivated" ||
		events[1].(map[string]any)["action"] != "reactivated" {
		t.Fatalf("event order mismatch: %v", events)
	}

	// 恢复后该身份可重新登录并建立会话。
	fresh := newBrowserClient(t)
	resp := fresh.login("acme", kcGlobexBob)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("post-reactivate login status=%d, want 302", resp.StatusCode)
	}
	_ = resp.Body.Close()
	_ = fresh.memberID("acme")
}

// TestOldDeactivationKeyAfterReactivationReflectsCurrentState：
// 停用→恢复后，重放旧的停用幂等键不应给出过期的 "deactivated" 结论，
// 而应反映身份当前 active 状态，且不产生任何新会话/事件。
func TestOldDeactivationKeyAfterReactivationReflectsCurrentState(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)
	idem := "old-deact-key"
	deactivateIdentity(t, b, "acme", issuer("globex"), globexSub, "cycle", kcGlobexBob, idem)
	reactivateIdentity(t, b, "acme", issuer("globex"), globexSub, kcGlobexBob)

	st, out := b.startDeactivation("acme", issuer("globex"), globexSub, "cycle", idem)
	if st != http.StatusOK {
		t.Fatalf("replay old key status=%d body=%v, want 200", st, out)
	}
	if out["status"] != "active" {
		t.Fatalf("replayed old deactivation key status=%v, want current 'active'", out["status"])
	}
	// 只有一条 deactivated 和一条 reactivated 历史，重放不新增。
	if n := countRows(t, env, `SELECT count(*) FROM identity_lifecycle_events`); n != 2 {
		t.Fatalf("events=%d, want 2 (replay must not append)", n)
	}
	if n := countRows(t, env, `SELECT count(*) FROM lifecycle_sessions`); n != 2 {
		t.Fatalf("lifecycle_sessions=%d, want 2 (one per operation)", n)
	}
}

// TestReactivateOutsideWindowRejected 验收 5b：窗口关闭后恢复被拒绝且不可登录。
func TestReactivateOutsideWindowRejected(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)
	deactivateIdentity(t, b, "acme", issuer("globex"), globexSub, "window test", kcGlobexBob)

	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE identities
		 SET reactivate_after = now() - interval '2 hour',
		     reactivate_until = now() - interval '1 hour'
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, issuer("globex"), globexSub); err != nil {
		t.Fatalf("move recovery window to past: %v", err)
	}

	st, out := b.startReactivation("acme", issuer("globex"), globexSub)
	if st != http.StatusConflict || out["error"] != "recovery_window_closed" {
		t.Fatalf("out-of-window reactivation status=%d body=%v, want 409 recovery_window_closed",
			st, out)
	}
	if n := countRows(t, env, `SELECT count(*) FROM identity_lifecycle_events
		WHERE action='reactivated'`); n != 0 {
		t.Fatalf("reactivated events=%d, want 0", n)
	}
	if got := identityStatusOf(t, b.identities("acme"), issuer("globex")); got != "deactivated" {
		t.Fatalf("identity status=%s, want still deactivated", got)
	}

	// 窗口外仍不能登录。
	stale := newBrowserClient(t)
	resp := stale.login("acme", kcGlobexBob)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login outside window status=%d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestRecoveryCooldownNotYetOpen 验收 5c：冷却期未到不能发起恢复。
func TestRecoveryCooldownNotYetOpen(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)
	deactivateIdentity(t, b, "acme", issuer("globex"), globexSub, "cooldown test", kcGlobexBob)

	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE identities
		 SET reactivate_after = now() + interval '1 hour',
		     reactivate_until = now() + interval '1 day'
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, issuer("globex"), globexSub); err != nil {
		t.Fatalf("set future cooldown: %v", err)
	}
	st, out := b.startReactivation("acme", issuer("globex"), globexSub)
	if st != http.StatusConflict || out["error"] != "recovery_window_closed" {
		t.Fatalf("cooldown reactivation status=%d body=%v, want 409 recovery_window_closed", st, out)
	}
	if got := identityStatusOf(t, b.identities("acme"), issuer("globex")); got != "deactivated" {
		t.Fatalf("status=%s, want deactivated", got)
	}
}

// TestCrossTenantSameEmailLifecycleIsolation 验收 6：
// 在 acme 租户停用某身份，不影响 globex 租户下相同邮箱的独立身份，
// 也不能用 globex 的会话跨租户操作 acme 的身份。
func TestCrossTenantSameEmailLifecycleIsolation(t *testing.T) {
	env := startEnv(t)

	// acme 成员：alice(acme) 关联 alice.globex(globex)，两条身份同邮箱。
	acmeB := newBrowserClient(t)
	respA := acmeB.login("acme", kcAcmeAlice)
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()
	_, linkURL := acmeB.startLink("acme", issuer("globex"))
	cb := acmeB.finishLink(linkURL, kcGlobexA)
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("setup link status=%d body=%s", cb.StatusCode, mustBody(t, cb))
	}
	_ = cb.Body.Close()
	globexSubInAcme := findIdentitySubject(t, acmeB.identities("acme"), issuer("globex"))

	// globex 租户自己的同名成员（同邮箱、不同锚点）。
	globexB := newBrowserClient(t)
	respG := globexB.login("globex", kcGlobexA)
	_, _ = io.Copy(io.Discard, respG.Body)
	_ = respG.Body.Close()
	globexOwnSub := findIdentitySubject(t, globexB.identities("globex"), issuer("globex"))
	// 同一个 Keycloak 用户被两个租户各自核实时 subject 可以相同 ——
	// 身份锚点的隔离维度是 tenant_id（从而 member 不同），而不是 subject。
	acmeMemberID := acmeB.memberID("acme")
	globexMemberID := globexB.memberID("globex")
	if acmeMemberID == globexMemberID {
		t.Fatalf("members collapsed across tenants: %s", acmeMemberID)
	}
	_ = globexOwnSub

	// 停用 acme 视角下的 globex 身份（KC 会话已以 alice.globex 登录，重认证同人）。
	deactivateIdentity(t, acmeB, "acme", issuer("globex"), globexSubInAcme,
		"cross-tenant isolation test", kcGlobexA)

	// globex 租户自己的同邮箱身份仍 active 且可登录。
	if got := identityStatusOf(t, globexB.identities("globex"), issuer("globex")); got != "active" {
		t.Fatalf("globex own identity status=%s, want active (must be unaffected)", got)
	}
	freshGlobex := newBrowserClient(t)
	r := freshGlobex.login("globex", kcGlobexA)
	if r.StatusCode != http.StatusFound {
		t.Fatalf("globex own identity login status=%d, want 302 (unaffected)", r.StatusCode)
	}
	_ = r.Body.Close()

	// acme 视角下被停用身份登录被拒。
	blocked := newBrowserClient(t)
	rb := blocked.login("acme", kcGlobexA)
	if rb.StatusCode != http.StatusForbidden {
		t.Fatalf("acme-view deactivated login status=%d, want 403", rb.StatusCode)
	}
	_ = rb.Body.Close()

	// 跨租户操作：globex 会话尝试停用一个只存在于 acme 视角的锚点 -> 404（不泄露存在性）。
	st, out := globexB.startDeactivation("globex", issuer("acme"),
		findIdentitySubject(t, acmeB.identities("acme"), issuer("acme")),
		"cross-tenant attempt")
	if st != http.StatusNotFound || out["error"] != "not_found" {
		t.Fatalf("cross-tenant deactivation status=%d body=%v, want 404 not_found", st, out)
	}

	if n := countRows(t, env,
		`SELECT count(*) FROM identity_lifecycle_events WHERE tenant_id=$1 AND action='deactivated'`,
		tenantAcmeID); n != 1 {
		t.Fatalf("acme deactivated events=%d, want 1", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identity_lifecycle_events WHERE tenant_id=$1`,
		tenantGlobexID); n != 0 {
		t.Fatalf("globex lifecycle events=%d, want 0", n)
	}
}

// TestDeactivationReasonRequired 停用必须给出原因，否则 400 且无任何状态产生。
func TestDeactivationReasonRequired(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	resp := b.login("acme", kcAcmeAlice)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	sub := findIdentitySubject(t, b.identities("acme"), issuer("acme"))

	st, out := b.startDeactivation("acme", issuer("acme"), sub, "   ")
	if st != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Fatalf("blank reason status=%d body=%v, want 400 invalid_request", st, out)
	}
	if n := countRows(t, env, `SELECT count(*) FROM lifecycle_sessions`); n != 0 {
		t.Fatalf("lifecycle_sessions=%d, want 0", n)
	}
}
