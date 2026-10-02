package integration

import (
	"io"
	"net/http"
	"testing"
)

// TestDeactivationRequiresCompletedProof 停用必须在“针对该身份完成新的 OIDC 证明”
// 之后才生效：仅发起挑战（不完成回调）绝不改变身份状态。
func TestDeactivationRequiresCompletedProof(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)

	// 只发起、不完成证明。
	st, out := b.startDeactivation("acme", issuer("globex"), globexSub,
		"proof not completed test")
	if st != http.StatusCreated || out["status"] != "pending" {
		t.Fatalf("start status=%d body=%v, want 201 pending", st, out)
	}

	// 身份仍 active，没有任何历史终态。
	if got := identityStatusOf(t, b.identities("acme"), issuer("globex")); got != "active" {
		t.Fatalf("identity status=%s after mere start, want active", got)
	}
	if n := countRows(t, env, `SELECT count(*) FROM identity_lifecycle_events`); n != 0 {
		t.Fatalf("events=%d, want 0 (no terminal state before proof)", n)
	}

	// 未完成停用前，该身份仍可正常登录。
	fresh := newBrowserClient(t)
	resp := fresh.login("acme", kcGlobexBob)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login while challenge pending status=%d, want 302", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// TestReactivationRequiresCompletedProof 恢复同样必须完成新证明：
// 仅发起恢复但不完成回调，身份保持 deactivated。
func TestReactivationRequiresCompletedProof(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)
	deactivateIdentity(t, b, "acme", issuer("globex"), globexSub, "reactivate proof test", kcGlobexBob)

	st, out := b.startReactivation("acme", issuer("globex"), globexSub)
	if st != http.StatusCreated || out["status"] != "pending" {
		t.Fatalf("start reactivation status=%d body=%v, want 201 pending", st, out)
	}
	if got := identityStatusOf(t, b.identities("acme"), issuer("globex")); got != "deactivated" {
		t.Fatalf("identity status=%s after mere reactivation start, want deactivated", got)
	}
	if n := countRows(t, env, `SELECT count(*) FROM identity_lifecycle_events WHERE action='reactivated'`); n != 0 {
		t.Fatalf("reactivated events=%d, want 0 (proof not completed)", n)
	}
}

// TestLifecycleProofMustMatchTargetIdentity 恢复证明必须精确证明目标身份本人：
// 用同一 issuer 下的另一个 subject（globex/bob）去为 globex/alice.globex 的恢复作证，
// 必须被拒绝，身份保持 deactivated（不接受同租户同邮箱或同 issuer 的别的身份顶替）。
func TestLifecycleProofMustMatchTargetIdentity(t *testing.T) {
	env := startEnv(t)

	// 成员先拥有 acme/alice 与 globex/alice.globex 两条身份（同邮箱 alice@example.com）。
	b := newBrowserClient(t)
	resp := b.login("acme", kcAcmeAlice)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_, linkURL := b.startLink("acme", issuer("globex"))
	cb := b.finishLink(linkURL, kcGlobexA)
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("setup link status=%d body=%s", cb.StatusCode, mustBody(t, cb))
	}
	_ = cb.Body.Close()
	targetSub := findIdentitySubject(t, b.identities("acme"), issuer("globex"))

	// 停用该 globex/alice.globex 身份（证明人就是本人）。
	deactivateIdentity(t, b, "acme", issuer("globex"), targetSub, "wrong proof test", kcGlobexA)

	// 发起对该身份的恢复，却用同 issuer 下不同 subject 的 globex/bob 完成证明。
	st, out := b.startReactivation("acme", issuer("globex"), targetSub)
	if st != http.StatusCreated {
		t.Fatalf("start reactivation status=%d body=%v", st, out)
	}
	cb2 := b.finishLifecycleFreshKC(out["auth_url"].(string), kcGlobexBob)
	body := readBody(t, cb2)
	if cb2.StatusCode != http.StatusUnauthorized || body["error"] != "reauthentication_required" {
		t.Fatalf("wrong-subject proof status=%d body=%v, want 401 reauthentication_required",
			cb2.StatusCode, body)
	}
	_ = cb2.Body.Close()

	if got := identityStatusOf(t, b.identities("acme"), issuer("globex")); got != "deactivated" {
		t.Fatalf("identity status=%s after wrong proof, want deactivated", got)
	}
	if n := countRows(t, env, `SELECT count(*) FROM identity_lifecycle_events WHERE action='reactivated'`); n != 0 {
		t.Fatalf("reactivated events=%d, want 0", n)
	}
}

// TestLifecycleCallbackStateIsOneTime 生命周期回调的 state 一次性：
// 同一回调 URL 重放必须被拒绝，不能二次完成或改写历史。
func TestLifecycleCallbackStateIsOneTime(t *testing.T) {
	env := startEnv(t)
	b := newBrowserClient(t)
	_, _, globexSub := linkAliceAndBob(t, b)

	st, out := b.startDeactivation("acme", issuer("globex"), globexSub, "state one-time test")
	if st != http.StatusCreated {
		t.Fatalf("start status=%d body=%v", st, out)
	}
	callbackURL := heldKCLogin(t, out["auth_url"].(string), kcGlobexBob)

	first := b.deliverCallback(callbackURL)
	fb := readBody(t, first)
	if first.StatusCode != http.StatusOK || fb["status"] != "deactivated" {
		t.Fatalf("first lifecycle callback status=%d body=%v, want 200 deactivated",
			first.StatusCode, fb)
	}
	_ = first.Body.Close()

	second := b.deliverCallback(callbackURL)
	sb := readBody(t, second)
	if second.StatusCode != http.StatusBadRequest || sb["error"] != "invalid_request" {
		t.Fatalf("replayed lifecycle callback status=%d body=%v, want 400 invalid_request",
			second.StatusCode, sb)
	}
	_ = second.Body.Close()

	if n := countRows(t, env, `SELECT count(*) FROM identity_lifecycle_events`); n != 1 {
		t.Fatalf("events=%d after replay, want 1", n)
	}
}
