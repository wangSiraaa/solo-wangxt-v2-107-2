package integration

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/store"
)

// startLinkViaAPI 调用 POST /api/links，返回 {"link_token","link_url"}。
// 本地用例一律以成员的 acme 身份为锚点关联 globex。
func startLinkViaAPI(t *testing.T, c *flowClient, slug, targetIssuer string) map[string]any {
	t.Helper()
	resp := c.post(c.env.baseURL+"/t/"+slug+"/api/links",
		map[string]string{"issuer": targetIssuer, "anchor_issuer": c.env.acme.issuer}, "")
	body := decodeBody(resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("start link status=%d body=%v", resp.StatusCode, body)
	}
	return body
}

// lifecycleResp 是停用/恢复发起接口的响应。
type lifecycleResp struct {
	status int
	body   map[string]any
}

func startLifecycle(t *testing.T, c *flowClient, slug, action string,
	body map[string]string, idemKey string) lifecycleResp {
	t.Helper()
	resp := c.post(c.env.baseURL+"/t/"+slug+"/api/identities/"+action, body, idemKey)
	return lifecycleResp{status: resp.StatusCode, body: decodeBody(resp)}
}

// completeIdPFlow 从 fake IdP 授权 URL 开始（已是 IdP 地址），选定用户发码并打应用回调。
func (c *flowClient) completeIdPFlow(idp *fakeOIDC, userKey, idpAuthURL string) *http.Response {
	idp.setCurrentUser(userKey)
	resp := c.get(idpAuthURL)
	cbLoc := resp.Header.Get("Location")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || cbLoc == "" {
		c.t.Fatalf("fake idp /auth status=%d loc=%q, want 302", resp.StatusCode, cbLoc)
	}
	return c.get(cbLoc)
}

func drainResp(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

func proveLifecycle(t *testing.T, c *flowClient, idp *fakeOIDC, userKey string, lr lifecycleResp) *http.Response {
	t.Helper()
	proofURL, _ := lr.body["proof_url"].(string)
	if proofURL == "" {
		t.Fatalf("no proof_url in lifecycle response: %v", lr.body)
	}
	return c.completeIdPFlow(idp, userKey, proofURL)
}

func identityStatuses(me map[string]any) map[string]string {
	out := map[string]string{}
	for _, raw := range me["identities"].([]any) {
		m := raw.(map[string]any)
		out[m["issuer"].(string)+"|"+m["subject"].(string)] = m["status"].(string)
	}
	return out
}

func dbIdentityStatus(t *testing.T, env *localEnv, tenantID uuid.UUID, issuer, subject string) string {
	t.Helper()
	var status string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT status FROM identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantID, issuer, subject).Scan(&status); err != nil {
		t.Fatalf("db identity status: %v", err)
	}
	return status
}

func dbCount(t *testing.T, env *localEnv, query string, args ...any) int {
	t.Helper()
	var n int
	if err := env.store.DB().QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("dbCount: %v", err)
	}
	return n
}

// TestDeactivateOneOfTwoIdentities 验收：
// 有两个身份的成员成功停用其中一个后，该身份不能再创建会话，而另一身份仍可登录。
func TestDeactivateOneOfTwoIdentities(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)
	browser := newFlowClient(t, env)

	// 成员先用 acme/alice 登录，再关联 globex/bob，得到两条身份。
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("initial login status=%d body=%v", resp.StatusCode, decodeBody(resp))
	}
	link := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	cb := browser.completeIdPFlow(env.globex, "bob", link["link_url"].(string))
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("link bob status=%d body=%v", cb.StatusCode, decodeBody(cb))
	}
	if len(browser.me("acme")["identities"].([]any)) != 2 {
		t.Fatalf("precondition: member should have 2 identities")
	}

	// 停用 globex/bob：必须用该身份完成一次新的 OIDC 证明才进入 disabled。
	lr := startLifecycle(t, browser, "acme", "deactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
		"reason": "employee no longer trusts this external identity",
	}, "deact-bob-1")
	if lr.status != http.StatusCreated {
		t.Fatalf("deactivate start status=%d body=%v", lr.status, lr.body)
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-bob-sub"); got != "deactivation_pending" {
		t.Fatalf("status after start=%s, want deactivation_pending", got)
	}
	if pr := proveLifecycle(t, browser, env.globex, "bob", lr); pr.StatusCode != http.StatusOK {
		t.Fatalf("deactivate proof status=%d body=%v", pr.StatusCode, decodeBody(pr))
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-bob-sub"); got != "disabled" {
		t.Fatalf("status after proof=%s, want disabled", got)
	}

	// 被停用身份不能再创建会话：全新浏览器走完整登录（新 state+新 code）也必须 403，
	// 且不得下发新的 sid 会话 Cookie。
	attacker := newFlowClient(t, env)
	resp := attacker.login("acme", "globex", "bob")
	body := decodeBody(resp)
	if resp.StatusCode != http.StatusForbidden || body["error"] != "identity_disabled" {
		t.Fatalf("disabled identity login status=%d body=%v, want 403 identity_disabled",
			resp.StatusCode, body)
	}
	if cookies := resp.Cookies(); len(cookies) != 0 {
		for _, ck := range cookies {
			if ck.Name == "sid" {
				t.Fatalf("disabled identity login must not set a session cookie")
			}
		}
	}

	// 原会话在停用证明完成的同一事务里被吊销：停用立即生效，必须改用其它身份重新登录。
	if resp := browser.get(browser.env.baseURL + "/t/acme/api/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("originating session after deactivation status=%d, want 401 revoked", resp.StatusCode)
	}
	// 用仍可用的另一身份重新登录后，可以看到两条身份（一 active 一 disabled）。
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("re-login with sibling identity status=%d, want 302", resp.StatusCode)
	}
	statuses := identityStatuses(browser.me("acme"))
	if statuses[env.acme.issuer+"|acme-alice-sub"] != "active" {
		t.Fatalf("other identity status=%v, want active", statuses)
	}
	if statuses[env.globex.issuer+"|globex-bob-sub"] != "disabled" {
		t.Fatalf("deactivated identity status=%v, want disabled", statuses)
	}
	// 另一身份在全新浏览器同样可登录。
	other := newFlowClient(t, env)
	if resp := other.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("sibling identity login status=%d, want 302", resp.StatusCode)
	}
	if got := other.me("acme"); len(got["identities"].([]any)) != 2 {
		t.Fatalf("sibling session should still see both identities incl. disabled")
	}

	// 历史归属完整：成员/身份行都还在，member_id 未变。
	if n := dbCount(t, env, `SELECT count(*) FROM members WHERE id=
	     (SELECT member_id FROM identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3)`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("historical membership row missing")
	}
}

// TestCannotDeactivateLastIdentity 验收：唯一身份被明确拒绝且数据不变。
func TestCannotDeactivateLastIdentity(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)
	browser := newFlowClient(t, env)
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}

	lr := startLifecycle(t, browser, "acme", "deactivate", map[string]string{
		"issuer": env.acme.issuer, "subject": "acme-alice-sub",
		"reason": "should be rejected",
	}, "deact-last-1")
	if lr.status != http.StatusConflict || lr.body["error"] != "last_identity" {
		t.Fatalf("last identity deactivation status=%d body=%v, want 409 last_identity", lr.status, lr.body)
	}

	if got := dbIdentityStatus(t, env, localAcmeID, env.acme.issuer, "acme-alice-sub"); got != "active" {
		t.Fatalf("identity status=%s, want active (data must not change)", got)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identity_lifecycles`); n != 0 {
		t.Fatalf("identity_lifecycles rows=%d, want 0", n)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identity_events`); n != 0 {
		t.Fatalf("identity_events rows=%d, want 0", n)
	}
}

// TestDeactivationRequestReplaySingleTerminalState 验收：
// 同一停用请求重放只产生一个终态和可查询历史。
func TestDeactivationRequestReplaySingleTerminalState(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)
	browser := newFlowClient(t, env)
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	link := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	if cb := browser.completeIdPFlow(env.globex, "bob", link["link_url"].(string)); cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d", cb.StatusCode)
	}

	body := map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
		"reason": "replay check",
	}
	first := startLifecycle(t, browser, "acme", "deactivate", body, "idem-xyz")
	if first.status != http.StatusCreated {
		t.Fatalf("first start status=%d body=%v", first.status, first.body)
	}
	// 同幂等键立即重放：命中同一流程（200 + replay 标记），不得新建任何 state/流程。
	second := startLifecycle(t, browser, "acme", "deactivate", body, "idem-xyz")
	if second.status != http.StatusOK || second.body["replay"] != "true" {
		t.Fatalf("idempotent replay status=%d body=%v, want 200 replay", second.status, second.body)
	}
	if second.body["lifecycle_token"] != nil {
		t.Fatalf("replay must not mint a new lifecycle token: %v", second.body)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM auth_requests
	     WHERE kind='lifecycle' AND link_token IS NOT NULL`); n != 1 {
		t.Fatalf("lifecycle auth_requests=%d, want 1 (replay must not create state)", n)
	}
	// 不同幂等键在流程未完成时必须冲突，不能开第二个并行终态。
	other := startLifecycle(t, browser, "acme", "deactivate", body, "idem-other")
	if other.status != http.StatusConflict || other.body["error"] != "identity_lifecycle_conflict" {
		t.Fatalf("parallel lifecycle status=%d body=%v, want 409", other.status, other.body)
	}

	if pr := proveLifecycle(t, browser, env.globex, "bob", first); pr.StatusCode != http.StatusOK {
		t.Fatalf("proof status=%d body=%v", pr.StatusCode, decodeBody(pr))
	}
	// 完成回调重放：state 已消费，而且发起会话也已被吊销 —— 旧回调不可能再推进状态。
	replayProof := browser.completeIdPFlow(env.globex, "bob", first.body["proof_url"].(string))
	if replayProof.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed proof callback status=%d, want 401 (state used, session revoked)",
			replayProof.StatusCode)
	}

	// 只有一个生命周期行、一个停用终态事件。
	if n := dbCount(t, env, `SELECT count(*) FROM identity_lifecycles
	     WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("lifecycle rows=%d, want 1 (replay must not duplicate)", n)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identity_events
	     WHERE kind='identity_deactivated' AND tenant_id=$1 AND issuer=$2 AND subject=$3`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("deactivated terminal events=%d, want 1", n)
	}

	// 历史可查询：包含 issuer/subject/时间/原因/证明信息。
	// （发起会话已随停用被吊销，先用另一身份重新登录再查询。）
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("re-login for history query status=%d", resp.StatusCode)
	}
	hist := browser.get(browser.env.baseURL + "/t/acme/api/identities/events?issuer=" +
		urlQueryEscape(env.globex.issuer) + "&subject=globex-bob-sub")
	hb := decodeBody(hist)
	if hist.StatusCode != http.StatusOK {
		t.Fatalf("events status=%d body=%v", hist.StatusCode, hb)
	}
	events := hb["events"].([]any)
	kinds := map[string]int{}
	var reason string
	for _, e := range events {
		m := e.(map[string]any)
		kinds[m["kind"].(string)]++
		if m["kind"] == "identity_deactivated" {
			reason = m["reason"].(string)
			if m["proof_subject"] != "globex-bob-sub" || m["issuer"] != env.globex.issuer {
				t.Fatalf("terminal event missing proof/anchor: %v", m)
			}
			if m["created_at"] == nil || m["proof_auth_time"] == nil {
				t.Fatalf("terminal event missing timestamps: %v", m)
			}
		}
	}
	if kinds["deactivation_requested"] != 1 || kinds["identity_deactivated"] != 1 {
		t.Fatalf("event kinds=%v, want requested=1 deactivated=1", kinds)
	}
	if reason != "replay check" {
		t.Fatalf("stored reason=%q", reason)
	}
}

// TestStaleCallbacksDuringDeactivationDoNotReactivate 验收：
// 停用过程中到达的旧登录或关联回调不会恢复该身份。
func TestStaleCallbacksDuringDeactivationDoNotReactivate(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)
	browser := newFlowClient(t, env)
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	link := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	if cb := browser.completeIdPFlow(env.globex, "bob", link["link_url"].(string)); cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d", cb.StatusCode)
	}

	// 1) 旧关联回调：先发起第二个指向 bob 的关联流程并拿到应用回调 URL，但暂不打回调。
	staleLink := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	env.globex.setCurrentUser("bob")
	authResp := browser.get(staleLink["link_url"].(string))
	staleCallbackURL := authResp.Header.Get("Location")
	drainResp(authResp)
	if staleCallbackURL == "" {
		t.Fatalf("stale link flow produced no callback url")
	}

	// 2) 发起停用但先不完成证明：身份处于 deactivation_pending。
	lr := startLifecycle(t, browser, "acme", "deactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
		"reason": "offboarding in progress",
	}, "deact-stale-1")
	if lr.status != http.StatusCreated {
		t.Fatalf("deactivate start status=%d", lr.status)
	}

	// 3) 此刻到达的旧登录回调（全新 state+code，OIDC 证明完全合法）必须被边界拒绝。
	staleLogin := newFlowClient(t, env).login("acme", "globex", "bob")
	if staleLogin.StatusCode != http.StatusForbidden ||
		decodeBody(staleLogin)["error"] != "identity_disabled" {
		t.Fatalf("login during pending deactivation status=%d, want 403 identity_disabled",
			staleLogin.StatusCode)
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-bob-sub"); got != "deactivation_pending" {
		t.Fatalf("stale login changed status to %s", got)
	}

	// 4) 完成停用证明 -> disabled。
	if pr := proveLifecycle(t, browser, env.globex, "bob", lr); pr.StatusCode != http.StatusOK {
		t.Fatalf("proof status=%d", pr.StatusCode)
	}

	// 5) 停用前就出发的旧关联回调此时才到达。发起它的会话已随停用被吊销，
	// 中间件直接 401 —— B leg 再新鲜也到不了绑定逻辑，身份当然不会被复活。
	staleCB := browser.get(staleCallbackURL)
	body := decodeBody(staleCB)
	if staleCB.StatusCode != http.StatusUnauthorized || body["error"] != "authentication_failed" {
		t.Fatalf("stale link callback status=%d body=%v, want 401 authentication_failed",
			staleCB.StatusCode, body)
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-bob-sub"); got != "disabled" {
		t.Fatalf("stale link callback revived identity: status=%s", got)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identities
	     WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("identity rows=%d, want exactly 1 anchor preserved", n)
	}

	// 6) 即便换成新会话重放同一旧回调 URL，也必须在会话边界被拒绝
	// （link 流程绑定的是已吊销的原会话 -> 401），彻底排除“延迟关联回调复活身份”。
	fresh := newFlowClient(t, env)
	if resp := fresh.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("fresh session login status=%d", resp.StatusCode)
	}
	replay := fresh.get(staleCallbackURL)
	rbody := decodeBody(replay)
	if replay.StatusCode != http.StatusUnauthorized || rbody["error"] != "authentication_failed" {
		t.Fatalf("stale callback under fresh session status=%d body=%v, want 401 authentication_failed",
			replay.StatusCode, rbody)
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-bob-sub"); got != "disabled" {
		t.Fatalf("identity status after stale replay=%s, want disabled", got)
	}
}

// TestReactivationWithinWindow 验收：窗口内恢复后重新认证可用，
// 且恢复建立新状态/新事件而不是覆写停用历史。
func TestReactivationWithinWindow(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)
	browser := newFlowClient(t, env)
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	link := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	if cb := browser.completeIdPFlow(env.globex, "bob", link["link_url"].(string)); cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d", cb.StatusCode)
	}

	deact := startLifecycle(t, browser, "acme", "deactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
		"reason": "temporary trust removal",
	}, "deact-r-1")
	if pr := proveLifecycle(t, browser, env.globex, "bob", deact); pr.StatusCode != http.StatusOK {
		t.Fatalf("deactivate proof status=%d", pr.StatusCode)
	}
	// 停用证明完成即吊销发起会话；恢复操作要先用仍可信的另一身份重新登录。
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("re-login with remaining identity status=%d", resp.StatusCode)
	}

	react := startLifecycle(t, browser, "acme", "reactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
	}, "react-r-1")
	if react.status != http.StatusCreated {
		t.Fatalf("reactivate start status=%d body=%v", react.status, react.body)
	}
	if pr := proveLifecycle(t, browser, env.globex, "bob", react); pr.StatusCode != http.StatusOK {
		t.Fatalf("reactivate proof status=%d body=%v", pr.StatusCode, decodeBody(pr))
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-bob-sub"); got != "active" {
		t.Fatalf("status after reactivation=%s, want active", got)
	}

	// 恢复后重新认证可创建会话。
	relogin := newFlowClient(t, env).login("acme", "globex", "bob")
	if relogin.StatusCode != http.StatusFound {
		t.Fatalf("post-reactivation login status=%d, want 302", relogin.StatusCode)
	}

	// 停用历史仍完整保留：两个生命周期行、停用与恢复事件都在。
	if n := dbCount(t, env, `SELECT count(*) FROM identity_lifecycles
	     WHERE tenant_id=$1 AND issuer=$2 AND subject=$3 AND status='deactivated'`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("deactivated lifecycle history rows=%d, want 1 (must not be overwritten)", n)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identity_lifecycles
	     WHERE tenant_id=$1 AND issuer=$2 AND subject=$3 AND status='reactivated'`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("reactivated lifecycle rows=%d, want 1 new state row", n)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identity_events WHERE kind='identity_deactivated'
	     AND tenant_id=$1 AND issuer=$2 AND subject=$3`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("deactivation event must remain queryable after reactivation")
	}
}

// TestReactivationOutsideWindowRejected 验收：窗口外恢复被拒绝，身份保持停用。
func TestReactivationOutsideWindowRejected(t *testing.T) {
	// 恢复窗口仅 2 秒。
	env := startLocalEnv(t, 30*time.Second, 2*time.Second)
	browser := newFlowClient(t, env)
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	link := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	if cb := browser.completeIdPFlow(env.globex, "bob", link["link_url"].(string)); cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d", cb.StatusCode)
	}
	deact := startLifecycle(t, browser, "acme", "deactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
		"reason": "window test",
	}, "deact-w-1")
	if pr := proveLifecycle(t, browser, env.globex, "bob", deact); pr.StatusCode != http.StatusOK {
		t.Fatalf("deactivate proof status=%d", pr.StatusCode)
	}

	time.Sleep(2500 * time.Millisecond)

	// 窗口外恢复前同样先用另一身份重新登录（发起会话已随停用被吊销）。
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("re-login with remaining identity status=%d", resp.StatusCode)
	}
	react := startLifecycle(t, browser, "acme", "reactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
	}, "react-w-1")
	if react.status != http.StatusGone || react.body["error"] != "identity_lifecycle_expired" {
		t.Fatalf("outside-window reactivation status=%d body=%v, want 410 identity_lifecycle_expired",
			react.status, react.body)
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-bob-sub"); got != "disabled" {
		t.Fatalf("identity status=%s, must stay disabled outside window", got)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identity_lifecycles WHERE kind='reactivate'`); n != 0 {
		t.Fatalf("reactivation lifecycle rows=%d, want 0", n)
	}
}

// TestCrossTenantSameEmailIdentitiesDoNotInterfere 验收：不同租户的同邮箱身份互不影响。
func TestCrossTenantSameEmailIdentitiesDoNotInterfere(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)

	// acme 租户的成员：acme/alice 关联 globex/alice.globex（刻意同邮箱）。
	acmeBrowser := newFlowClient(t, env)
	if resp := acmeBrowser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("acme login status=%d", resp.StatusCode)
	}
	link := startLinkViaAPI(t, acmeBrowser, "acme", env.globex.issuer)
	if cb := acmeBrowser.completeIdPFlow(env.globex, "alice.globex", link["link_url"].(string)); cb.StatusCode != http.StatusOK {
		t.Fatalf("cross-issuer same-email link status=%d", cb.StatusCode)
	}
	deact := startLifecycle(t, acmeBrowser, "acme", "deactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-alice-sub",
		"reason": "acme-side distrust",
	}, "deact-xt-1")
	if pr := proveLifecycle(t, acmeBrowser, env.globex, "alice.globex", deact); pr.StatusCode != http.StatusOK {
		t.Fatalf("acme-side deactivate proof status=%d", pr.StatusCode)
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-alice-sub"); got != "disabled" {
		t.Fatalf("acme-tenant identity should be disabled, got %s", got)
	}

	// globex 租户视角的同一个 (issuer,subject) 是另一条锚点（tenant 不同），必须仍可用。
	globexBrowser := newFlowClient(t, env)
	if resp := globexBrowser.login("globex", "globex", "alice.globex"); resp.StatusCode != http.StatusFound {
		t.Fatalf("globex natural login status=%d, cross-tenant deactivation leaked", resp.StatusCode)
	}
	if got := dbIdentityStatus(t, env, localGlobexID, env.globex.issuer, "globex-alice-sub"); got != "active" {
		t.Fatalf("globex-tenant identity status=%s, want active", got)
	}
	// globex 自然登录产生的是独立成员，与 acme 成员不重合。
	if n := dbCount(t, env, `SELECT count(DISTINCT member_id) FROM identities
	     WHERE issuer=$1 AND subject=$2`, env.globex.issuer, "globex-alice-sub"); n != 2 {
		t.Fatalf("distinct members across tenants=%d, want 2", n)
	}

	// acme 侧窗口内恢复只影响 acme 行（先用 acme/alice 重新建立会话）。
	if resp := acmeBrowser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("acme re-login status=%d", resp.StatusCode)
	}
	react := startLifecycle(t, acmeBrowser, "acme", "reactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-alice-sub",
	}, "react-xt-1")
	if pr := proveLifecycle(t, acmeBrowser, env.globex, "alice.globex", react); pr.StatusCode != http.StatusOK {
		t.Fatalf("acme reactivation status=%d", pr.StatusCode)
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-alice-sub"); got != "active" {
		t.Fatalf("acme identity after reactivation=%s", got)
	}
	if got := dbIdentityStatus(t, env, localGlobexID, env.globex.issuer, "globex-alice-sub"); got != "active" {
		t.Fatalf("globex identity changed unexpectedly: %s", got)
	}
}

// TestConcurrentFirstLoginsDoNotDuplicateWithBoundary 验收：并发首次登录
// （咨询锁+唯一约束）在新状态边界下仍只产生一个成员/一条身份。
func TestConcurrentFirstLoginsDoNotDuplicateWithBoundary(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)

	const n = 8
	callbacks := make([]string, n)
	for i := 0; i < n; i++ {
		c := newFlowClient(t, env)
		env.globex.setCurrentUser("bob")
		idpURL := c.startRedirect(env.baseURL + "/t/globex/login?issuer=" + urlQueryEscape(env.globex.issuer))
		env.globex.setCurrentUser("bob")
		resp := c.get(idpURL)
		callbacks[i] = resp.Header.Get("Location")
		drainResp(resp)
		if callbacks[i] == "" {
			t.Fatalf("flow %d produced no callback url", i)
		}
	}

	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := &http.Client{
				Timeout: 20 * time.Second,
				// 不跟随登录后的 302：我们只断言回调本身的状态码。
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			resp, err := c.Get(callbacks[i])
			if err != nil {
				t.Errorf("concurrent callback %d: %v", i, err)
				return
			}
			statuses[i] = resp.StatusCode
			drainResp(resp)
		}(i)
	}
	wg.Wait()

	for i, st := range statuses {
		if st != http.StatusFound {
			t.Fatalf("concurrent first login %d status=%d, want 302 (all share one member)", i, st)
		}
	}
	if n := dbCount(t, env, `SELECT count(*) FROM members WHERE tenant_id=$1`, localGlobexID); n != 1 {
		t.Fatalf("members after concurrent first logins=%d, want 1", n)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identities
	     WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		localGlobexID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("identities after concurrent first logins=%d, want 1", n)
	}
	if m := dbCount(t, env, `SELECT count(*) FROM sessions WHERE tenant_id=$1`, localGlobexID); m != 8 {
		t.Fatalf("sessions=%d, want 8 (one per successful callback, no member duplication)", m)
	}
}

// TestConcurrentProofCompletionSingleWinner 验收：同一停用令牌的并发完成
// 只有一个终态，其余在事务边界被拒绝。
func TestConcurrentProofCompletionSingleWinner(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)
	browser := newFlowClient(t, env)
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	link := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	if cb := browser.completeIdPFlow(env.globex, "bob", link["link_url"].(string)); cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d", cb.StatusCode)
	}
	lr := startLifecycle(t, browser, "acme", "deactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
		"reason": "concurrency",
	}, "deact-c-1")
	tok := lr.body["lifecycle_token"].(string)
	tokenHash := sec.HashToken(tok)

	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = env.store.CompleteLifecycleProof(context.Background(), store.LifecycleProof{
				TokenHash: tokenHash,
				Issuer:    env.globex.issuer,
				Subject:   "globex-bob-sub",
				AuthTime:  time.Now(),
			}, time.Now(), 5*time.Minute)
		}(i)
	}
	wg.Wait()

	winners, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, store.ErrLifecycleConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent proof error: %v", err)
		}
	}
	if winners != 1 || conflicts != n-1 {
		t.Fatalf("winners=%d conflicts=%d, want exactly 1 winner", winners, conflicts)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identity_events WHERE kind='identity_deactivated'
	     AND tenant_id=$1 AND issuer=$2 AND subject=$3`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("terminal deactivated events=%d, want 1", n)
	}
}

// TestConcurrentDeactivationCannotRemoveLastIdentity 验收：并发停用同一成员
// 两条身份时，“最后一个可用身份”边界不被穿透 —— 任意交织后仍至少有一条 active。
func TestConcurrentDeactivationCannotRemoveLastIdentity(t *testing.T) {
	env := startLocalEnv(t, 10*time.Minute, time.Hour)
	browser := newFlowClient(t, env)
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	link := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	if cb := browser.completeIdPFlow(env.globex, "bob", link["link_url"].(string)); cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d", cb.StatusCode)
	}

	targets := []struct {
		issuer, subject string
	}{
		{env.acme.issuer, "acme-alice-sub"},
		{env.globex.issuer, "globex-bob-sub"},
	}

	// 同一浏览器会话并发发起两条停用：最多一条进入 pending，另一条必须 last_identity/冲突。
	var startWG sync.WaitGroup
	startErrs := make([]lifecycleResp, 2)
	for i, tg := range targets {
		startWG.Add(1)
		go func(i int, tg struct{ issuer, subject string }) {
			defer startWG.Done()
			c := newFlowClientSharingJar(t, env, browser)
			startErrs[i] = startLifecycle(t, c, "acme", "deactivate", map[string]string{
				"issuer": tg.issuer, "subject": tg.subject, "reason": "race",
			}, "race-"+tg.subject)
		}(i, tg)
	}
	startWG.Wait()

	allowed := map[int]int{}
	for _, r := range startErrs {
		allowed[r.status]++
	}
	// 恰好一个 201（进入待证明），另一个被最后身份/流程冲突规则拒绝。
	if allowed[http.StatusCreated] != 1 {
		t.Fatalf("concurrent starts: exactly one should be 201, got %v", allowed)
	}
	if allowed[http.StatusConflict] != 1 {
		t.Fatalf("concurrent starts: exactly one should be 409, got %v", allowed)
	}

	// 无论哪个赢，证明完成后被停用的只能有一条；另一身份保持 active。
	var winner *lifecycleResp
	for i := range startErrs {
		if startErrs[i].status == http.StatusCreated {
			winner = &startErrs[i]
		}
	}
	if winner == nil {
		t.Fatalf("no winning deactivation start")
	}
	var winnerIssuer, winnerUser string
	if winner.body["proof_url"] == nil {
		t.Fatalf("winner missing proof_url: %v", winner.body)
	}
	// 由响应对应的 IdP 完成证明：proof_url 指向的 issuer 决定使用哪个 fake IdP。
	if u := winner.body["proof_url"].(string); strings.Contains(u, env.globex.issuer) {
		winnerIssuer, winnerUser = env.globex.issuer, "bob"
	} else {
		winnerIssuer, winnerUser = env.acme.issuer, "alice"
	}
	cb := browser.completeIdPFlow(env.idpByName(winnerIssuer), winnerUser, winner.body["proof_url"].(string))
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("winning proof status=%d body=%v", cb.StatusCode, decodeBody(cb))
	}

	var active, disabled, pending int
	for _, tg := range targets {
		switch dbIdentityStatus(t, env, localAcmeID, tg.issuer, tg.subject) {
		case "active":
			active++
		case "disabled":
			disabled++
		case "deactivation_pending":
			pending++
		}
	}
	if active != 1 || disabled != 1 || pending != 0 {
		t.Fatalf("post-race states active=%d disabled=%d pending=%d, want active=1 disabled=1",
			active, disabled, pending)
	}
}

func (e *localEnv) idpByName(iss string) *fakeOIDC {
	for _, p := range e.idps {
		if p.issuer == iss {
			return p
		}
	}
	e.t.Fatalf("no idp with issuer %s", iss)
	return nil
}

// newFlowClientSharingJar 复用已有浏览器 jar 的并发客户端（同一 sid 会话）。
func newFlowClientSharingJar(t *testing.T, env *localEnv, base *flowClient) *flowClient {
	t.Helper()
	u, err := url.Parse(env.baseURL)
	if err != nil {
		t.Fatalf("parse base url: %v", err)
	}
	cookies := base.http.Jar.Cookies(u)
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(u, cookies)
	return &flowClient{
		t: t, env: env,
		http: &http.Client{
			Jar: jar, Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// 窗口外到达的证明回调不能停用身份（流程过期、身份安全回到 active），
// 过期事件仍写入历史，身份锚点行不增不减。
// TestDeactivationProofWindowExpiry 验收：停用证明必须在明确窗口内完成。
// 窗口外到达的证明回调不能停用身份（流程过期、身份安全回到 active），
// 过期事件仍写入历史，身份锚点行不增不减。
func TestDeactivationProofWindowExpiry(t *testing.T) {
	env := startLocalEnv(t, 2*time.Second, time.Hour)
	browser := newFlowClient(t, env)
	if resp := browser.login("acme", "acme", "alice"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	link := startLinkViaAPI(t, browser, "acme", env.globex.issuer)
	if cb := browser.completeIdPFlow(env.globex, "bob", link["link_url"].(string)); cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d", cb.StatusCode)
	}
	lr := startLifecycle(t, browser, "acme", "deactivate", map[string]string{
		"issuer": env.globex.issuer, "subject": "globex-bob-sub",
		"reason": "late proof",
	}, "deact-exp-1")

	time.Sleep(2500 * time.Millisecond)

	// 此刻才走完证明：state/code 都是全新且合法的，但窗口已过 -> 410，不能停用。
	late := browser.completeIdPFlow(env.globex, "bob", lr.body["proof_url"].(string))
	body := decodeBody(late)
	if late.StatusCode != http.StatusGone || body["error"] != "identity_lifecycle_expired" {
		t.Fatalf("late proof status=%d body=%v, want 410 identity_lifecycle_expired", late.StatusCode, body)
	}
	if got := dbIdentityStatus(t, env, localAcmeID, env.globex.issuer, "globex-bob-sub"); got != "active" {
		t.Fatalf("identity status=%s, want active after deactivation attempt expired", got)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identity_events WHERE kind='lifecycle_expired'
	     AND tenant_id=$1 AND issuer=$2 AND subject=$3`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("lifecycle_expired events=%d, want 1", n)
	}

	// 身份重新可用：全新浏览器登录成功，不产生重复成员/身份。
	relogin := newFlowClient(t, env).login("acme", "globex", "bob")
	if relogin.StatusCode != http.StatusFound {
		t.Fatalf("login after expiry status=%d, want 302", relogin.StatusCode)
	}
	if n := dbCount(t, env, `SELECT count(*) FROM identities
	     WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		localAcmeID, env.globex.issuer, "globex-bob-sub"); n != 1 {
		t.Fatalf("identity anchor rows=%d, want 1", n)
	}
}
