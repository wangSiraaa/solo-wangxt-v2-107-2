package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// lifecycleAction 对真实 Keycloak 环境调用停用/恢复发起接口。
func lifecycleAction(t *testing.T, b *browserClient, tenantSlug, action, idemKey string,
	body map[string]string) (int, map[string]any) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost,
		appBaseURL+"/t/"+tenantSlug+"/api/identities/"+action, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new lifecycle request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := b.app.Do(req)
	if err != nil {
		t.Fatalf("post lifecycle %s: %v", action, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func identityEventsRaw(t *testing.T, b *browserClient, tenantSlug, iss, sub string, wantStatus int) map[string]any {
	t.Helper()
	raw := appBaseURL + "/t/" + tenantSlug + "/api/identities/events?issuer=" +
		url.QueryEscape(iss) + "&subject=" + url.QueryEscape(sub)
	resp, err := b.app.Get(raw)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode != wantStatus {
		t.Fatalf("events status=%d want=%d body=%s", resp.StatusCode, wantStatus, string(data))
	}
	return out
}

// TestIdentityDeactivationLifecycleKeycloak 是真实 Keycloak + 真实 PG 的端到端验收：
// 两条身份的成员停用其中一条（该身份重新 OIDC 证明后才生效），停用后：
//   - 该身份在全新浏览器里无法再创建会话（403 identity_disabled）；
//   - 另一条身份仍可登录；
//   - 发起请求幂等重放只产生一个终态，历史可查询（issuer/subject/时间/原因齐全）。
func TestIdentityDeactivationLifecycleKeycloak(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)

	// A：acme/alice 登录；B：globex/bob 关联，成员持有两条身份。
	respA := browser.login("acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()
	_, linkURL := browser.startLink("acme", issuer("globex"))
	cb := browser.finishLink(linkURL, keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d body=%s", cb.StatusCode, mustBody(t, cb))
	}
	_ = cb.Body.Close()

	bobSubject := subjectOf(t, env, "acme", "bob@example.com")

	// 发起停用：立即进入 deactivation_pending，必须由 bob 本人重新认证才生效。
	status, out := lifecycleAction(t, browser, "acme", "deactivate", "kc-deact-1", map[string]string{
		"issuer": issuer("globex"), "subject": bobSubject,
		"reason": "no longer trusted external identity",
	})
	if status != http.StatusCreated {
		t.Fatalf("deactivate start status=%d body=%v, want 201", status, out)
	}
	proofURL, _ := out["proof_url"].(string)
	if proofURL == "" {
		t.Fatalf("missing proof_url: %v", out)
	}

	// 同幂等键重放：200 replay，不产生第二个流程/state。
	replayStatus, replay := lifecycleAction(t, browser, "acme", "deactivate", "kc-deact-1", map[string]string{
		"issuer": issuer("globex"), "subject": bobSubject,
		"reason": "no longer trusted external identity",
	})
	if replayStatus != http.StatusOK || replay["replay"] != "true" {
		t.Fatalf("idempotent replay status=%d body=%v, want 200 replay", replayStatus, replay)
	}

	// bob 在 globex realm 强制重新认证后完成停用证明。
	proofCB := browser.finishLink(proofURL,
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	if proofCB.StatusCode != http.StatusOK {
		t.Fatalf("deactivation proof status=%d body=%s", proofCB.StatusCode, mustBody(t, proofCB))
	}
	_ = proofCB.Body.Close()

	var dbStatus string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT status FROM identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, issuer("globex"), bobSubject).Scan(&dbStatus); err != nil {
		t.Fatalf("db status: %v", err)
	}
	if dbStatus != "disabled" {
		t.Fatalf("identity status=%s, want disabled", dbStatus)
	}

	// 被停用身份不能再创建会话（全新浏览器的完整 OIDC 登录也被边界拒绝）。
	stale := newBrowserClient(t)
	denied := stale.login("acme", keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	body := readBody(t, denied)
	if denied.StatusCode != http.StatusForbidden || body["error"] != "identity_disabled" {
		t.Fatalf("disabled identity login status=%d body=%v, want 403 identity_disabled",
			denied.StatusCode, body)
	}

	// 另一条身份仍可登录。
	sibling := newBrowserClient(t)
	ok := sibling.login("acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, ok.Body)
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusFound {
		t.Fatalf("sibling identity login status=%d, want 302", ok.StatusCode)
	}

	// 只产生一个停用终态；历史可查询且保留原因/时间/证明信息。
	if n := countRows(t, env, `SELECT count(*) FROM identity_events
	     WHERE kind='identity_deactivated' AND tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, issuer("globex"), bobSubject); n != 1 {
		t.Fatalf("deactivated events=%d, want 1", n)
	}
	// 发起会话已随停用被吊销：用仍可信的另一身份重新登录后再查历史。
	histBrowser := newBrowserClient(t)
	hb := histBrowser.login("acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, hb.Body)
	_ = hb.Body.Close()
	if hb.StatusCode != http.StatusFound {
		t.Fatalf("sibling re-login status=%d, want 302", hb.StatusCode)
	}
	hist := identityEventsRaw(t, histBrowser, "acme", issuer("globex"), bobSubject, http.StatusOK)
	events := hist["events"].([]any)
	kinds := map[string]int{}
	var reason string
	for _, e := range events {
		m := e.(map[string]any)
		kinds[m["kind"].(string)]++
		if m["kind"] == "identity_deactivated" {
			reason = m["reason"].(string)
		}
	}
	if kinds["deactivation_requested"] != 1 || kinds["identity_deactivated"] != 1 {
		t.Fatalf("history kinds=%v, want requested=1 deactivated=1", kinds)
	}
	if reason != "no longer trusted external identity" {
		t.Fatalf("history reason=%q", reason)
	}
}

// TestLastIdentityCannotBeDeactivatedKeycloak 验收唯一身份停用被拒绝且数据不变。
func TestLastIdentityCannotBeDeactivatedKeycloak(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)
	resp := browser.login("acme", keycloakUser{realm: "acme", username: "carol", password: "carol-pass"})
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	carolSubject := subjectOf(t, env, "acme", "carol@example.com")

	status, out := lifecycleAction(t, browser, "acme", "deactivate", "kc-last-1", map[string]string{
		"issuer": issuer("acme"), "subject": carolSubject, "reason": "nope",
	})
	if status != http.StatusConflict || out["error"] != "last_identity" {
		t.Fatalf("last identity status=%d body=%v, want 409 last_identity", status, out)
	}
	if got := countRows(t, env, `SELECT count(*) FROM identity_lifecycles`); got != 0 {
		t.Fatalf("identity_lifecycles=%d, want 0", got)
	}
	var dbStatus string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT status FROM identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, issuer("acme"), carolSubject).Scan(&dbStatus); err != nil {
		t.Fatalf("db status: %v", err)
	}
	if dbStatus != "active" {
		t.Fatalf("identity status=%s, want active (data unchanged)", dbStatus)
	}
}

// TestReactivationWithinWindowKeycloak 验收窗口内恢复：重新认证后可再登录，
// 停用历史不被覆写。
func TestReactivationWithinWindowKeycloak(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)
	respA := browser.login("acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()
	_, linkURL := browser.startLink("acme", issuer("globex"))
	cb := browser.finishLink(linkURL, keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d", cb.StatusCode)
	}
	_ = cb.Body.Close()
	bobSubject := subjectOf(t, env, "acme", "bob@example.com")

	_, out := lifecycleAction(t, browser, "acme", "deactivate", "kc-react-d-1", map[string]string{
		"issuer": issuer("globex"), "subject": bobSubject, "reason": "temporary",
	})
	done := browser.finishLink(out["proof_url"].(string),
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	if done.StatusCode != http.StatusOK {
		t.Fatalf("deactivate proof status=%d", done.StatusCode)
	}
	_ = done.Body.Close()

	// 发起会话已随停用被吊销：用另一身份重新登录后再发起恢复。
	rel := browser.login("acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, rel.Body)
	_ = rel.Body.Close()
	if rel.StatusCode != http.StatusFound {
		t.Fatalf("re-login with remaining identity status=%d, want 302", rel.StatusCode)
	}

	rStatus, rOut := lifecycleAction(t, browser, "acme", "reactivate", "kc-react-r-1", map[string]string{
		"issuer": issuer("globex"), "subject": bobSubject,
	})
	if rStatus != http.StatusCreated {
		t.Fatalf("reactivate start status=%d body=%v, want 201", rStatus, rOut)
	}
	rDone := browser.finishLink(rOut["proof_url"].(string),
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	if rDone.StatusCode != http.StatusOK {
		t.Fatalf("reactivate proof status=%d body=%s", rDone.StatusCode, mustBody(t, rDone))
	}
	_ = rDone.Body.Close()

	relogin := newBrowserClient(t).login("acme",
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	_, _ = io.Copy(io.Discard, relogin.Body)
	_ = relogin.Body.Close()
	if relogin.StatusCode != http.StatusFound {
		t.Fatalf("post-reactivation login status=%d, want 302", relogin.StatusCode)
	}

	// 停用终态历史必须仍在（恢复是新增状态，不是覆写）。
	if n := countRows(t, env, `SELECT count(*) FROM identity_events
	     WHERE kind='identity_deactivated' AND tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, issuer("globex"), bobSubject); n != 1 {
		t.Fatalf("deactivation history rows=%d, want 1", n)
	}
}
