package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"
)

// postLifecycleRaw 调用停用/恢复发起端点并返回原始状态码与 JSON。
func (b *browserClient) postLifecycleRaw(tenantSlug, endpoint string, body any) (int, map[string]any) {
	b.t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := b.app.Post(appBaseURL+"/t/"+tenantSlug+"/api/identities/"+endpoint,
		"application/json", bytes.NewReader(buf))
	if err != nil {
		b.t.Fatalf("post lifecycle: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (b *browserClient) startDeactivation(tenantSlug, iss, sub, reason string, idemKey ...string) (int, map[string]any) {
	body := map[string]string{"issuer": iss, "subject": sub, "reason": reason}
	if len(idemKey) > 0 {
		body["idempotency_key"] = idemKey[0]
	}
	return b.postLifecycleRaw(tenantSlug, "deactivations", body)
}

func (b *browserClient) startReactivation(tenantSlug, iss, sub string, idemKey ...string) (int, map[string]any) {
	body := map[string]string{"issuer": iss, "subject": sub}
	if len(idemKey) > 0 {
		body["idempotency_key"] = idemKey[0]
	}
	return b.postLifecycleRaw(tenantSlug, "reactivations", body)
}

// finishLifecycle 完成停用/恢复挑战的强制重认证并打应用回调。
// authURL 必须是发起响应里的 Keycloak 授权地址。
func (b *browserClient) finishLifecycle(authURL string, user keycloakUser) *http.Response {
	b.t.Helper()
	callbackURL := b.kc.passwordLogin(authURL, user)
	if !urlHasPrefix(callbackURL, appBaseURL) {
		b.t.Fatalf("lifecycle login did not return to app: %s", callbackURL)
	}
	resp, err := b.app.Get(callbackURL)
	if err != nil {
		b.t.Fatalf("GET lifecycle callback: %v", err)
	}
	return resp
}

// finishLifecycleFreshKC 使用全新的 Keycloak cookie jar 完成 B 侧重认证，
// 避免与浏览器已有的同 realm SSO 会话（不同用户）冲突。
// 回调仍用本浏览器（成员）的应用 jar 交付。
func (b *browserClient) finishLifecycleFreshKC(authURL string, user keycloakUser) *http.Response {
	b.t.Helper()
	kcJar, _ := cookiejar.New(nil)
	noFollow := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	freshKC := &keycloakHTTP{
		base:   kcBaseURL(),
		client: &http.Client{Jar: kcJar, Timeout: 20 * time.Second, CheckRedirect: noFollow},
	}
	callbackURL := freshKC.passwordLogin(authURL, user)
	if !urlHasPrefix(callbackURL, appBaseURL) {
		b.t.Fatalf("fresh-KC lifecycle login did not return to app: %s", callbackURL)
	}
	resp, err := b.app.Get(callbackURL)
	if err != nil {
		b.t.Fatalf("GET lifecycle callback (fresh KC): %v", err)
	}
	return resp
}

// heldKCLogin 只完成 Keycloak 侧密码登录、持有应用回调 URL 不交付
// （用于模拟“在途、延迟到达的回调”）。使用独立 KC jar。
func heldKCLogin(t *testing.T, authURL string, user keycloakUser) string {
	t.Helper()
	kcJar, _ := cookiejar.New(nil)
	noFollow := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	kc := &keycloakHTTP{
		base:   kcBaseURL(),
		client: &http.Client{Jar: kcJar, Timeout: 20 * time.Second, CheckRedirect: noFollow},
	}
	callbackURL := kc.passwordLogin(authURL, user)
	if !urlHasPrefix(callbackURL, appBaseURL) {
		t.Fatalf("held login did not return to app: %s", callbackURL)
	}
	return callbackURL
}

func (b *browserClient) deliverCallback(raw string) *http.Response {
	b.t.Helper()
	resp, err := b.app.Get(raw)
	if err != nil {
		b.t.Fatalf("deliver callback: %v", err)
	}
	return resp
}

func (b *browserClient) identityHistory(tenantSlug, iss, sub string, wantStatus int) map[string]any {
	return getJSON(b.t, b.app, appBaseURL+"/t/"+tenantSlug+"/api/identities/history"+
		"?issuer="+url.QueryEscape(iss)+"&subject="+url.QueryEscape(sub), wantStatus)
}

// findIdentitySubject 在 /me 中按 issuer 找到对应 subject。
func findIdentitySubject(t *testing.T, ids []any, iss string) string {
	t.Helper()
	for _, raw := range ids {
		m := raw.(map[string]any)
		if m["issuer"].(string) == iss {
			return m["subject"].(string)
		}
	}
	t.Fatalf("identity for issuer %s not found", iss)
	return ""
}

// identityStatusOf 在 /me 中按 issuer 返回身份状态。
func identityStatusOf(t *testing.T, ids []any, iss string) string {
	t.Helper()
	for _, raw := range ids {
		m := raw.(map[string]any)
		if m["issuer"].(string) == iss {
			return m["status"].(string)
		}
	}
	t.Fatalf("identity for issuer %s not found", iss)
	return ""
}

func urlHasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
