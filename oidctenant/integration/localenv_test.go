package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/api"
	"github.com/example/oidctenant/internal/config"
	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

func embeddedNewDB(t *testing.T, port uint32) *embedded.EmbeddedPostgres {
	t.Helper()
	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Port(port).
		Database("oidctenant").
		DataPath(t.TempDir()).
		CachePath("/workspace/tools/ep-cache").
		Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}
	return pg
}

// localEnv 是不依赖 Keycloak 的端到端环境：嵌入式 PostgreSQL + 两个 fake OIDC。
type localEnv struct {
	t       *testing.T
	pg      interface{ Stop() error }
	store   *store.Store
	baseURL string
	idps    map[string]*fakeOIDC
	acme    *fakeOIDC
	globex  *fakeOIDC
	srv     *http.Server
}

var (
	localAcmeID   = uuid.MustParse("10000000-0000-0000-0000-0000000000a1")
	localGlobexID = uuid.MustParse("10000000-0000-0000-0000-0000000000b1")

	localAcmeSelfID   = uuid.MustParse("10000000-0000-0000-0000-0000000000a2")
	localAcmeGlobexID = uuid.MustParse("10000000-0000-0000-0000-0000000000a3")
	localGlobexSelfID = uuid.MustParse("10000000-0000-0000-0000-0000000000b2")
	localGlobexAcmeID = uuid.MustParse("10000000-0000-0000-0000-0000000000b3")
)

// startLocalEnv 启动进程内 PG、两个 fake IdP，并在空闲端口跑真实 HTTP 应用。
func startLocalEnv(t *testing.T, proofTTL, reactivationWindow time.Duration) *localEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	pgPort := freeTCPPort(t)
	ep := embeddedNewDB(t, pgPort)
	dsn := formatDSN(pgPort, "oidctenant")
	ctx := context.Background()
	database, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.New(database)

	acme := newFakeOIDC("acme-rp", map[string]*fakeUser{
		"alice": {subject: "acme-alice-sub", email: "alice@example.com", name: "Alice Acme"},
		"carol": {subject: "acme-carol-sub", email: "carol@example.com", name: "Carol"},
	})
	globex := newFakeOIDC("globex-rp", map[string]*fakeUser{
		"alice.globex": {subject: "globex-alice-sub", email: "alice@example.com", name: "Alice Globex"},
		"bob":          {subject: "globex-bob-sub", email: "bob@example.com", name: "Bob Globex"},
	})
	t.Cleanup(acme.close)
	t.Cleanup(globex.close)

	appPort := freeTCPPort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", appPort)
	callbacks := []string{
		baseURL + "/oauth/callback",
		baseURL + "/oauth/link/callback",
		baseURL + "/oauth/identity/callback",
	}
	mustSeedTenant(t, st, localAcmeID, "acme", "Acme Local", models.Provider{
		ID: localAcmeSelfID, TenantID: localAcmeID,
		Issuer: acme.issuer, ClientID: "acme-rp", ClientSecret: "acme-secret",
		RedirectURIs: callbacks, AuthTimeMaxAge: 300, Enabled: true,
	})
	mustSeedTenant(t, st, localAcmeID, "acme", "Acme Local", models.Provider{
		ID: localAcmeGlobexID, TenantID: localAcmeID,
		Issuer: globex.issuer, ClientID: "globex-rp", ClientSecret: "globex-secret",
		RedirectURIs: callbacks, AuthTimeMaxAge: 300, Enabled: true,
	})
	mustSeedTenant(t, st, localGlobexID, "globex", "Globex Local", models.Provider{
		ID: localGlobexSelfID, TenantID: localGlobexID,
		Issuer: globex.issuer, ClientID: "globex-rp", ClientSecret: "globex-secret",
		RedirectURIs: callbacks, AuthTimeMaxAge: 300, Enabled: true,
	})
	mustSeedTenant(t, st, localGlobexID, "globex", "Globex Local", models.Provider{
		ID: localGlobexAcmeID, TenantID: localGlobexID,
		Issuer: acme.issuer, ClientID: "acme-rp", ClientSecret: "acme-secret",
		RedirectURIs: callbacks, AuthTimeMaxAge: 300, Enabled: true,
	})

	cfg := &config.Config{
		DatabaseURL: dsn, BaseURL: baseURL, Addr: fmt.Sprintf("127.0.0.1:%d", appPort),
		SessionTTL:         time.Hour,
		LinkTTL:            10 * time.Minute,
		AuthRequestTTL:     10 * time.Minute,
		LifecycleProofTTL:  proofTTL,
		ReactivationWindow: reactivationWindow,
		CookieSecure:       false,
		CookieSameSite:     "lax",
	}
	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: api.NewServer(cfg, st, oidcx.NewManager(),
			log.New(os.Stdout, "[local-api] ", log.LstdFlags|log.Lmicroseconds)).Routes(),
	}
	go func() { _ = srv.ListenAndServe() }()
	waitReady(t, baseURL+"/healthz")
	t.Cleanup(func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		database.Close()
		_ = ep.Stop()
	})

	return &localEnv{
		t: t, store: st, baseURL: baseURL,
		idps: map[string]*fakeOIDC{"acme": acme, "globex": globex},
		acme: acme, globex: globex, srv: srv,
	}
}

func mustSeedTenant(t *testing.T, st *store.Store, id uuid.UUID, slug, name string, p models.Provider) {
	t.Helper()
	if err := st.UpsertTenant(context.Background(), id, slug, name); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	p.TenantID = id
	if err := st.UpsertProvider(context.Background(), &p); err != nil {
		t.Fatalf("upsert provider: %v", err)
	}
}

func (e *localEnv) idp(name string) *fakeOIDC {
	p, ok := e.idps[name]
	if !ok {
		e.t.Fatalf("unknown local idp %q", name)
	}
	return p
}

// flowClient 是一个手动跟随跳转的 HTTP 客户端（app 与 fake IdP 共用一个 jar，
// 因为二者是同源测试场景下的不同域；本应用所有状态都由服务端记录，cookie 仅 sid）。
type flowClient struct {
	t    *testing.T
	env  *localEnv
	http *http.Client
}

func newFlowClient(t *testing.T, env *localEnv) *flowClient {
	jar, _ := cookiejar.New(nil)
	return &flowClient{
		t: t, env: env,
		http: &http.Client{
			Jar: jar, Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *flowClient) get(raw string) *http.Response {
	c.t.Helper()
	resp, err := c.http.Get(raw)
	if err != nil {
		c.t.Fatalf("GET %s: %v", raw, err)
	}
	return resp
}

func (c *flowClient) post(raw string, body any, idempotencyKey string) *http.Response {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(http.MethodPost, raw, reader)
	if err != nil {
		c.t.Fatalf("new post: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("POST %s: %v", raw, err)
	}
	return resp
}

func decodeBody(resp *http.Response) map[string]any {
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}

// startRedirect 访问应用启动 URL，跟随到 fake IdP 的 /auth，返回 IdP 授权地址。
func (c *flowClient) startRedirect(appStartURL string) string {
	resp := c.get(appStartURL)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		c.t.Fatalf("expected app 302 to idp, got %d (%s)", resp.StatusCode, appStartURL)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		c.t.Fatalf("app start returned no Location")
	}
	return loc
}

// completeFlow 在 fake IdP 选定用户后走完全流程，返回应用最终回调响应。
func (c *flowClient) completeFlow(idp *fakeOIDC, userKey, appStartURL string) *http.Response {
	idp.setCurrentUser(userKey)
	idpAuthURL := c.startRedirect(appStartURL)
	resp := c.get(idpAuthURL)
	loc := resp.Header.Get("Location")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, c.env.baseURL) {
		c.t.Fatalf("fake idp authorize status=%d loc=%s, want 302 to app", resp.StatusCode, loc)
	}
	return c.get(loc)
}

func (c *flowClient) login(slug, idpName, userKey string) *http.Response {
	iss := c.env.idp(idpName).issuer
	start := c.env.baseURL + "/t/" + slug + "/login?issuer=" + url.QueryEscape(iss)
	return c.completeFlow(c.env.idp(idpName), userKey, start)
}

func (c *flowClient) me(slug string) map[string]any {
	resp := c.get(c.env.baseURL + "/t/" + slug + "/api/me")
	out := decodeBody(resp)
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("me status=%d body=%v", resp.StatusCode, out)
	}
	return out
}
