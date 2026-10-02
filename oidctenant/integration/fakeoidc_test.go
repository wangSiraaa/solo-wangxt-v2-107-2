package integration

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

// fakeOIDC 是进程内的最小 OIDC Provider：发现文档、JWKS（RS256）、
// 授权端点（直接 302 发码，模拟“浏览器已登录”）、令牌端点（授权码一次性）。
// 它让停用/恢复生命周期的端到端验收测试不依赖外部 Keycloak。
type fakeOIDC struct {
	srv      *httptest.Server
	issuer   string
	clientID string
	kid      string
	key      *rsa.PrivateKey

	mu       sync.Mutex
	users    map[string]*fakeUser
	current  string
	authTime time.Time
	codes    map[string]*issuedCode
}

type fakeUser struct {
	subject string
	email   string
	name    string
}

type issuedCode struct {
	userKey     string
	nonce       string
	redirectURI string
	used        bool
}

func newFakeOIDC(clientID string, users map[string]*fakeUser) *fakeOIDC {
	f := &fakeOIDC{
		clientID: clientID,
		users:    users,
		codes:    map[string]*issuedCode{},
		kid:      "fake-kid-1",
		authTime: time.Now(),
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	f.key = key
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/auth", f.authorize)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/jwks", f.jwks)
	f.srv = httptest.NewServer(mux)
	f.issuer = f.srv.URL
	return f
}

func (f *fakeOIDC) close() { f.srv.Close() }

func (f *fakeOIDC) setCurrentUser(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.current = key
}

// setAuthTime 设定后续签发 ID token 的 auth_time（测试证明新鲜度窗口）。
func (f *fakeOIDC) setAuthTime(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authTime = t
}

func (f *fakeOIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	writeFakeJSON(w, map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/auth",
		"token_endpoint":                        f.issuer + "/token",
		"jwks_uri":                              f.issuer + "/jwks",
		"response_types_supported":              []string{"code", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"grant_types_supported":                 []string{"authorization_code"},
	})
}

// authorize 不渲染登录页：测试预先 setCurrentUser 指定本次以谁的身份发码。
func (f *fakeOIDC) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	nonce := q.Get("nonce")
	state := q.Get("state")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	userKey := f.current
	f.mu.Unlock()
	if userKey == "" {
		http.Error(w, "no user selected on fake idp", http.StatusBadRequest)
		return
	}
	codeBytes := make([]byte, 24)
	_, _ = rand.Read(codeBytes)
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	f.mu.Lock()
	f.codes[code] = &issuedCode{userKey: userKey, nonce: nonce, redirectURI: redirectURI}
	f.mu.Unlock()

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	out := u.Query()
	out.Set("code", code)
	out.Set("state", state)
	u.RawQuery = out.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

func (f *fakeOIDC) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")

	f.mu.Lock()
	ic := f.codes[code]
	if ic != nil {
		if ic.used {
			ic = nil
		} else {
			ic.used = true
		}
	}
	user := (*fakeUser)(nil)
	authTime := f.authTime
	if ic != nil {
		user = f.users[ic.userKey]
	}
	f.mu.Unlock()

	if ic == nil || user == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
		return
	}

	now := time.Now()
	idToken := f.signJWT(map[string]any{
		"iss":            f.issuer,
		"sub":            user.subject,
		"aud":            f.clientID,
		"azp":            f.clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"nonce":          ic.nonce,
		"auth_time":      authTime.Unix(),
		"email":          user.email,
		"email_verified": true,
		"name":           user.name,
	})
	writeFakeJSON(w, map[string]any{
		"access_token": "fake-access-" + base64.RawURLEncoding.EncodeToString([]byte(code)),
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func (f *fakeOIDC) jwks(w http.ResponseWriter, _ *http.Request) {
	n := f.key.N
	e := big.NewInt(int64(f.key.E))
	writeFakeJSON(w, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": f.kid,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 256))),
			"e":   base64.RawURLEncoding.EncodeToString(e.Bytes()),
		}},
	})
}

func (f *fakeOIDC) signJWT(claims map[string]any) string {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": f.kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64url(hb) + "." + b64url(cb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + b64url(sig)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeFakeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
