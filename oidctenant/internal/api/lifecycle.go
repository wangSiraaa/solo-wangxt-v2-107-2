package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

const (
	lifecycleCBPath = "/oauth/identity/callback"
	// maxReasonLen 限制停用原因长度，防止滥用审计表。
	maxReasonLen = 500
)

type lifecycleRequest struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

// POST /t/{slug}/api/identities/deactivate
// body: {"issuer":"...","subject":"...","reason":"..."}
// 幂等：重复携带相同 Idempotency-Key 的请求只返回同一个待证明流程。
func (s *Server) deactivateStart(w http.ResponseWriter, r *http.Request) {
	s.startIdentityLifecycle(w, r, "deactivate")
}

// POST /t/{slug}/api/identities/reactivate
func (s *Server) reactivateStart(w http.ResponseWriter, r *http.Request) {
	s.startIdentityLifecycle(w, r, "reactivate")
}

func (s *Server) startIdentityLifecycle(w http.ResponseWriter, r *http.Request, kind string) {
	ac := authed(r)
	var req lifecycleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		writeAPIError(w, badRequest("invalid JSON body"))
		return
	}
	if req.Issuer == "" || req.Subject == "" {
		writeAPIError(w, badRequest("issuer and subject are required"))
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if kind == "deactivate" {
		if req.Reason == "" {
			writeAPIError(w, badRequest("reason is required when deactivating an identity"))
			return
		}
		if len(req.Reason) > maxReasonLen {
			writeAPIError(w, badRequest("reason is too long"))
			return
		}
	}

	tenant, prov, ae := s.loadTenantProvider(r.Context(), r.PathValue("slug"), req.Issuer)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}

	// 身份必须存在、属于本租户且属于当前成员；跨成员/跨租户操作不允许。
	identity, err := s.store.IdentityByAnchor(r.Context(), tenant.ID, req.Issuer, req.Subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, tenantForbidden("identity is not bound in this tenant"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lookup identity failed"))
		return
	}
	if identity.MemberID != ac.member.ID {
		// 不向其他成员暴露身份是否存在。
		writeAPIError(w, tenantForbidden("identity is not bound to the current member"))
		return
	}

	token, err := sec.LinkToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lifecycle token failed"))
		return
	}
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))

	var proofTTL, windowTTL = s.cfg.LifecycleProofTTL, s.cfg.ReactivationWindow
	res, err := s.store.StartLifecycle(r.Context(), store.LifecycleInput{
		TenantID:       tenant.ID,
		IdentityID:     identity.ID,
		MemberID:       ac.member.ID,
		Kind:           kind,
		Issuer:         req.Issuer,
		Subject:        req.Subject,
		Reason:         req.Reason,
		SessionID:      ac.session.ID,
		IdempotencyKey: idemKey,
		TokenHash:      sec.HashToken(token),
	}, proofTTL, windowTTL)
	if ae := s.mapLifecycleStartError(err); ae != nil {
		writeAPIError(w, ae)
		return
	}
	if res.Replayed {
		// 幂等重放：不新建令牌/state/任何状态，原流程继续有效；
		// 终态与历史仍然只有一份。调用方应沿用首次响应里的 proof_url。
		writeJSON(w, http.StatusOK, map[string]string{
			"kind":   kind,
			"status": "proof_pending",
			"replay": "true",
		})
		return
	}

	state, err := sec.State()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "state failed"))
		return
	}
	nonce, err := sec.Nonce()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "nonce failed"))
		return
	}
	verifier, err := sec.PKCEVerifier()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "pkce failed"))
		return
	}
	sessionID := ac.session.ID
	if err := s.store.CreateAuthRequest(r.Context(), &models.AuthRequest{
		State: state, Kind: "lifecycle", TenantID: tenant.ID, IDPID: prov.ID,
		Nonce: nonce, PKCEVerifier: verifier, ReturnTo: "/",
		LinkToken: nullString(token), SessionID: &sessionID,
	}); err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist auth request failed"))
		return
	}

	redirectURI := s.cfg.BaseURL + lifecycleCBPath
	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	// 强制全新交互式认证：新 OIDC 证明是停用/恢复生效的前提。
	proofURL := oidcx.AuthCodeURL(cfg, state, nonce, challenge, "S256", true, nil)

	status := http.StatusCreated
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"kind":            kind,
		"lifecycle_token": token,
		"proof_url":       proofURL,
		"status":          "proof_pending",
	})
}

// GET /oauth/identity/callback?state=...&code=...
//
// 停用与恢复共用同一回调和同一状态边界：一次性 state、一次性 lifecycle token、
// 强制重新认证、证明锚点必须就是目标身份本人。重放/过期回调一律无法推进状态。
func (s *Server) lifecycleCallback(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeAPIError(w, badRequest("missing state or code"))
		return
	}
	if ep := r.URL.Query().Get("error"); ep != "" {
		writeAPIError(w, authn("provider returned error: "+sanitizeErrParam(ep)))
		return
	}

	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("lifecycle authorization request is unknown or already used"))
		return
	}
	if ar.Kind != "lifecycle" || !ar.LinkToken.Valid {
		writeAPIError(w, badRequest("state is not valid for identity lifecycle proof"))
		return
	}
	// 必须用发起流程时的同一个会话、同一个租户完成证明。
	if ar.SessionID == nil || *ar.SessionID != ac.session.ID {
		writeAPIError(w, authn("lifecycle proof must be completed in the same browser session that started it"))
		return
	}
	if ar.TenantID != ac.session.TenantID {
		writeAPIError(w, tenantForbidden("lifecycle crosses tenant boundary"))
		return
	}

	lc, err := s.store.LifecycleByToken(r.Context(), sec.HashToken(ar.LinkToken.String))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, lifecycleConflict("lifecycle token not found or already used"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lookup lifecycle failed"))
		return
	}
	if lc.Status != "pending" {
		writeAPIError(w, lifecycleConflict("lifecycle is already in a terminal state"))
		return
	}
	if lc.SessionID != ac.session.ID || lc.MemberID != ac.member.ID {
		writeAPIError(w, tenantForbidden("lifecycle belongs to another member or session"))
		return
	}

	prov, err := s.store.ProviderByID(r.Context(), ar.TenantID, ar.IDPID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, tenantForbidden("provider is no longer authorized for the tenant"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed"))
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}
	redirectURI := s.cfg.BaseURL + lifecycleCBPath
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	ver, err := s.oidc.Verifier(r.Context(), prov, ar.Nonce)
	if err != nil {
		writeAPIError(w, authn("failed to initialize token verifier"))
		return
	}
	claims, _, err := s.oidc.ExchangeAndVerify(r.Context(), prov, cfg, ver, code, ar.PKCEVerifier)
	if err != nil {
		s.logVerifyFailure(err)
		writeAPIError(w, authn("token exchange or id token verification failed"))
		return
	}
	if claims.Issuer != prov.Issuer || claims.Issuer != lc.Issuer {
		writeAPIError(w, authn("id token issuer does not match the identity being changed"))
		return
	}
	if claims.Subject != lc.Subject {
		// 不能用同成员的另一身份（甚至他人）的认证来停用/恢复目标身份。
		writeAPIError(w, lifecycleConflict("proof subject does not match the target identity"))
		return
	}
	maxAge := providerAuthMaxAge(prov)
	if claims.AuthTime.IsZero() {
		writeAPIError(w, reauthRequired("provider did not report auth_time; cannot prove recent re-authentication"))
		return
	}
	if s.now().Sub(claims.AuthTime) > maxAge {
		writeAPIError(w, reauthRequired("lifecycle proof authentication is stale; re-authenticate"))
		return
	}

	err = s.store.CompleteLifecycleProof(r.Context(), store.LifecycleProof{
		TokenHash: sec.HashToken(ar.LinkToken.String),
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		AuthTime:  claims.AuthTime,
	}, s.now(), maxAge)
	if ae := s.mapLifecycleProofError(err); ae != nil {
		writeAPIError(w, ae)
		return
	}

	finalStatus := "deactivated"
	if lc.Kind == "reactivate" {
		finalStatus = "reactivated"
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  finalStatus,
		"issuer":  claims.Issuer,
		"subject": claims.Subject,
		"kind":    lc.Kind,
	})
}

func (s *Server) mapLifecycleStartError(err error) *APIError {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return tenantForbidden("identity is not bound in this tenant")
	case errors.Is(err, store.ErrLastIdentity):
		return lastIdentity("cannot deactivate the only usable identity of a member")
	case errors.Is(err, store.ErrLifecycleExpired):
		return lifecycleExpired("the reactivation window for this identity has closed; bind it again instead")
	case errors.Is(err, store.ErrLifecycleConflict):
		return lifecycleConflict("an identity lifecycle operation is already in progress or the state does not allow it")
	case errors.Is(err, store.ErrConflict):
		// 部分唯一索引兜底：并发发起同一流程。
		return lifecycleConflict("a conflicting lifecycle request was already accepted")
	}
	s.logger.Printf("start lifecycle failed: %v", err)
	return newAPIError(http.StatusInternalServerError, "internal_error", "start lifecycle failed")
}

func (s *Server) mapLifecycleProofError(err error) *APIError {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrLastIdentity):
		return lastIdentity("cannot deactivate the only usable identity of a member")
	case errors.Is(err, store.ErrLifecycleExpired):
		return lifecycleExpired("the lifecycle proof window has closed; the stale callback cannot change identity state")
	case errors.Is(err, store.ErrLifecycleConflict):
		return lifecycleConflict("the lifecycle proof cannot be applied in the current state")
	case errors.Is(err, store.ErrNotFound):
		return lifecycleConflict("lifecycle token not found or already consumed")
	}
	if msg, ok := store.AsReauth(err); ok {
		return reauthRequired(msg)
	}
	s.logger.Printf("complete lifecycle proof failed: %v", err)
	return newAPIError(http.StatusInternalServerError, "internal_error", "complete lifecycle failed")
}
