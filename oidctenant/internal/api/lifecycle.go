package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

const maxReasonLen = 500

type deactivateRequest struct {
	Issuer string `json:"issuer"`
	// Subject 用于在同 issuer 多身份时精确定位；也可传 subject。
	Subject string `json:"subject"`
	// Reason 必填：停用原因会与 issuer/subject/时间一起写入不可变历史。
	Reason string `json:"reason"`
	// IdempotencyKey 可选；缺失时由服务端生成（每次 HTTP 请求一个新键）。
	// 客户端重试应带上同一个键，重放只产生一个终态。
	IdempotencyKey string `json:"idempotency_key"`
}

type reactivateRequest struct {
	Issuer         string `json:"issuer"`
	Subject        string `json:"subject"`
	IdempotencyKey string `json:"idempotency_key"`
}

// POST /t/{slug}/api/identities/deactivations
func (s *Server) deactivateStart(w http.ResponseWriter, r *http.Request) {
	var req deactivateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		writeAPIError(w, badRequest("invalid JSON body"))
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		writeAPIError(w, badRequest("reason is required for deactivation"))
		return
	}
	if len(req.Reason) > maxReasonLen {
		writeAPIError(w, badRequest("reason is too long"))
		return
	}
	s.startLifecycle(w, r, "deactivate", req.Issuer, req.Subject, req.Reason, req.IdempotencyKey)
}

// POST /t/{slug}/api/identities/reactivations
func (s *Server) reactivateStart(w http.ResponseWriter, r *http.Request) {
	var req reactivateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		writeAPIError(w, badRequest("invalid JSON body"))
		return
	}
	s.startLifecycle(w, r, "reactivate", req.Issuer, req.Subject, "", req.IdempotencyKey)
}

// startLifecycle 同时承载停用与恢复发起：
// 解析锚点身份 -> 事务内校验状态/窗口/最后身份 -> 建立一次性挑战会话 ->
// 创建 state/nonce/PKCE 的 OIDC 授权请求（强制重新认证）。
func (s *Server) startLifecycle(w http.ResponseWriter, r *http.Request,
	kind, issuer, subject, reason, idemKey string) {
	ac := authed(r)
	slug := r.PathValue("slug")

	if issuer == "" || subject == "" {
		writeAPIError(w, badRequest("issuer and subject are required"))
		return
	}
	tenant, prov, ae := s.loadTenantProvider(r.Context(), slug, issuer)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	// 身份必须已绑定给当前成员（查找严格限定在本租户）。
	identity, err := s.store.IdentityByAnchor(r.Context(), tenant.ID, issuer, subject)
	if err != nil {
		writeAPIError(w, notFound("identity is not bound in this tenant"))
		return
	}
	if identity.MemberID != ac.member.ID {
		// 不暴露身份是否属于别人：统一按“本租户内不存在”处理。
		writeAPIError(w, notFound("identity is not bound to the current member"))
		return
	}

	if strings.TrimSpace(idemKey) == "" {
		idemKey, err = sec.IdempotencyKey()
		if err != nil {
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "idempotency key failed"))
			return
		}
	}

	lcToken, err := sec.LifecycleToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lifecycle token failed"))
		return
	}
	res, err := s.store.StartLifecycle(r.Context(), store.LifecycleStartInput{
		Kind:           kind,
		TenantID:       tenant.ID,
		IdentityID:     identity.ID,
		MemberID:       ac.member.ID,
		SessionID:      ac.session.ID,
		IDPID:          prov.ID,
		Issuer:         issuer,
		Subject:        subject,
		Reason:         reason,
		IdempotencyKey: idemKey,
		Token:          lcToken,
		ChallengeTTL:   s.cfg.LifecycleChallengeTTL,
	})
	if err != nil {
		writeAPIError(w, s.mapLifecycleStartError(err))
		return
	}
	if res.Terminal {
		// 该幂等键对应的会话已到终态。回传身份的“当前”状态，避免身份在那之后
		// 又被恢复/停用时旧请求给出过期结论；不新建任何状态。
		current, err := s.store.IdentityByAnchor(r.Context(), tenant.ID, issuer, subject)
		if err != nil {
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "load identity failed"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": lifecycleResponseStatus(current.Status),
			"state":  s.identityState(current),
		})
		return
	}
	ls := res.Session

	redirectURI := s.callbackPathForKind(kind)
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	// 重放（已有 pending 会话）：取回它未消费的授权请求，重建同一个授权 URL。
	var ar *models.AuthRequest
	if !res.Created {
		ar, err = s.store.AuthRequestByLifecycleToken(r.Context(), ls.Token)
		if err != nil {
			// 原授权请求已被消费/过期：旧挑战不能复活，返回当前会话状态让调用方重新发起。
			writeJSON(w, http.StatusOK, map[string]any{
				"lifecycle_token": ls.Token,
				"status":          ls.Status,
				"identity_status": s.identityState(identity),
			})
			return
		}
	} else {
		state, gerr := sec.State()
		if gerr != nil {
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "state failed"))
			return
		}
		nonce, gerr := sec.Nonce()
		if gerr != nil {
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "nonce failed"))
			return
		}
		verifier, gerr := sec.PKCEVerifier()
		if gerr != nil {
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "pkce failed"))
			return
		}
		sessionID := ac.session.ID
		ar = &models.AuthRequest{
			State: state, Kind: kind, TenantID: tenant.ID, IDPID: prov.ID,
			Nonce: nonce, PKCEVerifier: verifier, ReturnTo: "/",
			LifecycleToken: nullString(ls.Token), SessionID: &sessionID,
		}
		if err := s.store.CreateAuthRequest(r.Context(), ar); err != nil {
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist auth request failed"))
			return
		}
		if err := s.store.SetLifecyclePendingState(r.Context(), ls.Token, state); err != nil {
			writeAPIError(w, lifecycleConflict("lifecycle session is not in a usable state"))
			return
		}
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	challenge := oauth2.S256ChallengeFromVerifier(ar.PKCEVerifier)
	authURL := oidcx.AuthCodeURL(cfg, ar.State, ar.Nonce, challenge, "S256", true, nil)

	status := http.StatusCreated
	if !res.Created {
		// 重复请求：返回同一个挑战（200），绝不产生第二个终态。
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"lifecycle_token": ls.Token,
		"status":          "pending",
		"auth_url":        authURL,
	})
}

func (s *Server) callbackPathForKind(kind string) string {
	if kind == "reactivate" {
		return s.cfg.BaseURL + reactivateCBPath
	}
	return s.cfg.BaseURL + deactivateCBPath
}

func (s *Server) mapLifecycleStartError(err error) *APIError {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return notFound("identity is not bound to the current member")
	case errors.Is(err, store.ErrLastIdentity):
		return lastIdentity("the last active identity of a member cannot be deactivated")
	case errors.Is(err, store.ErrRecoveryWindow):
		return recoveryWindow("identity recovery is not allowed outside the configured window")
	case errors.Is(err, store.ErrLifecycleState), errors.Is(err, store.ErrConflict):
		return lifecycleConflict("identity lifecycle operation is not valid in the current state")
	default:
		s.logger.Printf("start lifecycle failed: %v", err)
		return newAPIError(http.StatusInternalServerError, "internal_error", "start lifecycle failed")
	}
}

// lifecycleCallback 返回停用/恢复共用的回调处理器（强制新 OIDC 证明）。
//
// 迟到回调保护：state 一次性消费；CompleteLifecycle 在身份行锁下复核
// 身份当前状态与恢复窗口，停用后的旧登录/关联回调无法把身份改回 active。
func (s *Server) lifecycleCallback(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if ar.Kind != kind || !ar.LifecycleToken.Valid {
			writeAPIError(w, badRequest("state is not valid for this identity lifecycle operation"))
			return
		}
		if ar.SessionID == nil || *ar.SessionID != ac.session.ID {
			writeAPIError(w, authn("lifecycle operation must be completed in the same browser session that started it"))
			return
		}
		if ar.TenantID != ac.session.TenantID {
			writeAPIError(w, tenantForbidden("lifecycle operation crosses tenant boundary"))
			return
		}

		ls, err := s.store.LifecycleSession(r.Context(), ar.LifecycleToken.String)
		if err != nil {
			writeAPIError(w, lifecycleConflict("lifecycle session not found"))
			return
		}
		if ls.Kind != kind || ls.Status != "pending" {
			writeAPIError(w, lifecycleConflict("lifecycle session already completed or consumed"))
			return
		}
		if ls.MemberID != ac.member.ID || ls.TenantID != ac.session.TenantID {
			writeAPIError(w, tenantForbidden("lifecycle session belongs to another member or tenant"))
			return
		}
		if ls.IDPID != ar.IDPID {
			writeAPIError(w, badRequest("state was issued for a different provider"))
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
		redirectURI := s.callbackPathForKind(kind)
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

		// 新证明必须是针对目标身份本身的、在 provider 窗口内的交互式重新认证。
		if claims.Issuer != ls.Issuer || claims.Subject != ls.Subject {
			writeAPIError(w, reauthRequired("the new proof does not identify the targeted identity"))
			return
		}
		maxAge := providerAuthMaxAge(prov)
		if claims.AuthTime.IsZero() {
			writeAPIError(w, reauthRequired("provider did not report auth_time; cannot prove fresh authentication"))
			return
		}
		if s.now().Sub(claims.AuthTime) > maxAge {
			writeAPIError(w, reauthRequired("identity proof is stale; re-authenticate"))
			return
		}

		event, err := s.store.CompleteLifecycle(r.Context(), store.LifecycleProof{
			Token:              ls.Token,
			State:              state,
			Issuer:             claims.Issuer,
			Subject:            claims.Subject,
			AuthTime:           claims.AuthTime,
			MaxAge:             maxAge,
			Now:                s.now(),
			ReactivateCooldown: s.cfg.ReactivateCooldown,
			ReactivateTTL:      s.cfg.ReactivateTTL,
		})
		if err != nil {
			writeAPIError(w, s.mapLifecycleCompleteError(err))
			return
		}
		if err := s.store.ConsumeCompletedLifecycle(r.Context(), ls.Token); err != nil {
			writeAPIError(w, lifecycleConflict("lifecycle completed but the one-time token could not be consumed"))
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":           kind + "d",
			"identity":         map[string]string{"issuer": ls.Issuer, "subject": ls.Subject},
			"identity_status":  lifecycleIdentityStatus(kind),
			"event_id":         event.ID.String(),
			"reactivate_after": rfc3339OrEmpty(event.ReactivateAfter),
			"reactivate_until": rfc3339OrEmpty(event.ReactivateUntil),
		})
	}
}

func lifecycleIdentityStatus(kind string) string {
	if kind == "reactivate" {
		return models.IdentityStatusActive
	}
	return models.IdentityStatusDeactivated
}

// lifecycleResponseStatus 把身份状态映射成发起/重放响应里的稳定 status 字符串。
func lifecycleResponseStatus(status string) string {
	if status == models.IdentityStatusActive {
		return "active"
	}
	return "deactivated"
}

func rfc3339OrEmpty(t models.NullTime) string {
	if !t.Valid {
		return ""
	}
	return t.Time.UTC().Format(time.RFC3339)
}

func (s *Server) mapLifecycleCompleteError(err error) *APIError {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return notFound("lifecycle session or identity no longer exists")
	case errors.Is(err, store.ErrLastIdentity):
		return lastIdentity("the last active identity of a member cannot be deactivated")
	case errors.Is(err, store.ErrRecoveryWindow):
		return recoveryWindow("identity recovery is outside the allowed window")
	case errors.Is(err, store.ErrIdentityDeactivated):
		return identityInactive("identity has been deactivated")
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrLifecycleState):
		return lifecycleConflict("lifecycle session is not in a valid state for completion")
	}
	if msg, ok := store.AsReauth(err); ok {
		return reauthRequired(msg)
	}
	s.logger.Printf("complete lifecycle failed: %v", err)
	return newAPIError(http.StatusInternalServerError, "internal_error", "complete lifecycle failed")
}

// GET /t/{slug}/api/identities/history?issuer=...&subject=...
//
// 返回该身份在本租户内的停用/恢复历史（issuer/subject/原因/时间/窗口），
// 严格限定为当前成员拥有的身份；历史只追加，恢复不会覆写停用记录。
func (s *Server) identityHistory(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	issuer := r.URL.Query().Get("issuer")
	subject := r.URL.Query().Get("subject")
	if issuer == "" || subject == "" {
		writeAPIError(w, badRequest("issuer and subject query parameters are required"))
		return
	}
	identity, err := s.store.IdentityByAnchor(r.Context(), ac.session.TenantID, issuer, subject)
	if err != nil {
		writeAPIError(w, notFound("identity is not bound in this tenant"))
		return
	}
	if identity.MemberID != ac.member.ID {
		writeAPIError(w, notFound("identity is not bound to the current member"))
		return
	}
	events, err := s.store.LifecycleEvents(r.Context(), ac.session.TenantID, identity.ID)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "load history failed"))
		return
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"event_id":         e.ID.String(),
			"action":           e.Action,
			"issuer":           e.Issuer,
			"subject":          e.Subject,
			"reason":           e.Reason,
			"proven_auth_time": e.ProvenAuthTime.UTC().Format(time.RFC3339),
			"created_at":       e.CreatedAt.UTC().Format(time.RFC3339),
			"reactivate_after": rfc3339OrEmpty(e.ReactivateAfter),
			"reactivate_until": rfc3339OrEmpty(e.ReactivateUntil),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"identity": map[string]string{"issuer": issuer, "subject": subject},
		"status":   s.identityState(identity),
		"events":   out,
	})
}

func (s *Server) identityState(identity *models.Identity) map[string]string {
	st := map[string]string{
		"status": identity.Status,
	}
	if identity.ReactivateAfter.Valid {
		st["reactivate_after"] = identity.ReactivateAfter.Time.UTC().Format(time.RFC3339)
	}
	if identity.ReactivateUntil.Valid {
		st["reactivate_until"] = identity.ReactivateUntil.Time.UTC().Format(time.RFC3339)
	}
	return st
}
