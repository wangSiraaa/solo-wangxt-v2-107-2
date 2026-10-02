package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/example/oidctenant/internal/store"
)

// GET /t/{slug}/api/identities/events?issuer=...&subject=...
//
// 返回该锚点身份只追加的生命周期历史：发起/终态/原因/证明人/时间齐全。
// 查询本身也严格按 (tenant, issuer, subject) 锚定，绝不按邮箱查询。
func (s *Server) identityEvents(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	issuer := r.URL.Query().Get("issuer")
	subject := r.URL.Query().Get("subject")
	if issuer == "" || subject == "" {
		writeAPIError(w, badRequest("issuer and subject query parameters are required"))
		return
	}

	identity, err := s.store.IdentityByAnchor(r.Context(), ac.session.TenantID, issuer, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, tenantForbidden("identity is not bound in this tenant"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lookup identity failed"))
		return
	}
	if identity.MemberID != ac.member.ID {
		writeAPIError(w, tenantForbidden("identity is not bound to the current member"))
		return
	}

	events, err := s.store.IdentityEvents(r.Context(), ac.session.TenantID, identity.ID)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "load identity history failed"))
		return
	}
	out := make([]identityEventView, 0, len(events))
	for _, e := range events {
		v := identityEventView{
			Kind:         e.Kind,
			Issuer:       e.Issuer,
			Subject:      e.Subject,
			Reason:       e.Reason,
			ProofIssuer:  e.ProofIssuer,
			ProofSubject: e.ProofSubject,
			CreatedAt:    e.CreatedAt,
		}
		if e.ProofAuthTime.Valid {
			t := e.ProofAuthTime.Time
			v.ProofAuthTime = &t
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"identity": identityView{
			Issuer:        identity.Issuer,
			Subject:       identity.Subject,
			Email:         identity.Email,
			EmailVerified: identity.EmailVerified,
			Status:        identity.Status,
		},
		"events": out,
	})
}

type identityEventView struct {
	Kind          string     `json:"kind"`
	Issuer        string     `json:"issuer"`
	Subject       string     `json:"subject"`
	Reason        string     `json:"reason,omitempty"`
	ProofIssuer   string     `json:"proof_issuer,omitempty"`
	ProofSubject  string     `json:"proof_subject,omitempty"`
	ProofAuthTime *time.Time `json:"proof_auth_time,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}
