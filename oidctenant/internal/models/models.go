// Package models 定义持久化层的数据结构。
package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// NullString / NullTime 复用标准库可空标量类型，便于 pgx 直接互操作。
type (
	NullString = sql.NullString
	NullTime   = sql.NullTime
	// NullUUID 是可空 uuid（Go 1.22+ 的泛型 sql.Null）。
	NullUUID = sql.Null[uuid.UUID]
)

type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	CreatedAt time.Time
}

type Provider struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	Issuer         string
	ClientID       string
	ClientSecret   string
	RedirectURIs   []string
	AuthTimeMaxAge int
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Member struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	DisplayName string
	CreatedAt   time.Time
}

type Identity struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	MemberID      uuid.UUID
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	// Status 为身份生命周期状态：
	// active（可用）/ deactivation_pending（停用待证明，已不可登录）/ disabled（已停用）。
	Status string
}

// IdentityLifecycle 是一次停用/恢复意图：必须由身份持有者完成新的 OIDC
// 证明（auth_time 在窗口内）后才推进到终态。
type IdentityLifecycle struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	IdentityID     uuid.UUID
	MemberID       uuid.UUID
	Kind           string // deactivate | reactivate
	Status         string // pending | deactivated | reactivated | expired
	TokenHash      []byte
	IdempotencyKey NullString
	Issuer         string
	Subject        string
	Reason         string
	SessionID      uuid.UUID
	ProofIssuer    string
	ProofSubject   string
	ProofAuthTime  NullTime
	CreatedAt      time.Time
	ExpiresAt      time.Time
	CompletedAt    NullTime
}

// IdentityEvent 是只追加的身份生命周期历史记录。
type IdentityEvent struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	IdentityID    NullUUID
	LifecycleID   NullUUID
	MemberID      NullUUID
	Kind          string
	Issuer        string
	Subject       string
	Reason        string
	ProofIssuer   string
	ProofSubject  string
	ProofAuthTime NullTime
	CreatedAt     time.Time
}

type AuthRequest struct {
	State        string
	Kind         string
	TenantID     uuid.UUID
	IDPID        uuid.UUID
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
	LinkToken    NullString
	SessionID    *uuid.UUID
	CreatedAt    time.Time
}

type Session struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	MemberID  uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
}

type LinkSession struct {
	Token          string
	TenantID       uuid.UUID
	AnchorMemberID uuid.UUID
	SessionID      uuid.UUID
	TargetIDPID    uuid.UUID
	AIssuer        string
	ASubject       string
	AAuthTime      NullTime
	BIssuer        string
	BSubject       string
	BEmail         string
	BAuthTime      NullTime
	BIDPID         uuid.UUID
	BState         string
	Status         string
	ExpiresAt      time.Time
}
