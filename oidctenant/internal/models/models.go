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

const (
	// IdentityStatusActive 身份正常，可登录/关联。
	IdentityStatusActive = "active"
	// IdentityStatusDeactivated 身份已停用：历史归属保留，但不能再建立会话或参与关联。
	IdentityStatusDeactivated = "deactivated"
)

type Identity struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	MemberID        uuid.UUID
	Issuer          string
	Subject         string
	Email           string
	EmailVerified   bool
	Status          string
	DeactivatedAt   NullTime
	ReactivateAfter NullTime
	ReactivateUntil NullTime
}

type AuthRequest struct {
	State          string
	Kind           string
	TenantID       uuid.UUID
	IDPID          uuid.UUID
	Nonce          string
	PKCEVerifier   string
	ReturnTo       string
	LinkToken      NullString
	LifecycleToken NullString
	SessionID      *uuid.UUID
	CreatedAt      time.Time
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

// LifecycleSession 是身份停用/恢复流程中等待 OIDC 证明的一次性会话。
type LifecycleSession struct {
	Token        string
	TenantID     uuid.UUID
	IdentityID   uuid.UUID
	MemberID     uuid.UUID
	SessionID    uuid.UUID
	IDPID        uuid.UUID
	Kind         string // "deactivate" | "reactivate"
	Issuer       string
	Subject      string
	Reason       string
	PendingState string
	Status       string // "pending" | "completed" | "consumed"
	ExpiresAt    time.Time
	WindowUntil  NullTime
	CreatedAt    time.Time
}

// LifecycleEvent 是身份生命周期的不可变历史事件（只追加）。
type LifecycleEvent struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	IdentityID      uuid.UUID
	MemberID        uuid.UUID
	Issuer          string
	Subject         string
	Action          string // "deactivated" | "reactivated"
	Reason          string
	ActorSessionID  uuid.NullUUID
	ProvenAuthTime  time.Time
	ReactivateAfter NullTime
	ReactivateUntil NullTime
	CreatedAt       time.Time
}
