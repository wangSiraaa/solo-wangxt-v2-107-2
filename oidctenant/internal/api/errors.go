// Package api 实现 OIDC 登录、会话与账号关联的 HTTP 接口。
package api

import (
	"errors"
	"net/http"
)

// ErrorType 是对客户端暴露的稳定错误类别。
type ErrorType string

const (
	// ErrAuthn 认证失败：state/nonce/PKCE/签名/受众/令牌交换等任何环节未通过。
	ErrAuthn ErrorType = "authentication_failed"
	// ErrTenantForbidden 租户未授权：租户未启用该 issuer，或身份不属于目标租户。
	ErrTenantForbidden ErrorType = "tenant_unauthorized"
	// ErrBindingConflict 绑定冲突：身份已关联到其他成员，或关联会话状态不允许。
	ErrBindingConflict ErrorType = "binding_conflict"
	// ErrInvalidRequest 请求参数非法或回调地址不在白名单。
	ErrInvalidRequest ErrorType = "invalid_request"
	// ErrReauthRequired 关联账号/身份生命周期操作时身份未在规定时间内重新认证。
	ErrReauthRequired ErrorType = "reauthentication_required"
	// ErrIdentityInactive 身份已停用：登录/关联回调命中停用状态边界。
	ErrIdentityInactive ErrorType = "identity_deactivated"
	// ErrLastIdentity 成员最后一个可用身份不允许停用。
	ErrLastIdentity ErrorType = "last_active_identity"
	// ErrRecoveryWindow 恢复不在允许窗口内（冷却期未到或窗口已关闭）。
	ErrRecoveryWindow ErrorType = "recovery_window_closed"
	// ErrIdentityLifecycle 生命周期会话状态非法（过期、已消费、与身份现状不符）。
	ErrIdentityLifecycle ErrorType = "identity_lifecycle_conflict"
	// ErrNotFound 资源不存在（或不属于当前成员/租户）。
	ErrNotFound ErrorType = "not_found"
)

// APIError 携带 HTTP 状态、稳定错误码与可展示的简短描述。
// 描述中绝不包含 ID token、access token、code 等敏感材料。
type APIError struct {
	Status  int       `json:"-"`
	Type    ErrorType `json:"error"`
	Message string    `json:"message"`
}

func (e *APIError) Error() string { return string(e.Type) + ": " + e.Message }

func newAPIError(status int, t ErrorType, msg string) *APIError {
	return &APIError{Status: status, Type: t, Message: msg}
}

func authn(msg string) *APIError {
	return newAPIError(http.StatusUnauthorized, ErrAuthn, msg)
}

func tenantForbidden(msg string) *APIError {
	return newAPIError(http.StatusForbidden, ErrTenantForbidden, msg)
}

func conflict(msg string) *APIError {
	return newAPIError(http.StatusConflict, ErrBindingConflict, msg)
}

func badRequest(msg string) *APIError {
	return newAPIError(http.StatusBadRequest, ErrInvalidRequest, msg)
}

func reauthRequired(msg string) *APIError {
	return newAPIError(http.StatusUnauthorized, ErrReauthRequired, msg)
}

func identityInactive(msg string) *APIError {
	return newAPIError(http.StatusForbidden, ErrIdentityInactive, msg)
}

func lastIdentity(msg string) *APIError {
	return newAPIError(http.StatusConflict, ErrLastIdentity, msg)
}

func recoveryWindow(msg string) *APIError {
	return newAPIError(http.StatusConflict, ErrRecoveryWindow, msg)
}

func lifecycleConflict(msg string) *APIError {
	return newAPIError(http.StatusConflict, ErrIdentityLifecycle, msg)
}

// notFound 用于身份/资源查找失败。业务上通常是“不属于当前成员或租户”，
// 状态码使用 404 而非 403，避免借此枚举其他成员的身份锚点。
func notFound(msg string) *APIError {
	return newAPIError(http.StatusNotFound, ErrNotFound, msg)
}

func asAPIError(err error) (*APIError, bool) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}
