// Package config 读取进程环境配置。
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string
	// BaseURL 是本应用对外可达地址，回调路径固定为 /oauth/callback。
	BaseURL string
	Addr    string

	SessionTTL     time.Duration
	LinkTTL        time.Duration
	AuthRequestTTL time.Duration
	// LifecycleProofTTL 是停用/恢复流程从发起到完成新 OIDC 证明的最长时间。
	LifecycleProofTTL time.Duration
	// ReactivationWindow 是停用完成后允许发起恢复的明确窗口；窗口外拒绝恢复。
	ReactivationWindow time.Duration
	CookieSecure       bool
	CookieSameSite     string
	CleanupInterval    time.Duration
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// parseDur 解析形如 "300s"/"10m"/"24h" 的时长环境变量，缺省或非法时回退默认值。
func parseDur(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		BaseURL:            strings.TrimRight(getenv("BASE_URL", "http://localhost:8080"), "/"),
		Addr:               getenv("ADDR", ":8080"),
		SessionTTL:         8 * time.Hour,
		LinkTTL:            10 * time.Minute,
		AuthRequestTTL:     10 * time.Minute,
		LifecycleProofTTL:  parseDur("LIFECYCLE_PROOF_TTL", 10*time.Minute),
		ReactivationWindow: parseDur("REACTIVATION_WINDOW", 24*time.Hour),
		CookieSecure:       os.Getenv("COOKIE_SECURE") == "true",
		CookieSameSite:     getenv("COOKIE_SAMESITE", "lax"),
		CleanupInterval:    time.Minute,
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("BASE_URL is required")
	}
	return cfg, nil
}
