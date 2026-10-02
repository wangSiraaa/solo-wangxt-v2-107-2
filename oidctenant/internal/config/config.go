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
	// LifecycleChallengeTTL 停用/恢复 OIDC 证明挑战自身的有效期。
	LifecycleChallengeTTL time.Duration
	// ReactivateCooldown 停用后必须等待多久才允许发起恢复。
	ReactivateCooldown time.Duration
	// ReactivateTTL 停用后恢复窗口的总长度（恢复必须在该时刻之前完成）。
	ReactivateTTL   time.Duration
	CookieSecure    bool
	CookieSameSite  string
	CleanupInterval time.Duration
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// getenvDuration 解析 Go duration 形式（如 "30s"/"10m"/"72h"）；
// 缺失或非法时回退到默认值，避免错误配置让服务启动失败。
func getenvDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		BaseURL:               strings.TrimRight(getenv("BASE_URL", "http://localhost:8080"), "/"),
		Addr:                  getenv("ADDR", ":8080"),
		SessionTTL:            8 * time.Hour,
		LinkTTL:               10 * time.Minute,
		AuthRequestTTL:        10 * time.Minute,
		LifecycleChallengeTTL: getenvDuration("LIFECYCLE_CHALLENGE_TTL", 10*time.Minute),
		// 停用 24 小时内是冷静期；恢复窗口在停用后 7 天关闭。
		ReactivateCooldown: getenvDuration("REACTIVATE_COOLDOWN", 24*time.Hour),
		ReactivateTTL:      getenvDuration("REACTIVATE_WINDOW_TTL", 7*24*time.Hour),
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
