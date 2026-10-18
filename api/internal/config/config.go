// Package config loads runtime configuration from environment variables.
// No secret has a default value outside development.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env              string // development | staging | production
	HTTPAddr         string
	DatabaseURL      string
	RedisURL         string
	PublicBaseURL    string
	AllowedOrigins   []string
	CookieSecure     bool
	TrustProxyHeader bool

	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string

	DataEncryptionKey []byte // 32 bytes, AES-256-GCM for MFA secrets
	APIKeyPepper      []byte // >= 32 bytes, HMAC key for API key verifiers

	SessionIdleTimeout     time.Duration
	SessionAbsoluteTimeout time.Duration
	AdminRequireMFA        bool
	MaxUploadBytes         int64
	StorageDir             string
}

func (c *Config) IsDev() bool { return c.Env == "development" }

func Load() (*Config, error) {
	c := &Config{
		Env:                    getenv("RB_ENV", "development"),
		HTTPAddr:               getenv("RB_HTTP_ADDR", ":8080"),
		DatabaseURL:            os.Getenv("RB_DATABASE_URL"),
		RedisURL:               os.Getenv("RB_REDIS_URL"),
		PublicBaseURL:          strings.TrimRight(getenv("RB_PUBLIC_BASE_URL", "http://localhost:5173"), "/"),
		StorageDir:             getenv("RB_STORAGE_DIR", "./data/storage"),
		SMTPHost:               getenv("RB_SMTP_HOST", "localhost"),
		SMTPUser:               os.Getenv("RB_SMTP_USER"),
		SMTPPassword:           os.Getenv("RB_SMTP_PASSWORD"),
		SMTPFrom:               getenv("RB_SMTP_FROM", "ReverseBug <no-reply@reversebug.local>"),
		SessionIdleTimeout:     getDuration("RB_SESSION_IDLE_TIMEOUT", 12*time.Hour),
		SessionAbsoluteTimeout: getDuration("RB_SESSION_ABSOLUTE_TIMEOUT", 7*24*time.Hour),
		TrustProxyHeader:       getBool("RB_TRUST_PROXY_HEADERS", false),
	}
	switch c.Env {
	case "development", "staging", "production":
	default:
		return nil, fmt.Errorf("RB_ENV must be development, staging or production (got %q)", c.Env)
	}
	if c.DatabaseURL == "" {
		return nil, errors.New("RB_DATABASE_URL is required")
	}
	c.SMTPPort = getInt("RB_SMTP_PORT", 1025)
	c.CookieSecure = getBool("RB_COOKIE_SECURE", !c.IsDev())
	c.AdminRequireMFA = getBool("RB_ADMIN_REQUIRE_MFA", !c.IsDev())
	c.MaxUploadBytes = int64(getInt("RB_MAX_UPLOAD_MB", 200)) * 1024 * 1024

	origins := getenv("RB_ALLOWED_ORIGINS", c.PublicBaseURL)
	for _, o := range strings.Split(origins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.AllowedOrigins = append(c.AllowedOrigins, o)
		}
	}

	var err error
	if c.DataEncryptionKey, err = loadKey("RB_DATA_ENCRYPTION_KEY", 32, c.IsDev()); err != nil {
		return nil, err
	}
	if c.APIKeyPepper, err = loadKey("RB_API_KEY_PEPPER", 32, c.IsDev()); err != nil {
		return nil, err
	}
	if !c.IsDev() && !c.CookieSecure {
		return nil, errors.New("RB_COOKIE_SECURE must be true outside development")
	}
	return c, nil
}

// loadKey reads a base64 key. In development only, a random ephemeral key is
// generated if unset (data encrypted with it will not survive restarts).
func loadKey(name string, minLen int, dev bool) ([]byte, error) {
	v := os.Getenv(name)
	if v == "" {
		if !dev {
			return nil, fmt.Errorf("%s is required outside development", name)
		}
		slog.Warn("generating ephemeral development key; set it in .env to persist", "var", name)
		b := make([]byte, minLen)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		return b, nil
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64: %w", name, err)
	}
	if len(b) < minLen {
		return nil, fmt.Errorf("%s must decode to at least %d bytes", name, minLen)
	}
	return b, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func getBool(k string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func getDuration(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return v
	}
	return def
}
