package config

import (
	"strings"
	"testing"
	"time"
)

var envKeys = []string{
	"PORT",
	"JWTSECRET",
	"MONGODB_URI",
	"DB_CONNECTION_STRING",
	"DB_NAME",
	"DB_USERNAME",
	"DB_PASSWORD",
	"DB_AUTH_SOURCE",
	"APP_BASE_URL",
	"CORS_ALLOWED_ORIGINS",
	"TRUST_PROXY",
	"DEBUG",
	"GMAIL_USERNAME",
	"GMAIL_APP_PASSWORD",
	"ACCESS_TOKEN_TTL",
	"REFRESH_TOKEN_TTL",
	"EMAIL_CONFIRMATION_TOKEN_TTL",
	"PASSWORD_RESET_TOKEN_TTL",
	"BCRYPT_COST",
	"MAX_BODY_MB",
	"MAX_PROFILE_PICTURE_MB",
}

func setValidEnv(t *testing.T) {
	t.Helper()
	for _, key := range envKeys {
		t.Setenv(key, "")
	}
	t.Setenv("JWTSECRET", strings.Repeat("s", 64))
	t.Setenv("MONGODB_URI", "mongodb://localhost:27017")
	t.Setenv("APP_BASE_URL", "https://api.example.com")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com,https://admin.example.com/")
}

func TestLoadDefaults(t *testing.T) {
	setValidEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}

	if cfg.Port != DefaultPort {
		t.Errorf("expected default port %d, got %d", DefaultPort, cfg.Port)
	}
	if cfg.DBName != DefaultDBName {
		t.Errorf("expected default db name %q, got %q", DefaultDBName, cfg.DBName)
	}
	if cfg.DBAuthSource != DefaultDBAuthSource {
		t.Errorf("expected default auth source %q, got %q", DefaultDBAuthSource, cfg.DBAuthSource)
	}
	if cfg.AccessTokenTTL != DefaultAccessTokenTTL {
		t.Errorf("expected default access TTL %s, got %s", DefaultAccessTokenTTL, cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != DefaultRefreshTokenTTL {
		t.Errorf("expected default refresh TTL %s, got %s", DefaultRefreshTokenTTL, cfg.RefreshTokenTTL)
	}
	if cfg.BcryptCost != DefaultBcryptCost {
		t.Errorf("expected default bcrypt cost %d, got %d", DefaultBcryptCost, cfg.BcryptCost)
	}
	if cfg.MaxBodyBytes != int64(DefaultMaxBodyMB)<<20 {
		t.Errorf("unexpected default max body: %d", cfg.MaxBodyBytes)
	}
	if cfg.MaxProfilePictureBytes != int64(DefaultMaxPictureMB)<<20 {
		t.Errorf("unexpected default max picture: %d", cfg.MaxProfilePictureBytes)
	}
	if cfg.BaseURL != "https://api.example.com" {
		t.Errorf("unexpected base URL: %q", cfg.BaseURL)
	}
	if len(cfg.CORSAllowedOrigins) != 2 || cfg.CORSAllowedOrigins[1] != "https://admin.example.com" {
		t.Errorf("unexpected CORS origins: %v", cfg.CORSAllowedOrigins)
	}
	if cfg.EmailEnabled {
		t.Error("expected email to be disabled without Gmail credentials")
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected a warning about disabled email delivery")
	}
}

func TestLoadAllowsCORSAnyOrigin(t *testing.T) {
	setValidEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", " * ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected wildcard CORS to load, got: %v", err)
	}
	if len(cfg.CORSAllowedOrigins) != 1 || cfg.CORSAllowedOrigins[0] != "*" {
		t.Fatalf("unexpected CORS origins: %v", cfg.CORSAllowedOrigins)
	}
}

func TestLoadOverrides(t *testing.T) {
	setValidEnv(t)
	t.Setenv("PORT", "8080")
	t.Setenv("DB_NAME", "gordian_test")
	t.Setenv("DB_AUTH_SOURCE", "test")
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("DEBUG", "true")
	t.Setenv("ACCESS_TOKEN_TTL", "5m")
	t.Setenv("REFRESH_TOKEN_TTL", "24h")
	t.Setenv("EMAIL_CONFIRMATION_TOKEN_TTL", "12h")
	t.Setenv("PASSWORD_RESET_TOKEN_TTL", "30m")
	t.Setenv("BCRYPT_COST", "10")
	t.Setenv("MAX_BODY_MB", "16")
	t.Setenv("MAX_PROFILE_PICTURE_MB", "8")
	t.Setenv("GMAIL_USERNAME", "from@example.com")
	t.Setenv("GMAIL_APP_PASSWORD", "app-password")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}

	if cfg.Port != 8080 || cfg.DBName != "gordian_test" || cfg.DBAuthSource != "test" {
		t.Errorf("unexpected scalar overrides: %+v", cfg)
	}
	if !cfg.TrustProxy || !cfg.Debug || !cfg.EmailEnabled {
		t.Errorf("unexpected boolean overrides: %+v", cfg)
	}
	if cfg.AccessTokenTTL != 5*time.Minute || cfg.RefreshTokenTTL != 24*time.Hour {
		t.Errorf("unexpected token TTL overrides: access=%s refresh=%s", cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	}
	if cfg.EmailConfirmationTokenTTL != 12*time.Hour || cfg.PasswordResetTokenTTL != 30*time.Minute {
		t.Errorf("unexpected email TTL overrides: confirmation=%s reset=%s", cfg.EmailConfirmationTokenTTL, cfg.PasswordResetTokenTTL)
	}
	if cfg.BcryptCost != 10 {
		t.Errorf("unexpected bcrypt cost: %d", cfg.BcryptCost)
	}
	if cfg.MaxBodyBytes != 16<<20 || cfg.MaxProfilePictureBytes != 8<<20 {
		t.Errorf("unexpected size overrides: body=%d picture=%d", cfg.MaxBodyBytes, cfg.MaxProfilePictureBytes)
	}
}

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "missing jwt secret", env: map[string]string{"JWTSECRET": ""}},
		{name: "missing mongo", env: map[string]string{"MONGODB_URI": "", "DB_CONNECTION_STRING": ""}},
		{name: "missing base url", env: map[string]string{"APP_BASE_URL": ""}},
		{name: "relative base url", env: map[string]string{"APP_BASE_URL": "/api"}},
		{name: "missing cors", env: map[string]string{"CORS_ALLOWED_ORIGINS": ""}},
		{name: "partial wildcard cors", env: map[string]string{"CORS_ALLOWED_ORIGINS": "https://*"}},
		{name: "wildcard mixed with origin", env: map[string]string{"CORS_ALLOWED_ORIGINS": "*,https://app.example.com"}},
		{name: "cors with path", env: map[string]string{"CORS_ALLOWED_ORIGINS": "https://app.example.com/foo"}},
		{name: "invalid port", env: map[string]string{"PORT": "70000"}},
		{name: "invalid bcrypt cost", env: map[string]string{"BCRYPT_COST": "31"}},
		{name: "bcrypt cost too low", env: map[string]string{"BCRYPT_COST": "4"}},
		{name: "invalid ttl", env: map[string]string{"ACCESS_TOKEN_TTL": "soon"}},
		{name: "refresh not longer than access", env: map[string]string{"ACCESS_TOKEN_TTL": "24h", "REFRESH_TOKEN_TTL": "12h"}},
		{name: "body too small for picture", env: map[string]string{"MAX_BODY_MB": "1", "MAX_PROFILE_PICTURE_MB": "10"}},
		{name: "partial gmail config", env: map[string]string{"GMAIL_USERNAME": "from@example.com"}},
		{name: "invalid trust proxy", env: map[string]string{"TRUST_PROXY": "yes"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setValidEnv(t)
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			if _, err := Load(); err == nil {
				t.Fatal("expected config validation error")
			}
		})
	}
}

func TestMongoURIHandling(t *testing.T) {
	setValidEnv(t)
	t.Setenv("MONGODB_URI", "")
	t.Setenv("DB_CONNECTION_STRING", "cluster.example.com")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if cfg.MongoURI != "mongodb+srv://cluster.example.com" {
		t.Fatalf("unexpected mongo URI: %q", cfg.MongoURI)
	}

	t.Setenv("DB_CONNECTION_STRING", "mongodb://localhost:27017")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if cfg.MongoURI != "mongodb://localhost:27017" {
		t.Fatalf("unexpected mongo URI: %q", cfg.MongoURI)
	}
}
