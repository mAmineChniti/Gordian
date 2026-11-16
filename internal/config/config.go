package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPort            = 10000
	DefaultDBName          = "gordian"
	DefaultDBAuthSource    = "admin"
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour
	DefaultEmailTokenTTL   = 48 * time.Hour
	DefaultResetTokenTTL   = time.Hour
	DefaultBcryptCost      = 12
	DefaultMaxBodyMB       = 8
	DefaultMaxPictureMB    = 5
)

type Config struct {
	Port int

	JWTSecret []byte

	MongoURI     string
	DBName       string
	DBUsername   string
	DBPassword   string
	DBAuthSource string

	BaseURL            string
	CORSAllowedOrigins []string
	TrustProxy         bool
	Debug              bool

	GmailUsername string
	GmailPassword string
	EmailEnabled  bool

	AccessTokenTTL            time.Duration
	RefreshTokenTTL           time.Duration
	EmailConfirmationTokenTTL time.Duration
	PasswordResetTokenTTL     time.Duration
	MaxBodyBytes              int64
	MaxProfilePictureBytes    int64
	BcryptCost                int

	Warnings []string
}

// Load reads and validates runtime configuration from the environment.
func Load() (*Config, error) {
	port, err := parseIntEnv("PORT", DefaultPort, 1, 65535)
	if err != nil {
		return nil, err
	}

	secret := os.Getenv("JWTSECRET")
	if secret == "" {
		return nil, errors.New("JWTSECRET is required")
	}
	var warnings []string
	if len(secret) < 32 {
		warnings = append(warnings, "JWTSECRET is shorter than 32 bytes; use a longer random secret in production")
	}

	mongoURI, err := mongoURI()
	if err != nil {
		return nil, err
	}

	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("APP_BASE_URL")), "/")
	if baseURL == "" {
		return nil, errors.New("APP_BASE_URL is required (for example https://api.example.com)")
	}
	if u, err := url.Parse(baseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("APP_BASE_URL must be an absolute http(s) URL, got %q", baseURL)
	}

	origins, err := parseOrigins(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if err != nil {
		return nil, err
	}

	trustProxy, err := parseBool("TRUST_PROXY", os.Getenv("TRUST_PROXY"))
	if err != nil {
		return nil, err
	}
	debug, err := parseBool("DEBUG", os.Getenv("DEBUG"))
	if err != nil {
		return nil, err
	}

	accessTTL, err := parseDurationEnv("ACCESS_TOKEN_TTL", DefaultAccessTokenTTL)
	if err != nil {
		return nil, err
	}
	refreshTTL, err := parseDurationEnv("REFRESH_TOKEN_TTL", DefaultRefreshTokenTTL)
	if err != nil {
		return nil, err
	}
	confirmationTTL, err := parseDurationEnv("EMAIL_CONFIRMATION_TOKEN_TTL", DefaultEmailTokenTTL)
	if err != nil {
		return nil, err
	}
	resetTTL, err := parseDurationEnv("PASSWORD_RESET_TOKEN_TTL", DefaultResetTokenTTL)
	if err != nil {
		return nil, err
	}
	bcryptCost, err := parseIntEnv("BCRYPT_COST", DefaultBcryptCost, 10, 14)
	if err != nil {
		return nil, err
	}
	maxBodyMB, err := parseIntEnv("MAX_BODY_MB", DefaultMaxBodyMB, 1, 32)
	if err != nil {
		return nil, err
	}
	maxPictureMB, err := parseIntEnv("MAX_PROFILE_PICTURE_MB", DefaultMaxPictureMB, 1, 10)
	if err != nil {
		return nil, err
	}

	maxBodyBytes := int64(maxBodyMB) << 20
	maxPictureBytes := int64(maxPictureMB) << 20
	if maxBodyBytes < (maxPictureBytes*4)/3+1024 {
		return nil, errors.New("MAX_BODY_MB must be large enough to hold MAX_PROFILE_PICTURE_MB in base64")
	}
	if refreshTTL <= accessTTL {
		return nil, errors.New("REFRESH_TOKEN_TTL must be longer than ACCESS_TOKEN_TTL")
	}

	gmailUser := strings.TrimSpace(os.Getenv("GMAIL_USERNAME"))
	gmailPass := os.Getenv("GMAIL_APP_PASSWORD")
	if (gmailUser == "") != (gmailPass == "") {
		return nil, errors.New("GMAIL_USERNAME and GMAIL_APP_PASSWORD must be set together")
	}
	if gmailUser == "" {
		warnings = append(warnings, "email delivery disabled: GMAIL_USERNAME/GMAIL_APP_PASSWORD are not set")
	}

	return &Config{
		Port:                      port,
		JWTSecret:                 []byte(secret),
		MongoURI:                  mongoURI,
		DBName:                    envOrDefault("DB_NAME", DefaultDBName),
		DBUsername:                os.Getenv("DB_USERNAME"),
		DBPassword:                os.Getenv("DB_PASSWORD"),
		DBAuthSource:              envOrDefault("DB_AUTH_SOURCE", DefaultDBAuthSource),
		BaseURL:                   baseURL,
		CORSAllowedOrigins:        origins,
		TrustProxy:                trustProxy,
		Debug:                     debug,
		GmailUsername:             gmailUser,
		GmailPassword:             gmailPass,
		EmailEnabled:              gmailUser != "" && gmailPass != "",
		AccessTokenTTL:            accessTTL,
		RefreshTokenTTL:           refreshTTL,
		EmailConfirmationTokenTTL: confirmationTTL,
		PasswordResetTokenTTL:     resetTTL,
		MaxBodyBytes:              maxBodyBytes,
		MaxProfilePictureBytes:    maxPictureBytes,
		BcryptCost:                bcryptCost,
		Warnings:                  warnings,
	}, nil
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func parseIntEnv(name string, fallback, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d, got %q", name, min, max, raw)
	}
	return value, nil
}

func parseDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration (for example 15m or 168h), got %q", name, raw)
	}
	return value, nil
}

func parseBool(name, raw string) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean, got %q", name, raw)
	}
	return v, nil
}

func parseOrigins(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("CORS_ALLOWED_ORIGINS is required (comma-separated, for example https://app.example.com)")
	}
	if raw == "*" {
		return []string{"*"}, nil
	}

	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}
		if strings.Contains(origin, "*") {
			return nil, fmt.Errorf("CORS_ALLOWED_ORIGINS wildcard must be used alone, not combined with other entries: %q", origin)
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("CORS_ALLOWED_ORIGINS contains an invalid origin: %q", origin)
		}
		if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("CORS_ALLOWED_ORIGINS entries must be bare origins without paths or queries: %q", origin)
		}
		origins = append(origins, strings.TrimRight(origin, "/"))
	}
	if len(origins) == 0 {
		return nil, errors.New("CORS_ALLOWED_ORIGINS must contain at least one origin")
	}
	return origins, nil
}

func mongoURI() (string, error) {
	if uri := strings.TrimSpace(os.Getenv("MONGODB_URI")); uri != "" {
		return uri, nil
	}

	conn := strings.TrimSpace(os.Getenv("DB_CONNECTION_STRING"))
	if conn == "" {
		return "", errors.New("MONGODB_URI or DB_CONNECTION_STRING is required")
	}
	if strings.HasPrefix(conn, "mongodb://") || strings.HasPrefix(conn, "mongodb+srv://") {
		return conn, nil
	}
	return "mongodb+srv://" + strings.TrimPrefix(conn, "@"), nil
}
