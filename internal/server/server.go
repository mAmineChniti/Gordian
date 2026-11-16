package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"github.com/mAmineChniti/Gordian/internal/config"
	"github.com/mAmineChniti/Gordian/internal/database"
)

const (
	loginAttemptLimit = 5
	loginWindow       = 10 * time.Minute
	loginBlock        = 15 * time.Minute

	loginIPAttemptLimit = 20
	loginIPWindow       = 10 * time.Minute
	loginIPBlock        = 15 * time.Minute

	registerAttemptLimit = 5
	registerWindow       = time.Hour
	registerBlock        = time.Hour

	passwordResetAttemptLimit   = 3
	passwordResetIPAttemptLimit = 10
	passwordResetWindow         = 15 * time.Minute
	passwordResetBlock          = 30 * time.Minute

	resendAttemptLimit   = 3
	resendIPAttemptLimit = 10
	resendWindow         = time.Hour
	resendBlock          = time.Hour

	lookupAttemptLimit = 120
	lookupWindow       = time.Minute
	lookupBlock        = 5 * time.Minute
)

type Server struct {
	port int
	cfg  *config.Config
	db   database.Service

	loginLimiter           *attemptLimiter
	loginIPLimiter         *attemptLimiter
	registerLimiter        *attemptLimiter
	passwordResetLimiter   *attemptLimiter
	passwordResetIPLimiter *attemptLimiter
	resendLimiter          *attemptLimiter
	resendIPLimiter        *attemptLimiter
	lookupLimiter          *attemptLimiter
}

// NewServer wires configuration, persistence and HTTP middleware together.
func NewServer(cfg *config.Config, db database.Service) (*http.Server, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if db == nil {
		return nil, errors.New("database service is required")
	}

	s := &Server{
		port: cfg.Port,
		cfg:  cfg,
		db:   db,
		loginLimiter: newAttemptLimiter(limiterConfig{
			limit:  loginAttemptLimit,
			window: loginWindow,
			block:  loginBlock,
		}),
		loginIPLimiter: newAttemptLimiter(limiterConfig{
			limit:  loginIPAttemptLimit,
			window: loginIPWindow,
			block:  loginIPBlock,
		}),
		registerLimiter: newAttemptLimiter(limiterConfig{
			limit:  registerAttemptLimit,
			window: registerWindow,
			block:  registerBlock,
		}),
		passwordResetLimiter: newAttemptLimiter(limiterConfig{
			limit:  passwordResetAttemptLimit,
			window: passwordResetWindow,
			block:  passwordResetBlock,
		}),
		passwordResetIPLimiter: newAttemptLimiter(limiterConfig{
			limit:  passwordResetIPAttemptLimit,
			window: passwordResetWindow,
			block:  passwordResetBlock,
		}),
		resendLimiter: newAttemptLimiter(limiterConfig{
			limit:  resendAttemptLimit,
			window: resendWindow,
			block:  resendBlock,
		}),
		resendIPLimiter: newAttemptLimiter(limiterConfig{
			limit:  resendIPAttemptLimit,
			window: resendWindow,
			block:  resendBlock,
		}),
		lookupLimiter: newAttemptLimiter(limiterConfig{
			limit:  lookupAttemptLimit,
			window: lookupWindow,
			block:  lookupBlock,
		}),
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", cfg.Port),
		Handler:           s.RegisterRoutes(),
		IdleTimeout:       75 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	return httpServer, nil
}
