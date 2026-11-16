package services

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func templatesDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "templates"))
	if err != nil {
		t.Fatalf("failed to resolve templates directory: %v", err)
	}
	t.Setenv("APP_TEMPLATES_DIR", dir)
	return dir
}

func TestNewGmailSMTPEmailService(t *testing.T) {
	templatesDir(t)

	svc, err := NewGmailSMTPEmailService("Gordian <from@example.com>", "secretpass", "https://api.example.com/")
	if err != nil {
		t.Fatalf("expected constructor to succeed, got: %v", err)
	}
	mailer, ok := svc.(*GmailSMTPEmailService)
	if !ok {
		t.Fatalf("expected *GmailSMTPEmailService, got %T", svc)
	}
	if mailer.from != "from@example.com" {
		t.Fatalf("expected parsed from address, got %q", mailer.from)
	}
	if mailer.password != "secretpass" {
		t.Fatalf("expected password to be stored, got %q", mailer.password)
	}
	if mailer.baseURL != "https://api.example.com" {
		t.Fatalf("expected trailing slash to be trimmed, got %q", mailer.baseURL)
	}
	if mailer.confirmationTmpl == nil || mailer.passwordResetTmpl == nil {
		t.Fatal("expected templates to be parsed")
	}
}

func TestNewGmailSMTPEmailServiceValidation(t *testing.T) {
	templatesDir(t)

	for _, tc := range []struct {
		name     string
		username string
		password string
		baseURL  string
	}{
		{name: "missing username", username: "", password: "secret", baseURL: "https://api.example.com"},
		{name: "missing password", username: "from@example.com", password: "", baseURL: "https://api.example.com"},
		{name: "invalid username", username: "not-an-address", password: "secret", baseURL: "https://api.example.com"},
		{name: "missing base url", username: "from@example.com", password: "secret", baseURL: ""},
		{name: "invalid base url", username: "from@example.com", password: "secret", baseURL: "not-a-url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewGmailSMTPEmailService(tc.username, tc.password, tc.baseURL); err == nil {
				t.Fatal("expected constructor to fail")
			}
		})
	}
}

func TestDisabledEmailService(t *testing.T) {
	svc := NewDisabledEmailService()
	if err := svc.SendConfirmationEmail("user@example.com", "token"); !errors.Is(err, ErrEmailNotConfigured) {
		t.Fatalf("expected ErrEmailNotConfigured, got: %v", err)
	}
	if err := svc.SendPasswordResetEmail("user@example.com", "token"); !errors.Is(err, ErrEmailNotConfigured) {
		t.Fatalf("expected ErrEmailNotConfigured, got: %v", err)
	}
	if err := svc.SendEmailChangedNotice("old@example.com", "new@example.com"); !errors.Is(err, ErrEmailNotConfigured) {
		t.Fatalf("expected ErrEmailNotConfigured, got: %v", err)
	}
}

func TestSanitizeAddress(t *testing.T) {
	if got, err := sanitizeAddress("User <user@example.com>"); err != nil || got != "user@example.com" {
		t.Fatalf("expected parsed address, got %q err=%v", got, err)
	}
	if _, err := sanitizeAddress("user@example.com\r\nBcc: attacker@example.com"); err == nil {
		t.Fatal("expected header injection attempt to be rejected")
	}
	if _, err := sanitizeAddress("not-an-address"); err == nil {
		t.Fatal("expected malformed address to be rejected")
	}
}

func TestConfirmationLinkUsesConfiguredBaseURL(t *testing.T) {
	templatesDir(t)
	svc, err := NewGmailSMTPEmailService("from@example.com", "secret", "https://staging.example.com")
	if err != nil {
		t.Fatalf("failed to build email service: %v", err)
	}
	mailer := svc.(*GmailSMTPEmailService)

	var buf strings.Builder
	err = mailer.confirmationTmpl.Execute(&buf, map[string]any{
		"Year":             2026,
		"ConfirmationLink": "https://staging.example.com/api/v1/confirm-email/token",
	})
	if err != nil {
		t.Fatalf("failed to execute confirmation template: %v", err)
	}
	if !strings.Contains(buf.String(), "https://staging.example.com") {
		t.Fatal("expected confirmation template to render the configured base URL")
	}
}
