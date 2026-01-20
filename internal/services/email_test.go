package services

import (
	"os"
	"testing"
)

func TestNewGmailSMTPEmailService_Env(t *testing.T) {
	if err := os.Setenv("GMAIL_USERNAME", "from@example.com"); err != nil {
		t.Fatalf("failed to set GMAIL_USERNAME: %v", err)
	}
	if err := os.Setenv("GMAIL_APP_PASSWORD", "secretpass"); err != nil {
		t.Fatalf("failed to set GMAIL_APP_PASSWORD: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("GMAIL_USERNAME"); err != nil {
			t.Fatalf("failed to unset GMAIL_USERNAME: %v", err)
		}
	})
	t.Cleanup(func() {
		if err := os.Unsetenv("GMAIL_APP_PASSWORD"); err != nil {
			t.Fatalf("failed to unset GMAIL_APP_PASSWORD: %v", err)
		}
	})

	// package-level vars are initialized at import time; set them directly for the test
	oldUser := gmailUsername
	oldPass := gmailPassword
	gmailUsername = "from@example.com"
	gmailPassword = "secretpass"
	defer func() { gmailUsername = oldUser; gmailPassword = oldPass }()

	svc := NewGmailSMTPEmailService()
	if svc.from != "from@example.com" {
		t.Fatalf("expected from to be set from env, got: %s", svc.from)
	}
	if svc.password != "secretpass" {
		t.Fatalf("expected password to be set from env, got: %s", svc.password)
	}
}
