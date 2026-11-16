//go:build integration

package database

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mAmineChniti/Gordian/internal/config"
	"github.com/mAmineChniti/Gordian/internal/data"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func integrationConfig(t *testing.T) *config.Config {
	t.Helper()
	uri := strings.TrimSpace(os.Getenv("MONGODB_URI"))
	if uri == "" {
		uri = strings.TrimSpace(os.Getenv("DB_CONNECTION_STRING"))
	}
	if uri == "" {
		t.Skip("MONGODB_URI is not set; skipping MongoDB integration test")
	}

	return &config.Config{
		MongoURI:                  uri,
		DBName:                    "gordian_it_" + primitive.NewObjectID().Hex(),
		JWTSecret:                 []byte(strings.Repeat("s", 64)),
		BaseURL:                   "https://api.example.com",
		AccessTokenTTL:            15 * time.Minute,
		RefreshTokenTTL:           7 * 24 * time.Hour,
		EmailConfirmationTokenTTL: time.Hour,
		PasswordResetTokenTTL:     time.Hour,
		MaxBodyBytes:              8 << 20,
		MaxProfilePictureBytes:    5 << 20,
		BcryptCost:                10,
	}
}

func TestIntegrationUserLifecycle(t *testing.T) {
	cfg := integrationConfig(t)
	email := &testEmailService{}

	svc, err := newWithEmailService(cfg, email)
	if err != nil {
		t.Fatalf("failed to initialize database service: %v", err)
	}

	rawService := svc.(*service)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = rawService.db.Drop(ctx)
		_ = svc.Close(ctx)
	})

	register := &data.RegisterRequest{
		Username:    "Alice",
		Email:       "Alice@Example.com",
		Password:    "Aa1!aaaa",
		FirstName:   "Alice",
		LastName:    "Doe",
		Birthdate:   time.Now().AddDate(-30, 0, 0).Format(time.RFC3339),
		AcceptTerms: true,
	}
	if err := svc.CreateUser(register); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if len(email.confirmationTokens) != 1 {
		t.Fatalf("expected one confirmation email, got %d", len(email.confirmationTokens))
	}

	// Usernames and emails are case-insensitively unique.
	duplicateUsername := *register
	duplicateUsername.Username = "alice"
	duplicateUsername.Email = "other@example.com"
	if err := svc.CreateUser(&duplicateUsername); !errors.Is(err, ErrUserExists) {
		t.Fatalf("expected duplicate username to be rejected, got: %v", err)
	}

	duplicateEmail := *register
	duplicateEmail.Username = "alice2"
	duplicateEmail.Email = "ALICE@example.com"
	if err := svc.CreateUser(&duplicateEmail); !errors.Is(err, ErrUserExists) {
		t.Fatalf("expected duplicate email to be rejected, got: %v", err)
	}

	if _, err := svc.FindUser(&data.LoginRequest{Identifier: "alice", Password: "Wrong1!aa"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got: %v", err)
	}
	user, err := svc.FindUser(&data.LoginRequest{Identifier: "alice", Password: register.Password})
	if err != nil {
		t.Fatalf("FindUser failed: %v", err)
	}
	if user.EmailConfirmed {
		t.Fatal("expected new account to be unconfirmed")
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("expected normalized email, got %q", user.Email)
	}

	if err := svc.ConfirmEmail(email.confirmationTokens[0]); err != nil {
		t.Fatalf("ConfirmEmail failed: %v", err)
	}
	user, err = svc.GetUser(user.ID)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if !user.EmailConfirmed {
		t.Fatal("expected email to be confirmed")
	}
	if err := svc.ConfirmEmail(email.confirmationTokens[0]); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected confirmation token to be single-use, got: %v", err)
	}

	tokens, err := svc.CreateSession(user.ID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("expected populated tokens")
	}

	// Email changes require the current password and reset confirmation.
	if _, err := svc.UpdateUser(user.ID, &data.UpdateRequest{Email: "new@example.com"}); !errors.Is(err, ErrCurrentPasswordNeeded) {
		t.Fatalf("expected current password requirement, got: %v", err)
	}
	if _, err := svc.UpdateUser(user.ID, &data.UpdateRequest{Email: "new@example.com", CurrentPassword: "Wrong1!aa"}); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected invalid current password, got: %v", err)
	}
	updated, err := svc.UpdateUser(user.ID, &data.UpdateRequest{Email: "new@example.com", CurrentPassword: register.Password})
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}
	if updated.EmailConfirmed {
		t.Fatal("expected email change to require re-confirmation")
	}
	if len(email.notices) != 1 || !strings.Contains(email.notices[0], "alice@example.com->new@example.com") {
		t.Fatalf("expected old-address change notice, got: %v", email.notices)
	}
	if len(email.confirmationTokens) != 2 {
		t.Fatalf("expected confirmation email to new address, got %d", len(email.confirmationTokens))
	}
	if err := svc.ConfirmEmail(email.confirmationTokens[1]); err != nil {
		t.Fatalf("ConfirmEmail for new address failed: %v", err)
	}

	// Password changes increment the token version, revoking existing sessions.
	versionBefore, err := svc.GetTokenVersion(user.ID)
	if err != nil {
		t.Fatalf("GetTokenVersion failed: %v", err)
	}
	if _, err := svc.UpdateUser(user.ID, &data.UpdateRequest{
		Password:        "Bb2@bbbb",
		CurrentPassword: register.Password,
	}); err != nil {
		t.Fatalf("password update failed: %v", err)
	}
	versionAfter, err := svc.GetTokenVersion(user.ID)
	if err != nil {
		t.Fatalf("GetTokenVersion failed: %v", err)
	}
	if versionAfter != versionBefore+1 {
		t.Fatalf("expected token version increment, got %d -> %d", versionBefore, versionAfter)
	}
	if _, err := svc.FindUser(&data.LoginRequest{Identifier: "alice", Password: register.Password}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected old password to stop working, got: %v", err)
	}
	if _, err := svc.FindUser(&data.LoginRequest{Identifier: "alice", Password: "Bb2@bbbb"}); err != nil {
		t.Fatalf("expected new password to work, got: %v", err)
	}

	// Password reset is single-use and also revokes sessions.
	if err := svc.InitiatePasswordReset("NEW@example.com"); err != nil {
		t.Fatalf("InitiatePasswordReset failed: %v", err)
	}
	if len(email.resetTokens) != 1 {
		t.Fatalf("expected password reset email, got %d", len(email.resetTokens))
	}
	if err := svc.ResetPassword(email.resetTokens[0], "Cc3#cccc"); err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}
	if err := svc.ResetPassword(email.resetTokens[0], "Dd4$dddd"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected reset token to be single-use, got: %v", err)
	}
	if _, err := svc.FindUser(&data.LoginRequest{Identifier: "new@example.com", Password: "Cc3#cccc"}); err != nil {
		t.Fatalf("expected reset password to work, got: %v", err)
	}

	if err := svc.RevokeSessions(user.ID); err != nil {
		t.Fatalf("RevokeSessions failed: %v", err)
	}
	if err := svc.DeleteUser(user.ID); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	if err := svc.DeleteUser(user.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected second delete to report not found, got: %v", err)
	}
}
