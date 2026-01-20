package data

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateRegisterRequest_Errors(t *testing.T) {
	// missing required fields
	req := &RegisterRequest{}
	errs := ValidateRegisterRequest(req)
	if errs == nil {
		t.Fatalf("expected errors for empty register request, got nil")
	}
	if _, ok := errs["Username"]; !ok {
		t.Fatalf("expected Username error, got: %v", errs)
	}

	// invalid email
	req2 := &RegisterRequest{
		Username:    "validuser",
		Email:       "not-an-email",
		Password:    "Aa1!aaaa",
		FirstName:   "FN",
		LastName:    "LN",
		Birthdate:   time.Now().AddDate(-25, 0, 0).Format(time.RFC3339),
		AcceptTerms: true,
	}
	errs2 := ValidateRegisterRequest(req2)
	if errs2 == nil {
		t.Fatalf("expected email validation error, got nil")
	}
	if v, ok := errs2["Email"]; !ok || v != "invalid email format" {
		t.Fatalf("expected invalid email format error, got: %v", errs2)
	}
}

func TestValidatePasswordResetConfirmRequest_Token(t *testing.T) {
	req := &PasswordResetConfirmRequest{
		Token:       "not-a-uuid",
		NewPassword: "Aa1!aaaa",
	}
	errs := ValidatePasswordResetConfirmRequest(req)
	if errs == nil {
		t.Fatalf("expected token format error, got nil")
	}
	if v, ok := errs["Token"]; !ok || v != "invalid token format" {
		t.Fatalf("expected invalid token format error, got: %v", errs)
	}
}

func TestValidateRegisterRequest_Success(t *testing.T) {
	// small valid profile picture
	pic := base64.StdEncoding.EncodeToString([]byte("smallpic"))
	req := &RegisterRequest{
		Username:       "validuser",
		Email:          "user@example.com",
		Password:       "Aa1!aaaa",
		FirstName:      "FN",
		LastName:       "LN",
		Birthdate:      time.Now().AddDate(-25, 0, 0).Format(time.RFC3339),
		AcceptTerms:    true,
		ProfilePicture: pic,
	}
	errs := ValidateRegisterRequest(req)
	if errs != nil {
		t.Fatalf("expected no errors for valid register request, got: %v", errs)
	}
}

func TestValidateLoginRequest(t *testing.T) {
	// missing identifier
	bad := &LoginRequest{Password: "Aa1!aaaa"}
	errs := ValidateLoginRequest(bad)
	if errs == nil {
		t.Fatalf("expected errors for missing identifier, got nil")
	}

	// valid
	good := &LoginRequest{Identifier: "validuser", Password: "Aa1!aaaa"}
	errs2 := ValidateLoginRequest(good)
	if errs2 != nil {
		t.Fatalf("expected no errors for valid login request, got: %v", errs2)
	}
}

func TestValidateUpdateRequest(t *testing.T) {
	// empty update should pass (all fields optional)
	empty := &UpdateRequest{}
	errs := ValidateUpdateRequest(empty)
	if errs != nil {
		t.Fatalf("expected no errors for empty update, got: %v", errs)
	}

	// invalid email
	bad := &UpdateRequest{Email: "not-an-email"}
	errs2 := ValidateUpdateRequest(bad)
	if errs2 == nil {
		t.Fatalf("expected email validation error for update, got nil")
	}
	if v, ok := errs2["Email"]; !ok || v != "invalid email format" {
		t.Fatalf("expected invalid email format error, got: %v", errs2)
	}
}

func TestValidatePasswordResetInitiateRequest(t *testing.T) {
	// missing email
	bad := &PasswordResetInitiateRequest{}
	errs := ValidatePasswordResetInitiateRequest(bad)
	if errs == nil {
		t.Fatalf("expected errors for missing email, got nil")
	}

	// valid
	good := &PasswordResetInitiateRequest{Email: "user@example.com"}
	errs2 := ValidatePasswordResetInitiateRequest(good)
	if errs2 != nil {
		t.Fatalf("expected no errors for valid password reset initiate, got: %v", errs2)
	}
}

func TestValidatePasswordResetConfirmRequest_Success(t *testing.T) {
	token := uuid.New().String()
	req := &PasswordResetConfirmRequest{
		Token:       token,
		NewPassword: "Aa1!aaaa",
	}
	errs := ValidatePasswordResetConfirmRequest(req)
	if errs != nil {
		t.Fatalf("expected no errors for valid password reset confirm, got: %v", errs)
	}
}
