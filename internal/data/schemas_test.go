package data

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

func validRegisterRequest() *RegisterRequest {
	return &RegisterRequest{
		Username:    "validuser",
		Email:       "user@example.com",
		Password:    "Aa1!aaaa",
		FirstName:   "First",
		LastName:    "Last",
		Birthdate:   time.Now().AddDate(-25, 0, 0).Format(time.RFC3339),
		AcceptTerms: true,
	}
}

func TestRegisterRequestValidation(t *testing.T) {
	errs := ValidationErrors(Validate.Struct(&RegisterRequest{}))
	if errs == nil {
		t.Fatal("expected errors for empty register request")
	}
	for _, field := range []string{"username", "email", "password", "first_name", "last_name", "birthdate", "accept_terms"} {
		if _, ok := errs[field]; !ok {
			t.Errorf("expected %s error, got: %v", field, errs)
		}
	}

	req := validRegisterRequest()
	if errs := ValidationErrors(Validate.Struct(req)); errs != nil {
		t.Fatalf("expected valid register request, got: %v", errs)
	}

	req.Email = "not-an-email"
	errs = ValidationErrors(Validate.Struct(req))
	if got := errs["email"]; got != "invalid email format" {
		t.Fatalf("expected invalid email format error, got: %v", errs)
	}
}

func TestRegisterRequestUsernameCharset(t *testing.T) {
	req := validRegisterRequest()
	req.Username = "user@example"
	errs := ValidationErrors(Validate.Struct(req))
	if _, ok := errs["username"]; !ok {
		t.Fatalf("expected username charset error, got: %v", errs)
	}
}

func TestRegisterRequestProfilePicture(t *testing.T) {
	req := validRegisterRequest()
	req.ProfilePicture = base64.StdEncoding.EncodeToString([]byte("smallpic"))
	if errs := ValidationErrors(Validate.Struct(req)); errs != nil {
		t.Fatalf("expected valid profile picture, got: %v", errs)
	}

	req.ProfilePicture = "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="
	errs := ValidationErrors(Validate.Struct(req))
	if _, ok := errs["profile_picture"]; !ok {
		t.Fatalf("expected unsupported image type error, got: %v", errs)
	}
}

func TestLoginRequestOnlyRequiresCredentials(t *testing.T) {
	// Login must not apply password complexity: legacy passwords must still work.
	req := &LoginRequest{Identifier: "validuser", Password: "-"}
	if errs := ValidationErrors(Validate.Struct(req)); errs != nil {
		t.Fatalf("expected legacy password to pass login validation, got: %v", errs)
	}

	errs := ValidationErrors(Validate.Struct(&LoginRequest{Password: "-"}))
	if _, ok := errs["identifier"]; !ok {
		t.Fatalf("expected identifier required error, got: %v", errs)
	}
}

func TestUpdateRequestValidation(t *testing.T) {
	if errs := ValidationErrors(Validate.Struct(&UpdateRequest{})); errs != nil {
		t.Fatalf("expected empty update to pass validation, got: %v", errs)
	}

	errs := ValidationErrors(Validate.Struct(&UpdateRequest{Email: "not-an-email"}))
	if got := errs["email"]; got != "invalid email format" {
		t.Fatalf("expected invalid email format error, got: %v", errs)
	}
}

func TestPasswordResetValidation(t *testing.T) {
	errs := ValidationErrors(Validate.Struct(&PasswordResetInitiateRequest{}))
	if _, ok := errs["email"]; !ok {
		t.Fatalf("expected email required error, got: %v", errs)
	}

	bad := &PasswordResetConfirmRequest{Token: "not-a-uuid", NewPassword: "Aa1!aaaa"}
	errs = ValidationErrors(Validate.Struct(bad))
	if got := errs["token"]; got != "invalid token format" {
		t.Fatalf("expected invalid token format error, got: %v", errs)
	}

	good := &PasswordResetConfirmRequest{Token: uuid.NewString(), NewPassword: "Aa1!aaaa"}
	if errs := ValidationErrors(Validate.Struct(good)); errs != nil {
		t.Fatalf("expected valid reset request, got: %v", errs)
	}
}

func TestResendConfirmationValidation(t *testing.T) {
	errs := ValidationErrors(Validate.Struct(&ResendConfirmationRequest{}))
	if _, ok := errs["email"]; !ok {
		t.Fatalf("expected email required error, got: %v", errs)
	}

	if errs := ValidationErrors(Validate.Struct(&ResendConfirmationRequest{Email: "user@example.com"})); errs != nil {
		t.Fatalf("expected valid resend request, got: %v", errs)
	}
}

func TestFetchUserByIDValidation(t *testing.T) {
	errs := ValidationErrors(Validate.Struct(&FetchUserByIDRequest{}))
	if _, ok := errs["user_id"]; !ok {
		t.Fatalf("expected user_id required error, got: %v", errs)
	}
}
