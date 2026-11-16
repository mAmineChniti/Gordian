package data

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestValidatePasswordComplexity(t *testing.T) {
	if err := Validate.Var("Aa1!aaaa", "password_complexity"); err != nil {
		t.Fatalf("expected valid password, got: %v", err)
	}

	for _, bad := range []string{
		"short",
		"alllowercase1!",
		"ALLUPPERCASE1!",
		"NoDigits!",
		"NoSpecial1",
		strings.Repeat("Aa1!", 20), // longer than bcrypt's 72-byte input
	} {
		if err := Validate.Var(bad, "password_complexity"); err == nil {
			t.Errorf("expected password %q to be rejected", bad)
		}
	}
}

func TestValidateBirthdate(t *testing.T) {
	adult := time.Now().AddDate(-20, 0, 0).Format(time.RFC3339)
	if err := Validate.Var(adult, "rfc3339"); err != nil {
		t.Fatalf("expected valid birthdate, got: %v", err)
	}

	underage := time.Now().AddDate(-17, 0, 0).Format(time.RFC3339)
	if err := Validate.Var(underage, "rfc3339"); err == nil {
		t.Fatal("expected underage birthdate to be invalid")
	}

	if err := Validate.Var("not-a-date", "rfc3339"); err == nil {
		t.Fatal("expected malformed birthdate to be invalid")
	}
}

func TestValidateUsername(t *testing.T) {
	for _, good := range []string{"user", "user.name", "user-name", "user_name", "u1"} {
		if err := Validate.Var(good, "username"); err != nil {
			t.Errorf("expected username %q to be valid, got: %v", good, err)
		}
	}
	for _, bad := range []string{"user@example.com", ".user", "-user", "user name", "user!"} {
		if err := Validate.Var(bad, "username"); err == nil {
			t.Errorf("expected username %q to be rejected", bad)
		}
	}
}

func TestProfilePictureSize(t *testing.T) {
	if size, err := ProfilePictureSize(""); err != nil || size != 0 {
		t.Fatalf("expected empty picture to be valid, got size=%d err=%v", size, err)
	}

	raw := base64.StdEncoding.EncodeToString([]byte("smallpic"))
	if size, err := ProfilePictureSize(raw); err != nil || size != int64(len("smallpic")) {
		t.Fatalf("expected decoded size, got size=%d err=%v", size, err)
	}

	if _, err := ProfilePictureSize("data:image/png;base64," + raw); err != nil {
		t.Fatalf("expected data URL to be valid, got: %v", err)
	}
	if _, err := ProfilePictureSize("data:image/svg+xml;base64," + raw); err == nil {
		t.Fatal("expected unsupported image type to be rejected")
	}
	if _, err := ProfilePictureSize("not base64!!!"); err == nil {
		t.Fatal("expected invalid base64 to be rejected")
	}

	tooLarge := strings.Repeat("A", int((MaxProfilePictureBytes*4)/3)+16)
	if _, err := ProfilePictureSize(tooLarge); err == nil {
		t.Fatal("expected oversized encoded image to be rejected")
	}
}

func TestValidationErrorsUsesJSONNames(t *testing.T) {
	err := Validate.Struct(&RegisterRequest{})
	errs := ValidationErrors(err)
	if _, ok := errs["username"]; !ok {
		t.Fatalf("expected json field name username, got: %v", errs)
	}
	if _, ok := errs["Username"]; ok {
		t.Fatalf("did not expect Go field name in errors: %v", errs)
	}
}
