package data

import (
	"strings"
	"testing"
	"time"
)

func TestValidatePasswordComplexity(t *testing.T) {
	good := "Aa1!aaaa"
	if err := Validate.Var(good, "password_complexity"); err != nil {
		t.Fatalf("expected valid password, got error: %v", err)
	}

	bad := "short"
	if err := Validate.Var(bad, "password_complexity"); err == nil {
		t.Fatalf("expected invalid password, got nil")
	}
}

func TestValidateBirthdate(t *testing.T) {
	// adult
	adult := time.Now().AddDate(-20, 0, 0).Format(time.RFC3339)
	if err := Validate.Var(adult, "rfc3339"); err != nil {
		t.Fatalf("expected valid birthdate, got error: %v", err)
	}

	// underage
	under := time.Now().AddDate(-17, 0, 0).Format(time.RFC3339)
	if err := Validate.Var(under, "rfc3339"); err == nil {
		t.Fatalf("expected underage birthdate to be invalid, got nil")
	}
}

func TestValidateBase64Max10MB(t *testing.T) {
	// empty should pass (optional field)
	if err := Validate.Var("", "base64_max_10mb"); err != nil {
		t.Fatalf("empty base64 should be valid, got: %v", err)
	}

	// small string should pass
	small := strings.Repeat("A", 100)
	if err := Validate.Var(small, "base64_max_10mb"); err != nil {
		t.Fatalf("small base64 should be valid, got: %v", err)
	}

	// large string that exceeds 10MB when decoded
	// len(base64Str)*3/4 > 10*1024*1024 => len > (10*1024*1024*4)/3
	// add a safety margin so integer division can't accidentally pass
	limit := (10*1024*1024*4)/3 + 1000
	big := strings.Repeat("A", limit)
	if err := Validate.Var(big, "base64_max_10mb"); err == nil {
		t.Fatalf("expected large base64 to be invalid, got nil")
	}
}
