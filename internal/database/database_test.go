package database

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mAmineChniti/Gordian/internal/config"
	"github.com/mAmineChniti/Gordian/internal/data"
	"github.com/mAmineChniti/Gordian/internal/services"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type testEmailService struct {
	confirmationEmails []string
	confirmationTokens []string
	resetEmails        []string
	resetTokens        []string
	notices            []string
	err                error
}

func (f *testEmailService) SendConfirmationEmail(email, token string) error {
	f.confirmationEmails = append(f.confirmationEmails, email)
	f.confirmationTokens = append(f.confirmationTokens, token)
	return f.err
}

func (f *testEmailService) SendPasswordResetEmail(email, token string) error {
	f.resetEmails = append(f.resetEmails, email)
	f.resetTokens = append(f.resetTokens, token)
	return f.err
}

func (f *testEmailService) SendEmailChangedNotice(oldEmail, newEmail string) error {
	f.notices = append(f.notices, oldEmail+"->"+newEmail)
	return f.err
}

var _ services.EmailService = (*testEmailService)(nil)

func TestNewSessionTokens(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	userID := bson.NewObjectID()
	secret := []byte("test-secret-that-is-long-enough-for-hs256")

	tokens, err := newSessionTokens(userID, 7, secret, now, 15*time.Minute, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("newSessionTokens returned error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("expected both tokens to be populated")
	}
	if !tokens.AccessCreatedAt.Equal(now) || !tokens.RefreshCreatedAt.Equal(now) {
		t.Fatalf("expected created timestamps to be %s, got access=%s refresh=%s", now, tokens.AccessCreatedAt, tokens.RefreshCreatedAt)
	}
	if want := now.Add(15 * time.Minute); !tokens.AccessExpiresAt.Equal(want) {
		t.Fatalf("expected access expiry %s, got %s", want, tokens.AccessExpiresAt)
	}
	if want := now.Add(7 * 24 * time.Hour); !tokens.RefreshExpiresAt.Equal(want) {
		t.Fatalf("expected refresh expiry %s, got %s", want, tokens.RefreshExpiresAt)
	}

	for _, tc := range []struct {
		name      string
		raw       string
		tokenType string
		ttl       time.Duration
	}{
		{name: "access", raw: tokens.AccessToken, tokenType: data.TokenTypeAccess, ttl: 15 * time.Minute},
		{name: "refresh", raw: tokens.RefreshToken, tokenType: data.TokenTypeRefresh, ttl: 7 * 24 * time.Hour},
	} {
		claims := &data.Claims{}
		parsed, err := jwt.ParseWithClaims(tc.raw, claims, func(token *jwt.Token) (any, error) {
			return secret, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer(data.TokenIssuer), jwt.WithAudience(data.TokenAudience))
		if err != nil || !parsed.Valid {
			t.Fatalf("%s token did not parse: %v", tc.name, err)
		}
		if claims.TokenType != tc.tokenType {
			t.Errorf("expected %s token type, got %q", tc.tokenType, claims.TokenType)
		}
		if claims.TokenVersion != 7 {
			t.Errorf("expected token version 7, got %d", claims.TokenVersion)
		}
		if claims.Subject != userID.Hex() {
			t.Errorf("expected subject %s, got %s", userID.Hex(), claims.Subject)
		}
		if claims.ID == "" {
			t.Error("expected a unique token id")
		}
		if claims.ExpiresAt == nil || !claims.ExpiresAt.Equal(now.Add(tc.ttl)) {
			t.Errorf("unexpected expiry for %s token: %v", tc.name, claims.ExpiresAt)
		}
		if claims.IssuedAt == nil || !claims.IssuedAt.Equal(now) {
			t.Errorf("unexpected issued-at for %s token: %v", tc.name, claims.IssuedAt)
		}
	}
}

func TestHashToken(t *testing.T) {
	raw := "123e4567-e89b-12d3-a456-426614174000"
	first := hashToken(raw)
	second := hashToken(raw)
	if first != second {
		t.Fatal("expected hashToken to be deterministic")
	}
	if first == raw {
		t.Fatal("expected token to be hashed at rest")
	}
	if len(first) != 64 {
		t.Fatalf("expected sha256 hex length 64, got %d", len(first))
	}
	if hashToken("other") == first {
		t.Fatal("expected different tokens to produce different hashes")
	}
}

func TestNormalizeEmail(t *testing.T) {
	if got := normalizeEmail("  User@Example.COM "); got != "user@example.com" {
		t.Fatalf("unexpected normalized email: %q", got)
	}
}

func TestURIHasCredentials(t *testing.T) {
	if !uriHasCredentials("mongodb://user:pass@localhost:27017/db") {
		t.Fatal("expected credentials to be detected")
	}
	if uriHasCredentials("mongodb://localhost:27017/db") {
		t.Fatal("expected URI without credentials to be detected")
	}
	if uriHasCredentials("://not a uri") {
		t.Fatal("expected malformed URI to return false")
	}
}

func TestIsDuplicateKey(t *testing.T) {
	if !isDuplicateKey(mongo.WriteException{WriteErrors: mongo.WriteErrors{{Code: 11000}}}) {
		t.Fatal("expected write exception duplicate key")
	}
	if !isDuplicateKey(mongo.CommandError{Code: 11000}) {
		t.Fatal("expected command error duplicate key")
	}
	if !isDuplicateKey(mongo.BulkWriteException{WriteErrors: []mongo.BulkWriteError{{Code: 11000}}}) {
		t.Fatal("expected bulk write duplicate key")
	}
	if isDuplicateKey(errors.New("not a duplicate")) {
		t.Fatal("expected non-duplicate error to return false")
	}
}

func TestCheckProfilePicture(t *testing.T) {
	svc := &service{cfg: &config.Config{MaxProfilePictureBytes: 8}}
	if err := svc.checkProfilePicture(""); err != nil {
		t.Fatalf("expected empty picture to be allowed, got: %v", err)
	}
	if err := svc.checkProfilePicture("c21hbGxwaWM="); err != nil {
		t.Fatalf("expected in-limit picture to be allowed, got: %v", err)
	}
	if err := svc.checkProfilePicture("bm90IGJhc2U2NCE="); !errors.Is(err, ErrProfilePictureTooLarge) {
		t.Fatalf("expected too large error, got: %v", err)
	}
	if err := svc.checkProfilePicture("not base64!!!"); !errors.Is(err, ErrProfilePictureInvalid) {
		t.Fatalf("expected invalid profile picture error, got: %v", err)
	}
}

func TestNewWithEmailServiceValidation(t *testing.T) {
	if _, err := newWithEmailService(nil, &testEmailService{}); err == nil {
		t.Fatal("expected nil config to be rejected")
	}
	if _, err := newWithEmailService(&config.Config{}, nil); err == nil {
		t.Fatal("expected nil email service to be rejected")
	}
}
