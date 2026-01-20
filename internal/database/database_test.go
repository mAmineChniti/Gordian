package database

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestCreateSession_GeneratesTokens(t *testing.T) {
	// ensure jwtSecret is present for signing
	old := jwtSecret
	jwtSecret = []byte("testsecret")
	defer func() { jwtSecret = old }()

	s := &service{}
	tok, err := s.CreateSession(primitive.NewObjectID())
	if err != nil {
		t.Fatalf("expected no error creating session tokens, got: %v", err)
	}
	if tok == nil {
		t.Fatalf("expected tokens, got nil")
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens, got access=%q refresh=%q", tok.AccessToken, tok.RefreshToken)
	}
}
