package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mAmineChniti/Gordian/internal/config"
	"github.com/mAmineChniti/Gordian/internal/data"
	"github.com/mAmineChniti/Gordian/internal/database"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type fakeDB struct {
	findUserFn           func(*data.LoginRequest) (*data.User, error)
	getUserFn            func(bson.ObjectID) (*data.User, error)
	getTokenVersionFn    func(bson.ObjectID) (int, error)
	createUserFn         func(*data.RegisterRequest) error
	updateUserFn         func(bson.ObjectID, *data.UpdateRequest) (*data.User, error)
	deleteUserFn         func(bson.ObjectID) error
	createSessionFn      func(bson.ObjectID) (*data.SessionTokens, error)
	confirmEmailFn       func(string) error
	resendConfirmationFn func(bson.ObjectID) error
	resendByEmailFn      func(string) error
	deleteUnconfirmedFn  func() error
	initiateResetFn      func(string) error
	resetPasswordFn      func(string, string) error
	revokeSessionsFn     func(bson.ObjectID) error
	healthFn             func() (map[string]string, error)
	closeFn              func(context.Context) error
}

func (f *fakeDB) FindUser(req *data.LoginRequest) (*data.User, error) {
	if f.findUserFn != nil {
		return f.findUserFn(req)
	}
	return nil, database.ErrInvalidCredentials
}

func (f *fakeDB) GetUser(id bson.ObjectID) (*data.User, error) {
	if f.getUserFn != nil {
		return f.getUserFn(id)
	}
	return nil, database.ErrUserNotFound
}

func (f *fakeDB) GetTokenVersion(id bson.ObjectID) (int, error) {
	if f.getTokenVersionFn != nil {
		return f.getTokenVersionFn(id)
	}
	return 0, nil
}

func (f *fakeDB) CreateUser(req *data.RegisterRequest) error {
	if f.createUserFn != nil {
		return f.createUserFn(req)
	}
	return nil
}

func (f *fakeDB) UpdateUser(id bson.ObjectID, req *data.UpdateRequest) (*data.User, error) {
	if f.updateUserFn != nil {
		return f.updateUserFn(id, req)
	}
	return &data.User{ID: id, Username: "user", EmailConfirmed: true}, nil
}

func (f *fakeDB) DeleteUser(id bson.ObjectID) error {
	if f.deleteUserFn != nil {
		return f.deleteUserFn(id)
	}
	return nil
}

func (f *fakeDB) CreateSession(id bson.ObjectID) (*data.SessionTokens, error) {
	if f.createSessionFn != nil {
		return f.createSessionFn(id)
	}
	return fakeTokens(), nil
}

func (f *fakeDB) ConfirmEmail(token string) error {
	if f.confirmEmailFn != nil {
		return f.confirmEmailFn(token)
	}
	return nil
}

func (f *fakeDB) ResendConfirmationEmail(id bson.ObjectID) error {
	if f.resendConfirmationFn != nil {
		return f.resendConfirmationFn(id)
	}
	return nil
}

func (f *fakeDB) ResendConfirmationEmailByEmail(email string) error {
	if f.resendByEmailFn != nil {
		return f.resendByEmailFn(email)
	}
	return nil
}

func (f *fakeDB) DeleteUnconfirmedUsers() error {
	if f.deleteUnconfirmedFn != nil {
		return f.deleteUnconfirmedFn()
	}
	return nil
}

func (f *fakeDB) InitiatePasswordReset(email string) error {
	if f.initiateResetFn != nil {
		return f.initiateResetFn(email)
	}
	return nil
}

func (f *fakeDB) ResetPassword(token, newPassword string) error {
	if f.resetPasswordFn != nil {
		return f.resetPasswordFn(token, newPassword)
	}
	return nil
}

func (f *fakeDB) RevokeSessions(id bson.ObjectID) error {
	if f.revokeSessionsFn != nil {
		return f.revokeSessionsFn(id)
	}
	return nil
}

func (f *fakeDB) Health() (map[string]string, error) {
	if f.healthFn != nil {
		return f.healthFn()
	}
	return map[string]string{"database": "ok"}, nil
}

func (f *fakeDB) Close(ctx context.Context) error {
	if f.closeFn != nil {
		return f.closeFn(ctx)
	}
	return nil
}

func fakeTokens() *data.SessionTokens {
	now := time.Now().UTC()
	return &data.SessionTokens{
		AccessToken:      "access-token",
		AccessCreatedAt:  now,
		AccessExpiresAt:  now.Add(15 * time.Minute),
		RefreshToken:     "refresh-token",
		RefreshCreatedAt: now,
		RefreshExpiresAt: now.Add(7 * 24 * time.Hour),
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Port:                      10000,
		JWTSecret:                 []byte(strings.Repeat("s", 64)),
		BaseURL:                   "https://api.example.com",
		CORSAllowedOrigins:        []string{"https://app.example.com"},
		AccessTokenTTL:            15 * time.Minute,
		RefreshTokenTTL:           7 * 24 * time.Hour,
		EmailConfirmationTokenTTL: time.Hour,
		PasswordResetTokenTTL:     time.Hour,
		MaxBodyBytes:              1 << 20,
		MaxProfilePictureBytes:    1 << 20,
		BcryptCost:                10,
	}
}

func newTestHandler(t *testing.T, db database.Service) (http.Handler, *config.Config) {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "templates"))
	if err != nil {
		t.Fatalf("failed to resolve templates directory: %v", err)
	}
	t.Setenv("APP_TEMPLATES_DIR", dir)

	cfg := testConfig()
	server, err := NewServer(cfg, db)
	if err != nil {
		t.Fatalf("failed to build server: %v", err)
	}
	return server.Handler, cfg
}

func doRequest(t *testing.T, handler http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	switch value := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(value)
	case []byte:
		reader = strings.NewReader(string(value))
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		reader = strings.NewReader(string(encoded))
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response %q: %v", rec.Body.String(), err)
	}
	return result
}

func signedToken(t *testing.T, cfg *config.Config, userID bson.ObjectID, tokenType string, version int) string {
	t.Helper()
	now := time.Now().UTC()
	claims := &data.Claims{
		TokenType:    tokenType,
		TokenVersion: version,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.Hex(),
			Issuer:    data.TokenIssuer,
			Audience:  jwt.ClaimStrings{data.TokenAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        bson.NewObjectID().Hex(),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(cfg.JWTSecret)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return token
}

func authHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func TestLoginUsesGenericInvalidCredentialsMessage(t *testing.T) {
	db := &fakeDB{findUserFn: func(*data.LoginRequest) (*data.User, error) {
		return nil, database.ErrInvalidCredentials
	}}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/login", map[string]string{
		"identifier": "user",
		"password":   "Password1!",
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeJSON[data.MessageResponse](t, rec)
	if body.Message != "Invalid username/email or password" {
		t.Fatalf("expected generic message, got %q", body.Message)
	}
	if strings.Contains(strings.ToLower(body.Message), "not found") || strings.Contains(strings.ToLower(body.Message), "incorrect") {
		t.Fatalf("message leaks account state: %q", body.Message)
	}
}

func TestLoginRateLimit(t *testing.T) {
	db := &fakeDB{findUserFn: func(*data.LoginRequest) (*data.User, error) {
		return nil, database.ErrInvalidCredentials
	}}
	handler, _ := newTestHandler(t, db)

	for i := 0; i < loginAttemptLimit; i++ {
		rec := doRequest(t, handler, http.MethodPost, "/api/v1/login", map[string]string{
			"identifier": "user",
			"password":   "Password1!",
		}, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/login", map[string]string{
		"identifier": "user",
		"password":   "Password1!",
	}, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", loginAttemptLimit, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestLoginRejectsUnconfirmedEmail(t *testing.T) {
	db := &fakeDB{findUserFn: func(*data.LoginRequest) (*data.User, error) {
		return &data.User{ID: bson.NewObjectID(), Username: "user", EmailConfirmed: false}, nil
	}}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/login", map[string]string{
		"identifier": "user",
		"password":   "Password1!",
	}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterValidationResponseShape(t *testing.T) {
	db := &fakeDB{}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/register", map[string]string{}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	body := decodeJSON[data.ValidationErrorResponse](t, rec)
	if body.Message != "Validation failed" {
		t.Fatalf("expected validation message, got %q", body.Message)
	}
	if _, ok := body.Errors["username"]; !ok {
		t.Fatalf("expected username error, got: %v", body.Errors)
	}
	if _, ok := body.Errors["email"]; !ok {
		t.Fatalf("expected email error, got: %v", body.Errors)
	}
}

func validRegisterBody() map[string]any {
	return map[string]any{
		"username":     "validuser",
		"email":        "user@example.com",
		"password":     "Aa1!aaaa",
		"first_name":   "First",
		"last_name":    "Last",
		"birthdate":    time.Now().AddDate(-25, 0, 0).Format(time.RFC3339),
		"accept_terms": true,
	}
}

func TestRegisterReturns201WhenEmailFails(t *testing.T) {
	db := &fakeDB{createUserFn: func(*data.RegisterRequest) error {
		return database.ErrEmailSendFailed
	}}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/register", validRegisterBody(), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterConflict(t *testing.T) {
	db := &fakeDB{createUserFn: func(*data.RegisterRequest) error {
		return database.ErrUserExists
	}}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/register", validRegisterBody(), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterRateLimit(t *testing.T) {
	db := &fakeDB{}
	handler, _ := newTestHandler(t, db)

	for i := 0; i < registerAttemptLimit; i++ {
		rec := doRequest(t, handler, http.MethodPost, "/api/v1/register", validRegisterBody(), nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("attempt %d: expected 201, got %d", i+1, rec.Code)
		}
	}
	rec := doRequest(t, handler, http.MethodPost, "/api/v1/register", validRegisterBody(), nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
}

func TestPasswordResetInitiateAlwaysReturns200ForAccountState(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "unknown or existing account", err: nil},
		{name: "email delivery failure", err: database.ErrEmailSendFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &fakeDB{initiateResetFn: func(string) error { return tc.err }}
			handler, _ := newTestHandler(t, db)

			rec := doRequest(t, handler, http.MethodPost, "/api/v1/password-reset/initiate", map[string]string{
				"email": "user@example.com",
			}, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
			}
			body := decodeJSON[data.MessageResponse](t, rec)
			if !strings.Contains(body.Message, "If an account exists") {
				t.Fatalf("unexpected message: %q", body.Message)
			}
		})
	}
}

func TestPasswordResetInitiateRateLimit(t *testing.T) {
	db := &fakeDB{}
	handler, _ := newTestHandler(t, db)

	for i := 0; i < passwordResetAttemptLimit; i++ {
		rec := doRequest(t, handler, http.MethodPost, "/api/v1/password-reset/initiate", map[string]string{
			"email": "user@example.com",
		}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, rec.Code)
		}
	}
	rec := doRequest(t, handler, http.MethodPost, "/api/v1/password-reset/initiate", map[string]string{
		"email": "user@example.com",
	}, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
}

func TestPasswordResetConfirmInvalidToken(t *testing.T) {
	db := &fakeDB{resetPasswordFn: func(string, string) error { return database.ErrTokenInvalid }}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/password-reset/confirm", map[string]string{
		"token":        "123e4567-e89b-12d3-a456-426614174000",
		"new_password": "Aa1!aaaa",
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteMissingAccountReturns404(t *testing.T) {
	userID := bson.NewObjectID()
	db := &fakeDB{
		getTokenVersionFn: func(bson.ObjectID) (int, error) { return 0, nil },
		deleteUserFn:      func(bson.ObjectID) error { return database.ErrUserNotFound },
	}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodDelete, "/api/v1/delete", nil, authHeader(signedToken(t, cfg, userID, data.TokenTypeAccess, 0)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestFetchUserByIDReturnsLimitedProfile(t *testing.T) {
	userID := bson.NewObjectID()
	targetID := bson.NewObjectID()
	db := &fakeDB{
		getTokenVersionFn: func(bson.ObjectID) (int, error) { return 0, nil },
		getUserFn: func(id bson.ObjectID) (*data.User, error) {
			if id != targetID {
				return nil, database.ErrUserNotFound
			}
			return &data.User{
				ID:             targetID,
				Username:       "target",
				Email:          "target@example.com",
				FirstName:      "Target",
				LastName:       "User",
				Birthdate:      time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
				DateJoined:     time.Now().UTC(),
				EmailConfirmed: true,
			}, nil
		},
	}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/fetchuserbyid", map[string]string{
		"user_id": targetID.Hex(),
	}, authHeader(signedToken(t, cfg, userID, data.TokenTypeAccess, 0)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "birthdate") {
		t.Fatalf("public profile must not expose birthdate: %s", body)
	}
	if strings.Contains(body, "email") {
		t.Fatalf("public profile must not expose email: %s", body)
	}
	if !strings.Contains(body, "target") {
		t.Fatalf("expected username in response: %s", body)
	}
}

func TestJWTRejectsRevokedToken(t *testing.T) {
	userID := bson.NewObjectID()
	db := &fakeDB{getTokenVersionFn: func(bson.ObjectID) (int, error) { return 2, nil }}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodGet, "/api/v1/fetchuser", nil, authHeader(signedToken(t, cfg, userID, data.TokenTypeAccess, 1)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestJWTRejectsDeletedUser(t *testing.T) {
	userID := bson.NewObjectID()
	db := &fakeDB{getTokenVersionFn: func(bson.ObjectID) (int, error) {
		return 0, database.ErrUserNotFound
	}}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodGet, "/api/v1/fetchuser", nil, authHeader(signedToken(t, cfg, userID, data.TokenTypeAccess, 0)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestJWTRejectsWrongTokenType(t *testing.T) {
	userID := bson.NewObjectID()
	db := &fakeDB{}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodGet, "/api/v1/fetchuser", nil, authHeader(signedToken(t, cfg, userID, data.TokenTypeRefresh, 0)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRefreshRejectsUnconfirmedEmail(t *testing.T) {
	userID := bson.NewObjectID()
	db := &fakeDB{
		getTokenVersionFn: func(bson.ObjectID) (int, error) { return 0, nil },
		getUserFn: func(bson.ObjectID) (*data.User, error) {
			return &data.User{ID: userID, EmailConfirmed: false}, nil
		},
	}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodGet, "/api/v1/refresh", nil, authHeader(signedToken(t, cfg, userID, data.TokenTypeRefresh, 0)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLogoutRevokesSessions(t *testing.T) {
	userID := bson.NewObjectID()
	called := false
	db := &fakeDB{
		getTokenVersionFn: func(bson.ObjectID) (int, error) { return 0, nil },
		revokeSessionsFn: func(id bson.ObjectID) error {
			called = true
			if id != userID {
				t.Errorf("unexpected user ID: %s", id.Hex())
			}
			return nil
		},
	}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/logout", nil, authHeader(signedToken(t, cfg, userID, data.TokenTypeAccess, 0)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !called {
		t.Fatal("expected RevokeSessions to be called")
	}
}

func TestUpdateRequiresCurrentPassword(t *testing.T) {
	userID := bson.NewObjectID()
	db := &fakeDB{
		getTokenVersionFn: func(bson.ObjectID) (int, error) { return 0, nil },
		updateUserFn: func(bson.ObjectID, *data.UpdateRequest) (*data.User, error) {
			return nil, database.ErrCurrentPasswordNeeded
		},
	}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPatch, "/api/v1/update", map[string]string{
		"email": "new@example.com",
	}, authHeader(signedToken(t, cfg, userID, data.TokenTypeAccess, 0)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdatePasswordReturnsNewTokens(t *testing.T) {
	userID := bson.NewObjectID()
	db := &fakeDB{
		getTokenVersionFn: func(bson.ObjectID) (int, error) { return 0, nil },
		updateUserFn: func(id bson.ObjectID, req *data.UpdateRequest) (*data.User, error) {
			return &data.User{ID: id, Username: "user", EmailConfirmed: true}, nil
		},
	}
	handler, cfg := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPut, "/api/v1/update", map[string]string{
		"password":         "Aa1!bbbb",
		"current_password": "Aa1!aaaa",
	}, authHeader(signedToken(t, cfg, userID, data.TokenTypeAccess, 0)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeJSON[data.UserResponse](t, rec)
	if body.Tokens == nil || body.Tokens.AccessToken == "" {
		t.Fatalf("expected new tokens after password change, got: %+v", body.Tokens)
	}
}

func TestPublicResendConfirmationAlwaysReturns200(t *testing.T) {
	db := &fakeDB{resendByEmailFn: func(string) error { return database.ErrEmailSendFailed }}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodPost, "/api/v1/resend-confirmation-email", map[string]string{
		"email": "user@example.com",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestConfirmEmailRendersFailurePage(t *testing.T) {
	db := &fakeDB{confirmEmailFn: func(string) error { return database.ErrTokenInvalid }}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodGet, "/api/v1/confirm-email/bad-token", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid or has expired") {
		t.Fatalf("expected failure page, got: %s", rec.Body.String())
	}
}

func TestBodyLimit(t *testing.T) {
	db := &fakeDB{}
	dir, err := filepath.Abs(filepath.Join("..", "templates"))
	if err != nil {
		t.Fatalf("failed to resolve templates directory: %v", err)
	}
	t.Setenv("APP_TEMPLATES_DIR", dir)
	cfg := testConfig()
	cfg.MaxBodyBytes = 64
	server, err := NewServer(cfg, db)
	if err != nil {
		t.Fatalf("failed to build server: %v", err)
	}

	rec := doRequest(t, server.Handler, http.MethodPost, "/api/v1/register", strings.Repeat("x", 256), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeJSON[data.MessageResponse](t, rec)
	if body.Message != "Request body too large" {
		t.Fatalf("unexpected message: %q", body.Message)
	}
}

func TestCORSAllowlist(t *testing.T) {
	db := &fakeDB{}
	handler, _ := newTestHandler(t, db)

	preflight := func(origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/login", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	allowed := preflight("https://app.example.com")
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected allowed origin header, got %q", got)
	}

	blocked := preflight("https://evil.example.com")
	if got := blocked.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected evil origin to be rejected, got %q", got)
	}
}

func TestCORSAllowAnyOrigin(t *testing.T) {
	cfg := testConfig()
	cfg.CORSAllowedOrigins = []string{"*"}

	server, err := NewServer(cfg, &fakeDB{})
	if err != nil {
		t.Fatalf("failed to build server: %v", err)
	}

	for _, origin := range []string{"https://anything.example", "http://localhost:3000"} {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/login", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("origin %q: expected wildcard allow-origin, got %q", origin, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Fatalf("origin %q: wildcard CORS must not allow credentials, got %q", origin, got)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	db := &fakeDB{}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodGet, "/api/v1/health", nil, nil)
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected nosniff header, got %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected DENY frame options, got %q", got)
	}
}

func TestRootAndAPIRoot(t *testing.T) {
	db := &fakeDB{}
	handler, _ := newTestHandler(t, db)

	root := doRequest(t, handler, http.MethodGet, "/", nil, nil)
	if root.Code != http.StatusFound || root.Header().Get("Location") != "/api/v1/docs" {
		t.Fatalf("unexpected root response: %d location=%q", root.Code, root.Header().Get("Location"))
	}

	apiRoot := doRequest(t, handler, http.MethodGet, "/api/v1", nil, nil)
	if apiRoot.Code != http.StatusOK {
		t.Fatalf("expected 200 for API root, got %d", apiRoot.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	db := &fakeDB{healthFn: func() (map[string]string, error) {
		return map[string]string{"database": "ok"}, nil
	}}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodGet, "/api/v1/health", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := decodeJSON[data.HealthResponse](t, rec)
	if body.Status != "ok" || body.Details["database"] != "ok" {
		t.Fatalf("unexpected health response: %+v", body)
	}

	db.healthFn = func() (map[string]string, error) { return nil, errors.New("down") }
	rec = doRequest(t, handler, http.MethodGet, "/api/v1/health", nil, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	db := &fakeDB{}
	handler, _ := newTestHandler(t, db)

	rec := doRequest(t, handler, http.MethodGet, "/api/v1/nope", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	rec = doRequest(t, handler, http.MethodGet, "/api/v1/login", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", rec.Code, rec.Body.String())
	}
}
