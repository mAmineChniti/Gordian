package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mAmineChniti/Gordian/internal/config"
	"github.com/mAmineChniti/Gordian/internal/data"
	"github.com/mAmineChniti/Gordian/internal/services"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const usersCollection = "users"

var caseInsensitive = options.Collation{Locale: "en", Strength: 2}

type Service interface {
	FindUser(user *data.LoginRequest) (*data.User, error)
	GetUser(userID bson.ObjectID) (*data.User, error)
	GetTokenVersion(userID bson.ObjectID) (int, error)
	CreateUser(user *data.RegisterRequest) error
	UpdateUser(userID bson.ObjectID, user *data.UpdateRequest) (*data.User, error)
	DeleteUser(userID bson.ObjectID) error
	CreateSession(userID bson.ObjectID) (*data.SessionTokens, error)
	ConfirmEmail(token string) error
	ResendConfirmationEmail(userID bson.ObjectID) error
	ResendConfirmationEmailByEmail(email string) error
	DeleteUnconfirmedUsers() error
	InitiatePasswordReset(email string) error
	ResetPassword(token, newPassword string) error
	RevokeSessions(userID bson.ObjectID) error
	Health() (map[string]string, error)
	Close(ctx context.Context) error
}

type service struct {
	client    *mongo.Client
	db        *mongo.Database
	email     services.EmailService
	jwtSecret []byte
	cfg       *config.Config
	dummyHash []byte
}

func New(cfg *config.Config) (Service, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}

	emailService, err := newEmailService(cfg)
	if err != nil {
		return nil, err
	}

	return newWithEmailService(cfg, emailService)
}

// newWithEmailService allows tests to inject an email implementation while
// keeping the production constructor limited to environment configuration.
func newWithEmailService(cfg *config.Config, emailService services.EmailService) (Service, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if emailService == nil {
		return nil, errors.New("email service is required")
	}

	dummyHash, err := bcrypt.GenerateFromPassword([]byte("gordian-dummy-password"), cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("generate dummy password hash: %w", err)
	}

	clientOptions := options.Client().
		ApplyURI(cfg.MongoURI).
		SetServerSelectionTimeout(10 * time.Second)

	if cfg.DBUsername != "" && !uriHasCredentials(cfg.MongoURI) {
		credential := options.Credential{
			Username:   cfg.DBUsername,
			Password:   cfg.DBPassword,
			AuthSource: cfg.DBAuthSource,
		}
		clientOptions.SetAuth(credential)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("connect to mongodb: %w", err)
	}

	if err := client.Ping(connectCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongodb: %w", err)
	}

	svc := &service{
		client:    client,
		db:        client.Database(cfg.DBName),
		email:     emailService,
		jwtSecret: cfg.JWTSecret,
		cfg:       cfg,
		dummyHash: dummyHash,
	}

	if err := svc.ensureIndexes(); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, err
	}

	return svc, nil
}

func newEmailService(cfg *config.Config) (services.EmailService, error) {
	if !cfg.EmailEnabled {
		log.Println("email delivery disabled: GMAIL_USERNAME/GMAIL_APP_PASSWORD are not set")
		return services.NewDisabledEmailService(), nil
	}
	return services.NewGmailSMTPEmailService(cfg.GmailUsername, cfg.GmailPassword, cfg.BaseURL)
}

func (s *service) ensureIndexes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	usernameIndex := options.Index().
		SetName("uniq_username").
		SetUnique(true).
		SetCollation(&caseInsensitive)
	emailIndex := options.Index().
		SetName("uniq_email").
		SetUnique(true).
		SetCollation(&caseInsensitive)

	_, err := s.users().Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "username", Value: 1}}, Options: usernameIndex},
		{Keys: bson.D{{Key: "email", Value: 1}}, Options: emailIndex},
		{Keys: bson.D{{Key: "email_token", Value: 1}}, Options: options.Index().SetName("email_token_idx").SetSparse(true)},
		{Keys: bson.D{{Key: "password_reset_token", Value: 1}}, Options: options.Index().SetName("password_reset_token_idx").SetSparse(true)},
		{Keys: bson.D{{Key: "email_confirmed", Value: 1}, {Key: "date_joined", Value: 1}}, Options: options.Index().SetName("unconfirmed_cleanup_idx")},
	})
	if err != nil {
		return fmt.Errorf("create mongodb indexes: %w", err)
	}
	return nil
}

func (s *service) users() *mongo.Collection {
	return s.db.Collection(usersCollection)
}

func (s *service) FindUser(req *data.LoginRequest) (*data.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identifier := strings.TrimSpace(req.Identifier)
	filter := bson.M{"username": identifier}
	opts := options.FindOne().SetCollation(&caseInsensitive)

	if strings.Contains(identifier, "@") {
		filter = bson.M{"email": normalizeEmail(identifier)}
		opts = options.FindOne().SetCollation(&caseInsensitive)
	}

	var foundUser data.User
	err := s.users().FindOne(ctx, filter, opts).Decode(&foundUser)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Equalize the response time with the bcrypt comparison below.
			_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(req.Password))
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Hash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &foundUser, nil
}

func (s *service) GetUser(userID bson.ObjectID) (*data.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var foundUser data.User
	err := s.users().FindOne(ctx, bson.M{"_id": userID}).Decode(&foundUser)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	return &foundUser, nil
}

func (s *service) GetTokenVersion(userID bson.ObjectID) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result struct {
		TokenVersion int `bson:"token_version"`
	}
	err := s.users().FindOne(
		ctx,
		bson.M{"_id": userID},
		options.FindOne().SetProjection(bson.M{"token_version": 1}),
	).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return 0, ErrUserNotFound
		}
		return 0, fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	return result.TokenVersion, nil
}

func (s *service) CreateUser(user *data.RegisterRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	username := strings.TrimSpace(user.Username)
	email := normalizeEmail(user.Email)

	count, err := s.users().CountDocuments(ctx, bson.M{
		"$or": []bson.M{
			{"username": username},
			{"email": email},
		},
	}, options.Count().SetCollation(&caseInsensitive))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	if count > 0 {
		return ErrUserExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), s.cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordHashFailed, err)
	}

	birthdate, err := time.Parse(time.RFC3339, user.Birthdate)
	if err != nil {
		return fmt.Errorf("%w: must be in ISO 8601 format (RFC3339)", ErrInvalidBirthdate)
	}

	if err := s.checkProfilePicture(user.ProfilePicture); err != nil {
		return err
	}

	now := time.Now().UTC()
	rawToken := uuid.NewString()
	endUser := data.User{
		ID:                        bson.NewObjectID(),
		Username:                  username,
		Email:                     email,
		Hash:                      string(hash),
		FirstName:                 strings.TrimSpace(user.FirstName),
		LastName:                  strings.TrimSpace(user.LastName),
		Birthdate:                 birthdate.UTC(),
		DateJoined:                now,
		EmailConfirmed:            false,
		EmailToken:                hashToken(rawToken),
		EmailTokenExpiry:          now.Add(s.cfg.EmailConfirmationTokenTTL),
		EmailConfirmationAttempts: 1,
		LastEmailAttemptTime:      now,
		AcceptTerms:               user.AcceptTerms,
		ProfilePicture:            user.ProfilePicture,
		TokenVersion:              0,
	}

	if _, err := s.users().InsertOne(ctx, endUser); err != nil {
		if isDuplicateKey(err) {
			return ErrUserExists
		}
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	log.Printf("audit: user registered user_id=%s", endUser.ID.Hex())

	if err := s.email.SendConfirmationEmail(endUser.Email, rawToken); err != nil {
		log.Printf("failed to send confirmation email for %s: %v", endUser.Email, err)
		return fmt.Errorf("%w: %v", ErrEmailSendFailed, err)
	}

	return nil
}

func (s *service) UpdateUser(userID bson.ObjectID, user *data.UpdateRequest) (*data.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	current, err := s.GetUser(userID)
	if err != nil {
		return nil, err
	}

	newEmail := normalizeEmail(user.Email)
	emailChanged := user.Email != "" && !strings.EqualFold(newEmail, current.Email)
	passwordChanged := user.Password != ""

	if emailChanged || passwordChanged {
		if user.CurrentPassword == "" {
			return nil, ErrCurrentPasswordNeeded
		}
		if err := bcrypt.CompareHashAndPassword([]byte(current.Hash), []byte(user.CurrentPassword)); err != nil {
			return nil, ErrInvalidCurrentPassword
		}
	}

	setFields := bson.M{}
	incFields := bson.M{}
	now := time.Now().UTC()

	var confirmationToken string
	if username := strings.TrimSpace(user.Username); username != "" {
		count, err := s.users().CountDocuments(ctx, bson.M{
			"username": username,
			"_id":      bson.M{"$ne": userID},
		}, options.Count().SetCollation(&caseInsensitive))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
		}
		if count > 0 {
			return nil, ErrUsernameTaken
		}
		setFields["username"] = username
	}

	if emailChanged {
		count, err := s.users().CountDocuments(ctx, bson.M{
			"email": newEmail,
			"_id":   bson.M{"$ne": userID},
		}, options.Count().SetCollation(&caseInsensitive))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
		}
		if count > 0 {
			return nil, ErrEmailTaken
		}

		confirmationToken = uuid.NewString()
		setFields["email"] = newEmail
		setFields["email_confirmed"] = false
		setFields["email_token"] = hashToken(confirmationToken)
		setFields["email_token_expiry"] = now.Add(s.cfg.EmailConfirmationTokenTTL)
		setFields["email_confirmation_attempts"] = 1
		setFields["last_email_attempt_time"] = now
	}

	if firstName := strings.TrimSpace(user.FirstName); firstName != "" {
		setFields["first_name"] = firstName
	}
	if lastName := strings.TrimSpace(user.LastName); lastName != "" {
		setFields["last_name"] = lastName
	}
	if passwordChanged {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), s.cfg.BcryptCost)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPasswordHashFailed, err)
		}
		setFields["hash"] = string(hashedPassword)
		incFields["token_version"] = 1
	}
	if user.Birthdate != "" {
		birthdate, err := time.Parse(time.RFC3339, user.Birthdate)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidBirthdate, err)
		}
		setFields["birthdate"] = birthdate.UTC()
	}
	if user.ProfilePicture != "" {
		if err := s.checkProfilePicture(user.ProfilePicture); err != nil {
			return nil, err
		}
		setFields["profile_picture"] = user.ProfilePicture
	}

	if len(setFields) == 0 && len(incFields) == 0 {
		return nil, ErrNoFieldsToUpdate
	}

	update := bson.M{}
	if len(setFields) > 0 {
		update["$set"] = setFields
	}
	if len(incFields) > 0 {
		update["$inc"] = incFields
	}

	var updatedUser data.User
	err = s.users().FindOneAndUpdate(
		ctx,
		bson.M{"_id": userID},
		update,
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&updatedUser)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserNotFound
		}
		if isDuplicateKey(err) {
			if emailChanged && strings.Contains(strings.ToLower(err.Error()), "email") {
				return nil, ErrEmailTaken
			}
			if _, ok := setFields["username"]; ok {
				return nil, ErrUsernameTaken
			}
			return nil, ErrUserExists
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	if emailChanged {
		confirmErr := s.email.SendConfirmationEmail(newEmail, confirmationToken)
		if confirmErr != nil {
			log.Printf("failed to send confirmation email to new address %s: %v", newEmail, confirmErr)
		}
		if noticeErr := s.email.SendEmailChangedNotice(current.Email, newEmail); noticeErr != nil {
			log.Printf("failed to send email-change notice to old address %s: %v", current.Email, noticeErr)
		}
		if confirmErr != nil {
			return &updatedUser, fmt.Errorf("%w: %v", ErrEmailSendFailed, confirmErr)
		}
	}

	if passwordChanged {
		log.Printf("audit: password changed user_id=%s", userID.Hex())
	}
	if emailChanged {
		log.Printf("audit: email changed user_id=%s old=%s new=%s", userID.Hex(), current.Email, newEmail)
	}

	return &updatedUser, nil
}

func (s *service) DeleteUser(userID bson.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := s.users().DeleteOne(ctx, bson.M{"_id": userID})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	if result.DeletedCount == 0 {
		return ErrUserNotFound
	}
	log.Printf("audit: account deleted user_id=%s", userID.Hex())

	return nil
}

func (s *service) CreateSession(userID bson.ObjectID) (*data.SessionTokens, error) {
	tokenVersion, err := s.GetTokenVersion(userID)
	if err != nil {
		return nil, err
	}

	return newSessionTokens(userID, tokenVersion, s.jwtSecret, time.Now().UTC(), s.cfg.AccessTokenTTL, s.cfg.RefreshTokenTTL)
}

func newSessionTokens(userID bson.ObjectID, tokenVersion int, secret []byte, now time.Time, accessTTL, refreshTTL time.Duration) (*data.SessionTokens, error) {
	accessExpiresAt := now.Add(accessTTL)
	refreshExpiresAt := now.Add(refreshTTL)

	accessClaims := &data.Claims{
		TokenType:    data.TokenTypeAccess,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.Hex(),
			Issuer:    data.TokenIssuer,
			Audience:  jwt.ClaimStrings{data.TokenAudience},
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	refreshClaims := &data.Claims{
		TokenType:    data.TokenTypeRefresh,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.Hex(),
			Issuer:    data.TokenIssuer,
			Audience:  jwt.ClaimStrings{data.TokenAudience},
			ExpiresAt: jwt.NewNumericDate(refreshExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(secret)
	if err != nil {
		return nil, fmt.Errorf("access token creation failed: %w", err)
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(secret)
	if err != nil {
		return nil, fmt.Errorf("refresh token creation failed: %w", err)
	}

	return &data.SessionTokens{
		AccessToken:      accessToken,
		AccessCreatedAt:  now,
		AccessExpiresAt:  accessExpiresAt,
		RefreshToken:     refreshToken,
		RefreshCreatedAt: now,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

func (s *service) ConfirmEmail(token string) error {
	if token == "" {
		return ErrTokenInvalid
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var foundUser data.User
	err := s.users().FindOne(ctx, bson.M{
		"email_token":        hashToken(token),
		"email_token_expiry": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&foundUser)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return ErrTokenInvalid
		}
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	if foundUser.EmailConfirmed {
		return ErrEmailAlreadyConfirmed
	}

	_, err = s.users().UpdateOne(
		ctx,
		bson.M{"_id": foundUser.ID},
		bson.M{
			"$set":   bson.M{"email_confirmed": true},
			"$unset": bson.M{"email_token": "", "email_token_expiry": ""},
		},
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	log.Printf("audit: email confirmed user_id=%s", foundUser.ID.Hex())

	return nil
}

func (s *service) ResendConfirmationEmail(userID bson.ObjectID) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	if user.EmailConfirmed {
		return ErrEmailAlreadyConfirmed
	}
	if user.EmailConfirmationAttempts >= 3 {
		return ErrConfirmationLimit
	}
	if time.Since(user.LastEmailAttemptTime) < 5*time.Minute {
		return ErrConfirmationCooldown
	}

	return s.issueConfirmationEmail(user)
}

func (s *service) ResendConfirmationEmailByEmail(email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user data.User
	err := s.users().FindOne(
		ctx,
		bson.M{"email": normalizeEmail(email)},
		options.FindOne().SetCollation(&caseInsensitive),
	).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	if user.EmailConfirmed || user.EmailConfirmationAttempts >= 3 || time.Since(user.LastEmailAttemptTime) < 5*time.Minute {
		return nil
	}

	return s.issueConfirmationEmail(&user)
}

func (s *service) issueConfirmationEmail(user *data.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rawToken := uuid.NewString()
	now := time.Now().UTC()
	result, err := s.users().UpdateOne(
		ctx,
		bson.M{
			"_id":                         user.ID,
			"email_confirmed":             false,
			"email_confirmation_attempts": bson.M{"$lt": 3},
			"last_email_attempt_time":     bson.M{"$lt": now.Add(-5 * time.Minute)},
		},
		bson.M{
			"$set": bson.M{
				"email_token":             hashToken(rawToken),
				"email_token_expiry":      now.Add(s.cfg.EmailConfirmationTokenTTL),
				"last_email_attempt_time": now,
			},
			"$inc": bson.M{"email_confirmation_attempts": 1},
		},
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	if result.MatchedCount == 0 {
		return ErrConfirmationCooldown
	}

	if err := s.email.SendConfirmationEmail(user.Email, rawToken); err != nil {
		return fmt.Errorf("%w: %v", ErrEmailSendFailed, err)
	}

	return nil
}

func (s *service) DeleteUnconfirmedUsers() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{
		"email_confirmed": false,
		"date_joined": bson.M{
			"$lt": time.Now().UTC().AddDate(0, 0, -3),
		},
	}

	result, err := s.users().DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	log.Printf("Deleted %d unconfirmed users older than 3 days", result.DeletedCount)
	return nil
}

func (s *service) InitiatePasswordReset(email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var foundUser data.User
	err := s.users().FindOne(
		ctx,
		bson.M{"email": normalizeEmail(email)},
		options.FindOne().SetCollation(&caseInsensitive),
	).Decode(&foundUser)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Do not reveal whether the address is registered.
			return nil
		}
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	rawToken := uuid.NewString()
	_, err = s.users().UpdateOne(
		ctx,
		bson.M{"_id": foundUser.ID},
		bson.M{
			"$set": bson.M{
				"password_reset_token":  hashToken(rawToken),
				"password_reset_expiry": time.Now().UTC().Add(s.cfg.PasswordResetTokenTTL),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	if err := s.email.SendPasswordResetEmail(foundUser.Email, rawToken); err != nil {
		return fmt.Errorf("%w: %v", ErrEmailSendFailed, err)
	}

	return nil
}

func (s *service) ResetPassword(token, newPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var foundUser data.User
	err := s.users().FindOne(ctx, bson.M{
		"password_reset_token":  hashToken(token),
		"password_reset_expiry": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&foundUser)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return ErrTokenInvalid
		}
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordHashFailed, err)
	}

	_, err = s.users().UpdateOne(
		ctx,
		bson.M{"_id": foundUser.ID},
		bson.M{
			"$set":   bson.M{"hash": string(hashedPassword)},
			"$unset": bson.M{"password_reset_token": "", "password_reset_expiry": ""},
			"$inc":   bson.M{"token_version": 1},
		},
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	log.Printf("audit: password reset user_id=%s", foundUser.ID.Hex())

	return nil
}

func (s *service) RevokeSessions(userID bson.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := s.users().UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{"$inc": bson.M{"token_version": 1}},
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	if result.MatchedCount == 0 {
		return ErrUserNotFound
	}
	log.Printf("audit: sessions revoked user_id=%s", userID.Hex())

	return nil
}

func (s *service) Health() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("db down: %w", err)
	}

	return map[string]string{"message": "It's healthy"}, nil
}

func (s *service) Close(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	return s.client.Disconnect(ctx)
}

func (s *service) checkProfilePicture(value string) error {
	if value == "" {
		return nil
	}
	size, err := data.ProfilePictureSize(value)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProfilePictureInvalid, err)
	}
	if size > s.cfg.MaxProfilePictureBytes {
		return ErrProfilePictureTooLarge
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func uriHasCredentials(uri string) bool {
	parsed, err := url.Parse(uri)
	return err == nil && parsed.User != nil
}

func isDuplicateKey(err error) bool {
	var writeErr mongo.WriteException
	if errors.As(err, &writeErr) {
		for _, e := range writeErr.WriteErrors {
			if e.Code == 11000 {
				return true
			}
		}
	}

	var commandErr mongo.CommandError
	if errors.As(err, &commandErr) {
		return commandErr.Code == 11000
	}

	var bulkErr mongo.BulkWriteException
	if errors.As(err, &bulkErr) {
		for _, e := range bulkErr.WriteErrors {
			if e.Code == 11000 {
				return true
			}
		}
	}

	return false
}
