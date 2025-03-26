package database

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/gommon/log"
	"github.com/mAmineChniti/Gordian/internal/data"
	"github.com/mAmineChniti/Gordian/internal/services"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	Health() (map[string]string, error)
	FindUser(user *data.LoginRequest) (*data.User, error)
	GetUser(userID primitive.ObjectID) (*data.User, error)
	CreateUser(user *data.RegisterRequest) error
	UpdateUser(userID primitive.ObjectID, user *data.UpdateRequest) (*data.User, error)
	DeleteUser(userID primitive.ObjectID) error
	CreateSession(userID primitive.ObjectID) (*data.SessionTokens, error)
	ConfirmEmail(token string) (bool, string)
	ResendConfirmationEmail(userID primitive.ObjectID) error
	DeleteUnconfirmedUsers() error
}

type service struct {
	db           *mongo.Client
	emailService services.EmailService
}

var (
	dbUsername       = os.Getenv("DB_USERNAME")
	dbPassword       = os.Getenv("DB_PASSWORD")
	connectionString = os.Getenv("DB_CONNECTION_STRING")
	jwtSecret        = []byte(os.Getenv("JWTSECRET"))
)

func New() Service {

	uri := fmt.Sprintf("mongodb+srv://%s:%s%s", dbUsername, dbPassword, connectionString)
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(uri))

	if err != nil {
		log.Fatal(err)

	}
	return &service{
		db:           client,
		emailService: services.NewGmailSMTPEmailService(),
	}
}

func (s *service) FindUser(req *data.LoginRequest) (*data.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var foundUser data.User
	filter := bson.M{"username": req.Identifier}

	if strings.Contains(req.Identifier, "@") {
		filter = bson.M{"email": req.Identifier}
	}

	err := s.db.Database("gordian").Collection("users").FindOne(ctx, filter).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found: %v", err)
		}
		return nil, fmt.Errorf("db error: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Hash), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("invalid password: %v", err)
	}

	return &foundUser, nil
}

func (s *service) GetUser(userID primitive.ObjectID) (*data.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var foundUser data.User
	err := s.db.Database("gordian").Collection("users").FindOne(ctx, bson.M{"_id": userID}).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found: %v", err)
		}
		return nil, fmt.Errorf("db error: %v", err)
	}

	return &foundUser, nil
}

func (s *service) CreateUser(user *data.RegisterRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	filter := bson.M{"$or": []bson.M{{"username": user.Username}, {"email": user.Email}}}
	foundUser, err := s.db.Database("gordian").Collection("users").CountDocuments(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to check if user exists: %v", err)
	}
	if foundUser > 0 {
		return fmt.Errorf("user already exists")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	birthdate, err := time.Parse(time.RFC3339, user.Birthdate)
	if err != nil {
		return fmt.Errorf("failed to parse birthdate: must be in ISO 8601 format (RFC3339)")
	}

	emailToken := uuid.New().String()

	endUser := data.User{
		ID:                        primitive.NewObjectID(),
		Username:                  user.Username,
		Email:                     user.Email,
		Hash:                      string(hash),
		FirstName:                 user.FirstName,
		LastName:                  user.LastName,
		Birthdate:                 birthdate,
		DateJoined:                time.Now(),
		EmailConfirmed:            false,
		EmailToken:                emailToken,
		EmailConfirmationAttempts: 1,
		LastEmailAttemptTime:      time.Now(),
	}
	_, err = s.db.Database("gordian").Collection("users").InsertOne(ctx, endUser)
	if err != nil {
		return fmt.Errorf("failed to insert user: %v", err)
	}

	if err := s.emailService.SendConfirmationEmail(endUser.Email, emailToken); err != nil {
		return fmt.Errorf("failed to send confirmation email: %v", err)
	}

	return nil
}

func (s *service) UpdateUser(userID primitive.ObjectID, user *data.UpdateRequest) (*data.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	updateFields := bson.M{}
	if user.Username != "" {
		updateFields["username"] = user.Username
	}
	if user.Email != "" {
		updateFields["email"] = user.Email
	}
	if user.FirstName != "" {
		updateFields["first_name"] = user.FirstName
	}
	if user.LastName != "" {
		updateFields["last_name"] = user.LastName
	}
	if user.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MaxCost)
		if err != nil {
			return nil, fmt.Errorf("password hashing failed: %w", err)
		}
		updateFields["hash"] = hashedPassword
	}
	if user.Birthdate != "" {
		birthdate, err := time.Parse(time.RFC3339, user.Birthdate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse birthdate: must be in ISO 8601 format (RFC3339)")
		}
		updateFields["birthdate"] = birthdate
	}

	if len(updateFields) == 0 {
		return nil, fmt.Errorf("no fields to update")
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var updatedUser data.User
	err := s.db.Database("gordian").Collection("users").FindOneAndUpdate(
		ctx,
		bson.M{"_id": userID},
		bson.M{"$set": updateFields},
		opts,
	).Decode(&updatedUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &updatedUser, nil
}

func (s *service) DeleteUser(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := s.db.Database("gordian").Collection("users").DeleteOne(ctx, bson.M{"_id": userID})
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	return nil
}

func (s *service) CreateSession(userID primitive.ObjectID) (*data.SessionTokens, error) {
	now := time.Now()

	accessClaims := &jwt.RegisteredClaims{
		Subject:   userID.Hex(),
		ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        "access",
	}

	refreshClaims := &jwt.RegisteredClaims{
		Subject:   userID.Hex(),
		ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        "refresh",
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("access token creation failed: %w", err)
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("refresh token creation failed: %w", err)
	}

	return &data.SessionTokens{
		AccessToken:      accessToken,
		AccessExpiresAt:  accessClaims.ExpiresAt.Time,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshClaims.ExpiresAt.Time,
	}, nil
}

func (s *service) ConfirmEmail(token string) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var foundUser data.User
	err := s.db.Database("gordian").Collection("users").FindOne(ctx, bson.M{"email_token": token}).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, "Invalid or expired confirmation link"
		}
		return false, "An error occurred while confirming your email"
	}

	if foundUser.EmailConfirmed {
		return false, "Email is already confirmed"
	}

	update := bson.M{
		"$set": bson.M{
			"email_confirmed": true,
		},
	}
	err = s.db.Database("gordian").Collection("users").FindOneAndUpdate(
		ctx,
		bson.M{"_id": foundUser.ID},
		update,
	).Err()

	if err != nil {
		return false, "Failed to confirm email. Please try again."
	}

	return true, ""
}

func (s *service) ResendConfirmationEmail(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user data.User
	err := s.db.Database("gordian").Collection("users").FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("database error: %v", err)
	}

	if user.EmailConfirmed {
		return fmt.Errorf("email already confirmed")
	}

	if user.EmailConfirmationAttempts >= 3 {
		return fmt.Errorf("maximum email confirmation attempts reached")
	}

	if time.Since(user.LastEmailAttemptTime) < 5*time.Minute {
		return fmt.Errorf("please wait 5 minutes before requesting another confirmation email")
	}

	newEmailToken := uuid.New().String()

	update := bson.M{
		"$set": bson.M{
			"email_token":                 newEmailToken,
			"email_confirmation_attempts": user.EmailConfirmationAttempts + 1,
			"last_email_attempt_time":     time.Now(),
		},
	}

	_, err = s.db.Database("gordian").Collection("users").UpdateOne(
		ctx,
		bson.M{"_id": userID},
		update,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}

	if err := s.emailService.SendConfirmationEmail(user.Email, newEmailToken); err != nil {
		return fmt.Errorf("failed to send confirmation email: %v", err)
	}

	return nil
}

func (s *service) DeleteUnconfirmedUsers() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	deleteFilter := bson.M{
		"email_confirmed": false,
		"date_joined": bson.M{
			"$lte": time.Now().AddDate(0, 0, -3),
		},
	}

	result, err := s.db.Database("gordian").Collection("users").DeleteMany(ctx, deleteFilter)
	if err != nil {
		return fmt.Errorf("failed to delete unconfirmed users: %v", err)
	}

	log.Printf("Deleted %d unconfirmed users older than 3 days", result.DeletedCount)
	return nil
}

func (s *service) Health() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := s.db.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("db down: %v", err)
	}

	return map[string]string{"message": "It's healthy"}, nil
}
