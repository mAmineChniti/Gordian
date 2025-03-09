package database

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/joho/godotenv/autoload"
	"github.com/mAmineChniti/Gordian/internal/data"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	Health() (map[string]string, error)
	FindUser(user *data.LoginRequest) (*data.User, error)
	CreateUser(user *data.RegisterRequest) (*data.User, *data.SessionTokens, error)
	UpdateUser(userID primitive.ObjectID, user *data.UpdateRequest) (*data.User, error)
	DeleteUser(userID primitive.ObjectID) error
	CreateSession(userID primitive.ObjectID) (*data.SessionTokens, error)
	ValidateToken(tokenString string) (primitive.ObjectID, error)
}

type service struct {
	db *mongo.Client
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
		db: client,
	}
}

func (s *service) FindUser(req *data.LoginRequest) (*data.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var foundUser data.User
	err := s.db.Database("gordian").Collection("users").FindOne(ctx, bson.M{"username": req.Username}).Decode(&foundUser)
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

func (s *service) CreateUser(user *data.RegisterRequest) (*data.User, *data.SessionTokens, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.M{"$or": []bson.M{{"username": user.Username}, {"email": user.Email}}}
	foundUser, err := s.db.Database("gordian").Collection("users").CountDocuments(ctx, filter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check if user exists: %v", err)
	}
	if foundUser > 0 {
		return nil, nil, fmt.Errorf("user already exists")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MaxCost)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %v", err)
	}
	endUser := data.User{
		ID:         primitive.NewObjectID(),
		Username:   user.Username,
		Email:      user.Email,
		Hash:       string(hash),
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		DateJoined: time.Now(),
	}
	_, err = s.db.Database("gordian").Collection("users").InsertOne(ctx, endUser)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to insert user: %v", err)
	}
	tokens, err := s.CreateSession(endUser.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %v", err)
	}
	return &endUser, tokens, nil

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
	accessExpirationTime := time.Now().Add(7 * 24 * time.Hour)
	accessCreatedAt := time.Now()
	accessClaims := &jwt.RegisteredClaims{
		Subject:   userID.Hex(),
		ExpiresAt: jwt.NewNumericDate(accessExpirationTime),
		IssuedAt:  jwt.NewNumericDate(accessCreatedAt),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return &data.SessionTokens{}, fmt.Errorf("failed to create access JWT token: %v", err)
	}

	refreshExpirationTime := time.Now().Add(7 * 24 * time.Hour)
	refreshCreatedAt := time.Now()
	refreshClaims := &jwt.RegisteredClaims{
		Subject:   userID.Hex(),
		ExpiresAt: jwt.NewNumericDate(refreshExpirationTime),
		IssuedAt:  jwt.NewNumericDate(refreshCreatedAt),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return &data.SessionTokens{}, fmt.Errorf("failed to create refresh JWT token: %v", err)
	}

	return &data.SessionTokens{
		AccessToken:      accessTokenString,
		AccessCreatedAt:  accessCreatedAt,
		AccessExpiresAt:  accessExpirationTime,
		RefreshToken:     refreshTokenString,
		RefreshCreatedAt: refreshCreatedAt,
		RefreshExpiresAt: refreshExpirationTime,
	}, nil
}

func (s *service) ValidateToken(authHeader string) (primitive.ObjectID, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return primitive.ObjectID{}, fmt.Errorf("invalid token format")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return jwtSecret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return primitive.ObjectID{}, fmt.Errorf("token expired: %v", err)
		}
		return primitive.ObjectID{}, fmt.Errorf("invalid token: %v", err)
	}

	if !token.Valid {
		return primitive.ObjectID{}, fmt.Errorf("invalid token")
	}

	userID, err := primitive.ObjectIDFromHex(claims.Subject)
	if err != nil {
		return primitive.ObjectID{}, fmt.Errorf("invalid user ID: %v", err)
	}

	return userID, nil
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
