package data

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type User struct {
	ID         primitive.ObjectID `json:"id" bson:"_id"`
	Username   string             `json:"username" bson:"username"`
	Email      string             `json:"email" bson:"email"`
	Hash       string             `json:"-" bson:"hash"`
	FirstName  string             `json:"first_name" bson:"first_name"`
	LastName   string             `json:"last_name" bson:"last_name"`
	DateJoined time.Time          `json:"date_joined" bson:"date_joined"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required,min=5"`
	Password   string `json:"password" validate:"required,min=6"`
}

type RegisterRequest struct {
	Username  string `json:"username" validate:"required,min=5"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=6"`
	FirstName string `json:"first_name" validate:"required,min=3"`
	LastName  string `json:"last_name" validate:"required,min=3"`
}

type UpdateRequest struct {
	Username  string `json:"username,omitempty" validate:"omitempty,min=5"`
	Email     string `json:"email,omitempty" validate:"omitempty,email"`
	Password  string `json:"password,omitempty" validate:"omitempty,min=6"`
	FirstName string `json:"first_name,omitempty" validate:"omitempty,min=3"`
	LastName  string `json:"last_name,omitempty" validate:"omitempty,min=3"`
}

type SessionTokens struct {
	AccessToken      string    `json:"access_token"`
	AccessCreatedAt  time.Time `json:"access_created_at"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshCreatedAt time.Time `json:"refresh_created_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

type TokenResponse struct {
	Message string         `json:"message"`
	Tokens  *SessionTokens `json:"tokens"`
}

type LoginRegisterResponse struct {
	Message string         `json:"message"`
	User    *User          `json:"user"`
	Tokens  *SessionTokens `json:"tokens"`
}
