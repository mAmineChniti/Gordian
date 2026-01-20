package data

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                        primitive.ObjectID `json:"id" bson:"_id"`
	Username                  string             `json:"username" bson:"username"`
	Email                     string             `json:"email" bson:"email"`
	Hash                      string             `json:"-" bson:"hash"`
	FirstName                 string             `json:"first_name" bson:"first_name"`
	LastName                  string             `json:"last_name" bson:"last_name"`
	Birthdate                 time.Time          `json:"birthdate" bson:"birthdate"`
	ProfilePicture            string             `json:"profile_picture" bson:"profile_picture"`
	EmailConfirmed            bool               `json:"email_confirmed" bson:"email_confirmed"`
	AcceptTerms               bool               `json:"accept_terms" bson:"accept_terms"`
	DateJoined                time.Time          `json:"date_joined" bson:"date_joined"`
	EmailToken                string             `json:"-" bson:"email_token"`
	EmailConfirmationAttempts int                `json:"-" bson:"email_confirmation_attempts"`
	LastEmailAttemptTime      time.Time          `json:"-" bson:"last_email_attempt_time"`
	PasswordResetToken        string             `json:"-" bson:"password_reset_token,omitempty"`
	PasswordResetExpiry       time.Time          `json:"-" bson:"password_reset_expiry,omitempty"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required,min=5" example:"johndoe"`
	Password   string `json:"password" validate:"required,password_complexity" example:"P@ssw0rd!"`
}

type RegisterRequest struct {
	Username       string `json:"username" validate:"required,min=5,max=20" example:"johndoe"`
	Email          string `json:"email" validate:"required,email" example:"john@example.com"`
	Password       string `json:"password" validate:"required,password_complexity" example:"P@ssw0rd!"`
	FirstName      string `json:"first_name" validate:"required,min=2,max=50" example:"John"`
	LastName       string `json:"last_name" validate:"required,min=2,max=50" example:"Doe"`
	Birthdate      string `json:"birthdate" validate:"required,rfc3339" example:"1990-01-01T00:00:00Z"`
	AcceptTerms    bool   `json:"accept_terms" validate:"required,eq=true" example:"true"`
	ProfilePicture string `json:"profile_picture,omitempty" validate:"omitempty,base64_max_10mb" example:"data:image/png;base64,iVBORw0..."`
}

type UpdateRequest struct {
	Username       string `json:"username,omitempty" validate:"omitempty,min=5,max=20" example:"johndoe"`
	Email          string `json:"email,omitempty" validate:"omitempty,email" example:"john@example.com"`
	Password       string `json:"password,omitempty" validate:"omitempty,password_complexity" example:"NewP@ssw0rd!"`
	FirstName      string `json:"first_name,omitempty" validate:"omitempty,min=2,max=50" example:"John"`
	LastName       string `json:"last_name,omitempty" validate:"omitempty,min=2,max=50" example:"Doe"`
	Birthdate      string `json:"birthdate,omitempty" validate:"omitempty,rfc3339" example:"1990-01-01T00:00:00Z"`
	ProfilePicture string `json:"profile_picture,omitempty" validate:"omitempty,base64_max_10mb" example:"data:image/png;base64,iVBORw0..."`
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

type PasswordResetInitiateRequest struct {
	Email string `json:"email" validate:"required,email" example:"john@example.com"`
}

type PasswordResetConfirmRequest struct {
	Token       string `json:"token" validate:"required,uuid" example:"123e4567-e89b-12d3-a456-426614174000"`
	NewPassword string `json:"new_password" validate:"required,password_complexity" example:"NewP@ssw0rd!"`
}
