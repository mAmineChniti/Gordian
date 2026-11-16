package data

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	TokenIssuer      = "gordian"
	TokenAudience    = "gordian-api"
)

// Claims is the JWT payload used for access and refresh tokens.
type Claims struct {
	TokenType    string `json:"typ"`
	TokenVersion int    `json:"ver"`
	jwt.RegisteredClaims
}

type User struct {
	ID                        bson.ObjectID `json:"id" bson:"_id"`
	Username                  string        `json:"username" bson:"username"`
	Email                     string        `json:"email" bson:"email"`
	Hash                      string        `json:"-" bson:"hash"`
	FirstName                 string        `json:"first_name" bson:"first_name"`
	LastName                  string        `json:"last_name" bson:"last_name"`
	Birthdate                 time.Time     `json:"birthdate" bson:"birthdate"`
	ProfilePicture            string        `json:"profile_picture" bson:"profile_picture"`
	EmailConfirmed            bool          `json:"email_confirmed" bson:"email_confirmed"`
	AcceptTerms               bool          `json:"accept_terms" bson:"accept_terms"`
	DateJoined                time.Time     `json:"date_joined" bson:"date_joined"`
	EmailToken                string        `json:"-" bson:"email_token,omitempty"`
	EmailTokenExpiry          time.Time     `json:"-" bson:"email_token_expiry,omitempty"`
	EmailConfirmationAttempts int           `json:"-" bson:"email_confirmation_attempts"`
	LastEmailAttemptTime      time.Time     `json:"-" bson:"last_email_attempt_time"`
	PasswordResetToken        string        `json:"-" bson:"password_reset_token,omitempty"`
	PasswordResetExpiry       time.Time     `json:"-" bson:"password_reset_expiry,omitempty"`
	TokenVersion              int           `json:"-" bson:"token_version"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required,max=254" example:"johndoe"`
	Password   string `json:"password" validate:"required,max=128" example:"P@ssw0rd!"`
}

type RegisterRequest struct {
	Username       string `json:"username" validate:"required,min=5,max=20,username" example:"johndoe"`
	Email          string `json:"email" validate:"required,email,max=254" example:"john@example.com"`
	Password       string `json:"password" validate:"required,password_complexity" example:"P@ssw0rd!"`
	FirstName      string `json:"first_name" validate:"required,min=2,max=50" example:"John"`
	LastName       string `json:"last_name" validate:"required,min=2,max=50" example:"Doe"`
	Birthdate      string `json:"birthdate" validate:"required,rfc3339" example:"1990-01-01T00:00:00Z"`
	AcceptTerms    bool   `json:"accept_terms" validate:"required,eq=true" example:"true"`
	ProfilePicture string `json:"profile_picture,omitempty" validate:"omitempty,profile_picture" example:"data:image/png;base64,iVBORw0..."`
}

type UpdateRequest struct {
	Username        string `json:"username,omitempty" validate:"omitempty,min=5,max=20,username" example:"johndoe"`
	Email           string `json:"email,omitempty" validate:"omitempty,email,max=254" example:"john@example.com"`
	CurrentPassword string `json:"current_password,omitempty" validate:"omitempty,max=128" example:"OldP@ssw0rd!"`
	Password        string `json:"password,omitempty" validate:"omitempty,password_complexity" example:"NewP@ssw0rd!"`
	FirstName       string `json:"first_name,omitempty" validate:"omitempty,min=2,max=50" example:"John"`
	LastName        string `json:"last_name,omitempty" validate:"omitempty,min=2,max=50" example:"Doe"`
	Birthdate       string `json:"birthdate,omitempty" validate:"omitempty,rfc3339" example:"1990-01-01T00:00:00Z"`
	ProfilePicture  string `json:"profile_picture,omitempty" validate:"omitempty,profile_picture" example:"data:image/png;base64,iVBORw0..."`
}

type FetchUserByIDRequest struct {
	ID string `json:"user_id" validate:"required" example:"615f2e0a6c6d5c0e1a1e4a01"`
}

type ResendConfirmationRequest struct {
	Email string `json:"email" validate:"required,email,max=254" example:"john@example.com"`
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
	Email string `json:"email" validate:"required,email,max=254" example:"john@example.com"`
}

type PasswordResetConfirmRequest struct {
	Token       string `json:"token" validate:"required,uuid" example:"123e4567-e89b-12d3-a456-426614174000"`
	NewPassword string `json:"new_password" validate:"required,password_complexity" example:"NewP@ssw0rd!"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

// PublicUser is the full profile returned to the authenticated owner.
type PublicUser struct {
	Username       string    `json:"username"`
	FirstName      string    `json:"first_name"`
	LastName       string    `json:"last_name"`
	Birthdate      time.Time `json:"birthdate"`
	DateJoined     time.Time `json:"date_joined"`
	ProfilePicture string    `json:"profile_picture,omitempty"`
	EmailConfirmed bool      `json:"email_confirmed"`
}

// PublicProfile is the limited profile returned when looking up another user.
type PublicProfile struct {
	Username       string    `json:"username"`
	FirstName      string    `json:"first_name"`
	LastName       string    `json:"last_name"`
	DateJoined     time.Time `json:"date_joined"`
	ProfilePicture string    `json:"profile_picture,omitempty"`
}

type UserResponse struct {
	Message string         `json:"message"`
	User    *PublicUser    `json:"user"`
	Tokens  *SessionTokens `json:"tokens,omitempty"`
}

type PublicProfileResponse struct {
	Message string         `json:"message"`
	User    *PublicProfile `json:"user"`
}

type HealthResponse struct {
	Status  string         `json:"status"`
	Details map[string]any `json:"details,omitempty"`
}

type ValidationErrorResponse struct {
	Message string            `json:"message,omitempty"`
	Errors  map[string]string `json:"errors,omitempty"`
}
