package database

import "errors"

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserExists             = errors.New("user already exists")
	ErrUsernameTaken          = errors.New("username already exists")
	ErrEmailTaken             = errors.New("email already exists")
	ErrNoFieldsToUpdate       = errors.New("no fields to update")
	ErrCurrentPasswordNeeded  = errors.New("current password is required")
	ErrInvalidCurrentPassword = errors.New("current password is incorrect")
	ErrEmailAlreadyConfirmed  = errors.New("email already confirmed")
	ErrConfirmationLimit      = errors.New("maximum confirmation attempts reached")
	ErrConfirmationCooldown   = errors.New("confirmation email cooldown")
	ErrTokenInvalid           = errors.New("invalid or expired token")
	ErrEmailSendFailed        = errors.New("failed to send email")
	ErrPasswordHashFailed     = errors.New("password hashing failed")
	ErrInvalidBirthdate       = errors.New("invalid birthdate")
	ErrProfilePictureInvalid  = errors.New("invalid profile picture")
	ErrProfilePictureTooLarge = errors.New("profile picture is too large")
	ErrDatabase               = errors.New("database error")
)
