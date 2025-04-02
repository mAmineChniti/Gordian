package data

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var Validate *validator.Validate

func init() {
	Validate = validator.New()

	if err := Validate.RegisterValidation("rfc3339", validateBirthdate); err != nil {
		panic(fmt.Sprintf("Failed to register birthdate validation: %v", err))
	}

	if err := Validate.RegisterValidation("password_complexity", validatePasswordComplexity); err != nil {
		panic(fmt.Sprintf("Failed to register password complexity validation: %v", err))
	}
}

func validateBirthdate(fl validator.FieldLevel) bool {
	birthdateStr := fl.Field().String()

	birthdate, err := time.Parse(time.RFC3339, birthdateStr)
	if err != nil {
		return false
	}

	today := time.Now()
	age := today.Year() - birthdate.Year()
	if today.Month() < birthdate.Month() ||
		(today.Month() == birthdate.Month() && today.Day() < birthdate.Day()) {
		age--
	}

	return age >= 18
}

func validatePasswordComplexity(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	if len(password) > 64 {
		return false
	}

	hasUppercase := false
	hasLowercase := false
	hasDigit := false
	hasSpecialChar := false

	specialChars := "!@#$%^&*(),.?"

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUppercase = true
		case unicode.IsLower(char):
			hasLowercase = true
		case unicode.IsDigit(char):
			hasDigit = true
		case strings.ContainsRune(specialChars, char):
			hasSpecialChar = true
		}
	}

	return hasUppercase && hasLowercase && hasDigit && hasSpecialChar
}

func ValidateRegisterRequest(req *RegisterRequest) error {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, e := range validationErrors {
				switch e.Tag() {
				case "required":
					return fmt.Errorf("%s is required", e.Field())
				case "min":
					return fmt.Errorf("%s must be at least %s characters", e.Field(), e.Param())
				case "max":
					return fmt.Errorf("%s must be at most %s characters", e.Field(), e.Param())
				case "email":
					return errors.New("invalid email format")
				case "rfc3339":
					return errors.New("invalid birthdate. Must be in RFC3339 format and user must be 18 or older")
				case "eq":
					return errors.New("you must accept the terms and conditions")
				}
			}
		}
		return err
	}
	return nil
}

func ValidateLoginRequest(req *LoginRequest) error {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, e := range validationErrors {
				switch e.Tag() {
				case "required":
					return fmt.Errorf("%s is required", e.Field())
				case "min":
					return fmt.Errorf("%s must be at least %s characters", e.Field(), e.Param())
				case "containsany":
					return errors.New("password must contain at least one uppercase, lowercase, number, or special character")
				}
			}
		}
		return err
	}
	return nil
}

func ValidateUpdateRequest(req *UpdateRequest) error {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, e := range validationErrors {
				switch e.Tag() {
				case "omitempty":
					continue
				case "min":
					return fmt.Errorf("%s must be at least %s characters", e.Field(), e.Param())
				case "max":
					return fmt.Errorf("%s must be at most %s characters", e.Field(), e.Param())
				case "email":
					return errors.New("invalid email format")
				case "rfc3339":
					return errors.New("invalid birthdate. Must be in RFC3339 format and user must be 18 or older")
				}
			}
		}
		return err
	}
	return nil
}

func ValidatePasswordResetInitiateRequest(req *PasswordResetInitiateRequest) error {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, e := range validationErrors {
				switch e.Tag() {
				case "required":
					return fmt.Errorf("%s is required", e.Field())
				case "email":
					return errors.New("invalid email format")
				}
			}
		}
		return err
	}
	return nil
}

func ValidatePasswordResetConfirmRequest(req *PasswordResetConfirmRequest) error {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, e := range validationErrors {
				switch e.Tag() {
				case "required":
					return fmt.Errorf("%s is required", e.Field())
				case "uuid":
					return errors.New("invalid token format")
				case "min":
					return fmt.Errorf("%s must be at least %s characters", e.Field(), e.Param())
				case "max":
					return fmt.Errorf("%s must be at most %s characters", e.Field(), e.Param())
				case "containsany":
					return errors.New("password must contain at least one uppercase, lowercase, number, or special character")
				}
			}
		}
		return err
	}
	return nil
}
