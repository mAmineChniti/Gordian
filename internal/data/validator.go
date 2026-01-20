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

	if err := Validate.RegisterValidation("base64_max_10mb", validateBase64Max10MB); err != nil {
		panic(fmt.Sprintf("Failed to register base64 size validation: %v", err))
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

func validateBase64Max10MB(fl validator.FieldLevel) bool {
	base64Str := fl.Field().String()
	if len(base64Str) == 0 {
		return true // Field is optional
	}

	// Calculate approximate size of base64 string in bytes
	sizeInBytes := len(base64Str) * 3 / 4
	return sizeInBytes <= 10*1024*1024 // 10MB
}

func ValidateRegisterRequest(req *RegisterRequest) map[string]string {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			errorMap := make(map[string]string)
			for _, e := range validationErrors {
				field := e.Field()
				switch e.Tag() {
				case "required":
					errorMap[field] = fmt.Sprintf("%s is required", field)
				case "min":
					errorMap[field] = fmt.Sprintf("%s must be at least %s characters", field, e.Param())
				case "max":
					errorMap[field] = fmt.Sprintf("%s must be at most %s characters", field, e.Param())
				case "email":
					errorMap[field] = "invalid email format"
				case "rfc3339":
					errorMap[field] = "invalid birthdate. Must be in RFC3339 format and user must be 18 or older"
				case "eq":
					errorMap[field] = "you must accept the terms and conditions"
				case "base64_max_10mb":
					errorMap[field] = "profile picture exceeds 10MB limit"
				}
			}
			if len(errorMap) > 0 {
				return errorMap
			}
		}
		return map[string]string{"general": err.Error()}
	}
	return nil
}

func ValidateLoginRequest(req *LoginRequest) map[string]string {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			errorMap := make(map[string]string)
			for _, e := range validationErrors {
				field := e.Field()
				switch e.Tag() {
				case "required":
					errorMap[field] = fmt.Sprintf("%s is required", field)
				case "min":
					errorMap[field] = fmt.Sprintf("%s must be at least %s characters", field, e.Param())
				case "containsany":
					errorMap[field] = "password must contain at least one uppercase, lowercase, number, or special character"
				}
			}
			if len(errorMap) > 0 {
				return errorMap
			}
		}
		return map[string]string{"general": err.Error()}
	}
	return nil
}

func ValidateUpdateRequest(req *UpdateRequest) map[string]string {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			errorMap := make(map[string]string)
			for _, e := range validationErrors {
				field := e.Field()
				switch e.Tag() {
				case "omitempty":
					continue
				case "min":
					errorMap[field] = fmt.Sprintf("%s must be at least %s characters", field, e.Param())
				case "max":
					errorMap[field] = fmt.Sprintf("%s must be at most %s characters", field, e.Param())
				case "email":
					errorMap[field] = "invalid email format"
				case "rfc3339":
					errorMap[field] = "invalid birthdate. Must be in RFC3339 format and user must be 18 or older"
				case "base64_max_10mb":
					errorMap[field] = "profile picture exceeds 10MB limit"
				}
			}
			if len(errorMap) > 0 {
				return errorMap
			}
		}
		return map[string]string{"general": err.Error()}
	}
	return nil
}

func ValidatePasswordResetInitiateRequest(req *PasswordResetInitiateRequest) map[string]string {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			errorMap := make(map[string]string)
			for _, e := range validationErrors {
				field := e.Field()
				switch e.Tag() {
				case "required":
					errorMap[field] = fmt.Sprintf("%s is required", field)
				case "email":
					errorMap[field] = "invalid email format"
				}
			}
			if len(errorMap) > 0 {
				return errorMap
			}
		}
		return map[string]string{"general": err.Error()}
	}
	return nil
}

func ValidatePasswordResetConfirmRequest(req *PasswordResetConfirmRequest) map[string]string {
	if err := Validate.Struct(req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			errorMap := make(map[string]string)
			for _, e := range validationErrors {
				field := e.Field()
				switch e.Tag() {
				case "required":
					errorMap[field] = fmt.Sprintf("%s is required", field)
				case "uuid":
					errorMap[field] = "invalid token format"
				case "min":
					errorMap[field] = fmt.Sprintf("%s must be at least %s characters", field, e.Param())
				case "max":
					errorMap[field] = fmt.Sprintf("%s must be at most %s characters", field, e.Param())
				case "containsany":
					errorMap[field] = "password must contain at least one uppercase, lowercase, number, or special character"
				}
			}
			if len(errorMap) > 0 {
				return errorMap
			}
		}
		return map[string]string{"general": err.Error()}
	}
	return nil
}
