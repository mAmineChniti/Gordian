package data

import (
	"fmt"
	"log"
	"time"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
	if err := validate.RegisterValidation("birthdate", validateBirthdate); err != nil {
		log.Fatalf("Failed to register birthdate validator: %v", err)
	}
}

func validateBirthdate(fl validator.FieldLevel) bool {
	dateStr := fl.Field().String()
	if dateStr == "" {
		return false
	}

	birthdate, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return false
	}

	now := time.Now()
	age := now.Year() - birthdate.Year()

	if now.Month() < birthdate.Month() || (now.Month() == birthdate.Month() && now.Day() < birthdate.Day()) {
		age--
	}

	return age >= 18
}

func ValidateStruct(s any) (string, error) {
	err := validate.Struct(s)
	if req, ok := s.(UpdateRequest); ok {
		if req.Username == "" && req.Email == "" && req.Password == "" && req.FirstName == "" && req.LastName == "" && req.Birthdate == "" {
			return "", fmt.Errorf("empty update request")
		}
	}
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return "", fmt.Errorf("invalid validation error: %w", err)
		}

		validationErrors := err.(validator.ValidationErrors)
		if len(validationErrors) > 0 {
			fieldErr := validationErrors[0]
			if fieldErr.Tag() == "birthdate" {
				return fmt.Sprintf("%s must indicate a user who is 18+ years old", fieldErr.Field()), fmt.Errorf("validation errors")
			} else {
				return fmt.Sprintf("%s failed on '%s' tag", fieldErr.Field(), fieldErr.Tag()), fmt.Errorf("validation errors")
			}
		}
		return "Unknown validation error", fmt.Errorf("validation errors")
	}
	return "", nil
}
