package data

import (
	"fmt"
	"log"
	"strings"
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
		if req.Username == "" && req.Email == "" && req.Password == "" &&
			req.FirstName == "" && req.LastName == "" && req.Birthdate == "" {
			return "", fmt.Errorf("no fields provided for update")
		}
	}
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return "", fmt.Errorf("invalid validation error: %w", err)
		}

		validationErrors := err.(validator.ValidationErrors)
		if len(validationErrors) > 0 {
			var errorMessages []string
			for _, fieldErr := range validationErrors {
				var errorMsg string
				switch fieldErr.Tag() {
				case "required":
					errorMsg = fmt.Sprintf("%s is a required field", fieldErr.Field())
				case "min":
					errorMsg = fmt.Sprintf("%s must be at least %s characters long", fieldErr.Field(), fieldErr.Param())
				case "max":
					errorMsg = fmt.Sprintf("%s must be at most %s characters long", fieldErr.Field(), fieldErr.Param())
				case "email":
					errorMsg = fmt.Sprintf("%s must be a valid email address", fieldErr.Field())
				case "birthdate":
					errorMsg = fmt.Sprintf("%s must indicate a user who is 18+ years old", fieldErr.Field())
				case "containsany":
					errorMsg = fmt.Sprintf("%s must contain at least one character from the specified set", fieldErr.Field())
				case "eqfield":
					errorMsg = fmt.Sprintf("%s must match %s", fieldErr.Field(), fieldErr.Param())
				case "uuid":
					errorMsg = fmt.Sprintf("%s must be a valid UUID", fieldErr.Field())
				case "eq":
					if fieldErr.Param() == "true" {
						errorMsg = fmt.Sprintf("%s must be true", fieldErr.Field())
					} else {
						errorMsg = fmt.Sprintf("%s failed validation", fieldErr.Field())
					}
				default:
					errorMsg = fmt.Sprintf("%s failed validation on '%s' tag", fieldErr.Field(), fieldErr.Tag())
				}
				errorMessages = append(errorMessages, errorMsg)
			}
			return strings.Join(errorMessages, "; "), fmt.Errorf("validation errors")
		}
		return "Unknown validation error", fmt.Errorf("validation errors")
	}
	return "", nil
}
