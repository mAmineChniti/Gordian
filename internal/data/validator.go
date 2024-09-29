package data

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
}

func ValidateStruct(s interface{}) error {
	err := validate.Struct(s)
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return fmt.Errorf("invalid validation error: %v", err)
		}

		validationErrors := err.(validator.ValidationErrors)
		errorMessages := ""
		for _, fieldErr := range validationErrors {
			errorMessages += fmt.Sprintf("Field '%s' failed on the '%s' tag\n", fieldErr.Field(), fieldErr.Tag())
		}
		return fmt.Errorf("validation errors:\n%s", errorMessages)
	}
	return nil
}
