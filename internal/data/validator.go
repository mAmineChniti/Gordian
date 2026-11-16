package data

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
)

// MaxProfilePictureBytes is the absolute ceiling accepted by the validator.
// The configured per-deployment limit is enforced again in the database layer.
const MaxProfilePictureBytes = int64(10 << 20)

var Validate *validator.Validate

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

var allowedImagePrefixes = map[string]struct{}{
	"data:image/png;base64":  {},
	"data:image/jpeg;base64": {},
	"data:image/jpg;base64":  {},
	"data:image/webp;base64": {},
	"data:image/gif;base64":  {},
}

func init() {
	Validate = validator.New()

	Validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "" || name == "-" {
			return fld.Name
		}
		return name
	})

	mustRegister("rfc3339", validateBirthdate)
	mustRegister("password_complexity", validatePasswordComplexity)
	mustRegister("profile_picture", validateProfilePicture)
	mustRegister("username", validateUsername)
}

func mustRegister(tag string, fn validator.Func) {
	if err := Validate.RegisterValidation(tag, fn); err != nil {
		panic(fmt.Sprintf("failed to register %s validation: %v", tag, err))
	}
}

func validateUsername(fl validator.FieldLevel) bool {
	return usernameRegex.MatchString(fl.Field().String())
}

func validateBirthdate(fl validator.FieldLevel) bool {
	birthdate, err := time.Parse(time.RFC3339, fl.Field().String())
	if err != nil {
		return false
	}

	now := time.Now().UTC()
	birthdate = birthdate.UTC()
	age := now.Year() - birthdate.Year()
	if now.Month() < birthdate.Month() ||
		(now.Month() == birthdate.Month() && now.Day() < birthdate.Day()) {
		age--
	}

	return age >= 18 && age <= 120
}

func validatePasswordComplexity(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// bcrypt only considers the first 72 bytes, so reject anything longer.
	if len(password) < 8 || len(password) > 72 {
		return false
	}

	var hasUppercase, hasLowercase, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUppercase = true
		case unicode.IsLower(char):
			hasLowercase = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char), unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUppercase && hasLowercase && hasDigit && hasSpecial
}

func validateProfilePicture(fl validator.FieldLevel) bool {
	_, err := ProfilePictureSize(fl.Field().String())
	return err == nil
}

// ProfilePictureSize validates a raw base64 or data-URL image and returns its
// decoded size in bytes.
func ProfilePictureSize(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}

	payload := value
	if strings.HasPrefix(strings.ToLower(value), "data:") {
		header, data, ok := strings.Cut(value, ",")
		if !ok {
			return 0, errors.New("malformed data URL")
		}
		header = strings.ToLower(strings.TrimSpace(header))
		if _, allowed := allowedImagePrefixes[header]; !allowed {
			return 0, errors.New("unsupported image type")
		}
		payload = data
	}

	// 4 base64 characters encode 3 bytes; allow a little padding slack.
	maxEncoded := (MaxProfilePictureBytes*4)/3 + 4
	if int64(len(payload)) > maxEncoded {
		return 0, errors.New("image is too large")
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return 0, errors.New("invalid base64 image")
	}
	if int64(len(decoded)) > MaxProfilePictureBytes {
		return 0, errors.New("image is too large")
	}

	return int64(len(decoded)), nil
}

// ValidationErrors converts validator errors into a JSON-field-keyed map whose
// values are safe to return to API clients.
func ValidationErrors(err error) map[string]string {
	if err == nil {
		return nil
	}

	var validationErrors validator.ValidationErrors
	if !errors.As(err, &validationErrors) {
		return map[string]string{"general": "invalid request"}
	}

	result := make(map[string]string, len(validationErrors))
	for _, e := range validationErrors {
		field := e.Field()
		switch e.Tag() {
		case "required":
			result[field] = fmt.Sprintf("%s is required", field)
		case "min":
			result[field] = fmt.Sprintf("%s must be at least %s characters", field, e.Param())
		case "max":
			result[field] = fmt.Sprintf("%s must be at most %s characters", field, e.Param())
		case "email":
			result[field] = "invalid email format"
		case "username":
			result[field] = "username may only contain letters, numbers, dots, hyphens and underscores"
		case "rfc3339":
			result[field] = "invalid birthdate. Must be in RFC3339 format and the user must be between 18 and 120 years old"
		case "eq":
			result[field] = "you must accept the terms and conditions"
		case "profile_picture":
			result[field] = "profile picture must be a valid PNG, JPEG, WebP or GIF image within the configured size limit"
		case "password_complexity":
			result[field] = "password must be 8-72 characters and include uppercase, lowercase, a number and a special character"
		case "uuid":
			result[field] = "invalid token format"
		default:
			result[field] = fmt.Sprintf("%s is invalid", field)
		}
	}

	return result
}
