package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	echoSwagger "github.com/swaggo/echo-swagger"
	"go.mongodb.org/mongo-driver/bson/primitive"

	_ "github.com/mAmineChniti/Gordian/docs"
	"github.com/mAmineChniti/Gordian/internal/data"
)

var (
	jwtSecret = []byte(os.Getenv("JWTSECRET"))
	debug     = os.Getenv("DEBUG") == "true"
)

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Use(middleware.Recover())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"https://*", "http://*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	e.Logger.SetLevel(log.DEBUG)
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus: true,
		LogURI:    true,
		LogMethod: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			c.Logger().Infof("method=%s, uri=%s, status=%d", v.Method, v.URI, v.Status)
			return nil
		},
	}))

	e.Renderer = NewTemplateRenderer()

	DEBUG(e)

	e.GET("/", func(c echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/api/v1")
	})

	v1 := e.Group("/api/v1")
	{
		v1.POST("/register", s.Register)
		v1.POST("/login", s.Login)
		v1.GET("/confirm-email/:token", s.ConfirmEmail)
		v1.GET("/health", s.healthHandler)

		v1.POST("/password-reset/initiate", s.PasswordResetInitiate)
		v1.POST("/password-reset/confirm", s.PasswordResetConfirm)

		v1.GET("/fetchuser", s.FetchUser, s.JWTMiddleware())
		v1.POST("/fetchuserbyid", s.FetchUserById, s.JWTMiddleware())
		v1.PUT("/update", s.Update, s.JWTMiddleware())
		v1.PATCH("/update", s.Update, s.JWTMiddleware())
		v1.DELETE("/delete", s.Delete, s.JWTMiddleware())
		v1.GET("/refresh", s.RefreshTokenHandler, s.RefreshTokenMiddleware())
		v1.GET("/resend-confirmation-email", s.reConfirmEmail, s.JWTMiddleware())

		v1.GET("/docs/*", echoSwagger.WrapHandler)
		v1.GET("/docs", func(c echo.Context) error {
			return c.Redirect(http.StatusMovedPermanently, "/api/v1/docs/index.html")
		})
	}

	e.RouteNotFound("/*", func(c echo.Context) error {
		return c.JSON(http.StatusNotFound, map[string]string{
			"message": "The requested endpoint does not exist",
		})
	})

	return e
}

// PasswordResetInitiate godoc
// @Summary Initiate password reset
// @Description Send a password reset link to the provided email address
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.PasswordResetInitiateRequest true "Password reset request"
// @Success 200 {object} map[string]string "message: If an account exists with this email, a reset link will be sent"
// @Failure 400 {object} map[string]string "message: Invalid request format or validation error"
// @Failure 404 {object} map[string]string "message: No user found with this email"
// @Failure 500 {object} map[string]string "message: Failed to send password reset email; check if the email is valid"
// @Router /password-reset/initiate [post]
func (s *Server) PasswordResetInitiate(c echo.Context) error {
	var req data.PasswordResetInitiateRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request format"})
	}

	if err := data.Validate.Struct(&req); err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": err.Error(),
		})
	}

	err := s.db.InitiatePasswordReset(req.Email)
	if err != nil {
		c.Logger().Error(err.Error())
		if strings.Contains(err.Error(), "no user found with email") {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "No user found with this email"})
		}
		if strings.Contains(err.Error(), "failed to send password reset email") {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to send password reset email check if the email is valid"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "If an account exists with this email, a reset link will be sent",
	})
}

// PasswordResetConfirm godoc
// @Summary Confirm password reset
// @Description Confirm a password reset using a token and provide a new password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.PasswordResetConfirmRequest true "Password reset confirm request"
// @Success 200 {object} map[string]string "message: Password reset successfully"
// @Failure 400 {object} map[string]string "message: Invalid request format, validation error, or invalid/expired reset token"
// @Router /password-reset/confirm [post]
func (s *Server) PasswordResetConfirm(c echo.Context) error {
	var req data.PasswordResetConfirmRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request format"})
	}

	if err := data.Validate.Struct(&req); err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": err.Error(),
		})
	}

	if err := s.db.ResetPassword(req.Token, req.NewPassword); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{
			"message": "Invalid or expired reset token",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Password reset successfully",
	})
}

// Register godoc
// @Summary Register a new user
// @Description Create a new user account and send confirmation email
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.RegisterRequest true "Registration request"
// @Success 200 {object} map[string]string "message: Registration successful"
// @Failure 206 {object} map[string]string "message: Registration successful, but confirmation email could not be sent"
// @Failure 400 {object} map[string]string "message: Invalid registration request format, validation error, or invalid birthdate format"
// @Failure 409 {object} map[string]string "message: Username or email is already registered"
// @Failure 500 {object} map[string]string "message: Unable to process password or Registration failed"
// @Router /register [post]
func (s *Server) Register(c echo.Context) error {
	var req data.RegisterRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid registration request format"})
	}

	if err := data.Validate.Struct(&req); err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": err.Error(),
		})
	}

	err := s.db.CreateUser(&req)
	if err != nil {
		c.Logger().Error(err.Error())
		if strings.Contains(err.Error(), "user already exists") {
			return c.JSON(http.StatusConflict, map[string]string{"message": "Username or email is already registered"})
		}
		if strings.Contains(err.Error(), "failed to hash password") {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Unable to process password"})
		}
		if strings.Contains(err.Error(), "failed to parse birthdate") {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid birthdate format"})
		}
		if strings.Contains(err.Error(), "failed to send confirmation email") {
			return c.JSON(http.StatusPartialContent, map[string]string{
				"message": "Registration successful, but confirmation email could not be sent",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Registration failed"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Registration successful"})
}

var loginAttempts = make(map[string][]time.Time)

const (
	maxLoginAttempts = 5
	loginWindow      = 10 * time.Minute
	blockDuration    = 15 * time.Minute
)

// Login godoc
// @Summary Login to the application
// @Description Authenticate with username/email and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.LoginRequest true "Login request"
// @Success 200 {object} map[string]any "message: Login successful, user: user object, tokens: token pair"
// @Failure 400 {object} map[string]string "message: Invalid request format or validation error"
// @Failure 401 {object} map[string]string "message: Username or email not found or Incorrect password"
// @Failure 403 {object} map[string]string "message: Email not confirmed. Please confirm your email before logging in."
// @Failure 429 {object} map[string]string "message: Too many failed login attempts. Please try again later."
// @Failure 500 {object} map[string]string "message: An error occurred during login or Unable to create session"
// @Router /login [post]
func (s *Server) Login(c echo.Context) error {
	var req data.LoginRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request format"})
	}

	if err := data.Validate.Struct(&req); err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": err.Error(),
		})
	}

	ip := c.RealIP()
	key := ip + ":" + req.Identifier
	now := time.Now()
	attempts := loginAttempts[key]
	var recent []time.Time
	for _, t := range attempts {
		if now.Sub(t) < loginWindow {
			recent = append(recent, t)
		}
	}
	if len(recent) >= maxLoginAttempts {
		lastAttempt := recent[len(recent)-1]
		if now.Sub(lastAttempt) < blockDuration {
			return c.JSON(http.StatusTooManyRequests, map[string]string{"message": "Too many failed login attempts. Please try again later."})
		}
		recent = []time.Time{}
	}
	loginAttempts[key] = recent

	user, err := s.db.FindUser(&req)
	if err != nil {
		c.Logger().Error(err.Error())
		if strings.Contains(err.Error(), "user not found") || strings.Contains(err.Error(), "invalid password") {
			loginAttempts[key] = append(loginAttempts[key], now)
		}
		if strings.Contains(err.Error(), "user not found") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Username or email not found"})
		}
		if strings.Contains(err.Error(), "invalid password") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Incorrect password"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "An error occurred during login"})
	}

	if !user.EmailConfirmed {
		return c.JSON(http.StatusForbidden, map[string]string{"message": "Email not confirmed. Please confirm your email before logging in."})
	}
	delete(loginAttempts, key)

	tokens, err := s.db.CreateSession(user.ID)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Unable to create session"})
	}

	return c.JSON(http.StatusOK, data.LoginRegisterResponse{
		Message: "Login successful",
		User:    user,
		Tokens:  tokens,
	})
}

// ConfirmEmail godoc
// @Summary Confirm email address
// @Description Confirm a user's email using a token sent by email. Renders a confirmation page.
// @Tags Auth
// @Accept  json
// @Produce  html
// @Param token path string true "Confirmation token"
// @Success 200 {string} string "HTML page with success message"
// @Failure 400 {string} string "HTML page with failure message"
// @Router /confirm-email/{token} [get]
func (s *Server) ConfirmEmail(c echo.Context) error {
	token := c.Param("token")
	c.Logger().Infof("Received email confirmation token: %s", token)

	confirmed, message := s.db.ConfirmEmail(token)
	c.Logger().Infof("Email confirmation result: confirmed=%v, message=%s", confirmed, message)

	if !confirmed {
		c.Logger().Errorf("Email confirmation failed: %s", message)
		return c.Render(http.StatusBadRequest, "confirmation_page.html", map[string]any{
			"Success": false,
			"Message": message,
			"Year":    time.Now().Year(),
		})
	}

	return c.Render(http.StatusOK, "confirmation_page.html", map[string]any{
		"Success": true,
		"Message": message,
		"Year":    time.Now().Year(),
	})
}

// reConfirmEmail godoc
// @Summary Resend confirmation email
// @Description Resend the email confirmation to the authenticated user
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]string "message: Confirmation email sent successfully"
// @Failure 401 {object} map[string]string "message: Unauthorized (handled by middleware)"
// @Failure 404 {object} map[string]string "message: User profile not found"
// @Failure 409 {object} map[string]string "message: Email is already confirmed"
// @Failure 429 {object} map[string]string "message: Too many confirmation email requests or Please wait 5 minutes before requesting another confirmation email"
// @Failure 500 {object} map[string]string "message: Unable to resend confirmation email"
// @Router /resend-confirmation-email [get]
func (s *Server) reConfirmEmail(c echo.Context) error {
	userID := c.Get("user_id").(primitive.ObjectID)
	err := s.db.ResendConfirmationEmail(userID)
	if err != nil {
		c.Logger().Error("ReConfirmEmail error:", err)
		if strings.Contains(err.Error(), "already confirmed") {
			return c.JSON(http.StatusConflict, map[string]string{
				"message": "Email is already confirmed",
			})
		}
		if strings.Contains(err.Error(), "too many attempts") {
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"message": "Too many confirmation email requests. Please try again later.",
			})
		}
		if strings.Contains(err.Error(), "user not found") {
			return c.JSON(http.StatusNotFound, map[string]string{
				"message": "User profile not found",
			})
		}
		if strings.Contains(err.Error(), "please wait 5 minutes before requesting another confirmation email") {
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"message": "Please wait 5 minutes before requesting another confirmation email",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"message": "Unable to resend confirmation email",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Confirmation email sent successfully",
	})
}

// FetchUser godoc
// @Summary Fetch current user
// @Description Retrieve the authenticated user's profile
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]any "message: User profile retrieved successfully, user: user object"
// @Failure 401 {object} map[string]string "message: Unauthorized (handled by middleware)"
// @Failure 404 {object} map[string]string "message: Your user profile could not be retrieved"
// @Failure 500 {object} map[string]string "message: An error occurred while fetching your profile"
// @Router /fetchuser [get]
func (s *Server) FetchUser(c echo.Context) error {
	userID := c.Get("user_id").(primitive.ObjectID)
	user, err := s.db.GetUser(userID)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "Your user profile could not be retrieved"})
		}
		c.Logger().Error("GetUser error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "An error occurred while fetching your profile"})
	}
	return c.JSON(http.StatusOK, map[string]any{"message": "User profile retrieved successfully", "user": user})
}

// FetchUserById godoc
// @Summary Fetch user by ID
// @Description Retrieve a user's public profile by user ID
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body object true "{\"user_id\": \"<objectId>\"}"
// @Success 200 {object} map[string]any "message: User fetched successfully, user: {username, first_name, last_name, birthdate, date_joined}"
// @Failure 400 {object} map[string]any "message: Invalid request or validation errors or Invalid user ID format"
// @Failure 401 {object} map[string]string "message: Unauthorized (handled by middleware)"
// @Failure 404 {object} map[string]string "message: The specified user could not be found"
// @Failure 500 {object} map[string]string "message: An error occurred while retrieving user information or An unexpected error occurred"
// @Router /fetchuserbyid [post]
func (s *Server) FetchUserById(c echo.Context) error {
	var req struct {
		ID string `json:"user_id" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		c.Logger().Error("Bind error: ", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	type userIdRequest struct {
		ID string `json:"user_id" validate:"required"`
	}
	reqObj := userIdRequest{ID: req.ID}
	if errors := data.Validate.Struct(reqObj); errors != nil {
		var validationErrors = make(map[string]string)
		if ve, ok := errors.(validator.ValidationErrors); ok {
			for _, e := range ve {
				field := e.Field()
				switch e.Tag() {
				case "required":
					validationErrors[field] = field + " is required"
				default:
					validationErrors[field] = e.Error()
				}
			}
		} else {
			validationErrors["general"] = errors.Error()
		}
		return c.JSON(http.StatusBadRequest, map[string]any{"errors": validationErrors})
	}

	objID, err := primitive.ObjectIDFromHex(req.ID)
	if err != nil {
		c.Logger().Error("Invalid ObjectID:", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid user ID format"})
	}

	user, err := s.db.GetUser(objID)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "The specified user could not be found"})
		}
		if strings.Contains(err.Error(), "db error") {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "An error occurred while retrieving user information"})
		}
		c.Logger().Error("Unexpected error in FetchUserById:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "An unexpected error occurred"})
	}

	type UserResponse struct {
		Username   string    `json:"username"`
		FistName   string    `json:"first_name"`
		LastName   string    `json:"last_name"`
		BirthDate  time.Time `json:"birthdate"`
		DateJoined time.Time `json:"date_joined"`
	}
	response := UserResponse{
		Username:   user.Username,
		FistName:   user.FirstName,
		LastName:   user.LastName,
		BirthDate:  user.Birthdate,
		DateJoined: user.DateJoined,
	}
	return c.JSON(http.StatusOK, map[string]any{
		"message": "User fetched successfully",
		"user":    response,
	})
}

// Update godoc
// @Summary Update user profile
// @Description Update fields of the authenticated user's profile
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body data.UpdateRequest true "Update request"
// @Success 200 {object} map[string]any "message: Profile updated successfully, user: updated user object"
// @Failure 400 {object} map[string]string "message: Invalid request format, validation error, No update fields provided, or Invalid birthdate format"
// @Failure 401 {object} map[string]string "message: Unauthorized (handled by middleware)"
// @Failure 404 {object} map[string]string "message: Your user profile could not be found"
// @Failure 409 {object} map[string]string "message: Username is already taken or Email is already registered"
// @Failure 500 {object} map[string]string "message: Unable to process password update, An error occurred while updating your profile, An error occurred while updating your profile picture, or Unable to check uniqueness of username or email"
// @Router /update [put]
// @Router /update [patch]
func (s *Server) Update(c echo.Context) error {
	var req data.UpdateRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error("Bind error:", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request format"})
	}

	if err := data.Validate.Struct(&req); err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": err.Error(),
		})
	}

	userID := c.Get("user_id").(primitive.ObjectID)
	updatedUser, err := s.db.UpdateUser(userID, &req)
	if err != nil {
		c.Logger().Error("UpdateUser error:", err)

		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "user not found"):
			return c.JSON(http.StatusNotFound, map[string]string{"message": "Your user profile could not be found"})
		case strings.Contains(errStr, "no fields to update"):
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "No update fields provided"})
		case strings.Contains(errStr, "password hashing failed"):
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Unable to process password update"})
		case strings.Contains(errStr, "failed to parse birthdate"):
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid birthdate format"})
		case strings.Contains(errStr, "failed to update user"):
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "An error occurred while updating your profile"})
		case strings.Contains(errStr, "failed to update profile picture"):
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "An error occurred while updating your profile picture"})
		case strings.Contains(errStr, "username already exists"):
			return c.JSON(http.StatusConflict, map[string]string{"message": "Username is already taken"})
		case strings.Contains(errStr, "email already exists"):
			return c.JSON(http.StatusConflict, map[string]string{"message": "Email is already registered"})
		case strings.Contains(errStr, "failed to check username uniqueness") || strings.Contains(errStr, "failed to check email uniqueness"):
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Unable to check uniqueness of username or email"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Unexpected error during profile update"})
		}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"message": "Profile updated successfully",
		"user":    updatedUser,
	})
}

// Delete godoc
// @Summary Delete user account
// @Description Permanently delete the authenticated user's account
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]string "message: Account deleted successfully"
// @Failure 401 {object} map[string]string "message: Unauthorized (handled by middleware)"
// @Failure 500 {object} map[string]string "message: An error occurred while deleting your account or Unexpected error during account deletion"
// @Router /delete [delete]
func (s *Server) Delete(c echo.Context) error {
	userID := c.Get("user_id").(primitive.ObjectID)
	err := s.db.DeleteUser(userID)
	if err != nil {
		c.Logger().Error("DeleteUser error:", err)
		if strings.Contains(err.Error(), "failed to delete user") {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"message": "An error occurred while deleting your account",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"message": "Unexpected error during account deletion",
		})
	}
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Account deleted successfully",
	})
}

// RefreshTokenHandler godoc
// @Summary Refresh authentication tokens
// @Description Exchange a valid refresh token for a new access/refresh token pair
// @Tags Auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]any "message: Tokens refreshed successfully, tokens: token pair"
// @Failure 401 {object} map[string]string "message: Unauthorized (handled by middleware)"
// @Failure 500 {object} map[string]string "message: Unable to refresh authentication tokens"
// @Router /refresh [get]
func (s *Server) RefreshTokenHandler(c echo.Context) error {
	userID := c.Get("user_id").(primitive.ObjectID)
	tokens, err := s.db.CreateSession(userID)
	if err != nil {
		c.Logger().Error("RefreshToken error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"message": "Unable to refresh authentication tokens",
		})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"message": "Tokens refreshed successfully",
		"tokens":  tokens,
	})
}

// healthHandler godoc
// @Summary Service health check
// @Description Returns service health status and details
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]any "status: ok, details: health details"
// @Failure 503 {object} map[string]any "status: error, message: Service health check failed"
// @Router /health [get]
func (s *Server) healthHandler(c echo.Context) error {
	status, err := s.db.Health()
	if err != nil {
		c.Logger().Error("Health check error:", err)
		return c.JSON(http.StatusServiceUnavailable, map[string]any{
			"status":  "error",
			"message": "Service health check failed",
		})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"status":  "ok",
		"details": status,
	})
}

func (s *Server) JWTMiddleware() echo.MiddlewareFunc {
	if len(jwtSecret) == 0 {
		panic("JWT secret is not set. Set JWTSECRET environment variable.")
	}
	config := echojwt.Config{
		SigningKey: jwtSecret,
		ParseTokenFunc: func(c echo.Context, auth string) (any, error) {
			tokenString := auth
			if strings.HasPrefix(auth, "Bearer ") {
				tokenString = strings.TrimPrefix(auth, "Bearer ")
			}
			if tokenString == "" {
				c.Logger().Error("Missing JWT token")
				return nil, errors.New("missing token")
			}
			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
				if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return jwtSecret, nil
			})
			if err != nil {
				c.Logger().Errorf("Token parsing error: %v", err)
				return nil, err
			}
			if !token.Valid {
				c.Logger().Error("Token is invalid")
				return nil, errors.New("invalid token")
			}
			if claims.ID != "access" {
				c.Logger().Errorf("Invalid token type: %s", claims.ID)
				return nil, errors.New("invalid token type")
			}
			userID, err := primitive.ObjectIDFromHex(claims.Subject)
			if err != nil {
				c.Logger().Errorf("Invalid user ID in token: %v", err)
				return nil, fmt.Errorf("invalid user ID: %v", err)
			}
			c.Set("user_id", userID)
			return token, nil
		},
		TokenLookup: "header:Authorization",
		ErrorHandler: func(c echo.Context, err error) error {
			c.Logger().Errorf("JWT Error: %v", err)
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"message": fmt.Sprintf("Unauthorized: %v", err.Error()),
			})
		},
	}
	return echojwt.WithConfig(config)
}

func (s *Server) RefreshTokenMiddleware() echo.MiddlewareFunc {
	if len(jwtSecret) == 0 {
		panic("JWT secret is not set. Set JWTSECRET environment variable.")
	}
	config := echojwt.Config{
		SigningKey: jwtSecret,
		ParseTokenFunc: func(c echo.Context, auth string) (any, error) {
			tokenString := auth
			if strings.HasPrefix(auth, "Bearer ") {
				tokenString = strings.TrimPrefix(auth, "Bearer ")
			}
			if tokenString == "" {
				c.Logger().Error("Missing JWT token")
				return nil, errors.New("missing token")
			}
			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
				if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return jwtSecret, nil
			})
			if err != nil {
				c.Logger().Errorf("Token parsing error: %v", err)
				return nil, err
			}
			if !token.Valid {
				c.Logger().Error("Token is invalid")
				return nil, errors.New("invalid token")
			}
			if claims.ID != "refresh" {
				c.Logger().Errorf("Invalid token type: %s", claims.ID)
				return nil, errors.New("invalid token type")
			}
			userID, err := primitive.ObjectIDFromHex(claims.Subject)
			if err != nil {
				c.Logger().Errorf("Invalid user ID in token: %v", err)
				return nil, fmt.Errorf("invalid user ID: %v", err)
			}
			c.Set("user_id", userID)
			return token, nil
		},
		TokenLookup: "header:Authorization",
		ErrorHandler: func(c echo.Context, err error) error {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"message": fmt.Sprintf("Unauthorized: %v", err.Error()),
			})
		},
	}
	return echojwt.WithConfig(config)
}

func DEBUG(e *echo.Echo) {
	if debug {
		e.Use(middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
			if len(reqBody) > 0 {
				var formattedReq any
				if err := json.Unmarshal(reqBody, &formattedReq); err != nil {
					log.Printf("Request Body (raw): \n%s\n", string(reqBody))
					c.Logger().Error("Error parsing request body: " + err.Error())
				} else {
					reqBodyJson, err := json.MarshalIndent(formattedReq, "", "  ")
					if err != nil {
						log.Printf("Request Body (raw): \n%s\n", string(reqBody))
						c.Logger().Error("Error marshaling request body: " + err.Error())
					} else {
						c.Logger().Debug("Request Body:\n" + string(reqBodyJson))
					}
				}
			}

			if len(resBody) > 0 {
				var formattedRes any
				if err := json.Unmarshal(resBody, &formattedRes); err != nil {
					log.Printf("Response Body (raw): \n%s\n", string(resBody))
					c.Logger().Error("Error parsing response body: " + err.Error())
				} else {
					resBodyJson, err := json.MarshalIndent(formattedRes, "", "  ")
					if err != nil {
						log.Printf("Response Body (raw): \n%s\n", string(resBody))
						c.Logger().Error("Error marshaling response body: " + err.Error())
					} else {
						c.Logger().Debug("Response Body:\n" + string(resBodyJson))
					}
				}
			}
		}))
	}
}
