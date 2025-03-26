package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/mAmineChniti/Gordian/internal/data"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func findTemplateFile(filename string) string {
	locations := []string{
		"internal/templates/" + filename,                        // Development path
		"../internal/templates/" + filename,                     // Compiled binary path
		"/app/internal/templates/" + filename,                   // Docker/production path
		filepath.Join(os.Getenv("APP_TEMPLATES_DIR"), filename), // Configurable path
	}

	for _, path := range locations {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	log.Fatal(fmt.Sprintf("Template file %s not found", filename))
	return ""
}

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	// Ensure the template name matches the filename
	if name == "" {
		name = "email_confirmation.html"
	}

	// Find the template by name
	tmpl := t.templates.Lookup(name)
	if tmpl == nil {
		return fmt.Errorf("template %s not found", name)
	}

	return tmpl.Execute(w, data)
}

func NewTemplateRenderer() *TemplateRenderer {
	tmplPath := findTemplateFile("email_confirmation.html")
	tmpl := template.Must(template.ParseFiles(tmplPath))
	return &TemplateRenderer{
		templates: tmpl,
	}
}

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"https://*", "http://*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	e.Logger.SetLevel(log.DEBUG)
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
	}))

	e.Renderer = NewTemplateRenderer()

	DEBUG(e)

	e.GET("/", func(c echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/api/v1")
	})
	e.POST("/api/v1/register", s.Register)
	e.POST("/api/v1/login", s.Login)
	e.GET("/api/v1/fetchuser", s.FetchUser, s.JWTMiddleware())
	e.POST("/api/v1/fetchuserbyid", s.FetchUserById, s.JWTMiddleware())
	e.PUT("/api/v1/update", s.Update, s.JWTMiddleware())
	e.PATCH("/api/v1/update", s.Update, s.JWTMiddleware())
	e.DELETE("/api/v1/delete", s.Delete, s.JWTMiddleware())
	e.GET("/api/v1/refresh", s.RefreshTokenHandler, s.RefreshTokenMiddleware())
	e.GET("/api/v1/health", s.healthHandler)
	e.GET("/api/v1/confirm-email", s.reConfirmEmail, s.JWTMiddleware())
	e.GET("/api/v1/confirm-email/:token", s.ConfirmEmail)
	e.RouteNotFound("/*", func(c echo.Context) error {
		return c.JSON(http.StatusNotFound, map[string]string{
			"message": "The requested endpoint does not exist",
		})
	})
	return e
}

var (
	jwtSecret = []byte(os.Getenv("JWTSECRET"))
	debug     = os.Getenv("DEBUG") == "true"
)

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

func (s *Server) Login(c echo.Context) error {
	var req data.LoginRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request format"})
	}
	errorMsg, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": errorMsg,
		})
	}
	user, err := s.db.FindUser(&req)
	if err != nil {
		c.Logger().Error(err.Error())
		if strings.Contains(err.Error(), "user not found") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Username or email not found"})
		}
		if strings.Contains(err.Error(), "invalid password") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Incorrect password"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "An error occurred during login"})
	}

	tokens, err := s.db.CreateSession(user.ID)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Unable to create session"})
	}

	return c.JSON(http.StatusOK, data.LoginRegisterResponse{Message: "Login successful", User: user, Tokens: tokens})
}

func (s *Server) Register(c echo.Context) error {
	var req data.RegisterRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid registration request format"})
	}
	errorMsg, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": errorMsg,
		})
	}
	err = s.db.CreateUser(&req)
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

func (s *Server) FetchUserById(c echo.Context) error {
	var req struct {
		ID string `json:"user_id" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		c.Logger().Error("Bind error: ", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	errorMsg, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Errorf("Validation error: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": errorMsg,
		})
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

func (s *Server) Update(c echo.Context) error {
	var req data.UpdateRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error("Bind error:", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request format"})
	}

	errorMsg, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": errorMsg,
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

		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Unexpected error during profile update"})
		}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"message": "Profile updated successfully",
		"user":    updatedUser,
	})
}

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

func (s *Server) JWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		SigningKey: jwtSecret,
		ParseTokenFunc: func(c echo.Context, auth string) (any, error) {
			tokenString := auth
			if strings.HasPrefix(auth, "Bearer ") {
				tokenString = strings.TrimPrefix(auth, "Bearer ")
			}

			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
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
	config := echojwt.Config{
		SigningKey: jwtSecret,
		ParseTokenFunc: func(c echo.Context, auth string) (any, error) {
			tokenString := auth
			if strings.HasPrefix(auth, "Bearer ") {
				tokenString = strings.TrimPrefix(auth, "Bearer ")
			}

			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
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

func (s *Server) ConfirmEmail(c echo.Context) error {
	token := c.Param("token")
	if token == "" {
		return c.Render(http.StatusOK, "email_confirmation.html", struct {
			Success      bool
			ErrorMessage string
		}{
			Success:      false,
			ErrorMessage: "Missing email confirmation token",
		})
	}

	success, errMsg := s.db.ConfirmEmail(token)

	return c.Render(http.StatusOK, "email_confirmation.html", struct {
		Success      bool
		ErrorMessage string
	}{
		Success:      success,
		ErrorMessage: errMsg,
	})
}

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
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"message": "Unable to resend confirmation email",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Confirmation email sent successfully",
	})
}

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
