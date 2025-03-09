package server

import (
	"net/http"
	"os"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/mAmineChniti/Gordian/internal/data"
	"go.mongodb.org/mongo-driver/mongo"
)

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

	e.Logger.SetLevel(log.INFO)
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
	}))

	DEBUG(e)

	e.GET("/", func(c echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/api/v1")
	})
	e.POST("/api/v1/register", s.Register)
	e.POST("/api/v1/login", s.Login)
	e.PUT("/api/v1/update", s.Update, s.JWTMiddleware())
	e.PATCH("/api/v1/update", s.Update, s.JWTMiddleware())
	e.DELETE("/api/v1/delete", s.Delete, s.JWTMiddleware())
	e.GET("/api/v1/refresh", s.RefreshTokenHandler, s.JWTMiddleware())
	e.GET("/api/v1/health", s.healthHandler)

	e.GET("/health", s.healthHandler)

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
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}
	validationErrors, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": "Validation failed",
			"errors":  validationErrors,
		})
	}
	user, err := s.db.FindUser(&req)
	if err != nil {
		c.Logger().Error(err.Error())
		if strings.Contains(err.Error(), "user not found") || strings.Contains(err.Error(), "invalid password") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid credentials"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}

	tokens, err := s.db.CreateSession(user.ID)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to create session"})
	}

	return c.JSON(http.StatusOK, data.LoginRegisterResponse{Message: "Login successful", User: user, Tokens: tokens})
}

func (s *Server) Register(c echo.Context) error {
	var req data.RegisterRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}
	validationErrors, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": "Validation failed",
			"errors":  validationErrors,
		})
	}
	user, tokens, err := s.db.CreateUser(&req)
	if err != nil {
		c.Logger().Error(err.Error())
		if strings.Contains(err.Error(), "failed to hash password") {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "err here"})
	}

	return c.JSON(http.StatusOK, data.LoginRegisterResponse{Message: "Registration successful", User: user, Tokens: tokens})
}

func (s *Server) Update(c echo.Context) error {
	var req data.UpdateRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Error("Bind error:", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request format"})
	}

	validationErrors, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": "Validation failed",
			"errors":  validationErrors,
		})
	}
	authHeader := c.Request().Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid token format"})
	}
	userID, err := s.db.ValidateToken(authHeader)

	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Unauthorized invalid token"})
	}

	updatedUser, err := s.db.UpdateUser(userID, &req)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "User not found"})
		}
		c.Logger().Error("UpdateUser error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"message": "User updated successfully",
		"user":    updatedUser,
	})
}

func (s *Server) Delete(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid token format"})
	}
	userID, err := s.db.ValidateToken(authHeader)

	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Unauthorized invalid token"})
	}
	err = s.db.DeleteUser(userID)
	if err != nil {
		c.Logger().Error("DeleteUser error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error: couldn't delete user"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

func (s *Server) RefreshTokenHandler(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid token format"})
	}
	userID, err := s.db.ValidateToken(authHeader)

	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Unauthorized invalid token"})
	}

	tokens, err := s.db.CreateSession(userID)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate new access token"})
	}

	return c.JSON(http.StatusOK, data.TokenResponse{Message: "Token refreshed successfully", Tokens: tokens})
}

func (s *Server) healthHandler(c echo.Context) error {
	health, err := s.db.Health()
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}
	return c.JSON(http.StatusOK, health)
}

func (s *Server) JWTMiddleware() echo.MiddlewareFunc {
	return echojwt.WithConfig(echojwt.Config{
		SigningKey: jwtSecret,
		ErrorHandler: func(c echo.Context, err error) error {
			if errors.Is(err, echojwt.ErrJWTMissing) {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Missing or malformed token"})
			}

			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid or expired token"})
		},
	})
}
