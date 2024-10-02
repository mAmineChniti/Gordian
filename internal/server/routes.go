package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/mAmineChniti/Gordian/internal/data"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	jwtSecret = []byte(os.Getenv("JWTSECRET"))
	debug     = os.Getenv("DEBUG") == "true"
)

func DEBUG(e *echo.Echo) {
	if debug {
		e.Use(middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
			formattedReq := json.RawMessage(reqBody)
			reqBodyJson, err := json.MarshalIndent(formattedReq, "", "  ")
			if err != nil {
				log.Printf("Request Body: \n%s\n", string(reqBody))
				c.Logger().Error(err.Error())
			} else {
				fmt.Printf("Request Body: \n%s\n", string(reqBodyJson))
			}

			formattedRes := json.RawMessage(resBody)
			resBodyJson, err := json.MarshalIndent(formattedRes, "", "  ")
			if err != nil {
				log.Printf("Response Body: \n%s\n", string(resBody))
				c.Logger().Error(err.Error())
			} else {
				fmt.Printf("Response Body: \n%s\n", string(resBodyJson))
			}
		}))
	}
}

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Logger.SetLevel(log.INFO)
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
	}))

	DEBUG(e)

	e.Use(middleware.Recover())

	//e.GET("/api/v1", s.Docs)
	e.POST("/api/v1/register", s.Register)
	e.POST("/api/v1/login", s.Login)
	e.PUT("/api/v1/update", s.Update, s.JWTMiddleware())
	e.PATCH("/api/v1/update", s.Update, s.JWTMiddleware())
	e.GET("/api/v1/health", s.healthHandler)
	e.GET("/api/v1/protected", s.ProtectedHandler, s.JWTMiddleware())
	e.POST("/api/v1/refresh", s.RefreshTokenHandler)

	return e
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
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
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

	accessToken, refreshToken, err := s.db.CreateSession(user.ID)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to create session"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":       "Login successful",
		"user":          user,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
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
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"message": "Validation failed",
			"errors":  validationErrors,
		})
	}
	user, accessToken, refreshToken, err := s.db.CreateUser(&req)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":       "User created successfully",
		"user":          user,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
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
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"message": "Validation failed",
			"errors":  validationErrors,
		})
	}

	// Assuming JWT middleware sets the user ID in the context
	userID, ok := c.Get("userID").(primitive.ObjectID)
	if !ok {
		c.Logger().Error("Invalid user ID in context")
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
	}

	updatedUser, err := s.db.UpdateUser(userID, &req)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "User not found"})
		}
		c.Logger().Error("UpdateUser error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "User updated successfully",
		"user":    updatedUser,
	})
}

func (s *Server) healthHandler(c echo.Context) error {
	health, err := s.db.Health()
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}
	return c.JSON(http.StatusOK, health)
}

func (s *Server) ProtectedHandler(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid token format"})
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, err := s.db.ValidateToken(tokenString)

	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Welcome to the protected route",
		"user_id": userID.Hex(),
	})
}

func (s *Server) RefreshTokenHandler(c echo.Context) error {
	var refreshTokenRequest struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.Bind(&refreshTokenRequest); err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(refreshTokenRequest.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid or expired refresh token"})
	}

	userID, err := primitive.ObjectIDFromHex(claims.Subject)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid user ID in token"})
	}

	accessToken, refreshToken, err := s.db.CreateSession(userID)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate new access token"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
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
