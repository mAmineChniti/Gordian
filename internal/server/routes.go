package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/mAmineChniti/Gordian/internal/data"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	e.GET("/api/v1/fetchuser", s.FetchUser, s.JWTMiddleware())
	e.POST("/api/v1/fetchuserbyid", s.FetchUserById, s.JWTMiddleware())
	e.PUT("/api/v1/update", s.Update, s.JWTMiddleware())
	e.PATCH("/api/v1/update", s.Update, s.JWTMiddleware())
	e.DELETE("/api/v1/delete", s.Delete, s.JWTMiddleware())
	e.GET("/api/v1/refresh", s.RefreshTokenHandler, s.RefreshTokenMiddleware())
	e.GET("/api/v1/health", s.healthHandler)
	e.RouteNotFound("/*", func(c echo.Context) error {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "Not found"})
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}

	return c.JSON(http.StatusOK, data.LoginRegisterResponse{Message: "Registration successful", User: user, Tokens: tokens})
}

func (s *Server) FetchUser(c echo.Context) error {
	userID := c.Get("user_id").(primitive.ObjectID)
	user, err := s.db.GetUser(userID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "User not found"})
		}
		c.Logger().Error("GetUser error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}
	return c.JSON(http.StatusOK, map[string]any{"message": "User fetched successfully", "user": user})
}

func (s *Server) FetchUserById(c echo.Context) error {
	var req struct {
		ID string `json:"user_id" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		c.Logger().Error("Bind error: ", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	validationErrors, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Errorf("Validation error: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": "Validation failed",
			"errors":  validationErrors,
		})
	}

	objID, err := primitive.ObjectIDFromHex(req.ID)
	if err != nil {
		c.Logger().Error("Invalid ObjectID:", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid user ID format"})
	}

	user, err := s.db.GetUser(objID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "User not found"})
		}
		c.Logger().Errorf("GetUser error: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}

	type UserResponse struct {
		Username   string    `json:"username"`
		FistName   string    `json:"first_name"`
		LastName   string    `json:"last_name"`
		DateJoined time.Time `json:"date_joined"`
	}
	response := UserResponse{
		Username:   user.Username,
		FistName:   user.FirstName,
		LastName:   user.LastName,
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

	validationErrors, err := data.ValidateStruct(req)
	if err != nil {
		c.Logger().Error("Validation error:", err)
		return c.JSON(http.StatusBadRequest, map[string]any{
			"message": "Validation failed",
			"errors":  validationErrors,
		})
	}
	userID := c.Get("user_id").(primitive.ObjectID)
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
	userID := c.Get("user_id").(primitive.ObjectID)
	err := s.db.DeleteUser(userID)
	if err != nil {
		c.Logger().Error("DeleteUser error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error: couldn't delete user"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

func (s *Server) RefreshTokenHandler(c echo.Context) error {
	userId := c.Get("user_id").(primitive.ObjectID)
	tokens, err := s.db.CreateSession(userId)
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate new access token"})
	}

	return c.JSON(http.StatusOK, data.TokenResponse{Message: "Token refreshed successfully", Tokens: tokens})
}

func (s *Server) JWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		SigningKey: jwtSecret,
		ParseTokenFunc: func(c echo.Context, auth string) (any, error) {
			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(auth, claims, func(t *jwt.Token) (any, error) {
				return jwtSecret, nil
			})
			if err != nil {
				return nil, err
			}
			if !token.Valid {
				return nil, errors.New("invalid token")
			}
			if claims.ID != "access" {
				return nil, errors.New("invalid token type")
			}
			userID, err := primitive.ObjectIDFromHex(claims.Subject)
			if err != nil {
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

func (s *Server) RefreshTokenMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		SigningKey: jwtSecret,
		ParseTokenFunc: func(c echo.Context, auth string) (any, error) {
			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(auth, claims, func(t *jwt.Token) (any, error) {
				return jwtSecret, nil
			})
			if err != nil {
				return nil, err
			}
			if !token.Valid {
				return nil, errors.New("invalid token")
			}
			if claims.ID != "refresh" {
				return nil, errors.New("invalid token type")
			}
			userID, err := primitive.ObjectIDFromHex(claims.Subject)
			if err != nil {
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

func (s *Server) healthHandler(c echo.Context) error {
	health, err := s.db.Health()
	if err != nil {
		c.Logger().Error(err.Error())
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}
	return c.JSON(http.StatusOK, health)
}
