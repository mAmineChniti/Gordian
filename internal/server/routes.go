package server

import (
	"net/http"
	"os"
	"strings"

	echojwt "github.com/labstack/echo-jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var jwtSecret = os.Getenv("JWTSECRET")

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/api/v1", s.HelloWorldHandler)
	e.POST("/api/v1/login", s.Login)
	e.GET("/api/v1/health", s.healthHandler)

	// Protected route
	e.GET("/api/v1/protected", s.ProtectedHandler, s.JWTMiddleware())

	return e
}

func (s *Server) Login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	user, err := s.db.FindUser(username, password)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") || strings.Contains(err.Error(), "invalid password") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid credentials"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}
	sessionToken, err := s.db.CreateSession(user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":       "Login successful",
		"user":          user,
		"session_token": sessionToken,
	})
}

func (s *Server) HelloWorldHandler(c echo.Context) error {
	resp := map[string]string{
		"message": "Hello World",
	}
	return c.JSON(http.StatusOK, resp)
}

func (s *Server) healthHandler(c echo.Context) error {
	health, err := s.db.Health()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal server error"})
	}
	return c.JSON(http.StatusOK, health)
}

func (s *Server) ProtectedHandler(c echo.Context) error {
	userID, err := s.db.ValidateToken(c.Request().Header.Get("Authorization"))
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Welcome to the protected route",
		"user_id": userID.Hex(),
	})
}

func (s *Server) JWTMiddleware() echo.MiddlewareFunc {
	return echojwt.WithConfig(echojwt.Config{
		SigningKey: jwtSecret,
	})
}
