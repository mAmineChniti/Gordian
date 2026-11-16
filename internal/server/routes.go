package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	echoSwagger "github.com/swaggo/echo-swagger"
	"go.mongodb.org/mongo-driver/v2/bson"

	_ "github.com/mAmineChniti/Gordian/docs"
	"github.com/mAmineChniti/Gordian/internal/data"
	"github.com/mAmineChniti/Gordian/internal/database"
)

const contextUserIDKey = "user_id"

// RegisterRoutes builds the HTTP router and its middleware chain.
func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	if s.cfg.TrustProxy {
		// Only enable this when the service is reachable exclusively through a
		// trusted reverse proxy; otherwise clients can spoof X-Forwarded-For.
		e.IPExtractor = echo.ExtractIPFromXFFHeader()
	} else {
		e.IPExtractor = echo.ExtractIPDirect()
	}

	if s.cfg.Debug {
		e.Logger.SetLevel(log.DEBUG)
	} else {
		e.Logger.SetLevel(log.INFO)
	}

	e.HTTPErrorHandler = s.httpErrorHandler

	e.Use(middleware.RequestID())
	e.Use(s.requestLogger())
	e.Use(middleware.Recover())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		HSTSMaxAge:            31536000,
		HSTSExcludeSubdomains: false,
		ReferrerPolicy:        "no-referrer",
	}))
	allowCredentials := true
	if len(s.cfg.CORSAllowedOrigins) == 1 && s.cfg.CORSAllowedOrigins[0] == "*" {
		// Browsers reject wildcard origins combined with credentials, and the
		// API uses bearer tokens rather than cookies.
		allowCredentials = false
	}
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     s.cfg.CORSAllowedOrigins,
		AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{echo.HeaderAccept, echo.HeaderAuthorization, echo.HeaderContentType, "X-CSRF-Token", echo.HeaderXRequestID},
		ExposeHeaders:    []string{echo.HeaderXRequestID, echo.HeaderRetryAfter},
		AllowCredentials: allowCredentials,
		MaxAge:           300,
	}))
	e.Use(middleware.BodyLimit(fmt.Sprintf("%dB", s.cfg.MaxBodyBytes)))

	e.Renderer = NewTemplateRenderer()

	e.GET("/", func(c echo.Context) error {
		return c.Redirect(http.StatusFound, "/api/v1/docs")
	})
	e.GET("/api/v1", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "Gordian API",
			"docs":    "/api/v1/docs",
			"health":  "/api/v1/health",
		})
	})

	v1 := e.Group("/api/v1")
	{
		v1.POST("/register", s.Register)
		v1.POST("/login", s.Login)
		v1.GET("/confirm-email/:token", s.ConfirmEmail)
		v1.GET("/health", s.healthHandler)
		v1.POST("/resend-confirmation-email", s.ResendConfirmationEmailByEmail)

		v1.POST("/password-reset/initiate", s.PasswordResetInitiate)
		v1.POST("/password-reset/confirm", s.PasswordResetConfirm)

		auth := s.jwtMiddleware(data.TokenTypeAccess)
		v1.GET("/fetchuser", s.FetchUser, auth)
		v1.POST("/fetchuserbyid", s.FetchUserById, auth)
		v1.PUT("/update", s.Update, auth)
		v1.PATCH("/update", s.Update, auth)
		v1.DELETE("/delete", s.Delete, auth)
		v1.POST("/logout", s.Logout, auth)
		v1.GET("/resend-confirmation-email", s.reConfirmEmail, auth)

		refresh := s.jwtMiddleware(data.TokenTypeRefresh)
		v1.GET("/refresh", s.RefreshTokenHandler, refresh)

		v1.GET("/docs/*", echoSwagger.WrapHandler)
		v1.GET("/docs", func(c echo.Context) error {
			return c.Redirect(http.StatusFound, "/api/v1/docs/index.html")
		})
	}

	return e
}

func (s *Server) requestLogger() echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogMethod:    true,
		LogRoutePath: true,
		LogStatus:    true,
		LogLatency:   true,
		LogRemoteIP:  true,
		LogRequestID: true,
		LogError:     true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			path := v.RoutePath
			if path == "" {
				path = "unmatched"
			}
			if v.Error != nil {
				c.Logger().Errorf(
					"method=%s path=%s status=%d latency=%s ip=%s request_id=%s error=%v",
					v.Method, path, v.Status, v.Latency, v.RemoteIP, v.RequestID, v.Error,
				)
			} else {
				c.Logger().Infof(
					"method=%s path=%s status=%d latency=%s ip=%s request_id=%s",
					v.Method, path, v.Status, v.Latency, v.RemoteIP, v.RequestID,
				)
			}
			return nil
		},
	})
}

func (s *Server) httpErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}

	code := http.StatusInternalServerError
	message := "Internal server error"

	var he *echo.HTTPError
	if errors.As(err, &he) {
		code = he.Code
		if m, ok := he.Message.(string); ok && m != "" {
			message = m
		}
	}

	switch code {
	case http.StatusNotFound:
		message = "The requested endpoint does not exist"
	case http.StatusMethodNotAllowed:
		message = "Method not allowed"
	case http.StatusRequestEntityTooLarge:
		message = "Request body too large"
	}

	if code >= http.StatusInternalServerError {
		c.Logger().Errorf("request failed: %v", err)
	}

	if c.Request().Method == http.MethodHead {
		_ = c.NoContent(code)
		return
	}
	_ = c.JSON(code, data.MessageResponse{Message: message})
}

func (s *Server) jwtMiddleware(tokenType string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rawToken, err := bearerToken(c.Request())
			if err != nil {
				return unauthorized(c)
			}

			claims := &data.Claims{}
			token, err := jwt.ParseWithClaims(
				rawToken,
				claims,
				func(t *jwt.Token) (any, error) {
					if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
						return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
					}
					return s.cfg.JWTSecret, nil
				},
				jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
				jwt.WithIssuer(data.TokenIssuer),
				jwt.WithAudience(data.TokenAudience),
				jwt.WithExpirationRequired(),
				jwt.WithLeeway(30*time.Second),
			)
			if err != nil || !token.Valid || claims.TokenType != tokenType {
				return unauthorized(c)
			}

			userID, err := bson.ObjectIDFromHex(claims.Subject)
			if err != nil {
				return unauthorized(c)
			}

			version, err := s.db.GetTokenVersion(userID)
			if err != nil {
				if errors.Is(err, database.ErrUserNotFound) {
					return unauthorized(c)
				}
				c.Logger().Errorf("token version lookup failed: %v", err)
				return c.JSON(http.StatusServiceUnavailable, data.MessageResponse{Message: "Authentication is temporarily unavailable"})
			}
			if version != claims.TokenVersion {
				return unauthorized(c)
			}

			c.Set(contextUserIDKey, userID)
			return next(c)
		}
	}
}

func bearerToken(r *http.Request) (string, error) {
	value := strings.TrimSpace(r.Header.Get(echo.HeaderAuthorization))
	if value == "" {
		return "", errors.New("missing authorization header")
	}
	if len(value) > len("Bearer ") && strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		value = strings.TrimSpace(value[len("Bearer "):])
	}
	if value == "" {
		return "", errors.New("empty bearer token")
	}
	return value, nil
}

func unauthorized(c echo.Context) error {
	return c.JSON(http.StatusUnauthorized, data.MessageResponse{Message: "Unauthorized"})
}

func userIDFromContext(c echo.Context) (bson.ObjectID, bool) {
	userID, ok := c.Get(contextUserIDKey).(bson.ObjectID)
	return userID, ok
}

func bindJSON(c echo.Context, dst any) error {
	if err := c.Bind(dst); err != nil {
		var he *echo.HTTPError
		if errors.As(err, &he) {
			return err
		}
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}
	return nil
}

func validationErrorResponse(c echo.Context, err error) error {
	return c.JSON(http.StatusBadRequest, data.ValidationErrorResponse{
		Message: "Validation failed",
		Errors:  data.ValidationErrors(err),
	})
}

func (s *Server) tooManyRequests(c echo.Context, retry time.Duration) error {
	seconds := int(retry.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	c.Response().Header().Set(echo.HeaderRetryAfter, strconv.Itoa(seconds))
	return c.JSON(http.StatusTooManyRequests, data.MessageResponse{
		Message: "Too many requests. Please try again later.",
	})
}

func clientIP(c echo.Context) string {
	ip := strings.TrimSpace(c.RealIP())
	if ip == "" {
		return "unknown"
	}
	return ip
}

func (s *Server) userResponse(message string, user *data.User) data.UserResponse {
	return data.UserResponse{
		Message: message,
		User: &data.PublicUser{
			Username:       user.Username,
			FirstName:      user.FirstName,
			LastName:       user.LastName,
			Birthdate:      user.Birthdate,
			DateJoined:     user.DateJoined,
			ProfilePicture: user.ProfilePicture,
			EmailConfirmed: user.EmailConfirmed,
		},
	}
}

// PasswordResetInitiate godoc
// @Summary Initiate password reset
// @Description Sends a password reset token if the account exists. The response is identical for unknown addresses so accounts cannot be enumerated.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.PasswordResetInitiateRequest true "Password reset request"
// @Success 200 {object} data.MessageResponse "If an account exists with this email, a reset link will be sent"
// @Failure 400 {object} data.ValidationErrorResponse "Validation error"
// @Failure 429 {object} data.MessageResponse "Too many password reset requests"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /password-reset/initiate [post]
func (s *Server) PasswordResetInitiate(c echo.Context) error {
	var req data.PasswordResetInitiateRequest
	if err := bindJSON(c, &req); err != nil {
		return err
	}
	if err := data.Validate.Struct(&req); err != nil {
		return validationErrorResponse(c, err)
	}

	ip := clientIP(c)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if ok, retry := s.passwordResetLimiter.Hit("reset:" + ip + ":" + email); !ok {
		return s.tooManyRequests(c, retry)
	}
	if ok, retry := s.passwordResetIPLimiter.Hit("reset-ip:" + ip); !ok {
		return s.tooManyRequests(c, retry)
	}

	if err := s.db.InitiatePasswordReset(req.Email); err != nil && !errors.Is(err, database.ErrEmailSendFailed) {
		c.Logger().Errorf("password reset initiation failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Internal server error"})
	}

	return c.JSON(http.StatusOK, data.MessageResponse{
		Message: "If an account exists with this email, a reset link will be sent",
	})
}

// PasswordResetConfirm godoc
// @Summary Confirm password reset
// @Description Sets a new password using a single-use reset token. All existing sessions are revoked.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.PasswordResetConfirmRequest true "Password reset confirm request"
// @Success 200 {object} data.MessageResponse "Password reset successfully"
// @Failure 400 {object} data.ValidationErrorResponse "Validation error or invalid/expired reset token"
// @Failure 429 {object} data.MessageResponse "Too many requests"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /password-reset/confirm [post]
func (s *Server) PasswordResetConfirm(c echo.Context) error {
	var req data.PasswordResetConfirmRequest
	if err := bindJSON(c, &req); err != nil {
		return err
	}
	if err := data.Validate.Struct(&req); err != nil {
		return validationErrorResponse(c, err)
	}

	if err := s.db.ResetPassword(req.Token, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, database.ErrTokenInvalid):
			return c.JSON(http.StatusBadRequest, data.MessageResponse{Message: "Invalid or expired reset token"})
		case errors.Is(err, database.ErrPasswordHashFailed), errors.Is(err, database.ErrDatabase):
			c.Logger().Errorf("password reset failed: %v", err)
			return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Internal server error"})
		default:
			c.Logger().Errorf("unexpected password reset error: %v", err)
			return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Internal server error"})
		}
	}

	return c.JSON(http.StatusOK, data.MessageResponse{Message: "Password reset successfully"})
}

// Register godoc
// @Summary Register a new user
// @Description Creates a new account and sends an email confirmation link. If email delivery fails the account is still created; use the resend endpoint.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.RegisterRequest true "Registration request"
// @Success 201 {object} data.MessageResponse "Registration successful"
// @Failure 400 {object} data.ValidationErrorResponse "Validation error"
// @Failure 409 {object} data.MessageResponse "Username or email is already registered"
// @Failure 429 {object} data.MessageResponse "Too many registration attempts"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /register [post]
func (s *Server) Register(c echo.Context) error {
	if ok, retry := s.registerLimiter.Hit("register:" + clientIP(c)); !ok {
		return s.tooManyRequests(c, retry)
	}

	var req data.RegisterRequest
	if err := bindJSON(c, &req); err != nil {
		return err
	}
	if err := data.Validate.Struct(&req); err != nil {
		return validationErrorResponse(c, err)
	}

	err := s.db.CreateUser(&req)
	switch {
	case err == nil:
		return c.JSON(http.StatusCreated, data.MessageResponse{
			Message: "Registration successful. Please check your email to confirm your account.",
		})
	case errors.Is(err, database.ErrEmailSendFailed):
		c.Logger().Warnf("registration succeeded but confirmation email failed: %v", err)
		return c.JSON(http.StatusCreated, data.MessageResponse{
			Message: "Registration successful, but the confirmation email could not be sent. Use the resend confirmation endpoint to try again.",
		})
	case errors.Is(err, database.ErrUserExists):
		return c.JSON(http.StatusConflict, data.MessageResponse{Message: "Username or email is already registered"})
	case errors.Is(err, database.ErrInvalidBirthdate),
		errors.Is(err, database.ErrProfilePictureInvalid),
		errors.Is(err, database.ErrProfilePictureTooLarge):
		return c.JSON(http.StatusBadRequest, data.MessageResponse{Message: err.Error()})
	case errors.Is(err, database.ErrPasswordHashFailed), errors.Is(err, database.ErrDatabase):
		c.Logger().Errorf("registration failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Registration failed"})
	default:
		c.Logger().Errorf("unexpected registration error: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Registration failed"})
	}
}

// Login godoc
// @Summary Login to the application
// @Description Authenticates with username/email and password. Invalid identifiers and passwords return the same response.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.LoginRequest true "Login request"
// @Success 200 {object} data.LoginRegisterResponse "Login successful"
// @Failure 400 {object} data.ValidationErrorResponse "Validation error"
// @Failure 401 {object} data.MessageResponse "Invalid credentials"
// @Failure 403 {object} data.MessageResponse "Email not confirmed"
// @Failure 429 {object} data.MessageResponse "Too many failed login attempts"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /login [post]
func (s *Server) Login(c echo.Context) error {
	var req data.LoginRequest
	if err := bindJSON(c, &req); err != nil {
		return err
	}
	if err := data.Validate.Struct(&req); err != nil {
		return validationErrorResponse(c, err)
	}

	ip := clientIP(c)
	identifier := strings.ToLower(strings.TrimSpace(req.Identifier))
	loginKey := "login:" + ip + ":" + identifier
	ipKey := "login-ip:" + ip

	if ok, retry := s.loginIPLimiter.Check(ipKey); !ok {
		return s.tooManyRequests(c, retry)
	}
	if ok, retry := s.loginLimiter.Check(loginKey); !ok {
		return s.tooManyRequests(c, retry)
	}

	user, err := s.db.FindUser(&req)
	if err != nil {
		if errors.Is(err, database.ErrInvalidCredentials) {
			s.loginLimiter.Fail(loginKey)
			s.loginIPLimiter.Fail(ipKey)
			return c.JSON(http.StatusUnauthorized, data.MessageResponse{Message: "Invalid username/email or password"})
		}
		c.Logger().Errorf("login lookup failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "An error occurred during login"})
	}

	if !user.EmailConfirmed {
		return c.JSON(http.StatusForbidden, data.MessageResponse{
			Message: "Email not confirmed. Please confirm your email before logging in.",
		})
	}

	tokens, err := s.db.CreateSession(user.ID)
	if err != nil {
		c.Logger().Errorf("session creation failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Unable to create session"})
	}

	s.loginLimiter.Reset(loginKey)
	s.loginIPLimiter.Reset(ipKey)

	return c.JSON(http.StatusOK, data.LoginRegisterResponse{
		Message: "Login successful",
		User:    user,
		Tokens:  tokens,
	})
}

// ConfirmEmail godoc
// @Summary Confirm email address
// @Description Confirms an email address using the token sent by email and renders a confirmation page.
// @Tags Auth
// @Produce html
// @Param token path string true "Confirmation token"
// @Success 200 {string} string "HTML page with success message"
// @Failure 400 {string} string "HTML page with failure message"
// @Failure 500 {string} string "HTML page with failure message"
// @Router /confirm-email/{token} [get]
func (s *Server) ConfirmEmail(c echo.Context) error {
	token := c.Param("token")
	year := time.Now().Year()

	err := s.db.ConfirmEmail(token)
	switch {
	case err == nil:
		return c.Render(http.StatusOK, "confirmation_page.html", map[string]any{
			"Success": true,
			"Message": "Your email address has been confirmed. You can now log in.",
			"Year":    year,
		})
	case errors.Is(err, database.ErrEmailAlreadyConfirmed):
		return c.Render(http.StatusOK, "confirmation_page.html", map[string]any{
			"Success": true,
			"Message": "Your email address is already confirmed.",
			"Year":    year,
		})
	case errors.Is(err, database.ErrTokenInvalid):
		return c.Render(http.StatusBadRequest, "confirmation_page.html", map[string]any{
			"Success": false,
			"Message": "This confirmation link is invalid or has expired.",
			"Year":    year,
		})
	default:
		c.Logger().Errorf("email confirmation failed: %v", err)
		return c.Render(http.StatusInternalServerError, "confirmation_page.html", map[string]any{
			"Success": false,
			"Message": "We could not confirm your email address. Please try again later.",
			"Year":    year,
		})
	}
}

// ResendConfirmationEmailByEmail godoc
// @Summary Resend confirmation email by address
// @Description Sends a new confirmation email when an unconfirmed account exists. Always returns the same response.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body data.ResendConfirmationRequest true "Email address"
// @Success 200 {object} data.MessageResponse "If an account exists and is unconfirmed, an email will be sent"
// @Failure 400 {object} data.ValidationErrorResponse "Validation error"
// @Failure 429 {object} data.MessageResponse "Too many requests"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /resend-confirmation-email [post]
func (s *Server) ResendConfirmationEmailByEmail(c echo.Context) error {
	var req data.ResendConfirmationRequest
	if err := bindJSON(c, &req); err != nil {
		return err
	}
	if err := data.Validate.Struct(&req); err != nil {
		return validationErrorResponse(c, err)
	}

	ip := clientIP(c)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if ok, retry := s.resendLimiter.Hit("resend:" + ip + ":" + email); !ok {
		return s.tooManyRequests(c, retry)
	}
	if ok, retry := s.resendIPLimiter.Hit("resend-ip:" + ip); !ok {
		return s.tooManyRequests(c, retry)
	}

	if err := s.db.ResendConfirmationEmailByEmail(req.Email); err != nil && !errors.Is(err, database.ErrEmailSendFailed) {
		c.Logger().Errorf("resend confirmation failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Internal server error"})
	}

	return c.JSON(http.StatusOK, data.MessageResponse{
		Message: "If an account exists with this email, a confirmation email has been sent",
	})
}

// reConfirmEmail godoc
// @Summary Resend confirmation email (authenticated)
// @Description Resends the email confirmation to the authenticated user. Prefer the unauthenticated POST variant when login is blocked.
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} data.MessageResponse "Confirmation email sent successfully"
// @Failure 401 {object} data.MessageResponse "Unauthorized"
// @Failure 404 {object} data.MessageResponse "User profile not found"
// @Failure 409 {object} data.MessageResponse "Email is already confirmed"
// @Failure 429 {object} data.MessageResponse "Too many confirmation email requests"
// @Failure 500 {object} data.MessageResponse "Unable to resend confirmation email"
// @Router /resend-confirmation-email [get]
func (s *Server) reConfirmEmail(c echo.Context) error {
	userID, ok := userIDFromContext(c)
	if !ok {
		return unauthorized(c)
	}

	if err := s.db.ResendConfirmationEmail(userID); err != nil {
		switch {
		case errors.Is(err, database.ErrEmailAlreadyConfirmed):
			return c.JSON(http.StatusConflict, data.MessageResponse{Message: "Email is already confirmed"})
		case errors.Is(err, database.ErrConfirmationLimit):
			return c.JSON(http.StatusTooManyRequests, data.MessageResponse{Message: "Too many confirmation email requests. Please try again later."})
		case errors.Is(err, database.ErrConfirmationCooldown):
			return c.JSON(http.StatusTooManyRequests, data.MessageResponse{Message: "Please wait 5 minutes before requesting another confirmation email"})
		case errors.Is(err, database.ErrUserNotFound):
			return c.JSON(http.StatusNotFound, data.MessageResponse{Message: "User profile not found"})
		case errors.Is(err, database.ErrEmailSendFailed):
			c.Logger().Errorf("resend confirmation failed: %v", err)
			return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Unable to resend confirmation email"})
		default:
			c.Logger().Errorf("unexpected resend confirmation error: %v", err)
			return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Unable to resend confirmation email"})
		}
	}

	return c.JSON(http.StatusOK, data.MessageResponse{Message: "Confirmation email sent successfully"})
}

// FetchUser godoc
// @Summary Fetch current user
// @Description Retrieves the authenticated user's profile.
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} data.UserResponse "User profile retrieved successfully"
// @Failure 401 {object} data.MessageResponse "Unauthorized"
// @Failure 404 {object} data.MessageResponse "User profile not found"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /fetchuser [get]
func (s *Server) FetchUser(c echo.Context) error {
	userID, ok := userIDFromContext(c)
	if !ok {
		return unauthorized(c)
	}

	user, err := s.db.GetUser(userID)
	if err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			return c.JSON(http.StatusNotFound, data.MessageResponse{Message: "Your user profile could not be retrieved"})
		}
		c.Logger().Errorf("get user failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "An error occurred while fetching your profile"})
	}

	return c.JSON(http.StatusOK, s.userResponse("User profile retrieved successfully", user))
}

// FetchUserById godoc
// @Summary Fetch user by ID
// @Description Retrieves a limited public profile by user ID. Birthdate, email and confirmation state are never returned.
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body data.FetchUserByIDRequest true "User ID"
// @Success 200 {object} data.PublicProfileResponse "User fetched successfully"
// @Failure 400 {object} data.ValidationErrorResponse "Validation error or invalid user ID format"
// @Failure 401 {object} data.MessageResponse "Unauthorized"
// @Failure 404 {object} data.MessageResponse "The specified user could not be found"
// @Failure 429 {object} data.MessageResponse "Too many requests"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /fetchuserbyid [post]
func (s *Server) FetchUserById(c echo.Context) error {
	userID, ok := userIDFromContext(c)
	if !ok {
		return unauthorized(c)
	}
	if ok, retry := s.lookupLimiter.Hit("lookup:" + userID.Hex()); !ok {
		return s.tooManyRequests(c, retry)
	}

	var req data.FetchUserByIDRequest
	if err := bindJSON(c, &req); err != nil {
		return err
	}
	if err := data.Validate.Struct(&req); err != nil {
		return validationErrorResponse(c, err)
	}

	objectID, err := bson.ObjectIDFromHex(req.ID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, data.MessageResponse{Message: "Invalid user ID format"})
	}

	user, err := s.db.GetUser(objectID)
	if err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			return c.JSON(http.StatusNotFound, data.MessageResponse{Message: "The specified user could not be found"})
		}
		c.Logger().Errorf("fetch user by id failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "An error occurred while retrieving user information"})
	}

	return c.JSON(http.StatusOK, data.PublicProfileResponse{
		Message: "User fetched successfully",
		User: &data.PublicProfile{
			Username:       user.Username,
			FirstName:      user.FirstName,
			LastName:       user.LastName,
			DateJoined:     user.DateJoined,
			ProfilePicture: user.ProfilePicture,
		},
	})
}

// Update godoc
// @Summary Update user profile
// @Description Updates the authenticated user's profile. Changing the email or password requires current_password; a password change also revokes all existing sessions and returns a new token pair.
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body data.UpdateRequest true "Update request"
// @Success 200 {object} data.UserResponse "Profile updated successfully"
// @Failure 400 {object} data.ValidationErrorResponse "Validation error, no update fields, or missing current password"
// @Failure 401 {object} data.MessageResponse "Unauthorized or current password incorrect"
// @Failure 404 {object} data.MessageResponse "User profile not found"
// @Failure 409 {object} data.MessageResponse "Username or email is already registered"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /update [put]
// @Router /update [patch]
func (s *Server) Update(c echo.Context) error {
	var req data.UpdateRequest
	if err := bindJSON(c, &req); err != nil {
		return err
	}
	if err := data.Validate.Struct(&req); err != nil {
		return validationErrorResponse(c, err)
	}

	userID, ok := userIDFromContext(c)
	if !ok {
		return unauthorized(c)
	}

	updatedUser, err := s.db.UpdateUser(userID, &req)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrUserNotFound):
			return c.JSON(http.StatusNotFound, data.MessageResponse{Message: "Your user profile could not be found"})
		case errors.Is(err, database.ErrNoFieldsToUpdate):
			return c.JSON(http.StatusBadRequest, data.MessageResponse{Message: "No update fields provided"})
		case errors.Is(err, database.ErrCurrentPasswordNeeded):
			return c.JSON(http.StatusBadRequest, data.MessageResponse{Message: "current_password is required when changing your email or password"})
		case errors.Is(err, database.ErrInvalidCurrentPassword):
			return c.JSON(http.StatusUnauthorized, data.MessageResponse{Message: "Current password is incorrect"})
		case errors.Is(err, database.ErrUsernameTaken):
			return c.JSON(http.StatusConflict, data.MessageResponse{Message: "Username is already taken"})
		case errors.Is(err, database.ErrEmailTaken), errors.Is(err, database.ErrUserExists):
			return c.JSON(http.StatusConflict, data.MessageResponse{Message: "Email is already registered"})
		case errors.Is(err, database.ErrInvalidBirthdate):
			return c.JSON(http.StatusBadRequest, data.MessageResponse{Message: "Invalid birthdate format"})
		case errors.Is(err, database.ErrProfilePictureInvalid),
			errors.Is(err, database.ErrProfilePictureTooLarge):
			return c.JSON(http.StatusBadRequest, data.MessageResponse{Message: err.Error()})
		case errors.Is(err, database.ErrPasswordHashFailed), errors.Is(err, database.ErrDatabase):
			c.Logger().Errorf("profile update failed: %v", err)
			return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "An error occurred while updating your profile"})
		case errors.Is(err, database.ErrEmailSendFailed):
			if updatedUser == nil {
				c.Logger().Errorf("profile update failed: %v", err)
				return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "An error occurred while updating your profile"})
			}
			response := s.userResponse("Profile updated, but the confirmation email could not be sent. Use the resend confirmation endpoint to try again.", updatedUser)
			s.attachTokens(userID, &response, req.Password != "")
			return c.JSON(http.StatusOK, response)
		default:
			c.Logger().Errorf("unexpected profile update error: %v", err)
			return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "An unexpected error occurred"})
		}
	}

	message := "Profile updated successfully"
	if req.Email != "" && !updatedUser.EmailConfirmed {
		message = "Profile updated. Please confirm your new email address before logging in again."
	}
	response := s.userResponse(message, updatedUser)
	s.attachTokens(userID, &response, req.Password != "")
	return c.JSON(http.StatusOK, response)
}

func (s *Server) attachTokens(userID bson.ObjectID, response *data.UserResponse, passwordChanged bool) {
	if !passwordChanged {
		return
	}
	tokens, err := s.db.CreateSession(userID)
	if err != nil {
		log.Printf("password changed but new session tokens could not be created: %v", err)
		return
	}
	response.Tokens = tokens
}

// Delete godoc
// @Summary Delete user account
// @Description Permanently deletes the authenticated user's account.
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} data.MessageResponse "Account deleted successfully"
// @Failure 401 {object} data.MessageResponse "Unauthorized"
// @Failure 404 {object} data.MessageResponse "Account not found or already deleted"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /delete [delete]
func (s *Server) Delete(c echo.Context) error {
	userID, ok := userIDFromContext(c)
	if !ok {
		return unauthorized(c)
	}

	if err := s.db.DeleteUser(userID); err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			return c.JSON(http.StatusNotFound, data.MessageResponse{Message: "Account not found or already deleted"})
		}
		c.Logger().Errorf("delete user failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "An error occurred while deleting your account"})
	}

	return c.JSON(http.StatusOK, data.MessageResponse{Message: "Account deleted successfully"})
}

// Logout godoc
// @Summary Log out
// @Description Revokes all access and refresh tokens for the authenticated user.
// @Tags Auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} data.MessageResponse "Logged out successfully"
// @Failure 401 {object} data.MessageResponse "Unauthorized"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /logout [post]
func (s *Server) Logout(c echo.Context) error {
	userID, ok := userIDFromContext(c)
	if !ok {
		return unauthorized(c)
	}

	if err := s.db.RevokeSessions(userID); err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			return unauthorized(c)
		}
		c.Logger().Errorf("logout failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "An error occurred while logging out"})
	}

	return c.JSON(http.StatusOK, data.MessageResponse{Message: "Logged out successfully"})
}

// RefreshTokenHandler godoc
// @Summary Refresh authentication tokens
// @Description Exchanges a valid refresh token for a new token pair. Deleted users, revoked sessions and unconfirmed email addresses are rejected.
// @Tags Auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} data.TokenResponse "Tokens refreshed successfully"
// @Failure 401 {object} data.MessageResponse "Unauthorized"
// @Failure 403 {object} data.MessageResponse "Email not confirmed"
// @Failure 500 {object} data.MessageResponse "Internal server error"
// @Router /refresh [get]
func (s *Server) RefreshTokenHandler(c echo.Context) error {
	userID, ok := userIDFromContext(c)
	if !ok {
		return unauthorized(c)
	}

	user, err := s.db.GetUser(userID)
	if err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			return unauthorized(c)
		}
		c.Logger().Errorf("refresh user lookup failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Unable to refresh authentication tokens"})
	}
	if !user.EmailConfirmed {
		return c.JSON(http.StatusForbidden, data.MessageResponse{Message: "Email not confirmed. Please confirm your email before refreshing your session."})
	}

	tokens, err := s.db.CreateSession(userID)
	if err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			return unauthorized(c)
		}
		c.Logger().Errorf("token refresh failed: %v", err)
		return c.JSON(http.StatusInternalServerError, data.MessageResponse{Message: "Unable to refresh authentication tokens"})
	}

	return c.JSON(http.StatusOK, data.TokenResponse{
		Message: "Tokens refreshed successfully",
		Tokens:  tokens,
	})
}

// healthHandler godoc
// @Summary Service health check
// @Description Returns service health status and details.
// @Tags Health
// @Produce json
// @Success 200 {object} data.HealthResponse "Service is healthy"
// @Failure 503 {object} data.MessageResponse "Service health check failed"
// @Router /health [get]
func (s *Server) healthHandler(c echo.Context) error {
	status, err := s.db.Health()
	if err != nil {
		c.Logger().Errorf("health check failed: %v", err)
		return c.JSON(http.StatusServiceUnavailable, data.MessageResponse{Message: "Service health check failed"})
	}

	details := make(map[string]any, len(status))
	for key, value := range status {
		details[key] = value
	}
	return c.JSON(http.StatusOK, data.HealthResponse{Status: "ok", Details: details})
}
