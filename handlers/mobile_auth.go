package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/middleware/jwt"
	"github.com/tech-arch1tect/brx/services/auth"
	jwtservice "github.com/tech-arch1tect/brx/services/jwt"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"brx-starter-kit/models"
)

type MobileAuthHandler struct {
	db      *gorm.DB
	authSvc *auth.Service
	jwtSvc  *jwtservice.Service
	logger  *logging.Service
}

func NewMobileAuthHandler(db *gorm.DB, authSvc *auth.Service, jwtSvc *jwtservice.Service, logger *logging.Service) *MobileAuthHandler {
	return &MobileAuthHandler{
		db:      db,
		authSvc: authSvc,
		jwtSvc:  jwtSvc,
		logger:  logger,
	}
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	User         UserInfo `json:"user"`
}

type RegisterRequest struct {
	Username string `json:"username" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserInfo struct {
	ID              uint    `json:"id"`
	Username        string  `json:"username"`
	Email           string  `json:"email"`
	EmailVerifiedAt *string `json:"email_verified_at"`
	TOTPEnabled     bool    `json:"totp_enabled"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (h *MobileAuthHandler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Warn("mobile login - invalid request format",
			zap.String("remote_ip", c.RealIP()),
			zap.Error(err))
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
	}

	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: "Username and password are required",
		})
	}

	h.logger.Info("mobile login attempt",
		zap.String("username", req.Username),
		zap.String("remote_ip", c.RealIP()),
		zap.String("user_agent", c.Request().UserAgent()),
	)

	var user models.User
	if err := h.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		h.logger.Warn("mobile login failed - user not found",
			zap.String("username", req.Username),
			zap.String("remote_ip", c.RealIP()),
		)
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid username or password",
		})
	}

	if err := h.authSvc.VerifyPassword(user.Password, req.Password); err != nil {
		h.logger.Warn("mobile login failed - invalid password",
			zap.String("username", req.Username),
			zap.Uint("user_id", user.ID),
			zap.String("remote_ip", c.RealIP()),
		)
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid username or password",
		})
	}

	if h.authSvc.IsEmailVerificationRequired() && !h.authSvc.IsEmailVerified(user.Email) {
		return c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "email_not_verified",
			Message: "Please verify your email before signing in",
		})
	}

	accessToken, err := h.jwtSvc.GenerateToken(user.ID)
	if err != nil {
		h.logger.Error("failed to generate access token",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "token_generation_failed",
			Message: "Failed to generate authentication token",
		})
	}

	refreshToken, err := h.jwtSvc.GenerateRefreshToken(user.ID)
	if err != nil {
		h.logger.Error("failed to generate refresh token",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "token_generation_failed",
			Message: "Failed to generate refresh token",
		})
	}

	h.logger.Info("mobile login successful",
		zap.String("username", req.Username),
		zap.Uint("user_id", user.ID),
		zap.String("remote_ip", c.RealIP()),
	)

	return c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.jwtSvc.GetAccessExpirySeconds(),
		User: UserInfo{
			ID:              user.ID,
			Username:        user.Username,
			Email:           user.Email,
			EmailVerifiedAt: formatTimePtr(user.EmailVerifiedAt),
			TOTPEnabled:     false, // TODO: Check TOTP status
			CreatedAt:       user.CreatedAt.Format(time.RFC3339),
			UpdatedAt:       user.UpdatedAt.Format(time.RFC3339),
		},
	})
}

func (h *MobileAuthHandler) Register(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Warn("mobile register - invalid request format",
			zap.String("remote_ip", c.RealIP()),
			zap.Error(err))
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: "Username, email, and password are required",
		})
	}

	if err := h.authSvc.ValidatePassword(req.Password); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "password_validation_failed",
			Message: err.Error(),
		})
	}

	hashedPassword, err := h.authSvc.HashPassword(req.Password)
	if err != nil {
		h.logger.Error("failed to hash password",
			zap.String("username", req.Username),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "password_hashing_failed",
			Message: "Failed to process password",
		})
	}

	user := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
	}

	if err := h.db.Create(&user).Error; err != nil {
		h.logger.Warn("mobile register failed - user creation failed",
			zap.String("username", req.Username),
			zap.String("email", req.Email),
			zap.Error(err),
		)
		return c.JSON(http.StatusConflict, ErrorResponse{
			Error:   "user_exists",
			Message: "Username or email already exists",
		})
	}

	if h.authSvc.IsEmailVerificationRequired() {
		if err := h.authSvc.RequestEmailVerification(req.Email); err != nil {
			h.logger.Error("failed to send email verification",
				zap.String("email", req.Email),
				zap.Error(err),
			)
			return c.JSON(http.StatusCreated, map[string]string{
				"message": "Account created successfully. Email verification is required but email service is unavailable.",
			})
		}
		return c.JSON(http.StatusCreated, map[string]string{
			"message": "Account created successfully. Please verify your email before signing in.",
		})
	}

	accessToken, err := h.jwtSvc.GenerateToken(user.ID)
	if err != nil {
		h.logger.Error("failed to generate access token for new user",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusCreated, map[string]string{
			"message": "Account created successfully. Please sign in.",
		})
	}

	refreshToken, err := h.jwtSvc.GenerateRefreshToken(user.ID)
	if err != nil {
		h.logger.Error("failed to generate refresh token for new user",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusCreated, map[string]string{
			"message": "Account created successfully. Please sign in.",
		})
	}

	h.logger.Info("mobile register successful",
		zap.String("username", req.Username),
		zap.Uint("user_id", user.ID),
		zap.String("remote_ip", c.RealIP()),
	)

	return c.JSON(http.StatusCreated, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.jwtSvc.GetAccessExpirySeconds(),
		User: UserInfo{
			ID:              user.ID,
			Username:        user.Username,
			Email:           user.Email,
			EmailVerifiedAt: formatTimePtr(user.EmailVerifiedAt),
			TOTPEnabled:     false, // TODO: Check TOTP status
			CreatedAt:       user.CreatedAt.Format(time.RFC3339),
			UpdatedAt:       user.UpdatedAt.Format(time.RFC3339),
		},
	})
}

func (h *MobileAuthHandler) RefreshToken(c echo.Context) error {
	var req RefreshRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
	}

	if req.RefreshToken == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: "Refresh token is required",
		})
	}

	newAccessToken, newRefreshToken, err := h.jwtSvc.RefreshToken(req.RefreshToken)
	if err != nil {
		switch err {
		case jwtservice.ErrExpiredToken:
			return c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "expired_token",
				Message: "Refresh token has expired",
			})
		case jwtservice.ErrInvalidToken, jwtservice.ErrMalformedToken, jwtservice.ErrInvalidSignature:
			return c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "invalid_token",
				Message: "Invalid refresh token",
			})
		default:
			h.logger.Error("failed to refresh token", zap.Error(err))
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "token_refresh_failed",
				Message: "Failed to refresh token",
			})
		}
	}

	return c.JSON(http.StatusOK, RefreshResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.jwtSvc.GetAccessExpirySeconds(),
	})
}

func (h *MobileAuthHandler) Profile(c echo.Context) error {
	userID := jwt.GetUserID(c)
	if userID == 0 {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "user_not_found",
				Message: "User not found",
			})
		}
		h.logger.Error("failed to fetch user profile",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "database_error",
			Message: "Failed to fetch user profile",
		})
	}

	return c.JSON(http.StatusOK, UserInfo{
		ID:              user.ID,
		Username:        user.Username,
		Email:           user.Email,
		EmailVerifiedAt: formatTimePtr(user.EmailVerifiedAt),
		TOTPEnabled:     false, // TODO: Check TOTP status
		CreatedAt:       user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       user.UpdatedAt.Format(time.RFC3339),
	})
}

func (h *MobileAuthHandler) Logout(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Logout successful. Please discard the token on client side.",
	})
}

// Helper function to format time pointer for JSON
func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	formatted := t.Format(time.RFC3339)
	return &formatted
}
