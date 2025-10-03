package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"brx-starter-kit/internal/dto"
	"brx-starter-kit/internal/rbac"
	"brx-starter-kit/models"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/middleware/jwtshared"
	"github.com/tech-arch1tect/brx/services/auth"
	jwtservice "github.com/tech-arch1tect/brx/services/jwt"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/services/refreshtoken"
	"github.com/tech-arch1tect/brx/services/totp"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type MobileAuthHandler struct {
	db              *gorm.DB
	authSvc         *auth.Service
	jwtSvc          *jwtservice.Service
	refreshTokenSvc refreshtoken.RefreshTokenService
	totpSvc         *totp.Service
	sessionSvc      session.SessionService
	logger          *logging.Service
	rbacSvc         *rbac.Service
}

func NewMobileAuthHandler(db *gorm.DB, authSvc *auth.Service, jwtSvc *jwtservice.Service, refreshTokenSvc refreshtoken.RefreshTokenService, totpSvc *totp.Service, sessionSvc session.SessionService, logger *logging.Service, rbacSvc *rbac.Service) *MobileAuthHandler {
	return &MobileAuthHandler{
		db:              db,
		authSvc:         authSvc,
		jwtSvc:          jwtSvc,
		refreshTokenSvc: refreshTokenSvc,
		totpSvc:         totpSvc,
		sessionSvc:      sessionSvc,
		logger:          logger,
		rbacSvc:         rbacSvc,
	}
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	AccessToken      string       `json:"access_token"`
	RefreshToken     string       `json:"refresh_token"`
	TokenType        string       `json:"token_type"`
	ExpiresIn        int          `json:"expires_in"`
	RefreshExpiresIn int          `json:"refresh_expires_in"`
	User             dto.UserInfo `json:"user"`
}

type RegisterRequest struct {
	Username string `json:"username" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type RefreshResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type TOTPRequiredResponse struct {
	Message        string `json:"message"`
	TOTPRequired   bool   `json:"totp_required"`
	TemporaryToken string `json:"temporary_token"`
}

type TOTPVerifyRequest struct {
	Code string `json:"code" validate:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type TOTPSetupResponse struct {
	QRCodeURI string `json:"qr_code_uri"`
	Secret    string `json:"secret"`
}

type TOTPStatusResponse struct {
	Enabled bool `json:"enabled"`
}

type TOTPEnableRequest struct {
	Code string `json:"code" validate:"required"`
}

type TOTPDisableRequest struct {
	Code     string `json:"code" validate:"required"`
	Password string `json:"password" validate:"required"`
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
	if err := h.db.Preload("Roles").Where("username = ?", req.Username).First(&user).Error; err != nil {
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

	if h.totpSvc.IsUserTOTPEnabled(user.ID) {
		temporaryToken, err := h.jwtSvc.GenerateTOTPToken(user.ID)
		if err != nil {
			h.logger.Error("failed to generate TOTP token",
				zap.Uint("user_id", user.ID),
				zap.Error(err),
			)
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "token_generation_failed",
				Message: "Failed to generate authentication token",
			})
		}

		h.logger.Info("mobile login - TOTP required",
			zap.String("username", req.Username),
			zap.Uint("user_id", user.ID),
			zap.String("remote_ip", c.RealIP()),
		)

		return c.JSON(http.StatusOK, TOTPRequiredResponse{
			Message:        "Two-factor authentication required",
			TOTPRequired:   true,
			TemporaryToken: temporaryToken,
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

	sessionInfo := refreshtoken.TokenSessionInfo{
		IPAddress:  c.RealIP(),
		UserAgent:  c.Request().UserAgent(),
		DeviceInfo: session.GetDeviceInfo(c.Request().UserAgent()),
	}

	refreshTokenData, err := h.refreshTokenSvc.GenerateRefreshToken(user.ID, sessionInfo)
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

	h.trackJWTSession(c, user.ID, accessToken, refreshTokenData)

	h.logger.Info("mobile login successful",
		zap.String("username", req.Username),
		zap.Uint("user_id", user.ID),
		zap.String("remote_ip", c.RealIP()),
	)

	userInfo := dto.ConvertUserToUserInfo(user)
	userInfo.TOTPEnabled = h.totpSvc.IsUserTOTPEnabled(user.ID)

	return c.JSON(http.StatusOK, LoginResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshTokenData.Token,
		TokenType:        "Bearer",
		ExpiresIn:        h.jwtSvc.GetAccessExpirySeconds(),
		RefreshExpiresIn: int(refreshTokenData.ExpiresAt.Sub(time.Now()).Seconds()),
		User:             userInfo,
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

	if err := h.rbacSvc.AssignUserRole(user.ID, "user"); err != nil {
		h.logger.Error("failed to assign default user role",
			zap.Uint("user_id", user.ID),
			zap.Error(err))
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

	sessionInfo := refreshtoken.TokenSessionInfo{
		IPAddress:  c.RealIP(),
		UserAgent:  c.Request().UserAgent(),
		DeviceInfo: session.GetDeviceInfo(c.Request().UserAgent()),
	}

	refreshTokenData, err := h.refreshTokenSvc.GenerateRefreshToken(user.ID, sessionInfo)
	if err != nil {
		h.logger.Error("failed to generate refresh token for new user",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusCreated, map[string]string{
			"message": "Account created successfully. Please sign in.",
		})
	}

	h.trackJWTSession(c, user.ID, accessToken, refreshTokenData)

	h.logger.Info("mobile register successful",
		zap.String("username", req.Username),
		zap.Uint("user_id", user.ID),
		zap.String("remote_ip", c.RealIP()),
	)

	return c.JSON(http.StatusCreated, LoginResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshTokenData.Token,
		TokenType:        "Bearer",
		ExpiresIn:        h.jwtSvc.GetAccessExpirySeconds(),
		RefreshExpiresIn: int(refreshTokenData.ExpiresAt.Sub(time.Now()).Seconds()),
		User: func() dto.UserInfo {
			userInfo := dto.ConvertUserToUserInfo(user)
			userInfo.TOTPEnabled = h.totpSvc.IsUserTOTPEnabled(user.ID)
			return userInfo
		}(),
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

	result, err := h.refreshTokenSvc.ValidateAndRotateRefreshToken(req.RefreshToken, h.jwtSvc)
	if err != nil {
		switch err {
		case refreshtoken.ErrRefreshTokenExpired:
			return c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "expired_token",
				Message: "Refresh token has expired",
			})
		case refreshtoken.ErrRefreshTokenNotFound, refreshtoken.ErrRefreshTokenInvalid:
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

	// Update the session with new tokens
	if h.sessionSvc != nil {
		accessJTI, _ := h.jwtSvc.ExtractJTI(result.AccessToken)
		err = h.sessionSvc.UpdateJWTSessionWithRefreshToken(result.OldTokenID, accessJTI, result.RefreshTokenID, result.ExpiresAt)
		if err != nil {
			h.logger.Warn("failed to update JWT session after token refresh",
				zap.Uint("old_refresh_token_id", result.OldTokenID),
				zap.Uint("new_refresh_token_id", result.RefreshTokenID),
				zap.Error(err),
			)
		}
	}

	return c.JSON(http.StatusOK, RefreshResponse{
		AccessToken:      result.AccessToken,
		RefreshToken:     result.RefreshToken,
		TokenType:        "Bearer",
		ExpiresIn:        h.jwtSvc.GetAccessExpirySeconds(),
		RefreshExpiresIn: int(result.ExpiresAt.Sub(time.Now()).Seconds()),
	})
}

func (h *MobileAuthHandler) Profile(c echo.Context) error {

	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_data_error",
			Message: "Failed to process user data",
		})
	}

	var fullUser models.User
	if err := h.db.Preload("Roles").Where("id = ?", userModel.ID).First(&fullUser).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "database_error",
			Message: "Failed to load user profile",
		})
	}

	userInfo := dto.ConvertUserToUserInfo(fullUser)
	userInfo.TOTPEnabled = h.totpSvc.IsUserTOTPEnabled(fullUser.ID)

	return c.JSON(http.StatusOK, userInfo)
}

func (h *MobileAuthHandler) Logout(c echo.Context) error {
	var req LogoutRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Warn("logout - invalid request format",
			zap.String("remote_ip", c.RealIP()),
			zap.Error(err))
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

	var revokedTokens []string

	authHeader := c.Request().Header.Get("Authorization")
	if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		accessToken := authHeader[7:]

		accessJTI, err := h.jwtSvc.ExtractJTI(accessToken)
		if err != nil {
			h.logger.Warn("failed to extract JTI from access token during logout",
				zap.Error(err))
		} else {
			if err := h.jwtSvc.RevokeToken(accessJTI, time.Now().Add(24*time.Hour)); err != nil {
				h.logger.Warn("failed to revoke access token JTI during logout",
					zap.String("jti", accessJTI),
					zap.Error(err))
			} else {
				revokedTokens = append(revokedTokens, "access_token")
			}
		}

		if h.sessionSvc != nil {
			refreshToken, err := h.refreshTokenSvc.ValidateRefreshToken(req.RefreshToken)
			if err == nil {
				sessionToken := h.generateSessionTokenFromID(refreshToken.ID)
				_ = h.sessionSvc.RemoveSessionByToken(sessionToken)
			}
		}
	}

	if err := h.refreshTokenSvc.RevokeRefreshToken(req.RefreshToken); err != nil {
		h.logger.Warn("failed to revoke refresh token during logout",
			zap.Error(err))
	} else {
		revokedTokens = append(revokedTokens, "refresh_token")
	}

	if len(revokedTokens) == 0 {
		h.logger.Error("failed to revoke any tokens during logout")
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "logout_failed",
			Message: "Failed to revoke tokens",
		})
	}

	h.logger.Info("logout successful",
		zap.Strings("revoked_tokens", revokedTokens),
		zap.String("remote_ip", c.RealIP()))

	return c.JSON(http.StatusOK, map[string]any{
		"message":        "Logout successful. Tokens have been revoked.",
		"revoked_tokens": revokedTokens,
	})
}

func (h *MobileAuthHandler) VerifyTOTP(c echo.Context) error {
	var req TOTPVerifyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
	}

	if req.Code == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: "TOTP code is required",
		})
	}

	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Missing or invalid authorization header",
		})
	}

	tokenString := authHeader[7:]
	claims, err := h.jwtSvc.ValidateToken(tokenString)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or expired token",
		})
	}

	if claims.TokenType != "totp_pending" {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_token_type",
			Message: "Invalid token for TOTP verification",
		})
	}

	if err := h.totpSvc.VerifyUserCode(claims.UserID, req.Code); err != nil {
		switch err {
		case totp.ErrInvalidCode:
			return c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "invalid_totp_code",
				Message: "Invalid TOTP code",
			})
		case totp.ErrCodeAlreadyUsed:
			return c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "code_already_used",
				Message: "TOTP code has already been used",
			})
		}
		h.logger.Error("TOTP verification failed",
			zap.Uint("user_id", claims.UserID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "totp_verification_failed",
			Message: "Failed to verify TOTP code",
		})
	}

	var user models.User
	if err := h.db.First(&user, claims.UserID).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_not_found",
			Message: "User not found",
		})
	}

	accessToken, err := h.jwtSvc.GenerateToken(claims.UserID)
	if err != nil {
		h.logger.Error("failed to generate access token after TOTP verification",
			zap.Uint("user_id", claims.UserID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "token_generation_failed",
			Message: "Failed to generate authentication token",
		})
	}

	sessionInfo := refreshtoken.TokenSessionInfo{
		IPAddress:  c.RealIP(),
		UserAgent:  c.Request().UserAgent(),
		DeviceInfo: session.GetDeviceInfo(c.Request().UserAgent()),
	}

	refreshTokenData, err := h.refreshTokenSvc.GenerateRefreshToken(claims.UserID, sessionInfo)
	if err != nil {
		h.logger.Error("failed to generate refresh token after TOTP verification",
			zap.Uint("user_id", claims.UserID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "token_generation_failed",
			Message: "Failed to generate refresh token",
		})
	}

	h.trackJWTSession(c, claims.UserID, accessToken, refreshTokenData)

	h.logger.Info("TOTP verification successful",
		zap.Uint("user_id", claims.UserID),
		zap.String("remote_ip", c.RealIP()),
	)

	return c.JSON(http.StatusOK, LoginResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshTokenData.Token,
		TokenType:        "Bearer",
		ExpiresIn:        h.jwtSvc.GetAccessExpirySeconds(),
		RefreshExpiresIn: int(refreshTokenData.ExpiresAt.Sub(time.Now()).Seconds()),
		User: func() dto.UserInfo {
			userInfo := dto.ConvertUserToUserInfo(user)
			userInfo.TOTPEnabled = h.totpSvc.IsUserTOTPEnabled(user.ID)
			return userInfo
		}(),
	})
}

func (h *MobileAuthHandler) GetTOTPSetup(c echo.Context) error {
	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_data_error",
			Message: "Failed to process user data",
		})
	}

	if h.totpSvc.IsUserTOTPEnabled(userModel.ID) {
		return c.JSON(http.StatusConflict, ErrorResponse{
			Error:   "totp_already_enabled",
			Message: "TOTP is already enabled for your account",
		})
	}

	existing, err := h.totpSvc.GetSecret(userModel.ID)
	if err != nil && err != totp.ErrSecretNotFound {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "totp_setup_failed",
			Message: "Failed to retrieve TOTP information",
		})
	}

	var secret *totp.TOTPSecret
	if existing != nil {
		secret = existing
	} else {
		secret, err = h.totpSvc.GenerateSecret(userModel.ID, userModel.Email)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "totp_setup_failed",
				Message: "Failed to generate TOTP secret",
			})
		}
	}

	qrCodeURI, err := h.totpSvc.GenerateProvisioningURI(secret, userModel.Email)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "totp_setup_failed",
			Message: "Failed to generate QR code",
		})
	}

	return c.JSON(http.StatusOK, TOTPSetupResponse{
		QRCodeURI: qrCodeURI,
		Secret:    secret.Secret,
	})
}

func (h *MobileAuthHandler) EnableTOTP(c echo.Context) error {
	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_data_error",
			Message: "Failed to process user data",
		})
	}

	var req TOTPEnableRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
	}

	if req.Code == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: "TOTP code is required",
		})
	}

	if err := h.totpSvc.EnableTOTP(userModel.ID, req.Code); err != nil {
		if err == totp.ErrInvalidCode {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "invalid_totp_code",
				Message: "Invalid TOTP code. Please try again.",
			})
		}
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "totp_enable_failed",
			Message: "Failed to enable TOTP",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Two-factor authentication has been enabled successfully",
	})
}

func (h *MobileAuthHandler) DisableTOTP(c echo.Context) error {
	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_data_error",
			Message: "Failed to process user data",
		})
	}

	var req TOTPDisableRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
	}

	if req.Code == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: "TOTP code and password are required to disable 2FA",
		})
	}

	if err := h.authSvc.VerifyPassword(userModel.Password, req.Password); err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_password",
			Message: "Invalid password",
		})
	}

	if err := h.totpSvc.VerifyUserCode(userModel.ID, req.Code); err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_totp_code",
			Message: "Invalid TOTP code",
		})
	}

	if err := h.totpSvc.DisableTOTP(userModel.ID); err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "totp_disable_failed",
			Message: "Failed to disable TOTP",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Two-factor authentication has been disabled",
	})
}

func (h *MobileAuthHandler) GetTOTPStatus(c echo.Context) error {
	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_data_error",
			Message: "Failed to process user data",
		})
	}

	enabled := h.totpSvc.IsUserTOTPEnabled(userModel.ID)

	return c.JSON(http.StatusOK, TOTPStatusResponse{
		Enabled: enabled,
	})
}

func (h *MobileAuthHandler) GetSessions(c echo.Context) error {
	if h.sessionSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Error:   "sessions_unavailable",
			Message: "Session service not available",
		})
	}

	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_data_error",
			Message: "Failed to process user data",
		})
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

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

	refreshToken, err := h.refreshTokenSvc.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_token",
			Message: "Invalid refresh token",
		})
	}
	currentToken := h.generateSessionTokenFromID(refreshToken.ID)

	sessions, err := h.sessionSvc.GetUserSessions(userModel.ID, currentToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "sessions_fetch_failed",
			Message: "Failed to retrieve sessions",
		})
	}

	sessionData := make([]map[string]any, len(sessions))
	for i, sess := range sessions {
		deviceInfo := session.GetDeviceInfo(sess.UserAgent)

		sessionData[i] = map[string]any{
			"id":          sess.ID,
			"user_id":     sess.UserID,
			"token":       sess.Token,
			"type":        string(sess.Type),
			"current":     sess.Current,
			"ip_address":  sess.IPAddress,
			"user_agent":  sess.UserAgent,
			"location":    session.GetLocationInfo(sess.IPAddress),
			"browser":     deviceInfo["browser"],
			"os":          deviceInfo["os"],
			"device_type": deviceInfo["device_type"],
			"device":      deviceInfo["device"],
			"mobile":      deviceInfo["mobile"],
			"tablet":      deviceInfo["tablet"],
			"desktop":     deviceInfo["desktop"],
			"bot":         deviceInfo["bot"],
			"created_at":  sess.CreatedAt,
			"last_used":   sess.LastUsed,
			"expires_at":  sess.ExpiresAt,
		}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"sessions": sessionData,
	})
}

func (h *MobileAuthHandler) RevokeSession(c echo.Context) error {
	if h.sessionSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Error:   "sessions_unavailable",
			Message: "Session service not available",
		})
	}

	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_data_error",
			Message: "Failed to process user data",
		})
	}

	var req struct {
		SessionID uint `json:"session_id"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
	}

	if req.SessionID == 0 {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: "Session ID is required",
		})
	}

	err := h.sessionSvc.RevokeSession(userModel.ID, req.SessionID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "session_revoke_failed",
			Message: "Failed to revoke session",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Session revoked successfully",
	})
}

func (h *MobileAuthHandler) RevokeAllOtherSessions(c echo.Context) error {
	if h.sessionSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Error:   "sessions_unavailable",
			Message: "Session service not available",
		})
	}

	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid or missing authentication token",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "user_data_error",
			Message: "Failed to process user data",
		})
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

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

	refreshToken, err := h.refreshTokenSvc.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_token",
			Message: "Invalid refresh token",
		})
	}
	currentToken := h.generateSessionTokenFromID(refreshToken.ID)

	err = h.sessionSvc.RevokeAllOtherSessions(userModel.ID, currentToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "sessions_revoke_failed",
			Message: "Failed to revoke other sessions",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "All other sessions revoked successfully",
	})
}

func (h *MobileAuthHandler) generateSessionTokenFromID(refreshTokenID uint) string {
	hash := sha256.Sum256(fmt.Appendf(nil, "refresh_token_id_%d", refreshTokenID))
	return hex.EncodeToString(hash[:])
}

func (h *MobileAuthHandler) trackJWTSession(c echo.Context, userID uint, accessToken string, refreshTokenData *refreshtoken.RefreshTokenData) {
	if h.sessionSvc == nil {
		return
	}

	ipAddress := c.RealIP()
	userAgent := c.Request().UserAgent()

	accessJTI, _ := h.jwtSvc.ExtractJTI(accessToken)
	err := h.sessionSvc.TrackJWTSessionWithRefreshToken(userID, accessJTI, refreshTokenData.TokenID, ipAddress, userAgent, refreshTokenData.ExpiresAt)
	if err != nil {
		h.logger.Warn("failed to track JWT session",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)
	}
}
