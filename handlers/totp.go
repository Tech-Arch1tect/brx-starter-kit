package handlers

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/services/totp"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"brx-starter-kit/models"
)

type TOTPHandler struct {
	db         *gorm.DB
	inertiaSvc *inertia.Service
	totpSvc    *totp.Service
	authSvc    *auth.Service
	logger     *logging.Service
}

func NewTOTPHandler(db *gorm.DB, inertiaSvc *inertia.Service, totpSvc *totp.Service, authSvc *auth.Service, logger *logging.Service) *TOTPHandler {
	return &TOTPHandler{
		db:         db,
		inertiaSvc: inertiaSvc,
		totpSvc:    totpSvc,
		authSvc:    authSvc,
		logger:     logger,
	}
}

func (h *TOTPHandler) ShowSetup(c echo.Context) error {
	userID := session.GetUserIDAsUint(c)

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "User not found")
	}

	if h.totpSvc.IsUserTOTPEnabled(userID) {
		session.AddFlashError(c, "TOTP is already enabled for your account")
		return c.Redirect(http.StatusFound, "/profile")
	}

	existing, err := h.totpSvc.GetSecret(userID)
	if err != nil && err != totp.ErrSecretNotFound {
		session.AddFlashError(c, "Failed to retrieve TOTP information")
		return c.Redirect(http.StatusFound, "/profile")
	}

	var secret *totp.TOTPSecret
	if existing != nil {
		secret = existing
	} else {
		secret, err = h.totpSvc.GenerateSecret(userID, user.Email)
		if err != nil {
			session.AddFlashError(c, "Failed to generate TOTP secret")
			return c.Redirect(http.StatusFound, "/profile")
		}
	}

	qrCodeURI, err := h.totpSvc.GenerateProvisioningURI(secret, user.Email)
	if err != nil {
		session.AddFlashError(c, "Failed to generate QR code")
		return c.Redirect(http.StatusFound, "/profile")
	}

	return h.inertiaSvc.Render(c, "Auth/TOTPSetup", map[string]any{
		"title":     "Setup Two-Factor Authentication",
		"qrCodeURI": qrCodeURI,
		"secret":    secret.Secret,
	})
}

func (h *TOTPHandler) EnableTOTP(c echo.Context) error {
	userID := session.GetUserIDAsUint(c)

	var req struct {
		Code string `form:"code" json:"code"`
	}

	if err := c.Bind(&req); err != nil {
		session.AddFlashError(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/auth/totp/setup")
	}

	if req.Code == "" {
		session.AddFlashError(c, "TOTP code is required")
		return c.Redirect(http.StatusFound, "/auth/totp/setup")
	}

	if err := h.totpSvc.EnableTOTP(userID, req.Code); err != nil {
		if err == totp.ErrInvalidCode {
			session.AddFlashError(c, "Invalid TOTP code. Please try again.")
		} else {
			session.AddFlashError(c, "Failed to enable TOTP")
		}
		return c.Redirect(http.StatusFound, "/auth/totp/setup")
	}

	session.SetTOTPEnabled(c, true)
	session.AddFlashSuccess(c, "Two-factor authentication has been enabled successfully!")
	return c.Redirect(http.StatusFound, "/profile")
}

func (h *TOTPHandler) DisableTOTP(c echo.Context) error {
	userID := session.GetUserIDAsUint(c)

	var req struct {
		Code     string `form:"code" json:"code"`
		Password string `form:"password" json:"password"`
	}

	if err := c.Bind(&req); err != nil {
		session.AddFlashError(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/profile")
	}

	if req.Code == "" || req.Password == "" {
		session.AddFlashError(c, "TOTP code and password are required to disable 2FA")
		return c.Redirect(http.StatusFound, "/profile")
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		session.AddFlashError(c, "User not found")
		return c.Redirect(http.StatusFound, "/profile")
	}

	if err := h.authSvc.VerifyPassword(user.Password, req.Password); err != nil {
		session.AddFlashError(c, "Invalid password")
		return c.Redirect(http.StatusFound, "/profile")
	}

	if err := h.totpSvc.VerifyUserCode(userID, req.Code); err != nil {
		session.AddFlashError(c, "Invalid TOTP code")
		return c.Redirect(http.StatusFound, "/profile")
	}

	if err := h.totpSvc.DisableTOTP(userID); err != nil {
		session.AddFlashError(c, "Failed to disable TOTP")
		return c.Redirect(http.StatusFound, "/profile")
	}

	session.SetTOTPEnabled(c, false)
	session.AddFlashSuccess(c, "Two-factor authentication has been disabled")
	return c.Redirect(http.StatusFound, "/profile")
}

func (h *TOTPHandler) ShowVerify(c echo.Context) error {
	if !session.IsAuthenticated(c) {
		return c.Redirect(http.StatusFound, "/auth/login")
	}

	if session.IsTOTPVerified(c) {
		return c.Redirect(http.StatusFound, "/")
	}

	userID := session.GetUserIDAsUint(c)
	if !h.totpSvc.IsUserTOTPEnabled(userID) {
		session.SetTOTPVerified(c, true)
		return c.Redirect(http.StatusFound, "/")
	}

	return h.inertiaSvc.Render(c, "Auth/TOTPVerify", map[string]any{
		"title": "Two-Factor Authentication",
	})
}

func (h *TOTPHandler) VerifyTOTP(c echo.Context) error {
	if !session.IsAuthenticated(c) {
		return c.Redirect(http.StatusFound, "/auth/login")
	}

	userID := session.GetUserIDAsUint(c)

	var req struct {
		Code string `form:"code" json:"code"`
	}

	if err := c.Bind(&req); err != nil {
		session.AddFlashError(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/auth/totp/verify")
	}

	if req.Code == "" {
		session.AddFlashError(c, "TOTP code is required")
		return c.Redirect(http.StatusFound, "/auth/totp/verify")
	}

	if err := h.totpSvc.VerifyUserCode(userID, req.Code); err != nil {
		session.AddFlashError(c, "Invalid TOTP code. Please try again.")
		return c.Redirect(http.StatusFound, "/auth/totp/verify")
	}

	session.SetTOTPVerified(c, true)

	if pendingRememberMe := session.Get(c, "pending_remember_me"); pendingRememberMe == true {
		if h.authSvc != nil && h.authSvc.IsRememberMeEnabled() {
			rememberToken, err := h.authSvc.CreateRememberMeToken(userID)
			if err != nil {
				if h.logger != nil {
					h.logger.Error("failed to create remember me token after TOTP verification",
						zap.Uint("user_id", userID),
						zap.Error(err),
					)
				}
			} else {
				setRememberMeCookie(c, h.authSvc, rememberToken.Token, rememberToken.ExpiresAt)
				if h.logger != nil {
					h.logger.Info("remember me token created after TOTP verification",
						zap.Uint("user_id", userID),
						zap.Time("expires_at", rememberToken.ExpiresAt),
					)
				}
			}
		}
		session.Set(c, "pending_remember_me", nil)
	}

	return c.Redirect(http.StatusFound, "/")
}

func (h *TOTPHandler) GetTOTPStatus(c echo.Context) error {
	userID := session.GetUserIDAsUint(c)
	enabled := h.totpSvc.IsUserTOTPEnabled(userID)

	return c.JSON(http.StatusOK, map[string]any{
		"enabled": enabled,
	})
}

func setRememberMeCookie(c echo.Context, authSvc *auth.Service, token string, expiresAt time.Time) {
	sameSite := http.SameSiteLaxMode
	switch authSvc.GetRememberMeCookieSameSite() {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	case "lax":
		sameSite = http.SameSiteLaxMode
	}

	maxAge := int(time.Until(expiresAt).Seconds())

	cookie := &http.Cookie{
		Name:     "remember_me",
		Value:    token,
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   authSvc.GetRememberMeCookieSecure(),
		SameSite: sameSite,
		Path:     "/",
	}
	c.SetCookie(cookie)
}
