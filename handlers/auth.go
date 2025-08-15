package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/session"
	"gorm.io/gorm"

	"brx-starter-kit/models"
)

type AuthHandler struct {
	db         *gorm.DB
	inertiaSvc *inertia.Service
	authSvc    *auth.Service
}

func NewAuthHandler(db *gorm.DB, inertiaSvc *inertia.Service, authSvc *auth.Service) *AuthHandler {
	return &AuthHandler{
		db:         db,
		inertiaSvc: inertiaSvc,
		authSvc:    authSvc,
	}
}

func (h *AuthHandler) ShowLogin(c echo.Context) error {
	if session.IsAuthenticated(c) {
		return c.Redirect(http.StatusFound, "/")
	}

	flash := session.GetFlash(c)

	return h.inertiaSvc.Render(c, "Auth/Login", map[string]any{
		"title": "Login",
		"flash": flash,
	})
}

func (h *AuthHandler) Login(c echo.Context) error {
	var req struct {
		Username string `form:"username" json:"username"`
		Password string `form:"password" json:"password"`
	}

	if err := c.Bind(&req); err != nil {
		session.SetFlash(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/auth/login")
	}

	if req.Username == "" || req.Password == "" {
		session.SetFlash(c, "Username and password are required")
		return c.Redirect(http.StatusFound, "/auth/login")
	}

	var user models.User
	if err := h.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		session.SetFlash(c, "Invalid credentials")
		return c.Redirect(http.StatusFound, "/auth/login")
	}

	if err := h.authSvc.VerifyPassword(user.Password, req.Password); err != nil {
		session.SetFlash(c, "Invalid credentials")
		return c.Redirect(http.StatusFound, "/auth/login")
	}

	session.Login(c, user.ID)
	session.SetFlash(c, "Login successful!")

	return c.Redirect(http.StatusFound, "/")
}

func (h *AuthHandler) ShowRegister(c echo.Context) error {
	if session.IsAuthenticated(c) {
		return c.Redirect(http.StatusFound, "/")
	}

	flash := session.GetFlash(c)

	return h.inertiaSvc.Render(c, "Auth/Register", map[string]any{
		"title": "Register",
		"flash": flash,
	})
}

func (h *AuthHandler) Register(c echo.Context) error {
	var req struct {
		Username string `form:"username" json:"username"`
		Email    string `form:"email" json:"email"`
		Password string `form:"password" json:"password"`
	}

	if err := c.Bind(&req); err != nil {
		session.SetFlash(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/auth/register")
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		session.SetFlash(c, "All fields are required")
		return c.Redirect(http.StatusFound, "/auth/register")
	}

	hashedPassword, err := h.authSvc.HashPassword(req.Password)
	if err != nil {
		session.SetFlash(c, err.Error())
		return c.Redirect(http.StatusFound, "/auth/register")
	}

	user := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
	}

	if err := h.db.Create(&user).Error; err != nil {
		session.SetFlash(c, "Username or email already exists")
		return c.Redirect(http.StatusFound, "/auth/register")
	}

	session.Login(c, user.ID)
	session.SetFlash(c, "Account created successfully!")

	return c.Redirect(http.StatusFound, "/")
}

func (h *AuthHandler) Logout(c echo.Context) error {
	session.Logout(c)
	session.SetFlash(c, "Logged out successfully")
	return c.Redirect(http.StatusFound, "/auth/login")
}

func (h *AuthHandler) Profile(c echo.Context) error {
	userID := session.GetUserIDAsUint(c)
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "User not found")
	}

	flash := session.GetFlash(c)

	return h.inertiaSvc.Render(c, "Profile", map[string]any{
		"title":       "Profile",
		"user":        user,
		"currentUser": user,
		"flash":       flash,
	})
}

func (h *AuthHandler) ShowPasswordReset(c echo.Context) error {
	if session.IsAuthenticated(c) {
		return c.Redirect(http.StatusFound, "/")
	}

	flash := session.GetFlash(c)

	return h.inertiaSvc.Render(c, "Auth/PasswordReset", map[string]any{
		"flash": flash,
	})
}

func (h *AuthHandler) RequestPasswordReset(c echo.Context) error {
	var req struct {
		Email string `form:"email" json:"email"`
	}

	if err := c.Bind(&req); err != nil {
		session.SetFlash(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/auth/password-reset")
	}

	if req.Email == "" {
		session.SetFlash(c, "Email is required")
		return c.Redirect(http.StatusFound, "/auth/password-reset")
	}

	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			session.SetFlash(c, "If an account with that email exists, you will receive a password reset email shortly.")
			return c.Redirect(http.StatusFound, "/auth/login")
		}
		session.SetFlash(c, "Something went wrong. Please try again.")
		return c.Redirect(http.StatusFound, "/auth/password-reset")
	}

	if err := h.authSvc.RequestPasswordReset(req.Email); err != nil {
		if strings.Contains(err.Error(), "disabled") {
			session.SetFlash(c, "Password reset is currently disabled")
		} else if strings.Contains(err.Error(), "mail service is not configured") {
			session.SetFlash(c, "Email service is not properly configured. Please contact support.")
		} else if strings.Contains(err.Error(), "failed to send password reset email") {
			session.SetFlash(c, "Failed to send password reset email. Please try again or contact support.")
		} else {
			session.SetFlash(c, "Something went wrong. Please try again or contact support.")
		}
		return c.Redirect(http.StatusFound, "/auth/password-reset")
	}

	session.SetFlash(c, "If an account with that email exists, you will receive a password reset email shortly.")
	return c.Redirect(http.StatusFound, "/auth/login")
}

func (h *AuthHandler) ShowPasswordResetConfirm(c echo.Context) error {
	if session.IsAuthenticated(c) {
		return c.Redirect(http.StatusFound, "/")
	}

	token := c.QueryParam("token")
	if token == "" {
		session.SetFlash(c, "Invalid password reset link")
		return c.Redirect(http.StatusFound, "/auth/login")
	}

	_, err := h.authSvc.ValidatePasswordResetToken(token)
	if err != nil {
		var message string
		switch err {
		case auth.ErrPasswordResetTokenExpired:
			message = "This password reset link has expired. Please request a new one."
		case auth.ErrPasswordResetTokenUsed:
			message = "This password reset link has already been used."
		case auth.ErrPasswordResetTokenInvalid:
			message = "Invalid password reset link."
		default:
			message = "Invalid password reset link."
		}
		session.SetFlash(c, message)
		return c.Redirect(http.StatusFound, "/auth/password-reset")
	}

	flash := session.GetFlash(c)

	return h.inertiaSvc.Render(c, "Auth/PasswordResetConfirm", map[string]any{
		"token": token,
		"flash": flash,
	})
}

func (h *AuthHandler) ConfirmPasswordReset(c echo.Context) error {
	var req struct {
		Token           string `form:"token" json:"token"`
		Password        string `form:"password" json:"password"`
		PasswordConfirm string `form:"password_confirm" json:"password_confirm"`
	}

	if err := c.Bind(&req); err != nil {
		session.SetFlash(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/auth/password-reset")
	}

	if req.Token == "" {
		session.SetFlash(c, "Invalid password reset link")
		return c.Redirect(http.StatusFound, "/auth/password-reset")
	}

	if req.Password == "" || req.PasswordConfirm == "" {
		session.SetFlash(c, "Password and confirmation are required")
		return c.Redirect(http.StatusFound, fmt.Sprintf("/auth/password-reset/confirm?token=%s", req.Token))
	}

	if req.Password != req.PasswordConfirm {
		session.SetFlash(c, "Passwords do not match")
		return c.Redirect(http.StatusFound, fmt.Sprintf("/auth/password-reset/confirm?token=%s", req.Token))
	}

	if err := h.authSvc.CompletePasswordReset(req.Token, req.Password); err != nil {
		var message string
		switch err {
		case auth.ErrPasswordResetTokenExpired:
			message = "This password reset link has expired. Please request a new one."
		case auth.ErrPasswordResetTokenUsed:
			message = "This password reset link has already been used."
		case auth.ErrPasswordResetTokenInvalid:
			message = "Invalid password reset link."
		default:
			if strings.Contains(err.Error(), "password must") {
				message = err.Error()
			} else {
				message = "Something went wrong. Please try again."
			}
		}

		if err == auth.ErrPasswordResetTokenExpired || err == auth.ErrPasswordResetTokenUsed || err == auth.ErrPasswordResetTokenInvalid {
			session.SetFlash(c, message)
			return c.Redirect(http.StatusFound, "/auth/password-reset")
		} else {
			session.SetFlash(c, message)
			return c.Redirect(http.StatusFound, fmt.Sprintf("/auth/password-reset/confirm?token=%s", req.Token))
		}
	}

	session.SetFlash(c, "Your password has been reset successfully. Please log in with your new password.")
	return c.Redirect(http.StatusFound, "/auth/login")
}
