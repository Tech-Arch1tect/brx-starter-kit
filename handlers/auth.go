package handlers

import (
	"net/http"

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
		return c.Redirect(http.StatusFound, "/login")
	}

	if req.Username == "" || req.Password == "" {
		session.SetFlash(c, "Username and password are required")
		return c.Redirect(http.StatusFound, "/login")
	}

	var user models.User
	if err := h.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		session.SetFlash(c, "Invalid credentials")
		return c.Redirect(http.StatusFound, "/login")
	}

	if err := h.authSvc.VerifyPassword(user.Password, req.Password); err != nil {
		session.SetFlash(c, "Invalid credentials")
		return c.Redirect(http.StatusFound, "/login")
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
		return c.Redirect(http.StatusFound, "/register")
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		session.SetFlash(c, "All fields are required")
		return c.Redirect(http.StatusFound, "/register")
	}

	hashedPassword, err := h.authSvc.HashPassword(req.Password)
	if err != nil {
		session.SetFlash(c, err.Error())
		return c.Redirect(http.StatusFound, "/register")
	}

	user := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
	}

	if err := h.db.Create(&user).Error; err != nil {
		session.SetFlash(c, "Username or email already exists")
		return c.Redirect(http.StatusFound, "/register")
	}

	session.Login(c, user.ID)
	session.SetFlash(c, "Account created successfully!")

	return c.Redirect(http.StatusFound, "/")
}

func (h *AuthHandler) Logout(c echo.Context) error {
	session.Logout(c)
	session.SetFlash(c, "Logged out successfully")
	return c.Redirect(http.StatusFound, "/login")
}

func (h *AuthHandler) Profile(c echo.Context) error {
	if !session.IsAuthenticated(c) {
		return c.Redirect(http.StatusFound, "/login")
	}

	userID := session.GetUserIDAsUint(c)
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		session.SetFlash(c, "User not found")
		return c.Redirect(http.StatusFound, "/login")
	}

	flash := session.GetFlash(c)

	return h.inertiaSvc.Render(c, "Profile", map[string]any{
		"user":        user,
		"currentUser": user,
		"flash":       flash,
	})
}
