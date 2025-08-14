package handlers

import (
	"brx-starter-kit/models"
	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/session"
	"gorm.io/gorm"
)

type DashboardHandler struct {
	inertiaSvc *inertia.Service
	db         *gorm.DB
}

func NewDashboardHandler(inertiaSvc *inertia.Service, db *gorm.DB) *DashboardHandler {
	return &DashboardHandler{
		inertiaSvc: inertiaSvc,
		db:         db,
	}
}

func (h *DashboardHandler) Dashboard(c echo.Context) error {
	var userCount int64
	h.db.Model(&models.User{}).Count(&userCount)

	userID := session.GetUserIDAsUint(c)
	var currentUser models.User
	h.db.First(&currentUser, userID)

	flash := session.GetFlash(c)

	return h.inertiaSvc.Render(c, "Dashboard", gonertia.Props{
		"title":       "Dashboard",
		"userCount":   userCount,
		"currentUser": currentUser,
		"flash":       flash,
	})
}
