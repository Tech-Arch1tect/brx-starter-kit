package handlers

import (
	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
	"github.com/tech-arch1tect/brx/services/inertia"
)

type DashboardHandler struct {
	inertiaSvc *inertia.Service
}

func NewDashboardHandler(inertiaSvc *inertia.Service) *DashboardHandler {
	return &DashboardHandler{
		inertiaSvc: inertiaSvc,
	}
}

func (h *DashboardHandler) Dashboard(c echo.Context) error {
	return h.inertiaSvc.Render(c, "Dashboard", gonertia.Props{
		"title": "Dashboard",
	})
}
