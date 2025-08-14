package handlers

import (
	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
	"github.com/tech-arch1tect/brx"
)

func DashboardHandler(app *brx.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		return app.InertiaService().Render(c, "Dashboard", gonertia.Props{
			"title": "Dashboard",
		})
	}
}
