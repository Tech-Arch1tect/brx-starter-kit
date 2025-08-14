package routes

import (
	"net/http"

	"brx-starter-kit/handlers"
	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/server"
)

func RegisterRoutes(srv *server.Server, dashboardHandler *handlers.DashboardHandler) {
	// Static file serving for Vite assets
	srv.Get("/build/*", echo.WrapHandler(http.StripPrefix("/build/", http.FileServer(http.Dir("public/build")))))

	// Application routes
	srv.Get("/", dashboardHandler.Dashboard)
}
