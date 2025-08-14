package routes

import (
	"net/http"
	"time"

	"brx-starter-kit/handlers"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/middleware/ratelimit"
	"github.com/tech-arch1tect/brx/server"
	"github.com/tech-arch1tect/brx/session"
)

func RegisterRoutes(srv *server.Server, dashboardHandler *handlers.DashboardHandler, authHandler *handlers.AuthHandler, sessionManager *session.Manager, rateLimitStore ratelimit.Store) {
	e := srv.Echo()
	e.Use(session.Middleware(sessionManager))

	// Static file serving for Vite assets
	srv.Get("/build/*", echo.WrapHandler(http.StripPrefix("/build/", http.FileServer(http.Dir("public/build")))))

	// Authentication routes with rate limiting
	authRateLimit := ratelimit.WithConfig(&ratelimit.Config{
		Store:        rateLimitStore,
		Rate:         5,
		Period:       time.Minute,
		CountMode:    config.CountFailures,
		KeyGenerator: ratelimit.SecureKeyGenerator,
	})

	srv.Get("/login", authHandler.ShowLogin)
	srv.Post("/login", authHandler.Login, authRateLimit)
	srv.Get("/register", authHandler.ShowRegister)
	srv.Post("/register", authHandler.Register, authRateLimit)
	srv.Post("/logout", authHandler.Logout)
	srv.Get("/profile", authHandler.Profile)

	// Protected application routes
	srv.Get("/", dashboardHandler.Dashboard)
}
