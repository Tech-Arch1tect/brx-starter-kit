package routes

import (
	"net/http"
	"time"

	"brx-starter-kit/handlers"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/middleware/ratelimit"
	"github.com/tech-arch1tect/brx/server"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/session"
)

func RegisterRoutes(srv *server.Server, dashboardHandler *handlers.DashboardHandler, authHandler *handlers.AuthHandler, sessionHandler *handlers.SessionHandler, sessionManager *session.Manager, sessionService session.SessionService, rateLimitStore ratelimit.Store, inertiaService *inertia.Service, cfg *config.Config) {
	e := srv.Echo()
	e.Use(session.Middleware(sessionManager))

	// Add session service middleware if available
	if sessionService != nil {
		e.Use(session.SessionServiceMiddleware(sessionService))
	}

	// Setup custom error handler for better 404/error handling
	handlers.SetupErrorHandler(e, inertiaService)

	// Static file serving for Vite assets
	srv.Get("/build/*", echo.WrapHandler(http.StripPrefix("/build/", http.FileServer(http.Dir("public/build")))))

	// Authentication route group with rate limiting
	auth := srv.Group("/auth")
	authRateLimit := ratelimit.WithConfig(&ratelimit.Config{
		Store:        rateLimitStore,
		Rate:         5,
		Period:       time.Minute,
		CountMode:    config.CountFailures,
		KeyGenerator: ratelimit.SecureKeyGenerator,
	})
	auth.Use(authRateLimit)

	// Authentication routes (all inherit rate limiting from group)
	auth.GET("/login", authHandler.ShowLogin)
	auth.POST("/login", authHandler.Login)
	auth.GET("/register", authHandler.ShowRegister)
	auth.POST("/register", authHandler.Register)
	auth.POST("/logout", authHandler.Logout)

	// Password reset routes
	auth.GET("/password-reset", authHandler.ShowPasswordReset)
	auth.POST("/password-reset", authHandler.RequestPasswordReset)
	auth.GET("/password-reset/confirm", authHandler.ShowPasswordResetConfirm)
	auth.POST("/password-reset/confirm", authHandler.ConfirmPasswordReset)

	// Protected routes group
	protected := srv.Group("")
	protected.Use(session.RequireAuthWeb("/auth/login"))

	// Protected application routes
	protected.GET("/", dashboardHandler.Dashboard)
	protected.GET("/profile", authHandler.Profile)

	// Session management routes
	if sessionHandler != nil {
		protected.GET("/sessions", sessionHandler.Sessions)
		protected.POST("/sessions/revoke", sessionHandler.RevokeSession)
		protected.POST("/sessions/revoke-all-others", sessionHandler.RevokeAllOtherSessions)
	}
}
