package routes

import (
	"net/http"
	"time"

	"brx-starter-kit/handlers"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/middleware/csrf"
	"github.com/tech-arch1tect/brx/middleware/inertiacsrf"
	"github.com/tech-arch1tect/brx/middleware/ratelimit"
	"github.com/tech-arch1tect/brx/server"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/session"
)

func RegisterRoutes(srv *server.Server, dashboardHandler *handlers.DashboardHandler, authHandler *handlers.AuthHandler, sessionHandler *handlers.SessionHandler, totpHandler *handlers.TOTPHandler, sessionManager *session.Manager, sessionService session.SessionService, rateLimitStore ratelimit.Store, inertiaService *inertia.Service, cfg *config.Config) {
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

	// Web routes group (requires CSRF protection)
	web := srv.Group("")
	if cfg.CSRF.Enabled {
		web.Use(csrf.WithConfig(&cfg.CSRF))
		web.Use(inertiacsrf.Middleware(cfg))
	}

	// Authentication route group with rate limiting
	auth := web.Group("/auth")
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

	// Email verification routes
	auth.GET("/verify-email", authHandler.ShowVerifyEmail)
	auth.POST("/verify-email", authHandler.VerifyEmail)
	auth.POST("/resend-verification", authHandler.ResendVerification)

	// TOTP verification routes (for already authenticated users) - with stricter rate limiting
	totpRateLimit := ratelimit.WithConfig(&ratelimit.Config{
		Store:        rateLimitStore,
		Rate:         3,
		Period:       time.Minute,
		CountMode:    config.CountFailures,
		KeyGenerator: ratelimit.SecureKeyGenerator,
	})

	auth.GET("/totp/verify", totpHandler.ShowVerify)
	auth.POST("/totp/verify", totpHandler.VerifyTOTP, totpRateLimit)

	// Protected routes group (requires auth + TOTP if user has TOTP enabled)
	protected := web.Group("")
	protected.Use(session.RequireAuthWeb("/auth/login"))
	protected.Use(session.RequireTOTPWeb("/auth/totp/verify"))

	// Application routes
	protected.GET("/", dashboardHandler.Dashboard)
	protected.GET("/profile", authHandler.Profile)

	// TOTP management routes
	protected.GET("/auth/totp/setup", totpHandler.ShowSetup)
	protected.POST("/auth/totp/enable", totpHandler.EnableTOTP)
	protected.POST("/auth/totp/disable", totpHandler.DisableTOTP)
	protected.GET("/api/totp/status", totpHandler.GetTOTPStatus)

	// Session management routes
	if sessionHandler != nil {
		protected.GET("/sessions", sessionHandler.Sessions)
		protected.POST("/sessions/revoke", sessionHandler.RevokeSession)
		protected.POST("/sessions/revoke-all-others", sessionHandler.RevokeAllOtherSessions)
	}
}
