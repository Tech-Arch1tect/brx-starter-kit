package routes

import (
	"net/http"
	"time"

	"brx-starter-kit/handlers"
	"brx-starter-kit/internal/rbac"
	"brx-starter-kit/internal/setup"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/middleware/csrf"
	"github.com/tech-arch1tect/brx/middleware/inertiacsrf"
	"github.com/tech-arch1tect/brx/middleware/jwt"
	"github.com/tech-arch1tect/brx/middleware/jwtshared"
	"github.com/tech-arch1tect/brx/middleware/ratelimit"
	"github.com/tech-arch1tect/brx/middleware/rememberme"
	"github.com/tech-arch1tect/brx/server"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/inertia"
	jwtservice "github.com/tech-arch1tect/brx/services/jwt"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/services/totp"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/fx"
)

type RegisterRoutesParams struct {
	fx.In

	Server         *server.Server
	Dashboard      *handlers.DashboardHandler
	Auth           *handlers.AuthHandler
	MobileAuth     *handlers.MobileAuthHandler
	SessionHandler *handlers.SessionHandler `optional:"true"`
	TOTPHandler    *handlers.TOTPHandler
	RBACHandler    *rbac.Handler    `optional:"true"`
	RBACAPIHandler *rbac.APIHandler `optional:"true"`
	RBACMiddleware *rbac.Middleware `optional:"true"`
	SetupHandler   *setup.Handler   `optional:"true"`
	SessionManager *session.Manager
	SessionService session.SessionService `optional:"true"`
	RateLimitStore ratelimit.Store
	Inertia        *inertia.Service
	JWTService     *jwtservice.Service    `optional:"true"`
	UserProvider   jwtshared.UserProvider `optional:"true"`
	AuthService    *auth.Service          `optional:"true"`
	TOTPService    *totp.Service          `optional:"true"`
	Logger         *logging.Service       `optional:"true"`
	Config         *config.Config
}

func RegisterRoutes(params RegisterRoutesParams) {
	e := params.Server.Echo()
	e.Use(session.Middleware(params.SessionManager))

	// Add session service middleware if available
	if params.SessionService != nil {
		e.Use(session.SessionServiceMiddleware(params.SessionService))
	}

	// Setup custom error handler for better 404/error handling
	handlers.SetupErrorHandler(e, params.Inertia)

	// Static file serving for Vite assets
	params.Server.Get("/build/*", echo.WrapHandler(http.StripPrefix("/build/", http.FileServer(http.Dir("public/build")))))

	// Setup routes (no authentication required)
	if params.SetupHandler != nil {
		params.Server.Get("/setup/admin", params.SetupHandler.ShowSetup)
		params.Server.Post("/setup/admin", params.SetupHandler.CreateAdmin)
	}

	// Web routes group (requires CSRF protection)
	web := params.Server.Group("")
	if params.Config.CSRF.Enabled {
		web.Use(csrf.WithConfig(&params.Config.CSRF))
		web.Use(inertiacsrf.Middleware(params.Config))
	}

	// Authentication route group with rate limiting
	auth := web.Group("/auth")
	authRateLimit := ratelimit.WithConfig(&ratelimit.Config{
		Store:        params.RateLimitStore,
		Rate:         5,
		Period:       time.Minute,
		CountMode:    config.CountFailures,
		KeyGenerator: ratelimit.SecureKeyGenerator,
	})
	auth.Use(authRateLimit)

	// Authentication routes (all inherit rate limiting from group)
	auth.GET("/login", params.Auth.ShowLogin)
	auth.POST("/login", params.Auth.Login)
	auth.GET("/register", params.Auth.ShowRegister)
	auth.POST("/register", params.Auth.Register)
	auth.POST("/logout", params.Auth.Logout)

	// Password reset routes
	auth.GET("/password-reset", params.Auth.ShowPasswordReset)
	auth.POST("/password-reset", params.Auth.RequestPasswordReset)
	auth.GET("/password-reset/confirm", params.Auth.ShowPasswordResetConfirm)
	auth.POST("/password-reset/confirm", params.Auth.ConfirmPasswordReset)

	// Email verification routes
	auth.GET("/verify-email", params.Auth.ShowVerifyEmail)
	auth.POST("/verify-email", params.Auth.VerifyEmail)
	auth.POST("/resend-verification", params.Auth.ResendVerification)

	// TOTP verification routes (for already authenticated users) - with stricter rate limiting
	totpRateLimit := ratelimit.WithConfig(&ratelimit.Config{
		Store:        params.RateLimitStore,
		Rate:         3,
		Period:       time.Minute,
		CountMode:    config.CountFailures,
		KeyGenerator: ratelimit.SecureKeyGenerator,
	})

	auth.GET("/totp/verify", params.TOTPHandler.ShowVerify)
	auth.POST("/totp/verify", params.TOTPHandler.VerifyTOTP, totpRateLimit)

	// Protected routes group (requires auth + TOTP if user has TOTP enabled)
	protected := web.Group("")
	protected.Use(rememberme.Middleware(rememberme.Config{
		AuthService:  params.AuthService,
		UserProvider: params.UserProvider,
		TOTPService:  params.TOTPService,
		Logger:       params.Logger,
	}))
	protected.Use(session.RequireAuthWeb("/auth/login"))
	protected.Use(session.RequireTOTPWeb("/auth/totp/verify"))

	// Application routes
	protected.GET("/", params.Dashboard.Dashboard)
	protected.GET("/profile", params.Auth.Profile)

	// TOTP management routes
	protected.GET("/auth/totp/setup", params.TOTPHandler.ShowSetup)
	protected.POST("/auth/totp/enable", params.TOTPHandler.EnableTOTP)
	protected.POST("/auth/totp/disable", params.TOTPHandler.DisableTOTP)
	protected.GET("/api/totp/status", params.TOTPHandler.GetTOTPStatus)

	// Session management routes
	if params.SessionHandler != nil {
		protected.GET("/sessions", params.SessionHandler.Sessions)
		protected.POST("/sessions/revoke", params.SessionHandler.RevokeSession)
		protected.POST("/sessions/revoke-all-others", params.SessionHandler.RevokeAllOtherSessions)
	}

	// Admin routes - require admin role
	if params.RBACHandler != nil && params.RBACMiddleware != nil {
		admin := protected.Group("/admin")
		admin.Use(params.RBACMiddleware.RequireRole("admin"))

		// User management
		admin.GET("/users", params.RBACHandler.ListUsers)
		admin.GET("/users/:id/roles", params.RBACHandler.ShowUserRoles)
		admin.POST("/users/assign-role", params.RBACHandler.AssignRole)
		admin.POST("/users/revoke-role", params.RBACHandler.RevokeRole)

		// Role management
		admin.GET("/roles", params.RBACHandler.ListRoles)
	}

	// JWT authentication api routes - for non-web clients (flutter)
	if params.MobileAuth != nil && params.JWTService != nil {
		api := params.Server.Group("/api/v1")

		// API rate limiting
		apiRateLimit := ratelimit.WithConfig(&ratelimit.Config{
			Store:        params.RateLimitStore,
			Rate:         50,
			Period:       time.Minute * 3,
			CountMode:    config.CountAll,
			KeyGenerator: ratelimit.DefaultKeyGenerator,
		})
		api.Use(apiRateLimit)

		// Public API routes
		api.POST("/auth/login", params.MobileAuth.Login)
		api.POST("/auth/register", params.MobileAuth.Register)
		api.POST("/auth/refresh", params.MobileAuth.RefreshToken)
		api.POST("/auth/totp/verify", params.MobileAuth.VerifyTOTP)

		// Protected API routes
		apiProtected := api.Group("")
		apiProtected.Use(jwt.RequireJWT(params.JWTService))
		apiProtected.Use(jwtshared.MiddlewareWithConfig(jwtshared.Config{
			UserProvider: params.UserProvider,
		}))
		apiProtected.GET("/profile", params.MobileAuth.Profile)
		apiProtected.POST("/auth/logout", params.MobileAuth.Logout)

		// TOTP management routes
		apiProtected.GET("/totp/setup", params.MobileAuth.GetTOTPSetup)
		apiProtected.POST("/totp/enable", params.MobileAuth.EnableTOTP)
		apiProtected.POST("/totp/disable", params.MobileAuth.DisableTOTP)
		apiProtected.GET("/totp/status", params.MobileAuth.GetTOTPStatus)

		// Session management routes for JWT users
		apiProtected.POST("/sessions", params.MobileAuth.GetSessions)
		apiProtected.POST("/sessions/revoke", params.MobileAuth.RevokeSession)
		apiProtected.POST("/sessions/revoke-all-others", params.MobileAuth.RevokeAllOtherSessions)

		// RBAC routes for JWT users
		if params.RBACAPIHandler != nil && params.RBACMiddleware != nil {
			// User permission checking
			apiProtected.GET("/rbac/permissions", params.RBACAPIHandler.GetCurrentUserPermissions)
			apiProtected.POST("/rbac/check-permission", params.RBACAPIHandler.CheckPermission)

			// Admin routes - require admin role
			apiAdmin := apiProtected.Group("/admin")
			apiAdmin.Use(params.RBACMiddleware.RequireRoleJWT("admin"))

			// User management
			apiAdmin.GET("/users", params.RBACAPIHandler.ListUsers)
			apiAdmin.GET("/users/:id/roles", params.RBACAPIHandler.GetUserRoles)
			apiAdmin.POST("/users/assign-role", params.RBACAPIHandler.AssignRole)
			apiAdmin.POST("/users/revoke-role", params.RBACAPIHandler.RevokeRole)

			// Role management
			apiAdmin.GET("/roles", params.RBACAPIHandler.ListRoles)
		}
	}
}
