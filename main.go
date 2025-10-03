package main

import (
	"brx-starter-kit/handlers"
	"brx-starter-kit/internal/rbac"
	"brx-starter-kit/internal/setup"
	"brx-starter-kit/models"
	"brx-starter-kit/providers"
	"brx-starter-kit/routes"
	"brx-starter-kit/seeds"

	"github.com/tech-arch1tect/brx"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/middleware/inertiashared"
	"github.com/tech-arch1tect/brx/middleware/jwtshared"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/jwt"
	"github.com/tech-arch1tect/brx/services/refreshtoken"
	"github.com/tech-arch1tect/brx/services/revocation"
	"github.com/tech-arch1tect/brx/services/totp"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

func main() {
	var cfg StarterKitConfig
	if err := config.LoadConfig(&cfg); err != nil {
		panic(err)
	}

	app, err := brx.NewApp().
		WithConfig(&cfg.Config).
		WithMail().
		WithDatabase(
			&models.User{}, &models.Role{}, &models.Permission{},
			&session.UserSession{}, &totp.TOTPSecret{}, &totp.UsedCode{},
			&auth.PasswordResetToken{}, &auth.EmailVerificationToken{}, &auth.RememberMeToken{},
			&revocation.RevokedToken{}, &refreshtoken.RefreshToken{},
		).
		WithSessions().
		WithInertia().
		WithAuth().
		WithTOTP().
		WithJWT().
		WithJWTRevocation().
		WithFxOptions(
			jwt.Options,
			fx.Provide(rbac.NewService),
			fx.Provide(rbac.NewMiddleware),
			fx.Provide(rbac.NewRBACHandler),
			fx.Provide(rbac.NewAPIHandler),
			fx.Provide(setup.NewService),
			fx.Provide(setup.NewHandler),
			fx.Provide(handlers.NewDashboardHandler),
			fx.Provide(handlers.NewAuthHandler),
			fx.Provide(handlers.NewMobileAuthHandler),
			fx.Provide(handlers.NewSessionHandler),
			fx.Provide(handlers.NewTOTPHandler),
			fx.Provide(fx.Annotate(
				providers.NewUserProvider,
				fx.As(new(inertiashared.UserProvider)),
			)),
			fx.Provide(fx.Annotate(
				providers.NewUserProvider,
				fx.As(new(jwtshared.UserProvider)),
			)),
			fx.Invoke(routes.RegisterRoutes),
			fx.Invoke(func(db *gorm.DB) {
				if err := seeds.SeedRBACData(db); err != nil {
					panic(err)
				}
			}),
		).
		Build()

	if err != nil {
		panic(err)
	}

	app.Run()
}
