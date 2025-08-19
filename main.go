package main

import (
	"brx-starter-kit/handlers"
	"brx-starter-kit/models"
	"brx-starter-kit/providers"
	"brx-starter-kit/routes"

	"github.com/tech-arch1tect/brx"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/middleware/inertiashared"
	"github.com/tech-arch1tect/brx/middleware/jwtshared"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/jwt"
	"github.com/tech-arch1tect/brx/services/totp"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/fx"
)

func main() {
	var cfg config.Config
	if err := config.LoadConfig(&cfg); err != nil {
		panic(err)
	}

	brx.New(
		brx.WithConfig(&cfg),
		brx.WithMail(),
		brx.WithDatabase(&models.User{}, &session.UserSession{}, &totp.TOTPSecret{}, &totp.UsedCode{}, &auth.PasswordResetToken{}, &auth.EmailVerificationToken{}, &auth.RememberMeToken{}),
		brx.WithSessions(),
		brx.WithInertia(),
		brx.WithAuth(),
		brx.WithTOTP(),
		brx.WithJWTRevocation(),
		brx.WithFxOptions(
			jwt.Options,
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
		),
	).Run()
}
