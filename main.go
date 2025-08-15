package main

import (
	"brx-starter-kit/handlers"
	"brx-starter-kit/models"
	"brx-starter-kit/routes"

	"github.com/tech-arch1tect/brx"
	"github.com/tech-arch1tect/brx/config"
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
		brx.WithDatabase(&models.User{}),
		brx.WithSessions(),
		brx.WithInertia(),
		brx.WithAuth(),
		brx.WithFxOptions(
			fx.Provide(handlers.NewDashboardHandler),
			fx.Provide(handlers.NewAuthHandler),
			fx.Invoke(routes.RegisterRoutes),
		),
	).Run()
}
