package main

import (
	"brx-starter-kit/handlers"
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
		brx.WithSessions(),
		brx.WithInertia(),
		brx.WithFxOptions(
			fx.Provide(handlers.NewDashboardHandler),
			fx.Invoke(routes.RegisterRoutes),
		),
	).Run()
}
