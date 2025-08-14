package main

import (
	"net/http"

	"brx-starter-kit/handlers"
	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx"
	"github.com/tech-arch1tect/brx/config"
)

var app *brx.App

func main() {
	var cfg config.Config
	if err := config.LoadConfig(&cfg); err != nil {
		panic(err)
	}

	app = brx.New(
		brx.WithConfig(&cfg),
		brx.WithSessions(),
		brx.WithInertia(),
	)

	// Static file serving for Vite assets
	app.Get("/build/*", echo.WrapHandler(http.StripPrefix("/build/", http.FileServer(http.Dir("public/build")))))

	// Routes
	app.Get("/", handlers.DashboardHandler(app))

	app.Start()
}
