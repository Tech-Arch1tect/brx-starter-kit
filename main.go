package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
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

	// Flash message demo routes
	app.Get("/", flashDemoHandler)
	app.Post("/flash/success", flashSuccessHandler)
	app.Post("/flash/error", flashErrorHandler)
	app.Post("/flash/warning", flashWarningHandler)
	app.Post("/flash/basic", flashBasicHandler)

	app.Start()
}

// Flash demo handlers
func flashDemoHandler(c echo.Context) error {
	return renderInertia(c, "FlashDemo", gonertia.Props{
		"title":       "Flash Messages Demo",
		"description": "Test different types of flash messages with brx and Inertia.js integration",
	})
}

func flashSuccessHandler(c echo.Context) error {
	// Use Gonertia's built-in validation error system for flash messages
	ctx := gonertia.SetValidationError(c.Request().Context(), "success", "Operation completed successfully!")
	c.SetRequest(c.Request().WithContext(ctx))

	return app.InertiaService().Redirect(c, "/")
}

func flashErrorHandler(c echo.Context) error {
	// Use Gonertia's built-in validation error system
	ctx := gonertia.SetValidationErrors(c.Request().Context(), gonertia.ValidationErrors{
		"email": "Email is required and must be valid",
		"name":  "Name is required",
	})
	c.SetRequest(c.Request().WithContext(ctx))

	return app.InertiaService().Redirect(c, "/")
}

func flashWarningHandler(c echo.Context) error {
	// Use a custom validation error for warning
	ctx := gonertia.SetValidationError(c.Request().Context(), "warning", "This action cannot be undone. Please proceed with caution.")
	c.SetRequest(c.Request().WithContext(ctx))

	return app.InertiaService().Redirect(c, "/")
}

func flashBasicHandler(c echo.Context) error {
	// Use a custom validation error for basic flash
	ctx := gonertia.SetValidationError(c.Request().Context(), "flash", "This is a basic flash message!")
	c.SetRequest(c.Request().WithContext(ctx))

	return app.InertiaService().Redirect(c, "/")
}

// Helper function to render Inertia responses
func renderInertia(c echo.Context, component string, props gonertia.Props) error {
	return app.InertiaService().Render(c, component, props)
}
