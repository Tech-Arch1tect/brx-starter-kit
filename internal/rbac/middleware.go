package rbac

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/session"
)

type Middleware struct {
	rbac *Service
}

func NewMiddleware(rbac *Service) *Middleware {
	return &Middleware{
		rbac: rbac,
	}
}

func (m *Middleware) RequireRole(roleName string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !session.IsAuthenticated(c) {
				return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
			}

			userID := session.GetUserID(c)
			if userID == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid session")
			}

			userIDUint, ok := userID.(uint)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid user ID")
			}

			hasRole, err := m.rbac.HasRole(userIDUint, roleName)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to check role")
			}

			if !hasRole {
				return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions")
			}

			return next(c)
		}
	}
}

func (m *Middleware) RequirePermission(resource, action string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !session.IsAuthenticated(c) {
				return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
			}

			userID := session.GetUserID(c)
			if userID == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid session")
			}

			userIDUint, ok := userID.(uint)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid user ID")
			}

			hasPermission, err := m.rbac.HasPermission(userIDUint, resource, action)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to check permission")
			}

			if !hasPermission {
				return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions")
			}

			return next(c)
		}
	}
}

func (m *Middleware) RequirePermissionByName(permissionName string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !session.IsAuthenticated(c) {
				return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
			}

			userID := session.GetUserID(c)
			if userID == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid session")
			}

			userIDUint, ok := userID.(uint)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid user ID")
			}

			hasPermission, err := m.rbac.HasPermissionByName(userIDUint, permissionName)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to check permission")
			}

			if !hasPermission {
				return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions")
			}

			return next(c)
		}
	}
}
