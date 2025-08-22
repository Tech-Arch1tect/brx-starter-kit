package rbac

import (
	"brx-starter-kit/models"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/session"
	"gorm.io/gorm"
)

type Handler struct {
	db         *gorm.DB
	inertiaSvc *inertia.Service
	rbac       *Service
}

func NewHandler(db *gorm.DB, inertiaSvc *inertia.Service, rbac *Service) *Handler {
	return &Handler{
		db:         db,
		inertiaSvc: inertiaSvc,
		rbac:       rbac,
	}
}

func (h *Handler) ListUsers(c echo.Context) error {
	var users []models.User
	if err := h.db.Preload("Roles").Find(&users).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch users")
	}

	return h.inertiaSvc.Render(c, "Admin/Users", map[string]any{
		"title": "User Management",
		"users": users,
	})
}

func (h *Handler) ShowUserRoles(c echo.Context) error {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user ID")
	}

	var user models.User
	if err := h.db.Preload("Roles").First(&user, uint(userID)).Error; err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	var allRoles []models.Role
	if err := h.db.Find(&allRoles).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch roles")
	}

	return h.inertiaSvc.Render(c, "Admin/UserRoles", map[string]any{
		"title":    "Manage User Roles",
		"user":     user,
		"allRoles": allRoles,
	})
}

func (h *Handler) AssignRole(c echo.Context) error {
	var req struct {
		UserID uint `json:"user_id"`
		RoleID uint `json:"role_id"`
	}

	if err := c.Bind(&req); err != nil {
		session.AddFlashError(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/admin/users")
	}

	if err := h.rbac.AssignRole(req.UserID, req.RoleID); err != nil {
		session.AddFlashError(c, "Failed to assign role")
		return c.Redirect(http.StatusFound, "/admin/users")
	}

	session.AddFlashSuccess(c, "Role assigned successfully")
	return c.Redirect(http.StatusFound, "/admin/users/"+strconv.Itoa(int(req.UserID))+"/roles")
}

func (h *Handler) RevokeRole(c echo.Context) error {
	var req struct {
		UserID uint `json:"user_id"`
		RoleID uint `json:"role_id"`
	}

	if err := c.Bind(&req); err != nil {
		session.AddFlashError(c, "Invalid request")
		return c.Redirect(http.StatusFound, "/admin/users")
	}

	if err := h.rbac.RevokeRole(req.UserID, req.RoleID); err != nil {
		session.AddFlashError(c, "Failed to revoke role")
		return c.Redirect(http.StatusFound, "/admin/users")
	}

	session.AddFlashSuccess(c, "Role revoked successfully")
	return c.Redirect(http.StatusFound, "/admin/users/"+strconv.Itoa(int(req.UserID))+"/roles")
}

func (h *Handler) ListRoles(c echo.Context) error {
	var roles []models.Role
	if err := h.db.Preload("Permissions").Find(&roles).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch roles")
	}

	return h.inertiaSvc.Render(c, "Admin/Roles", map[string]any{
		"title": "Role Management",
		"roles": roles,
	})
}

func (h *Handler) ListPermissions(c echo.Context) error {
	var permissions []models.Permission
	if err := h.db.Find(&permissions).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch permissions")
	}

	return h.inertiaSvc.Render(c, "Admin/Permissions", map[string]any{
		"title":       "Permission Management",
		"permissions": permissions,
	})
}

func NewRBACHandler(db *gorm.DB, inertiaSvc *inertia.Service, rbacSvc *Service) *Handler {
	return NewHandler(db, inertiaSvc, rbacSvc)
}
