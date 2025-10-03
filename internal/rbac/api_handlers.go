package rbac

import (
	"brx-starter-kit/internal/dto"
	"brx-starter-kit/models"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/middleware/jwtshared"
	"gorm.io/gorm"
)

type APIHandler struct {
	db      *gorm.DB
	rbacSvc *Service
}

func NewAPIHandler(db *gorm.DB, rbacSvc *Service) *APIHandler {
	return &APIHandler{
		db:      db,
		rbacSvc: rbacSvc,
	}
}

func (h *APIHandler) ListUsers(c echo.Context) error {
	var users []models.User
	if err := h.db.Preload("Roles").Find(&users).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch users",
		})
	}

	userInfos := make([]dto.UserInfo, len(users))
	for i, user := range users {
		userInfos[i] = dto.ConvertUserToUserInfo(user)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"users": userInfos,
	})
}

func (h *APIHandler) GetUserRoles(c echo.Context) error {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{
			"error": "Invalid user ID",
		})
	}

	var user models.User
	if err := h.db.Preload("Roles").First(&user, uint(userID)).Error; err != nil {
		return echo.NewHTTPError(http.StatusNotFound, map[string]string{
			"error": "User not found",
		})
	}

	var allRoles []models.Role
	if err := h.db.Find(&allRoles).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch roles",
		})
	}

	userInfo := dto.ConvertUserToUserInfo(user)

	roleInfos := make([]dto.RoleInfo, len(allRoles))
	for i, role := range allRoles {
		roleInfos[i] = dto.RoleInfo{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
		}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"user":      userInfo,
		"all_roles": roleInfos,
	})
}

func (h *APIHandler) AssignRole(c echo.Context) error {
	var req struct {
		UserID uint `json:"user_id"`
		RoleID uint `json:"role_id"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if err := h.rbacSvc.AssignRole(req.UserID, req.RoleID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Failed to assign role",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Role assigned successfully",
	})
}

func (h *APIHandler) RevokeRole(c echo.Context) error {
	var req struct {
		UserID uint `json:"user_id"`
		RoleID uint `json:"role_id"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if err := h.rbacSvc.RevokeRole(req.UserID, req.RoleID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Failed to revoke role",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Role revoked successfully",
	})
}

func (h *APIHandler) ListRoles(c echo.Context) error {
	var roles []models.Role
	if err := h.db.Preload("Permissions").Find(&roles).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch roles",
		})
	}

	// Convert to consistent DTO format
	roleInfos := make([]dto.RoleWithPermissions, len(roles))
	for i, role := range roles {
		roleInfos[i] = dto.ConvertRoleToRoleWithPermissions(role)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"roles": roleInfos,
	})
}

func (h *APIHandler) GetCurrentUserPermissions(c echo.Context) error {
	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{
			"error": "User not found in context",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Invalid user type",
		})
	}

	roles, err := h.rbacSvc.GetUserRoles(userModel.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user roles",
		})
	}

	permissions, err := h.rbacSvc.GetUserPermissions(userModel.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user permissions",
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"roles":       roles,
		"permissions": permissions,
	})
}

func (h *APIHandler) CheckPermission(c echo.Context) error {
	var req struct {
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	user := jwtshared.GetCurrentUser(c)
	if user == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{
			"error": "User not found in context",
		})
	}

	userModel, ok := user.(models.User)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Invalid user type",
		})
	}

	hasPermission, err := h.rbacSvc.HasPermission(userModel.ID, req.Resource, req.Action)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
			"error": "Failed to check permission",
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"has_permission": hasPermission,
		"resource":       req.Resource,
		"action":         req.Action,
	})
}
