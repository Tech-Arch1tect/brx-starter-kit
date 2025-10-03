package seeds

import (
	"brx-starter-kit/models"
	"gorm.io/gorm"
)

func SeedRBACData(db *gorm.DB) error {
	permissions := []models.Permission{
		{Name: "users.create", Resource: "users", Action: "create", Description: "Create new users"},
		{Name: "users.read", Resource: "users", Action: "read", Description: "View user information"},
		{Name: "users.update", Resource: "users", Action: "update", Description: "Update user information"},
		{Name: "users.delete", Resource: "users", Action: "delete", Description: "Delete users"},
		{Name: "admin.access", Resource: "admin", Action: "access", Description: "Access admin panel"},
		{Name: "profile.read", Resource: "profile", Action: "read", Description: "View own profile"},
		{Name: "profile.update", Resource: "profile", Action: "update", Description: "Update own profile"},
	}

	for _, permission := range permissions {
		if err := db.Where("name = ?", permission.Name).FirstOrCreate(&permission).Error; err != nil {
			return err
		}
	}

	roles := []models.Role{
		{Name: "admin", Description: "System administrator with full access"},
		{Name: "user", Description: "Standard user with basic permissions"},
		{Name: "moderator", Description: "Content moderator with limited admin access"},
	}

	for _, role := range roles {
		if err := db.Where("name = ?", role.Name).FirstOrCreate(&role).Error; err != nil {
			return err
		}
	}

	var adminRole models.Role
	if err := db.Where("name = ?", "admin").Preload("Permissions").First(&adminRole).Error; err != nil {
		return err
	}

	if len(adminRole.Permissions) == 0 {
		var allPermissions []models.Permission
		if err := db.Find(&allPermissions).Error; err != nil {
			return err
		}
		if err := db.Model(&adminRole).Association("Permissions").Replace(allPermissions); err != nil {
			return err
		}
	}

	var userRole models.Role
	if err := db.Where("name = ?", "user").Preload("Permissions").First(&userRole).Error; err != nil {
		return err
	}

	if len(userRole.Permissions) == 0 {
		var userPermissions []models.Permission
		if err := db.Where("name IN ?", []string{"profile.read", "profile.update"}).Find(&userPermissions).Error; err != nil {
			return err
		}
		if err := db.Model(&userRole).Association("Permissions").Replace(userPermissions); err != nil {
			return err
		}
	}

	var moderatorRole models.Role
	if err := db.Where("name = ?", "moderator").Preload("Permissions").First(&moderatorRole).Error; err != nil {
		return err
	}

	if len(moderatorRole.Permissions) == 0 {
		var moderatorPermissions []models.Permission
		if err := db.Where("name IN ?", []string{"users.read", "profile.read", "profile.update"}).Find(&moderatorPermissions).Error; err != nil {
			return err
		}
		if err := db.Model(&moderatorRole).Association("Permissions").Replace(moderatorPermissions); err != nil {
			return err
		}
	}

	return nil
}
