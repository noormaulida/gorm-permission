package permission

import "time"

// Permission mirrors Spatie's permissions table.
type Permission struct {
	ID        uint64 `gorm:"primaryKey;autoIncrement"`
	Name      string `gorm:"size:255;not null;uniqueIndex:permissions_name_guard_name_unique"`
	GuardName string `gorm:"size:255;not null;column:guard_name;uniqueIndex:permissions_name_guard_name_unique"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName keeps Spatie's default table name.
func (Permission) TableName() string { return "permissions" }

// Role mirrors Spatie's roles table.
type Role struct {
	ID        uint64 `gorm:"primaryKey;autoIncrement"`
	Name      string `gorm:"size:255;not null;uniqueIndex:roles_name_guard_name_unique"`
	GuardName string `gorm:"size:255;not null;column:guard_name;uniqueIndex:roles_name_guard_name_unique"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName keeps Spatie's default table name.
func (Role) TableName() string { return "roles" }

// ModelHasPermission is the polymorphic direct-permission pivot.
type ModelHasPermission struct {
	PermissionID uint64 `gorm:"primaryKey;column:permission_id"`
	ModelType    string `gorm:"size:255;primaryKey;column:model_type"`
	ModelID      uint64 `gorm:"primaryKey;column:model_id;index:model_has_permissions_model_id_model_type_index"`
}

// TableName keeps Spatie's default table name.
func (ModelHasPermission) TableName() string { return "model_has_permissions" }

// ModelHasRole is the polymorphic role assignment pivot.
type ModelHasRole struct {
	RoleID    uint64 `gorm:"primaryKey;column:role_id"`
	ModelType string `gorm:"size:255;primaryKey;column:model_type"`
	ModelID   uint64 `gorm:"primaryKey;column:model_id;index:model_has_roles_model_id_model_type_index"`
}

// TableName keeps Spatie's default table name.
func (ModelHasRole) TableName() string { return "model_has_roles" }

// RoleHasPermission links roles to permissions.
type RoleHasPermission struct {
	PermissionID uint64 `gorm:"primaryKey;column:permission_id"`
	RoleID       uint64 `gorm:"primaryKey;column:role_id"`
}

// TableName keeps Spatie's default table name.
func (RoleHasPermission) TableName() string { return "role_has_permissions" }
