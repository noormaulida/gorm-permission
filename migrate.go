package permission

import "gorm.io/gorm"

// Migrate creates Spatie-compatible permission tables when they do not exist.
// Skip this when the database already comes from Laravel Spatie migrations.
func Migrate(db *gorm.DB) error {
	if db == nil {
		return ErrInvalidArgument
	}
	return db.AutoMigrate(
		&Permission{},
		&Role{},
		&ModelHasPermission{},
		&ModelHasRole{},
		&RoleHasPermission{},
	)
}
