// Package permission provides Spatie Laravel Permission–compatible roles and
// permissions for GORM applications.
//
// It uses the same default table layout (permissions, roles,
// model_has_roles, model_has_permissions, role_has_permissions) so a Go app
// can share a database with an existing Spatie Laravel Permission install when
// morph aliases are aligned.
//
// Basic usage:
//
//	if err := permission.Migrate(db); err != nil {
//	    return err
//	}
//	perm := permission.New(db, permission.WithDefaultGuard("cms"))
//
//	role, _ := perm.FindOrCreateRole("super-administrator")
//	_, _ = perm.FindOrCreatePermission("cms.admins.view")
//	_ = perm.GivePermissionToRole(role, "cms.admins.view")
//	_ = perm.AssignRole(admin, "super-administrator")
//	ok, _ := perm.HasPermissionTo(admin, "cms.admins.view")
package permission
