package permission

import (
	"fmt"
	"sort"

	"gorm.io/gorm"
)

// GetRoles returns roles assigned to model.
func (m *Manager) GetRoles(model Authorizable) ([]Role, error) {
	ref, err := m.resolveModel(model)
	if err != nil {
		return nil, err
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	var roles []Role
	err = db.Table("roles").
		Joins("JOIN model_has_roles ON model_has_roles.role_id = roles.id").
		Where("model_has_roles.model_type = ? AND model_has_roles.model_id = ?", ref.Type, ref.ID).
		Where("roles.guard_name = ?", ref.Guard).
		Find(&roles).Error
	return roles, err
}

// GetDirectPermissions returns permissions assigned directly to model.
func (m *Manager) GetDirectPermissions(model Authorizable) ([]Permission, error) {
	ref, err := m.resolveModel(model)
	if err != nil {
		return nil, err
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	var perms []Permission
	err = db.Table("permissions").
		Joins("JOIN model_has_permissions ON model_has_permissions.permission_id = permissions.id").
		Where("model_has_permissions.model_type = ? AND model_has_permissions.model_id = ?", ref.Type, ref.ID).
		Where("permissions.guard_name = ?", ref.Guard).
		Find(&perms).Error
	return perms, err
}

// GetPermissionsViaRoles returns permissions inherited through roles.
func (m *Manager) GetPermissionsViaRoles(model Authorizable) ([]Permission, error) {
	ref, err := m.resolveModel(model)
	if err != nil {
		return nil, err
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	var perms []Permission
	err = db.Raw(`
		SELECT DISTINCT permissions.*
		FROM permissions
		JOIN role_has_permissions ON role_has_permissions.permission_id = permissions.id
		JOIN model_has_roles ON model_has_roles.role_id = role_has_permissions.role_id
		JOIN roles ON roles.id = model_has_roles.role_id
		WHERE model_has_roles.model_type = ? AND model_has_roles.model_id = ?
		  AND permissions.guard_name = ?
		  AND roles.guard_name = ?
	`, ref.Type, ref.ID, ref.Guard, ref.Guard).Scan(&perms).Error
	return perms, err
}

// GetAllPermissions returns the union of direct and role permissions,
// sorted by permission ID ascending.
func (m *Manager) GetAllPermissions(model Authorizable) ([]Permission, error) {
	direct, err := m.GetDirectPermissions(model)
	if err != nil {
		return nil, err
	}
	viaRoles, err := m.GetPermissionsViaRoles(model)
	if err != nil {
		return nil, err
	}
	byID := make(map[uint64]Permission, len(direct)+len(viaRoles))
	for _, p := range direct {
		byID[p.ID] = p
	}
	for _, p := range viaRoles {
		byID[p.ID] = p
	}
	out := make([]Permission, 0, len(byID))
	for _, p := range byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// HasRole reports whether model has the given role name.
func (m *Manager) HasRole(model Authorizable, roleName string) (bool, error) {
	if roleName == "" {
		return false, fmt.Errorf("%w: role name is empty", ErrInvalidArgument)
	}
	ref, err := m.resolveModel(model)
	if err != nil {
		return false, err
	}
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	var count int64
	err = db.Table("model_has_roles").
		Joins("JOIN roles ON roles.id = model_has_roles.role_id").
		Where("model_has_roles.model_type = ? AND model_has_roles.model_id = ?", ref.Type, ref.ID).
		Where("roles.name = ? AND roles.guard_name = ?", roleName, ref.Guard).
		Count(&count).Error
	return count > 0, err
}

// HasAnyRole reports whether model has at least one of the given roles.
func (m *Manager) HasAnyRole(model Authorizable, roleNames ...string) (bool, error) {
	names, err := normalizeNames(roleNames)
	if err != nil {
		return false, err
	}
	ref, err := m.resolveModel(model)
	if err != nil {
		return false, err
	}
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	var count int64
	err = db.Table("model_has_roles").
		Joins("JOIN roles ON roles.id = model_has_roles.role_id").
		Where("model_has_roles.model_type = ? AND model_has_roles.model_id = ?", ref.Type, ref.ID).
		Where("roles.name IN ? AND roles.guard_name = ?", names, ref.Guard).
		Count(&count).Error
	return count > 0, err
}

// HasAllRoles reports whether model has every given role.
func (m *Manager) HasAllRoles(model Authorizable, roleNames ...string) (bool, error) {
	names, err := normalizeNames(roleNames)
	if err != nil {
		return false, err
	}
	ref, err := m.resolveModel(model)
	if err != nil {
		return false, err
	}
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	var matched []string
	err = db.Table("roles").
		Joins("JOIN model_has_roles ON model_has_roles.role_id = roles.id").
		Where("model_has_roles.model_type = ? AND model_has_roles.model_id = ?", ref.Type, ref.ID).
		Where("roles.name IN ? AND roles.guard_name = ?", names, ref.Guard).
		Pluck("roles.name", &matched).Error
	if err != nil {
		return false, err
	}
	found := make(map[string]struct{}, len(matched))
	for _, name := range matched {
		found[name] = struct{}{}
	}
	for _, name := range names {
		if _, ok := found[name]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// HasDirectPermission reports whether model was given the permission directly.
func (m *Manager) HasDirectPermission(model Authorizable, permissionName string) (bool, error) {
	if permissionName == "" {
		return false, fmt.Errorf("%w: permission name is empty", ErrInvalidArgument)
	}
	ref, err := m.resolveModel(model)
	if err != nil {
		return false, err
	}
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	return m.hasDirectPermission(db, ref, permissionName)
}

func (m *Manager) hasDirectPermission(db *gorm.DB, ref modelRef, permissionName string) (bool, error) {
	var count int64
	err := db.Table("model_has_permissions").
		Joins("JOIN permissions ON permissions.id = model_has_permissions.permission_id").
		Where("model_has_permissions.model_type = ? AND model_has_permissions.model_id = ?", ref.Type, ref.ID).
		Where("permissions.name = ? AND permissions.guard_name = ?", permissionName, ref.Guard).
		Count(&count).Error
	return count > 0, err
}

// HasPermissionTo reports whether model may perform permission via direct
// assignment or through any of its roles (Spatie default behaviour).
func (m *Manager) HasPermissionTo(model Authorizable, permissionName string) (bool, error) {
	if permissionName == "" {
		return false, fmt.Errorf("%w: permission name is empty", ErrInvalidArgument)
	}
	ref, err := m.resolveModel(model)
	if err != nil {
		return false, err
	}
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	ok, err := m.hasDirectPermission(db, ref, permissionName)
	if err != nil || ok {
		return ok, err
	}
	var count int64
	err = db.Table("role_has_permissions").
		Joins("JOIN permissions ON permissions.id = role_has_permissions.permission_id").
		Joins("JOIN model_has_roles ON model_has_roles.role_id = role_has_permissions.role_id").
		Joins("JOIN roles ON roles.id = model_has_roles.role_id").
		Where("model_has_roles.model_type = ? AND model_has_roles.model_id = ?", ref.Type, ref.ID).
		Where("permissions.name = ? AND permissions.guard_name = ?", permissionName, ref.Guard).
		Where("roles.guard_name = ?", ref.Guard).
		Count(&count).Error
	return count > 0, err
}

// HasAnyPermission reports whether model has at least one of the permissions.
func (m *Manager) HasAnyPermission(model Authorizable, permissionNames ...string) (bool, error) {
	names, err := normalizeNames(permissionNames)
	if err != nil {
		return false, err
	}
	ref, err := m.resolveModel(model)
	if err != nil {
		return false, err
	}
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	var count int64
	err = db.Table("model_has_permissions").
		Joins("JOIN permissions ON permissions.id = model_has_permissions.permission_id").
		Where("model_has_permissions.model_type = ? AND model_has_permissions.model_id = ?", ref.Type, ref.ID).
		Where("permissions.name IN ? AND permissions.guard_name = ?", names, ref.Guard).
		Count(&count).Error
	if err != nil || count > 0 {
		return count > 0, err
	}
	err = db.Table("role_has_permissions").
		Joins("JOIN permissions ON permissions.id = role_has_permissions.permission_id").
		Joins("JOIN model_has_roles ON model_has_roles.role_id = role_has_permissions.role_id").
		Joins("JOIN roles ON roles.id = model_has_roles.role_id").
		Where("model_has_roles.model_type = ? AND model_has_roles.model_id = ?", ref.Type, ref.ID).
		Where("permissions.name IN ? AND permissions.guard_name = ?", names, ref.Guard).
		Where("roles.guard_name = ?", ref.Guard).
		Count(&count).Error
	return count > 0, err
}

// HasAllPermissions reports whether model has every given permission.
func (m *Manager) HasAllPermissions(model Authorizable, permissionNames ...string) (bool, error) {
	names, err := normalizeNames(permissionNames)
	if err != nil {
		return false, err
	}
	ref, err := m.resolveModel(model)
	if err != nil {
		return false, err
	}
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	var matched []string
	err = db.Raw(`
		SELECT DISTINCT name FROM (
			SELECT permissions.name AS name
			FROM permissions
			JOIN model_has_permissions ON model_has_permissions.permission_id = permissions.id
			WHERE model_has_permissions.model_type = ? AND model_has_permissions.model_id = ?
			  AND permissions.name IN ? AND permissions.guard_name = ?
			UNION
			SELECT permissions.name AS name
			FROM permissions
			JOIN role_has_permissions ON role_has_permissions.permission_id = permissions.id
			JOIN model_has_roles ON model_has_roles.role_id = role_has_permissions.role_id
			JOIN roles ON roles.id = model_has_roles.role_id
			WHERE model_has_roles.model_type = ? AND model_has_roles.model_id = ?
			  AND permissions.name IN ? AND permissions.guard_name = ?
			  AND roles.guard_name = ?
		) AS matched_permissions
	`, ref.Type, ref.ID, names, ref.Guard,
		ref.Type, ref.ID, names, ref.Guard, ref.Guard).Scan(&matched).Error
	if err != nil {
		return false, err
	}
	found := make(map[string]struct{}, len(matched))
	for _, name := range matched {
		found[name] = struct{}{}
	}
	for _, name := range names {
		if _, ok := found[name]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// Can is an alias for HasPermissionTo.
func (m *Manager) Can(model Authorizable, permissionName string) (bool, error) {
	return m.HasPermissionTo(model, permissionName)
}

// RoleHasPermission reports whether a role owns a permission by name.
func (m *Manager) RoleHasPermission(role *Role, permissionName string) (bool, error) {
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	role, err = m.loadRole(db, role)
	if err != nil {
		return false, err
	}
	if permissionName == "" {
		return false, fmt.Errorf("%w: permission name is empty", ErrInvalidArgument)
	}
	var count int64
	err = db.Table("role_has_permissions").
		Joins("JOIN permissions ON permissions.id = role_has_permissions.permission_id").
		Where("role_has_permissions.role_id = ?", role.ID).
		Where("permissions.name = ? AND permissions.guard_name = ?", permissionName, role.GuardName).
		Count(&count).Error
	return count > 0, err
}

// GetRolePermissions returns permissions attached to a role.
func (m *Manager) GetRolePermissions(role *Role) ([]Permission, error) {
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	role, err = m.loadRole(db, role)
	if err != nil {
		return nil, err
	}
	var perms []Permission
	err = db.Table("permissions").
		Joins("JOIN role_has_permissions ON role_has_permissions.permission_id = permissions.id").
		Where("role_has_permissions.role_id = ?", role.ID).
		Where("permissions.guard_name = ?", role.GuardName).
		Find(&perms).Error
	return perms, err
}
