package permission

import (
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AssignRole attaches one or more roles to model (by role name).
func (m *Manager) AssignRole(model Authorizable, roleNames ...string) error {
	ref, err := m.resolveModel(model)
	if err != nil {
		return err
	}
	return m.tx(func(tx *gorm.DB) error {
		roles, err := m.resolveRoles(tx, ref.Guard, roleNames)
		if err != nil {
			return err
		}
		for _, role := range roles {
			if role.GuardName != ref.Guard {
				return fmt.Errorf("%w: role %q has guard %q, model expects %q",
					ErrGuardMismatch, role.Name, role.GuardName, ref.Guard)
			}
			row := ModelHasRole{RoleID: role.ID, ModelType: ref.Type, ModelID: ref.ID}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// RemoveRole detaches one or more roles from model.
func (m *Manager) RemoveRole(model Authorizable, roleNames ...string) error {
	ref, err := m.resolveModel(model)
	if err != nil {
		return err
	}
	return m.tx(func(tx *gorm.DB) error {
		roles, err := m.resolveRoles(tx, ref.Guard, roleNames)
		if err != nil {
			return err
		}
		ids := make([]uint64, len(roles))
		for i, role := range roles {
			ids[i] = role.ID
		}
		return tx.Where("model_type = ? AND model_id = ? AND role_id IN ?", ref.Type, ref.ID, ids).
			Delete(&ModelHasRole{}).Error
	})
}

// SyncRoles replaces all roles on model with the given set (empty clears all).
func (m *Manager) SyncRoles(model Authorizable, roleNames ...string) error {
	ref, err := m.resolveModel(model)
	if err != nil {
		return err
	}
	return m.tx(func(tx *gorm.DB) error {
		var roles []Role
		if len(roleNames) > 0 {
			roles, err = m.resolveRoles(tx, ref.Guard, roleNames)
			if err != nil {
				return err
			}
		}
		if err := tx.Where("model_type = ? AND model_id = ?", ref.Type, ref.ID).
			Delete(&ModelHasRole{}).Error; err != nil {
			return err
		}
		for _, role := range roles {
			row := ModelHasRole{RoleID: role.ID, ModelType: ref.Type, ModelID: ref.ID}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// GivePermissionTo grants direct permissions to model (by permission name).
func (m *Manager) GivePermissionTo(model Authorizable, permissionNames ...string) error {
	ref, err := m.resolveModel(model)
	if err != nil {
		return err
	}
	return m.tx(func(tx *gorm.DB) error {
		perms, err := m.resolvePermissions(tx, ref.Guard, permissionNames)
		if err != nil {
			return err
		}
		for _, perm := range perms {
			if perm.GuardName != ref.Guard {
				return fmt.Errorf("%w: permission %q has guard %q, model expects %q",
					ErrGuardMismatch, perm.Name, perm.GuardName, ref.Guard)
			}
			row := ModelHasPermission{PermissionID: perm.ID, ModelType: ref.Type, ModelID: ref.ID}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokePermissionTo removes direct permissions from model.
func (m *Manager) RevokePermissionTo(model Authorizable, permissionNames ...string) error {
	ref, err := m.resolveModel(model)
	if err != nil {
		return err
	}
	return m.tx(func(tx *gorm.DB) error {
		perms, err := m.resolvePermissions(tx, ref.Guard, permissionNames)
		if err != nil {
			return err
		}
		ids := make([]uint64, len(perms))
		for i, perm := range perms {
			ids[i] = perm.ID
		}
		return tx.Where("model_type = ? AND model_id = ? AND permission_id IN ?", ref.Type, ref.ID, ids).
			Delete(&ModelHasPermission{}).Error
	})
}

// SyncPermissions replaces all direct permissions on model (empty clears all).
func (m *Manager) SyncPermissions(model Authorizable, permissionNames ...string) error {
	ref, err := m.resolveModel(model)
	if err != nil {
		return err
	}
	return m.tx(func(tx *gorm.DB) error {
		var perms []Permission
		if len(permissionNames) > 0 {
			perms, err = m.resolvePermissions(tx, ref.Guard, permissionNames)
			if err != nil {
				return err
			}
		}
		if err := tx.Where("model_type = ? AND model_id = ?", ref.Type, ref.ID).
			Delete(&ModelHasPermission{}).Error; err != nil {
			return err
		}
		for _, perm := range perms {
			row := ModelHasPermission{PermissionID: perm.ID, ModelType: ref.Type, ModelID: ref.ID}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// GivePermissionToRole attaches permissions to a role (by permission name).
// The role is reloaded from the database so caller-supplied GuardName is ignored.
func (m *Manager) GivePermissionToRole(role *Role, permissionNames ...string) error {
	return m.tx(func(tx *gorm.DB) error {
		role, err := m.loadRole(tx, role)
		if err != nil {
			return err
		}
		perms, err := m.resolvePermissions(tx, role.GuardName, permissionNames)
		if err != nil {
			return err
		}
		for _, perm := range perms {
			if perm.GuardName != role.GuardName {
				return fmt.Errorf("%w: permission %q has guard %q, role expects %q",
					ErrGuardMismatch, perm.Name, perm.GuardName, role.GuardName)
			}
			row := RoleHasPermission{PermissionID: perm.ID, RoleID: role.ID}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokePermissionFromRole removes permissions from a role.
func (m *Manager) RevokePermissionFromRole(role *Role, permissionNames ...string) error {
	return m.tx(func(tx *gorm.DB) error {
		role, err := m.loadRole(tx, role)
		if err != nil {
			return err
		}
		perms, err := m.resolvePermissions(tx, role.GuardName, permissionNames)
		if err != nil {
			return err
		}
		ids := make([]uint64, len(perms))
		for i, perm := range perms {
			ids[i] = perm.ID
		}
		return tx.Where("role_id = ? AND permission_id IN ?", role.ID, ids).
			Delete(&RoleHasPermission{}).Error
	})
}

// SyncPermissionsToRole replaces all permissions on a role (empty clears all).
func (m *Manager) SyncPermissionsToRole(role *Role, permissionNames ...string) error {
	return m.tx(func(tx *gorm.DB) error {
		role, err := m.loadRole(tx, role)
		if err != nil {
			return err
		}
		var perms []Permission
		if len(permissionNames) > 0 {
			perms, err = m.resolvePermissions(tx, role.GuardName, permissionNames)
			if err != nil {
				return err
			}
		}
		if err := tx.Where("role_id = ?", role.ID).Delete(&RoleHasPermission{}).Error; err != nil {
			return err
		}
		for _, perm := range perms {
			row := RoleHasPermission{PermissionID: perm.ID, RoleID: role.ID}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
