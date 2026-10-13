package permission

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// CreatePermission inserts a permission for the given guard (default guard when empty).
func (m *Manager) CreatePermission(name string, guard ...string) (*Permission, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: permission name is empty", ErrInvalidArgument)
	}
	g := m.guardOrDefault(first(guard))
	p := &Permission{Name: name, GuardName: g}
	if err := m.db.Create(p).Error; err != nil {
		return nil, err
	}
	return p, nil
}

// FindPermission looks up a permission by name and guard.
func (m *Manager) FindPermission(name string, guard ...string) (*Permission, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: permission name is empty", ErrInvalidArgument)
	}
	g := m.guardOrDefault(first(guard))
	var p Permission
	err := m.db.Where("name = ? AND guard_name = ?", name, g).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: permission %q guard %q", ErrNotFound, name, g)
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// FindOrCreatePermission returns an existing permission or creates it.
func (m *Manager) FindOrCreatePermission(name string, guard ...string) (*Permission, error) {
	p, err := m.FindPermission(name, guard...)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return m.CreatePermission(name, guard...)
}

// CreateRole inserts a role for the given guard (default guard when empty).
func (m *Manager) CreateRole(name string, guard ...string) (*Role, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: role name is empty", ErrInvalidArgument)
	}
	g := m.guardOrDefault(first(guard))
	r := &Role{Name: name, GuardName: g}
	if err := m.db.Create(r).Error; err != nil {
		return nil, err
	}
	return r, nil
}

// FindRole looks up a role by name and guard.
func (m *Manager) FindRole(name string, guard ...string) (*Role, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: role name is empty", ErrInvalidArgument)
	}
	g := m.guardOrDefault(first(guard))
	var r Role
	err := m.db.Where("name = ? AND guard_name = ?", name, g).First(&r).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: role %q guard %q", ErrNotFound, name, g)
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// FindOrCreateRole returns an existing role or creates it.
func (m *Manager) FindOrCreateRole(name string, guard ...string) (*Role, error) {
	r, err := m.FindRole(name, guard...)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return m.CreateRole(name, guard...)
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func normalizeNames(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: at least one name is required", ErrInvalidArgument)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			return nil, fmt.Errorf("%w: empty name", ErrInvalidArgument)
		}
		out = append(out, n)
	}
	return out, nil
}

func (m *Manager) resolvePermissions(guard string, names []string) ([]Permission, error) {
	names, err := normalizeNames(names)
	if err != nil {
		return nil, err
	}
	g := m.guardOrDefault(guard)
	var perms []Permission
	if err := m.db.Where("name IN ? AND guard_name = ?", names, g).Find(&perms).Error; err != nil {
		return nil, err
	}
	if len(perms) != len(names) {
		found := make(map[string]struct{}, len(perms))
		for _, p := range perms {
			found[p.Name] = struct{}{}
		}
		for _, name := range names {
			if _, ok := found[name]; !ok {
				return nil, fmt.Errorf("%w: permission %q guard %q", ErrNotFound, name, g)
			}
		}
	}
	return perms, nil
}

func (m *Manager) resolveRoles(guard string, names []string) ([]Role, error) {
	names, err := normalizeNames(names)
	if err != nil {
		return nil, err
	}
	g := m.guardOrDefault(guard)
	var roles []Role
	if err := m.db.Where("name IN ? AND guard_name = ?", names, g).Find(&roles).Error; err != nil {
		return nil, err
	}
	if len(roles) != len(names) {
		found := make(map[string]struct{}, len(roles))
		for _, r := range roles {
			found[r.Name] = struct{}{}
		}
		for _, name := range names {
			if _, ok := found[name]; !ok {
				return nil, fmt.Errorf("%w: role %q guard %q", ErrNotFound, name, g)
			}
		}
	}
	return roles, nil
}
