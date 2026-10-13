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
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	g := m.guardOrDefault(first(guard))
	p := &Permission{Name: name, GuardName: g}
	if err := db.Create(p).Error; err != nil {
		return nil, err
	}
	return p, nil
}

// FindPermission looks up a permission by name and guard.
func (m *Manager) FindPermission(name string, guard ...string) (*Permission, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: permission name is empty", ErrInvalidArgument)
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	g := m.guardOrDefault(first(guard))
	var p Permission
	err = db.Where("name = ? AND guard_name = ?", name, g).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: permission %q guard %q", ErrNotFound, name, g)
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// FindOrCreatePermission returns an existing permission or creates it.
// Concurrent creates that hit the unique (name, guard_name) index re-fetch.
func (m *Manager) FindOrCreatePermission(name string, guard ...string) (*Permission, error) {
	p, err := m.FindPermission(name, guard...)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	p, err = m.CreatePermission(name, guard...)
	if err == nil {
		return p, nil
	}
	if existing, findErr := m.FindPermission(name, guard...); findErr == nil {
		return existing, nil
	}
	return nil, err
}

// CreateRole inserts a role for the given guard (default guard when empty).
func (m *Manager) CreateRole(name string, guard ...string) (*Role, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: role name is empty", ErrInvalidArgument)
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	g := m.guardOrDefault(first(guard))
	r := &Role{Name: name, GuardName: g}
	if err := db.Create(r).Error; err != nil {
		return nil, err
	}
	return r, nil
}

// FindRole looks up a role by name and guard.
func (m *Manager) FindRole(name string, guard ...string) (*Role, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: role name is empty", ErrInvalidArgument)
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	g := m.guardOrDefault(first(guard))
	var r Role
	err = db.Where("name = ? AND guard_name = ?", name, g).First(&r).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: role %q guard %q", ErrNotFound, name, g)
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// FindOrCreateRole returns an existing role or creates it.
// Concurrent creates that hit the unique (name, guard_name) index re-fetch.
func (m *Manager) FindOrCreateRole(name string, guard ...string) (*Role, error) {
	r, err := m.FindRole(name, guard...)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	r, err = m.CreateRole(name, guard...)
	if err == nil {
		return r, nil
	}
	if existing, findErr := m.FindRole(name, guard...); findErr == nil {
		return existing, nil
	}
	return nil, err
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
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			return nil, fmt.Errorf("%w: empty name", ErrInvalidArgument)
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out, nil
}

func (m *Manager) resolvePermissions(guard string, names []string) ([]Permission, error) {
	names, err := normalizeNames(names)
	if err != nil {
		return nil, err
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	g := m.guardOrDefault(guard)
	var perms []Permission
	if err := db.Where("name IN ? AND guard_name = ?", names, g).Find(&perms).Error; err != nil {
		return nil, err
	}
	byName := make(map[string]Permission, len(perms))
	for _, p := range perms {
		byName[p.Name] = p
	}
	out := make([]Permission, 0, len(names))
	for _, name := range names {
		p, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("%w: permission %q guard %q", ErrNotFound, name, g)
		}
		out = append(out, p)
	}
	return out, nil
}

func (m *Manager) resolveRoles(guard string, names []string) ([]Role, error) {
	names, err := normalizeNames(names)
	if err != nil {
		return nil, err
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	g := m.guardOrDefault(guard)
	var roles []Role
	if err := db.Where("name IN ? AND guard_name = ?", names, g).Find(&roles).Error; err != nil {
		return nil, err
	}
	byName := make(map[string]Role, len(roles))
	for _, r := range roles {
		byName[r.Name] = r
	}
	out := make([]Role, 0, len(names))
	for _, name := range names {
		r, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("%w: role %q guard %q", ErrNotFound, name, g)
		}
		out = append(out, r)
	}
	return out, nil
}

func (m *Manager) loadRole(role *Role) (*Role, error) {
	if role == nil || role.ID == 0 {
		return nil, fmt.Errorf("%w: role is required", ErrInvalidArgument)
	}
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	var r Role
	err = db.First(&r, role.ID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: role id %d", ErrNotFound, role.ID)
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}
