package permission

import (
	"fmt"
	"reflect"
)

// Authorizable is any model that can receive roles and permissions.
//
// ModelType should be a stable morph alias (for example "admins") when sharing
// a database with Laravel. Prefer the same value as a Spatie morph map entry
// rather than a raw PHP class name when both stacks write rows.
type Authorizable interface {
	PermissionModelID() uint64
	PermissionModelType() string
}

// GuardedAuthorizable optionally declares which guard checks should use.
// When absent, Manager.DefaultGuard is used.
type GuardedAuthorizable interface {
	Authorizable
	PermissionGuardName() string
}

type modelRef struct {
	ID    uint64
	Type  string
	Guard string
}

func (m *Manager) resolveModel(model Authorizable) (modelRef, error) {
	if m == nil {
		return modelRef{}, ErrInvalidArgument
	}
	if model == nil {
		return modelRef{}, fmt.Errorf("%w: model is nil", ErrInvalidArgument)
	}
	id := model.PermissionModelID()
	if id == 0 {
		return modelRef{}, fmt.Errorf("%w: model id cannot be zero", ErrInvalidArgument)
	}
	typ := model.PermissionModelType()
	if typ == "" {
		return modelRef{}, fmt.Errorf("%w: model type cannot be empty", ErrInvalidArgument)
	}
	guard := m.defaultGuard
	if g, ok := model.(GuardedAuthorizable); ok {
		if name := g.PermissionGuardName(); name != "" {
			guard = name
		}
	}
	return modelRef{ID: id, Type: typ, Guard: guard}, nil
}

// ModelFrom returns an Authorizable backed by an explicit id and morph type.
func ModelFrom(id uint64, modelType string) Authorizable {
	return staticModel{id: id, modelType: modelType}
}

// ModelFromGuard is ModelFrom with an explicit guard.
func ModelFromGuard(id uint64, modelType, guard string) Authorizable {
	return staticModel{id: id, modelType: modelType, guard: guard}
}

type staticModel struct {
	id        uint64
	modelType string
	guard     string
}

func (m staticModel) PermissionModelID() uint64   { return m.id }
func (m staticModel) PermissionModelType() string { return m.modelType }
func (m staticModel) PermissionGuardName() string { return m.guard }

// PrimaryKeyID extracts a numeric primary key from a GORM model value.
// Useful when wiring Authorizable without embedding permission helpers.
func PrimaryKeyID(model any) (uint64, error) {
	if model == nil {
		return 0, fmt.Errorf("%w: model is nil", ErrInvalidArgument)
	}
	v := reflect.ValueOf(model)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, fmt.Errorf("%w: model is nil", ErrInvalidArgument)
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, fmt.Errorf("%w: model must be a struct", ErrInvalidArgument)
	}
	field := v.FieldByName("ID")
	if !field.IsValid() {
		return 0, fmt.Errorf("%w: model has no ID field", ErrInvalidArgument)
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		id := field.Uint()
		if id == 0 {
			return 0, fmt.Errorf("%w: model id cannot be zero", ErrInvalidArgument)
		}
		return id, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		id := field.Int()
		if id <= 0 {
			return 0, fmt.Errorf("%w: model id must be positive", ErrInvalidArgument)
		}
		return uint64(id), nil
	default:
		return 0, fmt.Errorf("%w: unsupported ID type %s", ErrInvalidArgument, field.Kind())
	}
}
