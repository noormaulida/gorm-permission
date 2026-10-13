package permission

import (
	"errors"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openSilent(t *testing.T, name string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+name+"?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	_ = db.Exec("PRAGMA foreign_keys = ON")
	return db
}

func TestGuardOrDefaultNilManager(t *testing.T) {
	var m *Manager
	if got := m.guardOrDefault(""); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := m.guardOrDefault("cms"); got != "cms" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveModelNilManager(t *testing.T) {
	var m *Manager
	_, err := m.resolveModel(ModelFrom(1, "admins"))
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}

func TestFindOrCreateCreateFailsAndFindFails(t *testing.T) {
	db := openSilent(t, "find_or_create_fail")
	m := New(db, WithDefaultGuard("cms"))

	cb := "fail_create_only"
	_ = db.Callback().Create().Before("gorm:create").Register(cb, func(tx *gorm.DB) {
		_ = tx.AddError(errors.New("create blocked"))
	})
	t.Cleanup(func() { _ = db.Callback().Create().Remove(cb) })

	_, err := m.FindOrCreatePermission("missing.perm")
	if err == nil {
		t.Fatal("expected permission error")
	}
	_, err = m.FindOrCreateRole("missing.role")
	if err == nil {
		t.Fatal("expected role error")
	}
}

func TestLoadRoleDBError(t *testing.T) {
	db := openSilent(t, "load_role_db_err")
	m := New(db, WithDefaultGuard("cms"))
	role, err := m.CreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()
	_, err = m.loadRole(db, role)
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected db error, got %v", err)
	}
}

func TestNilDBCheckPaths(t *testing.T) {
	m := New(nil, WithDefaultGuard("cms"))
	model := ModelFromGuard(1, "admins", "cms")
	role := &Role{ID: 1, GuardName: "cms"}

	if _, err := m.GetDirectPermissions(model); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("GetDirectPermissions: %v", err)
	}
	if _, err := m.GetPermissionsViaRoles(model); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("GetPermissionsViaRoles: %v", err)
	}
	if _, err := m.HasAnyRole(model, "editor"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("HasAnyRole: %v", err)
	}
	if _, err := m.HasAllRoles(model, "editor"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("HasAllRoles: %v", err)
	}
	if _, err := m.HasDirectPermission(model, "p"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("HasDirectPermission: %v", err)
	}
	if _, err := m.HasPermissionTo(model, "p"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("HasPermissionTo: %v", err)
	}
	if _, err := m.HasAnyPermission(model, "p"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("HasAnyPermission: %v", err)
	}
	if _, err := m.HasAllPermissions(model, "p"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("HasAllPermissions: %v", err)
	}
	if _, err := m.RoleHasPermission(role, "p"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("RoleHasPermission: %v", err)
	}
	if _, err := m.GetRolePermissions(role); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("GetRolePermissions: %v", err)
	}
	if _, err := m.CreateRole("x"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("CreateRole: %v", err)
	}
	if _, err := m.FindRole("x"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("FindRole: %v", err)
	}
	if _, err := m.resolvePermissions(nil, "cms", []string{"p"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("resolvePermissions: %v", err)
	}
	if _, err := m.resolveRoles(nil, "cms", []string{"r"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("resolveRoles: %v", err)
	}
	if _, err := m.loadRole(nil, role); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("loadRole nil db: %v", err)
	}
}

func TestResolveFindDBErrors(t *testing.T) {
	db := openSilent(t, "resolve_find_err")
	m := New(db, WithDefaultGuard("cms"))
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()
	if _, err := m.resolvePermissions(db, "cms", []string{"p"}); err == nil {
		t.Fatal("resolvePermissions expected error")
	}
	if _, err := m.resolveRoles(db, "cms", []string{"r"}); err == nil {
		t.Fatal("resolveRoles expected error")
	}
}
