package permission_test

import (
	"errors"
	"testing"

	permission "github.com/noormaulida/gorm-permission"
	"gorm.io/gorm"
)

func TestSyncDedupesDuplicateNames(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}

	if err := perm.SyncRoles(admin, "editor", "editor"); err != nil {
		t.Fatalf("SyncRoles duplicate names: %v", err)
	}
	if err := perm.SyncPermissions(admin, "p1", "p1"); err != nil {
		t.Fatalf("SyncPermissions duplicate names: %v", err)
	}
	role, err := perm.FindRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if err := perm.SyncPermissionsToRole(role, "p1", "p1"); err != nil {
		t.Fatalf("SyncPermissionsToRole duplicate names: %v", err)
	}
}

func TestUniqueNameGuardConstraint(t *testing.T) {
	_, perm := setup(t)
	if _, err := perm.CreatePermission("dup"); err != nil {
		t.Fatal(err)
	}
	if _, err := perm.CreatePermission("dup"); err == nil {
		t.Fatal("expected unique constraint on permission (name, guard_name)")
	}
	if _, err := perm.CreateRole("dup"); err != nil {
		t.Fatal(err)
	}
	if _, err := perm.CreateRole("dup"); err == nil {
		t.Fatal("expected unique constraint on role (name, guard_name)")
	}
}

func TestFindOrCreateRecoversWhenCreateConflicts(t *testing.T) {
	db, perm := setup(t)

	simRaceCreate := func(table, name string) {
		cb := "sim_race_" + table + "_" + t.Name()
		_ = db.Callback().Create().Before("gorm:create").Register(cb, func(tx *gorm.DB) {
			// Insert on a separate session so a failed Create does not roll it back.
			now := "2026-01-01 00:00:00"
			_ = db.Session(&gorm.Session{NewDB: true}).Exec(
				"INSERT INTO "+table+" (name, guard_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
				name, "cms", now, now,
			).Error
			_ = tx.AddError(errors.New("simulated unique conflict"))
		})
		t.Cleanup(func() { _ = db.Callback().Create().Remove(cb) })
	}

	simRaceCreate("permissions", "race.perm")
	p, err := perm.FindOrCreatePermission("race.perm")
	if err != nil || p == nil || p.Name != "race.perm" {
		t.Fatalf("permission recovery: p=%+v err=%v", p, err)
	}

	simRaceCreate("roles", "race.role")
	r, err := perm.FindOrCreateRole("race.role")
	if err != nil || r == nil || r.Name != "race.role" {
		t.Fatalf("role recovery: r=%+v err=%v", r, err)
	}
}
func TestNilManagerAndNilDB(t *testing.T) {
	var nilMgr *permission.Manager
	if nilMgr.DB() != nil {
		t.Fatal("nil manager DB()")
	}
	if nilMgr.DefaultGuard() != "" {
		t.Fatal("nil manager DefaultGuard()")
	}
	if _, err := nilMgr.FindPermission("x"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil manager FindPermission: %v", err)
	}
	if err := nilMgr.AssignRole(permission.ModelFrom(1, "admins"), "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil manager AssignRole: %v", err)
	}

	perm := permission.New(nil)
	if _, err := perm.HasRole(permission.ModelFromGuard(1, "admins", "cms"), "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil db HasRole: %v", err)
	}
	if _, err := perm.GetRoles(permission.ModelFromGuard(1, "admins", "cms")); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil db GetRoles: %v", err)
	}
	if _, err := perm.CreatePermission("x"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil db CreatePermission: %v", err)
	}
}

func TestLoadRoleNotFound(t *testing.T) {
	_, perm := setup(t)
	_, err := perm.RoleHasPermission(&permission.Role{ID: 99999, GuardName: "cms"}, "p1")
	if !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := perm.GivePermissionToRole(&permission.Role{ID: 99999}, "p1"); !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("GivePermissionToRole missing role: %v", err)
	}
}

func TestRoleHasPermissionEmptyName(t *testing.T) {
	_, perm := setup(t)
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := perm.RoleHasPermission(role, ""); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}
