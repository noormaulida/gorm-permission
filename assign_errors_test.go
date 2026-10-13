package permission_test

import (
	"errors"
	"testing"

	permission "github.com/noormaulida/gorm-permission"
	"gorm.io/gorm"
)

func forceCreateError(t *testing.T, db *gorm.DB) {
	t.Helper()
	name := "force_create_err_" + t.Name()
	_ = db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		_ = tx.AddError(errors.New("forced create failure"))
	})
	t.Cleanup(func() { _ = db.Callback().Create().Remove(name) })
}

func forceDeleteError(t *testing.T, db *gorm.DB) {
	t.Helper()
	name := "force_delete_err_" + t.Name()
	_ = db.Callback().Delete().Before("gorm:delete").Register(name, func(tx *gorm.DB) {
		_ = tx.AddError(errors.New("forced delete failure"))
	})
	t.Cleanup(func() { _ = db.Callback().Delete().Remove(name) })
}

func TestGivePermissionToInvalidModel(t *testing.T) {
	_, perm := setup(t)
	if err := perm.GivePermissionTo(nil, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}

func TestAssignRoleCreateError(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}
	forceCreateError(t, db)
	if err := perm.AssignRole(admin, "editor"); err == nil {
		t.Fatal("expected create error")
	}
}

func TestGivePermissionToCreateError(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}
	forceCreateError(t, db)
	if err := perm.GivePermissionTo(admin, "p1"); err == nil {
		t.Fatal("expected create error")
	}
}

func TestGivePermissionToRoleCreateError(t *testing.T) {
	db, perm := setup(t)
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}
	forceCreateError(t, db)
	if err := perm.GivePermissionToRole(role, "p1"); err == nil {
		t.Fatal("expected create error")
	}
}

func TestSyncRolesDeleteAndCreateErrors(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}

	forceDeleteError(t, db)
	if err := perm.SyncRoles(admin); err == nil {
		t.Fatal("expected delete error")
	}
	_ = db.Callback().Delete().Remove("force_delete_err_" + t.Name())

	forceCreateError(t, db)
	if err := perm.SyncRoles(admin, "editor"); err == nil {
		t.Fatal("expected create error")
	}
}

func TestSyncPermissionsDeleteAndCreateErrors(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}

	forceDeleteError(t, db)
	if err := perm.SyncPermissions(admin); err == nil {
		t.Fatal("expected delete error")
	}
	_ = db.Callback().Delete().Remove("force_delete_err_" + t.Name())

	forceCreateError(t, db)
	if err := perm.SyncPermissions(admin, "p1"); err == nil {
		t.Fatal("expected create error")
	}
}

func TestSyncPermissionsToRoleDeleteAndCreateErrors(t *testing.T) {
	db, perm := setup(t)
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}

	forceDeleteError(t, db)
	if err := perm.SyncPermissionsToRole(role); err == nil {
		t.Fatal("expected delete error")
	}
	_ = db.Callback().Delete().Remove("force_delete_err_" + t.Name())

	forceCreateError(t, db)
	if err := perm.SyncPermissionsToRole(role, "p1"); err == nil {
		t.Fatal("expected create error")
	}
}
