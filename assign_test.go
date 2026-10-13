package permission_test

import (
	"errors"
	"testing"

	permission "github.com/noormaulida/gorm-permission"
	"gorm.io/gorm"
)

func TestRemoveRoleAndRevokePermission(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("cms.pages.view"); err != nil {
		t.Fatal(err)
	}
	if err := perm.AssignRole(admin, "editor"); err != nil {
		t.Fatal(err)
	}
	if err := perm.GivePermissionTo(admin, "cms.pages.view"); err != nil {
		t.Fatal(err)
	}

	if err := perm.RemoveRole(admin, "editor"); err != nil {
		t.Fatal(err)
	}
	ok, err := perm.HasRole(admin, "editor")
	if err != nil || ok {
		t.Fatalf("role should be removed: ok=%v err=%v", ok, err)
	}

	if err := perm.RevokePermissionTo(admin, "cms.pages.view"); err != nil {
		t.Fatal(err)
	}
	ok, err = perm.HasDirectPermission(admin, "cms.pages.view")
	if err != nil || ok {
		t.Fatalf("permission should be revoked: ok=%v err=%v", ok, err)
	}
}

func TestSyncRolesAndPermissionsEmptyClears(t *testing.T) {
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
	_ = perm.AssignRole(admin, "editor")
	_ = perm.GivePermissionTo(admin, "p1")

	if err := perm.SyncRoles(admin); err != nil {
		t.Fatal(err)
	}
	roles, err := perm.GetRoles(admin)
	if err != nil || len(roles) != 0 {
		t.Fatalf("expected no roles, got %d err=%v", len(roles), err)
	}

	if err := perm.SyncPermissions(admin); err != nil {
		t.Fatal(err)
	}
	perms, err := perm.GetDirectPermissions(admin)
	if err != nil || len(perms) != 0 {
		t.Fatalf("expected no perms, got %d err=%v", len(perms), err)
	}
}

func TestRolePermissionAttachRevokeSync(t *testing.T) {
	_, perm := setup(t)
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p1", "p2", "p3"} {
		if _, err := perm.FindOrCreatePermission(name); err != nil {
			t.Fatal(err)
		}
	}

	if err := perm.GivePermissionToRole(nil, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil role: %v", err)
	}
	if err := perm.GivePermissionToRole(&permission.Role{}, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("zero id role: %v", err)
	}

	if err := perm.GivePermissionToRole(role, "p1", "p2"); err != nil {
		t.Fatal(err)
	}
	ok, err := perm.RoleHasPermission(role, "p1")
	if err != nil || !ok {
		t.Fatalf("RoleHasPermission: ok=%v err=%v", ok, err)
	}
	got, err := perm.GetRolePermissions(role)
	if err != nil || len(got) != 2 {
		t.Fatalf("GetRolePermissions: len=%d err=%v", len(got), err)
	}

	if err := perm.RevokePermissionFromRole(role, "p1"); err != nil {
		t.Fatal(err)
	}
	ok, _ = perm.RoleHasPermission(role, "p1")
	if ok {
		t.Fatal("p1 should be revoked")
	}

	if err := perm.SyncPermissionsToRole(role, "p3"); err != nil {
		t.Fatal(err)
	}
	ok, _ = perm.RoleHasPermission(role, "p2")
	if ok {
		t.Fatal("p2 should be cleared by sync")
	}
	ok, err = perm.RoleHasPermission(role, "p3")
	if err != nil || !ok {
		t.Fatalf("p3 missing: ok=%v err=%v", ok, err)
	}

	if err := perm.SyncPermissionsToRole(role); err != nil {
		t.Fatal(err)
	}
	got, err = perm.GetRolePermissions(role)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected cleared role perms, got %d err=%v", len(got), err)
	}

	if err := perm.RevokePermissionFromRole(nil, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("revoke nil role: %v", err)
	}
	if err := perm.SyncPermissionsToRole(&permission.Role{ID: 0}, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("sync zero role: %v", err)
	}
}

func TestAssignRoleIdempotentOnConflict(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}
	if err := perm.AssignRole(admin, "editor"); err != nil {
		t.Fatal(err)
	}
	if err := perm.AssignRole(admin, "editor"); err != nil {
		t.Fatalf("second assign should be no-op: %v", err)
	}
}

func TestGivePermissionToIdempotentOnConflict(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}
	if err := perm.GivePermissionTo(admin, "p1"); err != nil {
		t.Fatal(err)
	}
	if err := perm.GivePermissionTo(admin, "p1"); err != nil {
		t.Fatalf("second give should be no-op: %v", err)
	}
}

func TestGuardMismatchViaCallback(t *testing.T) {
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

	// After loading roles/permissions, rewrite GuardName so Assign/Give hit ErrGuardMismatch.
	_ = db.Callback().Query().After("gorm:query").Register("corrupt_role_guard", func(tx *gorm.DB) {
		switch dest := tx.Statement.Dest.(type) {
		case *[]permission.Role:
			for i := range *dest {
				(*dest)[i].GuardName = "tampered"
			}
		case *[]permission.Permission:
			for i := range *dest {
				(*dest)[i].GuardName = "tampered"
			}
		}
	})
	t.Cleanup(func() {
		_ = db.Callback().Query().Remove("corrupt_role_guard")
	})

	if err := perm.AssignRole(admin, "editor"); !errors.Is(err, permission.ErrGuardMismatch) {
		t.Fatalf("AssignRole guard mismatch: %v", err)
	}
	if err := perm.GivePermissionTo(admin, "p1"); !errors.Is(err, permission.ErrGuardMismatch) {
		t.Fatalf("GivePermissionTo guard mismatch: %v", err)
	}
}

func TestGivePermissionToRoleGuardMismatch(t *testing.T) {
	_, perm := setup(t)
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}
	// Empty role guard → resolvePermissions uses default guard, then compares to "".
	role.GuardName = ""
	if err := perm.GivePermissionToRole(role, "p1"); !errors.Is(err, permission.ErrGuardMismatch) {
		t.Fatalf("expected ErrGuardMismatch, got %v", err)
	}
}

func TestAssignValidationErrors(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	if err := perm.RemoveRole(nil, "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("RemoveRole nil: %v", err)
	}
	if err := perm.RevokePermissionTo(Admin{ID: 0}, "p"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("RevokePermissionTo zero id: %v", err)
	}
	if err := perm.SyncRoles(bareModel{id: 1, typ: ""}); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("SyncRoles bad model: %v", err)
	}
	if err := perm.SyncPermissions(bareModel{id: 1, typ: ""}); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("SyncPermissions bad model: %v", err)
	}

	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}
	if err := perm.SyncRoles(admin, "missing"); !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("SyncRoles missing: %v", err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}
	if err := perm.SyncPermissions(admin, "missing"); !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("SyncPermissions missing: %v", err)
	}
	if err := perm.RemoveRole(admin, "missing"); !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("RemoveRole missing: %v", err)
	}
	if err := perm.RevokePermissionTo(admin, "missing"); !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("RevokePermissionTo missing: %v", err)
	}
	role, _ := perm.FindOrCreateRole("editor")
	if err := perm.SyncPermissionsToRole(role, "missing"); !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("SyncPermissionsToRole missing: %v", err)
	}
	if err := perm.RevokePermissionFromRole(role, "missing"); !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("RevokePermissionFromRole missing: %v", err)
	}
	if err := perm.GivePermissionToRole(role, "missing"); !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("GivePermissionToRole missing: %v", err)
	}
}

func TestAssignClosedDBErrors(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}

	sqlDB, err := perm.DB().DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()

	if err := perm.AssignRole(admin, "editor"); err == nil {
		t.Fatal("AssignRole expected error")
	}
	if err := perm.RemoveRole(admin, "editor"); err == nil {
		t.Fatal("RemoveRole expected error")
	}
	if err := perm.SyncRoles(admin, "editor"); err == nil {
		t.Fatal("SyncRoles expected error")
	}
	if err := perm.GivePermissionTo(admin, "p1"); err == nil {
		t.Fatal("GivePermissionTo expected error")
	}
	if err := perm.RevokePermissionTo(admin, "p1"); err == nil {
		t.Fatal("RevokePermissionTo expected error")
	}
	if err := perm.SyncPermissions(admin, "p1"); err == nil {
		t.Fatal("SyncPermissions expected error")
	}
	if err := perm.GivePermissionToRole(role, "p1"); err == nil {
		t.Fatal("GivePermissionToRole expected error")
	}
	if err := perm.RevokePermissionFromRole(role, "p1"); err == nil {
		t.Fatal("RevokePermissionFromRole expected error")
	}
	if err := perm.SyncPermissionsToRole(role, "p1"); err == nil {
		t.Fatal("SyncPermissionsToRole expected error")
	}
}
