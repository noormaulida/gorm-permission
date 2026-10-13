package permission_test

import (
	"testing"

	permission "github.com/noormaulida/gorm-permission"
)

func TestDeletingRoleCascadesPivots(t *testing.T) {
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
	if err := perm.GivePermissionToRole(role, "p1"); err != nil {
		t.Fatal(err)
	}
	if err := perm.AssignRole(admin, "editor"); err != nil {
		t.Fatal(err)
	}

	if err := db.Delete(&permission.Role{}, role.ID).Error; err != nil {
		t.Fatalf("delete role: %v", err)
	}

	var roleLinks int64
	if err := db.Model(&permission.ModelHasRole{}).Where("role_id = ?", role.ID).Count(&roleLinks).Error; err != nil {
		t.Fatal(err)
	}
	if roleLinks != 0 {
		t.Fatalf("expected model_has_roles cascaded, got %d", roleLinks)
	}
	var permLinks int64
	if err := db.Model(&permission.RoleHasPermission{}).Where("role_id = ?", role.ID).Count(&permLinks).Error; err != nil {
		t.Fatal(err)
	}
	if permLinks != 0 {
		t.Fatalf("expected role_has_permissions cascaded, got %d", permLinks)
	}
}

func TestDeletingPermissionCascadesPivots(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	p, err := perm.FindOrCreatePermission("p1")
	if err != nil {
		t.Fatal(err)
	}
	if err := perm.GivePermissionTo(admin, "p1"); err != nil {
		t.Fatal(err)
	}
	if err := perm.GivePermissionToRole(role, "p1"); err != nil {
		t.Fatal(err)
	}

	if err := db.Delete(&permission.Permission{}, p.ID).Error; err != nil {
		t.Fatalf("delete permission: %v", err)
	}

	var direct int64
	if err := db.Model(&permission.ModelHasPermission{}).Where("permission_id = ?", p.ID).Count(&direct).Error; err != nil {
		t.Fatal(err)
	}
	if direct != 0 {
		t.Fatalf("expected model_has_permissions cascaded, got %d", direct)
	}
	var viaRole int64
	if err := db.Model(&permission.RoleHasPermission{}).Where("permission_id = ?", p.ID).Count(&viaRole).Error; err != nil {
		t.Fatal(err)
	}
	if viaRole != 0 {
		t.Fatalf("expected role_has_permissions cascaded, got %d", viaRole)
	}
}

func TestHasAnyAndAllPermissionsViaRoleBatched(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"via.a", "via.b", "other"} {
		if _, err := perm.FindOrCreatePermission(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := perm.GivePermissionToRole(role, "via.a", "via.b"); err != nil {
		t.Fatal(err)
	}
	if err := perm.AssignRole(admin, "editor"); err != nil {
		t.Fatal(err)
	}

	ok, err := perm.HasAnyPermission(admin, "other", "via.a")
	if err != nil || !ok {
		t.Fatalf("HasAnyPermission via role: ok=%v err=%v", ok, err)
	}
	ok, err = perm.HasAllPermissions(admin, "via.a", "via.b")
	if err != nil || !ok {
		t.Fatalf("HasAllPermissions via role: ok=%v err=%v", ok, err)
	}
	ok, err = perm.HasAllPermissions(admin, "via.a", "other")
	if err != nil || ok {
		t.Fatalf("HasAllPermissions should fail for missing: ok=%v err=%v", ok, err)
	}
}
