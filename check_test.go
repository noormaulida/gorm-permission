package permission_test

import (
	"errors"
	"testing"

	permission "github.com/noormaulida/gorm-permission"
)

type flakyModel struct {
	id    uint64
	typ   string
	guard string
}

func (f *flakyModel) PermissionModelID() uint64   { return f.id }
func (f *flakyModel) PermissionModelType() string { return f.typ }
func (f *flakyModel) PermissionGuardName() string { return f.guard }

func TestGetRolesAndPermissions(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("direct"); err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("via.role"); err != nil {
		t.Fatal(err)
	}
	_ = perm.GivePermissionToRole(role, "via.role")
	_ = perm.AssignRole(admin, "editor")
	_ = perm.GivePermissionTo(admin, "direct")

	roles, err := perm.GetRoles(admin)
	if err != nil || len(roles) != 1 || roles[0].Name != "editor" {
		t.Fatalf("GetRoles: %+v err=%v", roles, err)
	}
	direct, err := perm.GetDirectPermissions(admin)
	if err != nil || len(direct) != 1 {
		t.Fatalf("GetDirectPermissions: %+v err=%v", direct, err)
	}
	via, err := perm.GetPermissionsViaRoles(admin)
	if err != nil || len(via) != 1 {
		t.Fatalf("GetPermissionsViaRoles: %+v err=%v", via, err)
	}
}

func TestGetHelpersInvalidModel(t *testing.T) {
	_, perm := setup(t)
	if _, err := perm.GetRoles(nil); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("GetRoles: %v", err)
	}
	if _, err := perm.GetDirectPermissions(Admin{}); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("GetDirectPermissions: %v", err)
	}
	if _, err := perm.GetPermissionsViaRoles(bareModel{id: 1, typ: ""}); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("GetPermissionsViaRoles: %v", err)
	}
	if _, err := perm.GetAllPermissions(nil); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("GetAllPermissions: %v", err)
	}
}

func TestHasRoleVariants(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"editor", "writer"} {
		if _, err := perm.FindOrCreateRole(name); err != nil {
			t.Fatal(err)
		}
	}
	_ = perm.AssignRole(admin, "editor")

	if _, err := perm.HasRole(admin, ""); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty role: %v", err)
	}
	if _, err := perm.HasRole(nil, "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil model: %v", err)
	}
	ok, err := perm.HasRole(admin, "writer")
	if err != nil || ok {
		t.Fatalf("should not have writer: ok=%v err=%v", ok, err)
	}

	if _, err := perm.HasAnyRole(admin); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("HasAnyRole empty: %v", err)
	}
	if _, err := perm.HasAnyRole(nil, "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("HasAnyRole nil: %v", err)
	}
	ok, err = perm.HasAnyRole(admin, "writer", "viewer")
	if err != nil || ok {
		t.Fatalf("HasAnyRole none: ok=%v err=%v", ok, err)
	}

	if _, err := perm.HasAllRoles(admin); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("HasAllRoles empty: %v", err)
	}
	if _, err := perm.HasAllRoles(nil, "editor"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("HasAllRoles nil: %v", err)
	}
	ok, err = perm.HasAllRoles(admin, "editor", "writer")
	if err != nil || ok {
		t.Fatalf("HasAllRoles incomplete: ok=%v err=%v", ok, err)
	}
}

func TestHasPermissionVariants(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p1", "p2", "p3"} {
		if _, err := perm.FindOrCreatePermission(name); err != nil {
			t.Fatal(err)
		}
	}
	_ = perm.GivePermissionTo(admin, "p1")

	if _, err := perm.HasDirectPermission(admin, ""); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := perm.HasDirectPermission(nil, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil: %v", err)
	}

	if _, err := perm.HasPermissionTo(admin, ""); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("HasPermissionTo empty: %v", err)
	}
	if _, err := perm.HasPermissionTo(nil, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("HasPermissionTo nil model: %v", err)
	}

	ok, err := perm.HasAnyPermission(admin, "p2", "p1")
	if err != nil || !ok {
		t.Fatalf("HasAnyPermission: ok=%v err=%v", ok, err)
	}
	ok, err = perm.HasAnyPermission(admin, "p2", "p3")
	if err != nil || ok {
		t.Fatalf("HasAnyPermission none: ok=%v err=%v", ok, err)
	}
	if _, err := perm.HasAnyPermission(admin); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("HasAnyPermission empty: %v", err)
	}

	ok, err = perm.HasAllPermissions(admin, "p1", "p2")
	if err != nil || ok {
		t.Fatalf("HasAllPermissions incomplete: ok=%v err=%v", ok, err)
	}
	if _, err := perm.HasAllPermissions(admin); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("HasAllPermissions empty: %v", err)
	}
}

func TestHasPermissionToViaRole(t *testing.T) {
	_, perm := setup(t)
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("via"); err != nil {
		t.Fatal(err)
	}
	_ = perm.GivePermissionToRole(role, "via")

	model := &flakyModel{id: 99, typ: "admins", guard: "cms"}
	_ = perm.AssignRole(model, "editor")

	ok, err := perm.HasPermissionTo(model, "via")
	if err != nil || !ok {
		t.Fatalf("via role: ok=%v err=%v", ok, err)
	}
}

func TestCrossGuardViaRoleDoesNotGrant(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	// cms permission linked through a web role — must not grant to a cms model.
	cmsPerm, err := perm.CreatePermission("secret", "cms")
	if err != nil {
		t.Fatal(err)
	}
	webRole, err := perm.CreateRole("leaky", "web")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&permission.RoleHasPermission{PermissionID: cmsPerm.ID, RoleID: webRole.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&permission.ModelHasRole{RoleID: webRole.ID, ModelType: "admins", ModelID: admin.ID}).Error; err != nil {
		t.Fatal(err)
	}

	ok, err := perm.HasPermissionTo(admin, "secret")
	if err != nil || ok {
		t.Fatalf("cms model must not inherit cms perm via web role: ok=%v err=%v", ok, err)
	}
	via, err := perm.GetPermissionsViaRoles(admin)
	if err != nil || len(via) != 0 {
		t.Fatalf("GetPermissionsViaRoles should be empty, got %+v err=%v", via, err)
	}
}
func TestRoleHasPermissionValidation(t *testing.T) {
	_, perm := setup(t)
	role, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}
	_ = perm.GivePermissionToRole(role, "p1")

	if _, err := perm.RoleHasPermission(nil, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil role: %v", err)
	}
	if _, err := perm.RoleHasPermission(&permission.Role{}, "p1"); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("zero role: %v", err)
	}
	if _, err := perm.RoleHasPermission(role, ""); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty perm: %v", err)
	}
	ok, err := perm.RoleHasPermission(role, "missing")
	if err != nil || ok {
		t.Fatalf("missing: ok=%v err=%v", ok, err)
	}

	if _, err := perm.GetRolePermissions(nil); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("GetRolePermissions nil: %v", err)
	}
	if _, err := perm.GetRolePermissions(&permission.Role{ID: 0}); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("GetRolePermissions zero: %v", err)
	}
}

func TestCheckClosedDBErrors(t *testing.T) {
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
	_ = perm.AssignRole(admin, "editor")
	_ = perm.GivePermissionTo(admin, "p1")
	_ = perm.GivePermissionToRole(role, "p1")

	sqlDB, err := perm.DB().DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()

	if _, err := perm.GetRoles(admin); err == nil {
		t.Fatal("GetRoles expected error")
	}
	if _, err := perm.GetDirectPermissions(admin); err == nil {
		t.Fatal("GetDirectPermissions expected error")
	}
	if _, err := perm.GetPermissionsViaRoles(admin); err == nil {
		t.Fatal("GetPermissionsViaRoles expected error")
	}
	if _, err := perm.GetAllPermissions(admin); err == nil {
		t.Fatal("GetAllPermissions expected error")
	}
	if _, err := perm.HasRole(admin, "editor"); err == nil {
		t.Fatal("HasRole expected error")
	}
	if _, err := perm.HasAnyRole(admin, "editor"); err == nil {
		t.Fatal("HasAnyRole expected error")
	}
	if _, err := perm.HasAllRoles(admin, "editor"); err == nil {
		t.Fatal("HasAllRoles expected error")
	}
	if _, err := perm.HasDirectPermission(admin, "p1"); err == nil {
		t.Fatal("HasDirectPermission expected error")
	}
	if _, err := perm.HasPermissionTo(admin, "p1"); err == nil {
		t.Fatal("HasPermissionTo expected error")
	}
	if _, err := perm.HasAnyPermission(admin, "p1"); err == nil {
		t.Fatal("HasAnyPermission expected error")
	}
	if _, err := perm.HasAllPermissions(admin, "p1"); err == nil {
		t.Fatal("HasAllPermissions expected error")
	}
	if _, err := perm.RoleHasPermission(role, "p1"); err == nil {
		t.Fatal("RoleHasPermission expected error")
	}
	if _, err := perm.GetRolePermissions(role); err == nil {
		t.Fatal("GetRolePermissions expected error")
	}
}

func TestGetAllPermissionsViaRolesError(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("p1"); err != nil {
		t.Fatal(err)
	}
	_ = perm.GivePermissionTo(admin, "p1")

	// Drop join table so via-roles query fails after direct succeeds.
	if err := perm.DB().Migrator().DropTable(&permission.ModelHasRole{}); err != nil {
		t.Fatal(err)
	}
	// Recreate empty roles path — actually GetPermissionsViaRoles joins model_has_roles;
	// dropping the table should error.
	if _, err := perm.GetAllPermissions(admin); err == nil {
		t.Fatal("expected error from via-roles query")
	}
}

func TestNilDBManagerTx(t *testing.T) {
	perm := permission.New(nil, permission.WithDefaultGuard("cms"))
	model := permission.ModelFromGuard(1, "admins", "cms")
	if err := perm.SyncRoles(model); !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("nil db tx: got %v", err)
	}
}
