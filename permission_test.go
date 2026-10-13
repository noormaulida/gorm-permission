package permission_test

import (
	"errors"
	"os"
	"testing"

	permission "github.com/noormaulida/gorm-permission"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type Admin struct {
	ID    uint64
	Name  string
	Email string
}

func (a Admin) PermissionModelID() uint64   { return a.ID }
func (a Admin) PermissionModelType() string { return "admins" }
func (a Admin) PermissionGuardName() string { return "cms" }

func setup(t *testing.T) (*gorm.DB, *permission.Manager) {
	t.Helper()
	db := openTestDB(t)
	if err := db.AutoMigrate(&Admin{}); err != nil {
		t.Fatalf("migrate admin: %v", err)
	}
	if err := permission.Migrate(db); err != nil {
		t.Fatalf("migrate permission: %v", err)
	}
	enableForeignKeys(t, db)
	resetPermissionTables(t, db)
	return db, permission.New(db, permission.WithDefaultGuard("cms"))
}

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)}
	if dsn := os.Getenv("GORM_PERMISSION_MYSQL_DSN"); dsn != "" {
		db, err := gorm.Open(mysql.Open(dsn), cfg)
		if err != nil {
			t.Fatalf("open mysql: %v", err)
		}
		return db
	}
	if dsn := os.Getenv("GORM_PERMISSION_POSTGRES_DSN"); dsn != "" {
		db, err := gorm.Open(postgres.Open(dsn), cfg)
		if err != nil {
			t.Fatalf("open postgres: %v", err)
		}
		return db
	}
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), cfg)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

func enableForeignKeys(t *testing.T, db *gorm.DB) {
	t.Helper()
	if db.Dialector.Name() == "sqlite" {
		if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			t.Fatalf("enable sqlite foreign keys: %v", err)
		}
	}
}

func resetPermissionTables(t *testing.T, db *gorm.DB) {
	t.Helper()
	tables := []string{
		"role_has_permissions",
		"model_has_roles",
		"model_has_permissions",
		"roles",
		"permissions",
		"admins",
	}
	switch db.Dialector.Name() {
	case "mysql":
		if err := db.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
			t.Fatalf("disable fk checks: %v", err)
		}
		for _, table := range tables {
			if db.Migrator().HasTable(table) {
				if err := db.Exec("TRUNCATE TABLE " + table).Error; err != nil {
					t.Fatalf("truncate %s: %v", table, err)
				}
			}
		}
		if err := db.Exec("SET FOREIGN_KEY_CHECKS = 1").Error; err != nil {
			t.Fatalf("enable fk checks: %v", err)
		}
	case "postgres":
		for _, table := range tables {
			if db.Migrator().HasTable(table) {
				if err := db.Exec("TRUNCATE TABLE " + table + " RESTART IDENTITY CASCADE").Error; err != nil {
					t.Fatalf("truncate %s: %v", table, err)
				}
			}
		}
	}
}
func TestAssignRoleGivesPermissionsViaRole(t *testing.T) {
	db, perm := setup(t)

	admin := Admin{Name: "Noor", Email: "noor@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}

	role, err := perm.FindOrCreateRole("super-administrator")
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := perm.FindOrCreatePermission("cms.admins.view"); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if _, err := perm.FindOrCreatePermission("cms.admins.update"); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := perm.GivePermissionToRole(role, "cms.admins.view", "cms.admins.update"); err != nil {
		t.Fatalf("give permissions to role: %v", err)
	}
	if err := perm.AssignRole(admin, "super-administrator"); err != nil {
		t.Fatalf("assign role: %v", err)
	}

	ok, err := perm.HasPermissionTo(admin, "cms.admins.view")
	if err != nil || !ok {
		t.Fatalf("HasPermissionTo view: ok=%v err=%v", ok, err)
	}
	ok, err = perm.Can(admin, "cms.admins.update")
	if err != nil || !ok {
		t.Fatalf("Can update: ok=%v err=%v", ok, err)
	}
	ok, err = perm.HasRole(admin, "super-administrator")
	if err != nil || !ok {
		t.Fatalf("HasRole: ok=%v err=%v", ok, err)
	}
	ok, err = perm.HasPermissionTo(admin, "cms.settings.view")
	if err != nil || ok {
		t.Fatalf("unexpected permission: ok=%v err=%v", ok, err)
	}
}

func TestDirectPermissionAndSync(t *testing.T) {
	db, perm := setup(t)

	admin := Admin{Name: "Editor", Email: "editor@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	for _, name := range []string{"cms.pages.view", "cms.pages.update", "cms.pages.delete"} {
		if _, err := perm.FindOrCreatePermission(name); err != nil {
			t.Fatalf("create permission %s: %v", name, err)
		}
	}

	if err := perm.GivePermissionTo(admin, "cms.pages.view"); err != nil {
		t.Fatalf("give permission: %v", err)
	}
	ok, err := perm.HasDirectPermission(admin, "cms.pages.view")
	if err != nil || !ok {
		t.Fatalf("HasDirectPermission: ok=%v err=%v", ok, err)
	}

	if err := perm.SyncPermissions(admin, "cms.pages.update", "cms.pages.delete"); err != nil {
		t.Fatalf("sync permissions: %v", err)
	}
	ok, _ = perm.HasDirectPermission(admin, "cms.pages.view")
	if ok {
		t.Fatal("expected view permission revoked after sync")
	}
	ok, err = perm.HasAllPermissions(admin, "cms.pages.update", "cms.pages.delete")
	if err != nil || !ok {
		t.Fatalf("HasAllPermissions: ok=%v err=%v", ok, err)
	}
}

func TestSyncRoles(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	for _, name := range []string{"editor", "writer", "viewer"} {
		if _, err := perm.FindOrCreateRole(name); err != nil {
			t.Fatalf("create role %s: %v", name, err)
		}
	}
	if err := perm.AssignRole(admin, "editor", "writer"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := perm.SyncRoles(admin, "viewer"); err != nil {
		t.Fatalf("sync roles: %v", err)
	}
	ok, _ := perm.HasRole(admin, "editor")
	if ok {
		t.Fatal("editor should be removed")
	}
	ok, err := perm.HasRole(admin, "viewer")
	if err != nil || !ok {
		t.Fatalf("viewer missing: ok=%v err=%v", ok, err)
	}
	ok, err = perm.HasAllRoles(admin, "viewer")
	if err != nil || !ok {
		t.Fatalf("HasAllRoles: ok=%v err=%v", ok, err)
	}
	ok, err = perm.HasAnyRole(admin, "editor", "viewer")
	if err != nil || !ok {
		t.Fatalf("HasAnyRole: ok=%v err=%v", ok, err)
	}
}

func TestFindOrCreateIdempotent(t *testing.T) {
	_, perm := setup(t)
	r1, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := perm.FindOrCreateRole("editor")
	if err != nil {
		t.Fatal(err)
	}
	if r1.ID != r2.ID {
		t.Fatalf("expected same role id, got %d and %d", r1.ID, r2.ID)
	}
}

func TestMissingPermissionReturnsErrNotFound(t *testing.T) {
	_, perm := setup(t)
	_, err := perm.FindPermission("missing")
	if !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestModelFromHelper(t *testing.T) {
	_, perm := setup(t)
	if _, err := perm.FindOrCreateRole("editor"); err != nil {
		t.Fatal(err)
	}
	model := permission.ModelFromGuard(42, "admins", "cms")
	if err := perm.AssignRole(model, "editor"); err != nil {
		t.Fatalf("assign via ModelFrom: %v", err)
	}
	ok, err := perm.HasRole(model, "editor")
	if err != nil || !ok {
		t.Fatalf("HasRole: ok=%v err=%v", ok, err)
	}
}

func TestPrimaryKeyID(t *testing.T) {
	id, err := permission.PrimaryKeyID(Admin{ID: 9})
	if err != nil || id != 9 {
		t.Fatalf("PrimaryKeyID: id=%d err=%v", id, err)
	}
	_, err = permission.PrimaryKeyID(Admin{})
	if !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestGetAllPermissionsMergesDirectAndRole(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "Merge", Email: "m@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	role, _ := perm.FindOrCreateRole("editor")
	_, _ = perm.FindOrCreatePermission("via.role")
	_, _ = perm.FindOrCreatePermission("direct.perm")
	_ = perm.GivePermissionToRole(role, "via.role")
	_ = perm.AssignRole(admin, "editor")
	_ = perm.GivePermissionTo(admin, "direct.perm")

	all, err := perm.GetAllPermissions(admin)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range all {
		names[p.Name] = true
	}
	if !names["via.role"] || !names["direct.perm"] {
		t.Fatalf("expected merged permissions, got %#v", names)
	}
}
