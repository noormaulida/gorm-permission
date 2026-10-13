package permission_test

import (
	"errors"
	"testing"

	permission "github.com/noormaulida/gorm-permission"
)

func TestCreateAndFindPermission(t *testing.T) {
	_, perm := setup(t)

	_, err := perm.CreatePermission("")
	if !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty name: %v", err)
	}

	p, err := perm.CreatePermission("cms.a.view")
	if err != nil {
		t.Fatal(err)
	}
	if p.GuardName != "cms" {
		t.Fatalf("guard: %q", p.GuardName)
	}

	found, err := perm.FindPermission("cms.a.view")
	if err != nil || found.ID != p.ID {
		t.Fatalf("FindPermission: %+v err=%v", found, err)
	}

	_, err = perm.FindPermission("")
	if !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty find: %v", err)
	}

	explicit, err := perm.CreatePermission("web.only", "web")
	if err != nil {
		t.Fatal(err)
	}
	_, err = perm.FindPermission("web.only", "web")
	if err != nil {
		t.Fatal(err)
	}
	_, err = perm.FindPermission(explicit.Name) // default cms → not found
	if !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("expected not found on wrong guard, got %v", err)
	}
}

func TestCreateAndFindRole(t *testing.T) {
	_, perm := setup(t)

	_, err := perm.CreateRole("")
	if !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty name: %v", err)
	}
	_, err = perm.FindRole("")
	if !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty find: %v", err)
	}

	r, err := perm.CreateRole("editor", "cms")
	if err != nil {
		t.Fatal(err)
	}
	found, err := perm.FindRole("editor")
	if err != nil || found.ID != r.ID {
		t.Fatalf("FindRole: %+v err=%v", found, err)
	}
	_, err = perm.FindRole("missing")
	if !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFindOrCreatePermission(t *testing.T) {
	_, perm := setup(t)
	p1, err := perm.FindOrCreatePermission("p.create")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := perm.FindOrCreatePermission("p.create")
	if err != nil {
		t.Fatal(err)
	}
	if p1.ID != p2.ID {
		t.Fatalf("idempotent ids %d vs %d", p1.ID, p2.ID)
	}
}

func TestFindClosedDBErrors(t *testing.T) {
	_, perm := setup(t)
	sqlDB, err := perm.DB().DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()

	_, err = perm.CreatePermission("x")
	if err == nil {
		t.Fatal("CreatePermission expected error")
	}
	_, err = perm.FindPermission("x")
	if err == nil || errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("FindPermission expected db error, got %v", err)
	}
	_, err = perm.FindOrCreatePermission("x")
	if err == nil || errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("FindOrCreatePermission expected db error, got %v", err)
	}
	_, err = perm.CreateRole("x")
	if err == nil {
		t.Fatal("CreateRole expected error")
	}
	_, err = perm.FindRole("x")
	if err == nil || errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("FindRole expected db error, got %v", err)
	}
	_, err = perm.FindOrCreateRole("x")
	if err == nil || errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("FindOrCreateRole expected db error, got %v", err)
	}
}

func TestResolveMissingNames(t *testing.T) {
	db, perm := setup(t)
	admin := Admin{Name: "A", Email: "a@example.com"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreatePermission("exists"); err != nil {
		t.Fatal(err)
	}
	if _, err := perm.FindOrCreateRole("exists"); err != nil {
		t.Fatal(err)
	}

	err := perm.GivePermissionTo(admin, "exists", "missing")
	if !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("GivePermissionTo missing: %v", err)
	}
	err = perm.AssignRole(admin, "exists", "missing")
	if !errors.Is(err, permission.ErrNotFound) {
		t.Fatalf("AssignRole missing: %v", err)
	}
	err = perm.GivePermissionTo(admin)
	if !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("no names: %v", err)
	}
	err = perm.AssignRole(admin, "exists", "")
	if !errors.Is(err, permission.ErrInvalidArgument) {
		t.Fatalf("empty name in list: %v", err)
	}
}
